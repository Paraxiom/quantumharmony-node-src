//! # Pallet Substrate Attestation
//!
//! On-chain commitments to LLM weights provenance. Specified in
//! *Identity as Accountability Chain*, §11.5, and tracked as roadmap
//! item #6 in the treatise's §14 implementation plan
//! (Paraxiom/quantumharmony#34).
//!
//! ## What this pallet closes
//!
//! Today, "this model is a fine-tune of Mistral-7B" is a sentence in
//! a README. Nothing on chain disambiguates a clean fine-tune from a
//! quiet weight swap done on a forked branch. With AI agents
//! producing artifacts that get re-used as substrate for further
//! agents (Karmonic on Mistral on the 100k SMDR run, scheming-proofs
//! validators trained against …), the provenance graph is what makes
//! the *Identity as Accountability Chain* claim hold at the substrate
//! layer, not just at the per-task layer.
//!
//! This pallet records:
//!
//! - Model identity (auto-incremented `u64` so we don't bake in any
//!   particular naming convention) and the `ArtifactKind` (base,
//!   fine-tune, adapter, distilled).
//! - The weights hash and the IPFS CID for the manifest.
//! - The parent-model link, when applicable. For non-base
//!   artifacts the parent is *required*, by extrinsic-level check.
//! - An optional pointer to a `pallet_axiom_attestation` row, so a
//!   verifier can chase: weights → training run → agent task →
//!   audit chain.
//!
//! ## What this pallet is NOT
//!
//! - It does not store weights. They live on IPFS.
//! - It does not verify training. The chain only records the claim
//!   and the attester's identity; training-correctness proofs are
//!   off-chain (or future) work.
//! - It does not enforce a canonicalization of the weights manifest.
//!   The hash is whatever the attester committed to; consumers MUST
//!   verify the hash against the manifest they fetched, not trust
//!   the chain to have done it for them.
//!
//! ## Extrinsics
//!
//! - `commit_weights` — publish a new model commitment. Caller
//!   becomes its owner (only they can `revoke`).
//! - `revoke` — mark a model commitment as withdrawn. The row stays
//!   on chain for audit; only `revoked_at` is set.
//! - `attest_use` — emit an event recording that this model was
//!   used as substrate by the caller. Useful as input to
//!   `pallet_axiom_attestation` for Falcon-signed receipts.

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;
pub mod types;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use codec::Encode;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_io::hashing::blake2_256;
    use sp_std::vec::Vec;
    use types::{ArtifactKind, WeightCommitment, bound_cid};

    pub const LOG_TARGET: &str = "runtime::substrate-attestation";

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>>
            + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Maximum number of model commitments a single attester
        /// identity can carry at once. Cheap defence against
        /// runaway storage growth from a misconfigured pipeline; a
        /// separate governance process handles raising it
        /// deliberately.
        #[pallet::constant]
        type MaxModelsPerAttester: Get<u32>;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    /// Monotonically increasing model id. Allocated at
    /// `commit_weights` time; consumers refer to it in `revoke`,
    /// `attest_use`, and as the `parent_model` for derived
    /// artifacts.
    #[pallet::storage]
    pub type NextModelId<T: Config> = StorageValue<_, u64, ValueQuery>;

    /// The model commitments themselves, keyed by id.
    #[pallet::storage]
    pub type Models<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        u64,
        WeightCommitment<BlockNumberFor<T>>,
    >;

    /// Per-attester model count, used to enforce
    /// `MaxModelsPerAttester` and to make attester-side enumeration
    /// tractable without scanning.
    #[pallet::storage]
    pub type AttesterModelCount<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        u64,        // attester_identity
        u32,
        ValueQuery,
    >;

    /// Map from model id back to the AccountId that committed it,
    /// so `revoke` can require the same AccountId without re-reading
    /// the full commitment row.
    #[pallet::storage]
    pub type ModelOwner<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        u64,
        T::AccountId,
    >;

    /// How many on-chain descendants this model has. Pre-computed so
    /// `try_state` can sanity-check the lineage graph without
    /// iterating all models on each block.
    #[pallet::storage]
    pub type DescendantCount<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        u64,        // parent model id
        u32,
        ValueQuery,
    >;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A new model commitment was published.
        WeightsCommitted {
            id: u64,
            attester_identity: u64,
            kind: ArtifactKind,
            weights_hash: [u8; 32],
            parent_model: Option<u64>,
            owner: T::AccountId,
        },
        /// A model commitment was revoked.
        Revoked {
            id: u64,
            at: BlockNumberFor<T>,
        },
        /// A use of this model was attested by the caller. Used as
        /// input to downstream audit pallets.
        UseAttested {
            id: u64,
            caller: T::AccountId,
            caller_context_hash: [u8; 32],
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// No model with this id.
        UnknownModel,
        /// Caller isn't the original committer.
        NotCommitter,
        /// Attester already has the maximum number of models.
        ModelLimitReached,
        /// `ipfs_cid` exceeded the 128-byte bound.
        CidTooLong,
        /// `BaseModel` may not have a parent.
        BaseModelMustNotHaveParent,
        /// `FineTune`, `Adapter`, `Distilled` must have a parent.
        DerivedModelRequiresParent,
        /// The parent model id does not exist.
        ParentModelNotFound,
        /// Cannot inherit from a revoked parent — would graft a
        /// withdrawn artifact into the new commitment's lineage.
        ParentModelRevoked,
        /// Model is already revoked — revoking twice is a caller
        /// error, not a no-op.
        AlreadyRevoked,
        /// Cannot attest use of a revoked model.
        ModelRevoked,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Publish a new weights commitment. Caller becomes the
        /// owner (only they can `revoke` it). The chain does not
        /// validate `weights_hash` against IPFS — that's a
        /// consumer-side check.
        ///
        /// Parent-link discipline:
        /// - `BaseModel` MUST NOT carry a parent.
        /// - `FineTune`, `Adapter`, `Distilled` MUST carry a parent
        ///   that exists and is active.
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(60_000_000, 0))]
        pub fn commit_weights(
            origin: OriginFor<T>,
            attester_identity: u64,
            kind: ArtifactKind,
            weights_hash: [u8; 32],
            parent_model: Option<u64>,
            ipfs_cid: Vec<u8>,
            training_attestation_id: Option<u64>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let bounded_cid = bound_cid(ipfs_cid)
                .map_err(|_| Error::<T>::CidTooLong)?;

            match kind {
                ArtifactKind::BaseModel => {
                    ensure!(parent_model.is_none(), Error::<T>::BaseModelMustNotHaveParent);
                }
                ArtifactKind::FineTune | ArtifactKind::Adapter | ArtifactKind::Distilled => {
                    let parent_id = parent_model.ok_or(Error::<T>::DerivedModelRequiresParent)?;
                    let parent = Models::<T>::get(parent_id)
                        .ok_or(Error::<T>::ParentModelNotFound)?;
                    ensure!(parent.is_active(), Error::<T>::ParentModelRevoked);
                }
            }

            let count = AttesterModelCount::<T>::get(attester_identity);
            ensure!(
                count < T::MaxModelsPerAttester::get(),
                Error::<T>::ModelLimitReached
            );

            let id = NextModelId::<T>::get();
            let now = frame_system::Pallet::<T>::block_number();
            let commitment = WeightCommitment {
                attester_identity,
                kind: kind.clone(),
                weights_hash,
                parent_model,
                ipfs_cid: bounded_cid,
                training_attestation_id,
                created_at: now,
                revoked_at: None,
            };

            Models::<T>::insert(id, commitment);
            ModelOwner::<T>::insert(id, who.clone());
            AttesterModelCount::<T>::insert(
                attester_identity,
                count.saturating_add(1),
            );
            if let Some(parent_id) = parent_model {
                let prev = DescendantCount::<T>::get(parent_id);
                DescendantCount::<T>::insert(parent_id, prev.saturating_add(1));
            }
            NextModelId::<T>::put(id.saturating_add(1));

            log::info!(target: LOG_TARGET,
                "commit_weights id={} attester={} kind={:?} parent={:?} owner={:?}",
                id, attester_identity, kind, parent_model, who);

            Self::deposit_event(Event::WeightsCommitted {
                id,
                attester_identity,
                kind,
                weights_hash,
                parent_model,
                owner: who,
            });
            Ok(())
        }

        /// Mark a model commitment as revoked. The chain does not
        /// retroactively invalidate descendants — that would let a
        /// single revoke nuke an arbitrary lineage; instead,
        /// descendants stay live and consumers are expected to
        /// notice the revoked ancestor via the on-chain audit.
        ///
        /// Revocation is monotonic: once set, the operation cannot
        /// be undone, and `attest_use` against this model will fail
        /// from this block forward.
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(40_000_000, 0))]
        pub fn revoke(origin: OriginFor<T>, id: u64) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let owner = ModelOwner::<T>::get(id)
                .ok_or(Error::<T>::UnknownModel)?;
            ensure!(owner == who, Error::<T>::NotCommitter);

            let mut commitment = Models::<T>::get(id)
                .ok_or(Error::<T>::UnknownModel)?;
            ensure!(commitment.revoked_at.is_none(), Error::<T>::AlreadyRevoked);

            let now = frame_system::Pallet::<T>::block_number();
            commitment.revoked_at = Some(now);
            Models::<T>::insert(id, commitment);

            log::info!(target: LOG_TARGET,
                "revoke id={} at block {:?}", id, now);

            Self::deposit_event(Event::Revoked { id, at: now });
            Ok(())
        }

        /// Record an on-chain use of this model. The caller hashes
        /// their context (which agent, what dataset, etc.) and
        /// supplies it; we store only the hash so the row stays
        /// compact. Downstream audit pallets (e.g.
        /// `pallet_axiom_attestation`) can consume `UseAttested`
        /// events to produce Falcon-signed receipts.
        #[pallet::call_index(2)]
        #[pallet::weight(Weight::from_parts(30_000_000, 0))]
        pub fn attest_use(
            origin: OriginFor<T>,
            id: u64,
            caller_context: Vec<u8>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let commitment = Models::<T>::get(id)
                .ok_or(Error::<T>::UnknownModel)?;
            ensure!(commitment.is_active(), Error::<T>::ModelRevoked);

            let mut payload = Vec::with_capacity(caller_context.len() + 32);
            payload.extend_from_slice(&caller_context);
            payload.extend_from_slice(&id.encode());
            let caller_context_hash = blake2_256(&payload);

            Self::deposit_event(Event::UseAttested {
                id,
                caller: who,
                caller_context_hash,
            });
            Ok(())
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        #[cfg(feature = "try-runtime")]
        fn try_state(_n: BlockNumberFor<T>) -> Result<(), sp_runtime::TryRuntimeError> {
            // Invariant 1: per-attester model count == actual
            // models for that attester. Quadratic, but try-state is
            // debug-only.
            for (attester, count) in AttesterModelCount::<T>::iter() {
                let actual = Models::<T>::iter()
                    .filter(|(_, m)| m.attester_identity == attester)
                    .count() as u32;
                if actual != count {
                    log::error!(
                        target: LOG_TARGET,
                        "try_state: attester {} count mismatch (stored {}, actual {})",
                        attester, count, actual
                    );
                    return Err(sp_runtime::TryRuntimeError::Other(
                        "attester model count mismatch",
                    ));
                }
            }
            // Invariant 2: every model has an owner row.
            for (id, _) in Models::<T>::iter() {
                if !ModelOwner::<T>::contains_key(id) {
                    log::error!(
                        target: LOG_TARGET,
                        "try_state: model {} has no owner",
                        id
                    );
                    return Err(sp_runtime::TryRuntimeError::Other(
                        "model without owner",
                    ));
                }
            }
            // Invariant 3: descendant-count consistency.
            for (parent, count) in DescendantCount::<T>::iter() {
                let actual = Models::<T>::iter()
                    .filter(|(_, m)| m.parent_model == Some(parent))
                    .count() as u32;
                if actual != count {
                    log::error!(
                        target: LOG_TARGET,
                        "try_state: parent {} descendant count mismatch (stored {}, actual {})",
                        parent, count, actual
                    );
                    return Err(sp_runtime::TryRuntimeError::Other(
                        "descendant count mismatch",
                    ));
                }
            }
            Ok(())
        }
    }
}
