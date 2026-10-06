//! # Pallet Credential Vault
//!
//! On-chain commitments to off-chain (IPFS-resident) encrypted
//! credentials. Specified in *Identity as Accountability Chain*,
//! Appendix B.3, and tracked as roadmap item #4 in the treatise's
//! §14 implementation plan (Paraxiom/quantumharmony#35).
//!
//! ## What this pallet closes
//!
//! The 2026-05-28 testnet incident
//! (Paraxiom/quantumharmony#33) cost ~24 hours of operational
//! attention because the chain's sudo signer was a single keystore
//! file on a single host with no on-chain pointer. Recovery worked
//! only because the file was still there; if the host had been
//! lost, we would not have been able to recover finality at all.
//!
//! The credential vault makes this incident class
//! *cryptographically* preventable on mainnet:
//!
//! - Sudo (or any operationally-critical) secret is encrypted with a
//!   symmetric key whose master is split among an N-of-M holder
//!   quorum off-chain. The ciphertext is published to IPFS.
//! - The chain stores only the *commitment*: holder identity,
//!   service name, CID, content hash, IV hint, and the activation
//!   block.
//! - Revocation is a one-way `revoke` extrinsic that records the
//!   master-key destruction event. Once a commitment is revoked, no
//!   adversary — including the chain operator — can decrypt the
//!   ciphertext, because the master key has been provably destroyed
//!   off-chain.
//!
//! This last property is the on-chain expression of Theorem 11
//! (crypto-shredding completeness) from the treatise. A future
//! "the sudo key was lost" incident either (a) doesn't happen,
//! because the holder accesses the vault, or (b) is provably
//! unrecoverable, because the master key was destroyed — a
//! deliberate act with on-chain audit, instead of the ambiguous
//! "we can't find the file" state we lived through.
//!
//! ## What this pallet is NOT
//!
//! - It does not perform decryption. Off-chain holders fetch the
//!   ciphertext from IPFS, gather quorum signatures off-chain, and
//!   reconstruct the master key in a protected enclave.
//! - It does not enforce a quorum scheme. The chain only records
//!   commitments and their activation/revocation; how the
//!   off-chain holders organize is policy.
//! - It does not hold the secret on chain. Storing the secret would
//!   defeat the entire architecture.
//!
//! ## Extrinsics
//!
//! - `commit` — publish a new commitment. Caller becomes its
//!   holder for the purpose of `revoke` authorization.
//! - `revoke` — mark a commitment as no longer valid. The
//!   commitment row stays on chain for audit; only the
//!   `revoked_at` field is set.
//! - `attest_use` — emit an event recording that this commitment
//!   was retrieved off-chain. Useful as input to
//!   `pallet_axiom_attestation` for Falcon-signed audit receipts.

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
    use types::{Commitment, CredentialKind, bound_cid, bound_service_name};

    pub const LOG_TARGET: &str = "runtime::credential-vault";

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>>
            + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Maximum number of commitments a single holder identity
        /// can carry at once. Cheap defence against runaway storage
        /// growth from a compromised holder; a separate governance
        /// process handles raising it deliberately.
        #[pallet::constant]
        type MaxCommitmentsPerHolder: Get<u32>;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    /// Monotonically increasing commitment id. Allocated at `commit`
    /// time; consumers refer to it in `revoke` and `attest_use`.
    #[pallet::storage]
    pub type NextCommitmentId<T: Config> = StorageValue<_, u64, ValueQuery>;

    /// The commitments themselves, keyed by id.
    #[pallet::storage]
    pub type Commitments<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        u64,
        Commitment<BlockNumberFor<T>>,
    >;

    /// Per-holder count, used to enforce `MaxCommitmentsPerHolder`
    /// and to make holder-side enumeration tractable without a
    /// scan.
    #[pallet::storage]
    pub type HolderCommitmentCount<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        u64,        // holder_identity
        u32,
        ValueQuery,
    >;

    /// Map from commitment id back to its committer's AccountId, so
    /// `revoke` can require the same AccountId without re-reading the
    /// full commitment row.
    #[pallet::storage]
    pub type CommitmentOwner<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        u64,
        T::AccountId,
    >;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A new commitment was published.
        Committed {
            id: u64,
            holder_identity: u64,
            credential_kind: CredentialKind,
            ciphertext_hash: [u8; 32],
            owner: T::AccountId,
        },
        /// A commitment was revoked (the master key has been
        /// destroyed off-chain; future decryption is infeasible).
        Revoked {
            id: u64,
            at: BlockNumberFor<T>,
        },
        /// A use of this commitment was attested by the caller.
        /// Used as input to downstream audit pallets.
        UseAttested {
            id: u64,
            caller: T::AccountId,
            caller_context_hash: [u8; 32],
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// No commitment with this id.
        UnknownCommitment,
        /// Caller isn't the original committer.
        NotCommitter,
        /// Holder already has the maximum number of commitments.
        CommitmentLimitReached,
        /// `service_name` exceeded the 64-byte bound.
        ServiceNameTooLong,
        /// `ciphertext_cid` exceeded the 128-byte bound.
        CidTooLong,
        /// Commitment is already revoked — revoking twice is a
        /// caller error, not a no-op.
        AlreadyRevoked,
        /// Cannot attest use of a revoked commitment.
        CommitmentRevoked,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Publish a new credential commitment. Caller becomes the
        /// owner (only they can `revoke` it). The chain does not
        /// validate `ciphertext_hash` against IPFS — that's a
        /// consumer-side check.
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(60_000_000, 0))]
        pub fn commit(
            origin: OriginFor<T>,
            holder_identity: u64,
            service_name: Vec<u8>,
            credential_kind: CredentialKind,
            ciphertext_cid: Vec<u8>,
            ciphertext_hash: [u8; 32],
            iv_hint: [u8; 12],
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let bounded_name = bound_service_name(service_name)
                .map_err(|_| Error::<T>::ServiceNameTooLong)?;
            let bounded_cid = bound_cid(ciphertext_cid)
                .map_err(|_| Error::<T>::CidTooLong)?;

            let count = HolderCommitmentCount::<T>::get(holder_identity);
            ensure!(
                count < T::MaxCommitmentsPerHolder::get(),
                Error::<T>::CommitmentLimitReached
            );

            let id = NextCommitmentId::<T>::get();
            let now = frame_system::Pallet::<T>::block_number();
            let commitment = Commitment {
                holder_identity,
                service_name: bounded_name,
                credential_kind: credential_kind.clone(),
                ciphertext_cid: bounded_cid,
                ciphertext_hash,
                iv_hint,
                created_at: now,
                revoked_at: None,
            };

            Commitments::<T>::insert(id, commitment);
            CommitmentOwner::<T>::insert(id, who.clone());
            HolderCommitmentCount::<T>::insert(
                holder_identity,
                count.saturating_add(1),
            );
            NextCommitmentId::<T>::put(id.saturating_add(1));

            log::info!(target: LOG_TARGET,
                "commit id={} holder={} kind={:?} owner={:?}",
                id, holder_identity, credential_kind, who);

            Self::deposit_event(Event::Committed {
                id,
                holder_identity,
                credential_kind,
                ciphertext_hash,
                owner: who,
            });
            Ok(())
        }

        /// Mark a commitment as revoked. The chain doesn't verify
        /// that the master key was actually destroyed off-chain —
        /// that's an off-chain quorum protocol. What we *do*
        /// guarantee on chain is that once a commitment is revoked,
        /// no later call can un-revoke it: the operation is
        /// monotonic and audited.
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(40_000_000, 0))]
        pub fn revoke(origin: OriginFor<T>, id: u64) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let owner = CommitmentOwner::<T>::get(id)
                .ok_or(Error::<T>::UnknownCommitment)?;
            ensure!(owner == who, Error::<T>::NotCommitter);

            let mut commitment = Commitments::<T>::get(id)
                .ok_or(Error::<T>::UnknownCommitment)?;
            ensure!(commitment.revoked_at.is_none(), Error::<T>::AlreadyRevoked);

            let now = frame_system::Pallet::<T>::block_number();
            commitment.revoked_at = Some(now);
            Commitments::<T>::insert(id, commitment);

            log::info!(target: LOG_TARGET,
                "revoke id={} at block {:?}", id, now);

            Self::deposit_event(Event::Revoked { id, at: now });
            Ok(())
        }

        /// Record an off-chain retrieval of this commitment. The
        /// caller hashes their context (audit trail metadata,
        /// quorum signatures, …) and supplies it; we only store the
        /// hash so the on-chain row stays compact. Downstream audit
        /// pallets (e.g. `pallet_axiom_attestation`) can consume
        /// `UseAttested` events to produce Falcon-signed receipts.
        ///
        /// Attempting to attest use of a revoked commitment is a
        /// caller error: a revoked commitment is by definition
        /// undecryptable, so any claim of "using" it after
        /// revocation is suspect.
        #[pallet::call_index(2)]
        #[pallet::weight(Weight::from_parts(30_000_000, 0))]
        pub fn attest_use(
            origin: OriginFor<T>,
            id: u64,
            caller_context: Vec<u8>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let commitment = Commitments::<T>::get(id)
                .ok_or(Error::<T>::UnknownCommitment)?;
            ensure!(commitment.is_active(), Error::<T>::CommitmentRevoked);

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
            // Invariant 1: per-holder count == actual commitments for
            // that holder. Quadratic in commitment count, but
            // try-state is debug-only.
            for (holder, count) in HolderCommitmentCount::<T>::iter() {
                let actual = Commitments::<T>::iter()
                    .filter(|(_, c)| c.holder_identity == holder)
                    .count() as u32;
                if actual != count {
                    log::error!(
                        target: LOG_TARGET,
                        "try_state: holder {} count mismatch (stored {}, actual {})",
                        holder, count, actual
                    );
                    return Err(sp_runtime::TryRuntimeError::Other(
                        "holder commitment count mismatch",
                    ));
                }
            }
            // Invariant 2: every Commitments key has a matching
            // CommitmentOwner entry. If not, `revoke` will fail
            // permanently.
            for (id, _) in Commitments::<T>::iter() {
                if !CommitmentOwner::<T>::contains_key(id) {
                    log::error!(
                        target: LOG_TARGET,
                        "try_state: commitment {} has no owner",
                        id
                    );
                    return Err(sp_runtime::TryRuntimeError::Other(
                        "commitment without owner",
                    ));
                }
            }
            Ok(())
        }
    }
}
