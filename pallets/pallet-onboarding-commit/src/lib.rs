//! # Pallet Onboarding Commit
//!
//! Commit-reveal flow that binds an aura public key to an AccountId at
//! commit-time, with a dispute window and a slashable bond. Replaces the
//! silent-failure surface of the old `addValidator` extrinsic.
//!
//! ## Flow
//!
//! 1. Operator generates `(aura_pubkey, account_id)` locally.
//! 2. Operator computes `commit_hash = blake2_256(aura_pubkey || account_id || nonce)`.
//! 3. Operator calls `commit(commit_hash)` with bond reserved from their account.
//! 4. Operator waits `DisputeWindow` blocks. During this window, anyone can
//!    `challenge(commit_hash, evidence)` if the commit appears bad-faith.
//! 5. After the window, operator calls `reveal(aura_pubkey, account_id, nonce)`.
//!    The pallet:
//!    - verifies the hash matches,
//!    - releases the bond,
//!    - calls into `ValidatorMutator::add_validator(account_id)`.
//! 6. If the operator never reveals, the bond stays locked forever — discouraging spam.
//!
//! ## Why this beats the old extrinsic
//!
//! The old `addValidator(validator_id)` was unilateral: sudo signs, and the
//! validator joins immediately. There was no public commitment phase, so:
//! - typo'd pubkeys went silently into the active set,
//! - key-takeover attempts couldn't be challenged before binding,
//! - failure modes were silent (the orchestrator caught some, runtime caught none).
//!
//! With commit-reveal:
//! - the pubkey is bound at commit-time (any later reveal must match the hash),
//! - challengers have a 50-block window to surface bad-faith commits,
//! - bond + slashing make spam economically unattractive.

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
    use frame_support::{
        pallet_prelude::*,
        sp_runtime::Saturating,
        traits::{Currency, ReservableCurrency},
    };
    use frame_system::pallet_prelude::*;
    use sp_io::hashing::blake2_256;
    use sp_std::vec::Vec;
    use types::{CommitInfo, OnboardingKind};

    pub const LOG_TARGET: &str = "runtime::onboarding-commit";

    pub type BalanceOf<T> =
        <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

    /// Hook into whatever pallet actually maintains the validator set.
    /// In QuantumHarmony, this is implemented by `substrate-validator-set`'s
    /// `add_validator_internal`.
    pub trait ValidatorMutator<AccountId> {
        fn add_validator(account_id: AccountId) -> DispatchResult;
    }

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>>
            + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Currency type for bond reservation.
        type Currency: ReservableCurrency<Self::AccountId>;

        /// Bond required at commit-time. Slashed on successful challenge,
        /// returned on successful reveal.
        #[pallet::constant]
        type CommitBond: Get<BalanceOf<Self>>;

        /// Number of blocks between commit and earliest possible reveal.
        /// Anyone can `challenge` during this window. Default 50 (~5 min).
        #[pallet::constant]
        type DisputeWindow: Get<BlockNumberFor<Self>>;

        /// Hook to actually add the validator after a clean reveal.
        type ValidatorMutator: ValidatorMutator<Self::AccountId>;
    }

    /// SPHINCS+-256f-simple public key length in this fork.
    /// `reveal()` rejects any submission of a different length so a
    /// malformed key never reaches the validator-mutator hook.
    pub const AURA_PUBKEY_LEN: usize = 64;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    /// Outstanding commits, keyed by `commit_hash`.
    #[pallet::storage]
    pub type Commits<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        [u8; 32],
        CommitInfo<T::AccountId, BlockNumberFor<T>, BalanceOf<T>>,
    >;

    /// Aura pubkeys that have been successfully revealed and added, keyed
    /// by `blake2_256(aura_pubkey)`. Storing the hash (fixed 32 bytes) instead
    /// of the raw pubkey (variable length, breaks MaxEncodedLen) costs us
    /// nothing — we only ever look up by computed hash anyway.
    /// Prevents a second commit from later re-revealing the same pubkey
    /// under a different account.
    #[pallet::storage]
    pub type RevealedPubkeys<T: Config> =
        StorageMap<_, Blake2_128Concat, [u8; 32], T::AccountId>;

    /// What kind of onboarding this commit is for. New storage map
    /// with `ValueQuery` default = `OnboardingKind::Validator` so any
    /// pre-v43 commit row (committed via the original `commit()`
    /// extrinsic before this generalization shipped) decodes as
    /// `Validator` — preserves the existing reveal flow without a
    /// storage migration. The v43+ kind-aware extrinsic
    /// `commit_with_kind()` writes here explicitly.
    #[pallet::storage]
    pub type CommitKind<T: Config> =
        StorageMap<_, Blake2_128Concat, [u8; 32], OnboardingKind, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        Committed {
            who: T::AccountId,
            commit_hash: [u8; 32],
            bond: BalanceOf<T>,
            window_ends: BlockNumberFor<T>,
        },
        Revealed {
            who: T::AccountId,
            commit_hash: [u8; 32],
        },
        ChallengedDuplicatePubkey {
            challenger: T::AccountId,
            commit_hash: [u8; 32],
        },
        Slashed {
            commit_hash: [u8; 32],
            amount: BalanceOf<T>,
        },
        /// A generic-kind commit was revealed. Downstream pallets
        /// (gov-app event subscriber, …) listen for this and act on
        /// the payload off-chain or in their own state.
        GenericRevealed {
            who: T::AccountId,
            commit_hash: [u8; 32],
            payload_hash: [u8; 32],
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Commit hash already exists.
        DuplicateCommit,
        /// No commit found for this hash.
        UnknownCommit,
        /// Reveal attempted before dispute window expired.
        DisputeWindowOpen,
        /// Reveal hash doesn't match the original commit.
        HashMismatch,
        /// Aura pubkey already bound to a different account.
        PubkeyAlreadyRevealed,
        /// Bond reservation failed (insufficient balance).
        BondFailed,
        /// Reveal called by a different account than the committer.
        NotCommitter,
        /// Already revealed.
        AlreadyRevealed,
        /// Aura pubkey was not the expected SPHINCS+ length (64 bytes).
        InvalidPubkeyLength,
        /// Reveal extrinsic was called on a commit whose `OnboardingKind`
        /// doesn't match it (e.g. `reveal()` on a Generic commit, or
        /// `reveal_generic()` on a Validator commit).
        WrongOnboardingKind,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Lock a bond and publish a commitment to onboard.
        ///
        /// `commit_hash = blake2_256(aura_pubkey || account_id || nonce)`
        ///
        /// The committer is `origin`. They will be the only account allowed
        /// to call `reveal()` for this commit hash.
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(50_000_000, 0))]
        pub fn commit(origin: OriginFor<T>, commit_hash: [u8; 32]) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(
                !Commits::<T>::contains_key(&commit_hash),
                Error::<T>::DuplicateCommit
            );

            let bond = T::CommitBond::get();
            T::Currency::reserve(&who, bond).map_err(|_| Error::<T>::BondFailed)?;

            let now = frame_system::Pallet::<T>::block_number();
            let window = T::DisputeWindow::get();
            Commits::<T>::insert(
                &commit_hash,
                CommitInfo {
                    committer: who.clone(),
                    block: now,
                    bond,
                    revealed: false,
                },
            );

            log::info!(target: LOG_TARGET, "commit accepted from {:?} at block {:?}", who, now);
            Self::deposit_event(Event::Committed {
                who,
                commit_hash,
                bond,
                window_ends: now.saturating_add(window),
            });
            Ok(())
        }

        /// After dispute window expires, reveal the underlying values to
        /// onboard the validator. The bond is unreserved.
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(80_000_000, 0))]
        pub fn reveal(
            origin: OriginFor<T>,
            aura_pubkey: Vec<u8>,
            account_id: T::AccountId,
            nonce: [u8; 32],
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            // Fail-fast on malformed keys so a wrong-length pubkey never
            // reaches the validator-mutator hook (defence in depth: the
            // mutator would reject it too, but the rejection there is
            // less specific to operators debugging onboarding).
            ensure!(
                aura_pubkey.len() == AURA_PUBKEY_LEN,
                Error::<T>::InvalidPubkeyLength
            );

            let mut payload = Vec::with_capacity(aura_pubkey.len() + 32 + 32);
            payload.extend_from_slice(&aura_pubkey);
            payload.extend_from_slice(&account_id.encode());
            payload.extend_from_slice(&nonce);
            let commit_hash = blake2_256(&payload);

            let mut info = Commits::<T>::get(&commit_hash).ok_or(Error::<T>::UnknownCommit)?;
            ensure!(info.committer == who, Error::<T>::NotCommitter);
            ensure!(!info.revealed, Error::<T>::AlreadyRevealed);

            // v43 generalization: refuse to reveal a Generic-kind commit
            // through the validator path. ValueQuery default = Validator,
            // so pre-v43 entries unaffected.
            ensure!(
                CommitKind::<T>::get(&commit_hash) == OnboardingKind::Validator,
                Error::<T>::WrongOnboardingKind
            );

            let now = frame_system::Pallet::<T>::block_number();
            let window = T::DisputeWindow::get();
            ensure!(
                now >= info.block.saturating_add(window),
                Error::<T>::DisputeWindowOpen
            );

            let pubkey_hash = blake2_256(&aura_pubkey);
            ensure!(
                !RevealedPubkeys::<T>::contains_key(&pubkey_hash),
                Error::<T>::PubkeyAlreadyRevealed
            );

            // Bind the pubkey first, so that any subsequent commit using the
            // same pubkey can be challenged via DuplicatePubkey.
            RevealedPubkeys::<T>::insert(&pubkey_hash, &account_id);
            info.revealed = true;
            Commits::<T>::insert(&commit_hash, info.clone());

            // Hook into validator-set: add the validator.
            T::ValidatorMutator::add_validator(account_id.clone())?;

            // Release the bond.
            T::Currency::unreserve(&who, info.bond);

            log::info!(target: LOG_TARGET, "reveal accepted from {:?} at block {:?}", who, now);
            Self::deposit_event(Event::Revealed { who, commit_hash });
            Ok(())
        }

        /// Surface a bad-faith commit during the dispute window.
        ///
        /// `evidence` is the raw aura_pubkey that the challenger believes was
        /// committed under a different account. If the pubkey is already in
        /// `RevealedPubkeys` and bound to a *different* account, the original
        /// commit is forfeit.
        #[pallet::call_index(2)]
        #[pallet::weight(Weight::from_parts(60_000_000, 0))]
        pub fn challenge(
            origin: OriginFor<T>,
            commit_hash: [u8; 32],
            evidence_pubkey: Vec<u8>,
        ) -> DispatchResult {
            let challenger = ensure_signed(origin)?;
            let info = Commits::<T>::get(&commit_hash).ok_or(Error::<T>::UnknownCommit)?;
            ensure!(!info.revealed, Error::<T>::AlreadyRevealed);

            let now = frame_system::Pallet::<T>::block_number();
            let window = T::DisputeWindow::get();
            ensure!(
                now < info.block.saturating_add(window),
                Error::<T>::DisputeWindowOpen
            );

            // Successful challenge: the same pubkey was already revealed
            // under a different account.
            let evidence_hash = blake2_256(&evidence_pubkey);
            let prior = RevealedPubkeys::<T>::get(&evidence_hash);
            ensure!(prior.is_some(), Error::<T>::UnknownCommit);
            let prior_account = prior.expect("checked is_some");
            ensure!(
                prior_account != info.committer,
                Error::<T>::DuplicateCommit
            );

            // Slash the bond and remove the commit.
            let (imbalance, _) = T::Currency::slash_reserved(&info.committer, info.bond);
            drop(imbalance);
            Commits::<T>::remove(&commit_hash);

            log::warn!(
                target: LOG_TARGET,
                "commit {:?} challenged by {:?}: pubkey already bound to {:?}",
                commit_hash, challenger, prior_account
            );
            Self::deposit_event(Event::ChallengedDuplicatePubkey {
                challenger,
                commit_hash,
            });
            Self::deposit_event(Event::Slashed {
                commit_hash,
                amount: info.bond,
            });
            Ok(())
        }

        /// v43 generalization: commit with an explicit `OnboardingKind`.
        /// Same semantics as `commit()` plus a write to `CommitKind`.
        /// Use this when the reveal path is `reveal_generic`, not the
        /// validator hook.
        #[pallet::call_index(3)]
        #[pallet::weight(Weight::from_parts(55_000_000, 0))]
        pub fn commit_with_kind(
            origin: OriginFor<T>,
            commit_hash: [u8; 32],
            kind: OnboardingKind,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(
                !Commits::<T>::contains_key(&commit_hash),
                Error::<T>::DuplicateCommit
            );

            let bond = T::CommitBond::get();
            T::Currency::reserve(&who, bond).map_err(|_| Error::<T>::BondFailed)?;

            let now = frame_system::Pallet::<T>::block_number();
            let window = T::DisputeWindow::get();
            Commits::<T>::insert(
                &commit_hash,
                CommitInfo {
                    committer: who.clone(),
                    block: now,
                    bond,
                    revealed: false,
                },
            );
            CommitKind::<T>::insert(&commit_hash, kind);

            log::info!(
                target: LOG_TARGET,
                "commit_with_kind {:?} from {:?} at block {:?}",
                kind, who, now,
            );
            Self::deposit_event(Event::Committed {
                who,
                commit_hash,
                bond,
                window_ends: now.saturating_add(window),
            });
            Ok(())
        }

        /// v43 generalization: reveal a `Generic`-kind commit. Performs
        /// the same dispute-window + hash-match checks as `reveal()`
        /// but emits a `GenericRevealed` event instead of calling the
        /// validator mutator. Downstream pallets subscribe to the
        /// event and act on the payload.
        ///
        /// The `payload` is hashed (blake2_256) and the hash is
        /// surfaced in the event so on-chain history records what was
        /// revealed without storing the raw bytes.
        #[pallet::call_index(4)]
        #[pallet::weight(Weight::from_parts(70_000_000, 0))]
        pub fn reveal_generic(
            origin: OriginFor<T>,
            commit_hash: [u8; 32],
            payload: Vec<u8>,
            nonce: [u8; 32],
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let mut info = Commits::<T>::get(&commit_hash).ok_or(Error::<T>::UnknownCommit)?;
            ensure!(info.committer == who, Error::<T>::NotCommitter);
            ensure!(!info.revealed, Error::<T>::AlreadyRevealed);
            ensure!(
                CommitKind::<T>::get(&commit_hash) == OnboardingKind::Generic,
                Error::<T>::WrongOnboardingKind
            );

            let now = frame_system::Pallet::<T>::block_number();
            let window = T::DisputeWindow::get();
            ensure!(
                now >= info.block.saturating_add(window),
                Error::<T>::DisputeWindowOpen
            );

            // commit_hash = blake2_256(payload || nonce)
            let mut buf = Vec::with_capacity(payload.len() + 32);
            buf.extend_from_slice(&payload);
            buf.extend_from_slice(&nonce);
            let computed = blake2_256(&buf);
            ensure!(computed == commit_hash, Error::<T>::HashMismatch);

            let payload_hash = blake2_256(&payload);

            info.revealed = true;
            Commits::<T>::insert(&commit_hash, info.clone());
            T::Currency::unreserve(&who, info.bond);

            log::info!(
                target: LOG_TARGET,
                "generic reveal from {:?} at block {:?}, payload_hash={:?}",
                who, now, payload_hash,
            );
            Self::deposit_event(Event::GenericRevealed {
                who,
                commit_hash,
                payload_hash,
            });
            Ok(())
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        #[cfg(feature = "try-runtime")]
        fn try_state(_n: BlockNumberFor<T>) -> Result<(), sp_runtime::TryRuntimeError> {
            // Invariant: every revealed pubkey-hash corresponds to a committer
            // who has at least one commit with revealed=true.
            for (pubkey_hash, account) in RevealedPubkeys::<T>::iter() {
                let mut found = false;
                for (_hash, info) in Commits::<T>::iter() {
                    if info.committer == account && info.revealed {
                        found = true;
                        break;
                    }
                }
                if !found {
                    log::error!(
                        target: LOG_TARGET,
                        "try_state: revealed pubkey_hash {:?} for {:?} has no matching commit",
                        pubkey_hash, account
                    );
                    return Err(sp_runtime::TryRuntimeError::Other(
                        "revealed pubkey without matching commit",
                    ));
                }
            }
            Ok(())
        }
    }
}
