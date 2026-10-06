//! # Pallet Thin Slasher
//!
//! Thin slashing pallet for **permissioned** QuantumHarmony validators.
//! Closes the BGFL 4-layer justice "stake" layer (topological → replay
//! → PoC → **stake**) without dragging in `pallet-staking`'s nominator
//! model, bonding/unbonding-period UX, or open-PoS economics. Tracks
//! Paraxiom/quantumharmony#51 (mainnet pre-req).
//!
//! ## Design rationale
//!
//! Pulling in upstream `pallet-staking` would force several decisions
//! that don't fit QH's permissioned-via-identity-registry model:
//!
//! - **Nominators.** QH validators are registered via
//!   `pallet-validator-governance` + identity-registry stratum;
//!   there's no open delegation surface.
//! - **Bonding/unbonding period.** Doesn't match the identity-
//!   stratum onboarding flow.
//! - **Spec-version blast radius.** Adding the full staking pallet
//!   is a 2–4 week integration + a much larger upgrade.
//!
//! This pallet ships **three pieces**:
//!
//! 1. **Onboarding deposit.** Each validator self-posts a
//!    `ReservableCurrency` deposit at `post_deposit()`. The bond
//!    stays reserved while the validator participates; it's
//!    returned via `withdraw_deposit()` once the validator has no
//!    pending convictions.
//! 2. **Misbehavior reporters.** Two extrinsics, signed by any
//!    account (the bar is "you have to pay the tx fee"). `report()`
//!    files a `ConvictionRecord` against a target and is queued for
//!    governance review. No slashing happens at report time.
//! 3. **Governance-confirmed conviction.** `confirm()` /
//!    `dismiss()` are gated by `T::ConvictionOrigin`. Confirm slashes
//!    `T::SlashFraction` of the target's deposit; dismiss drops the
//!    record with no penalty. This defends against false-positive
//!    reports.
//!
//! ## What this is NOT (deliberately, per #51)
//!
//! - An economic-security model. Deposit sizes will be small relative
//!   to a pure-PoS chain — that's fine; QH's primary defense is
//!   identity + governance, stake is the *fourth* layer of justice,
//!   not the first.
//! - A nominator system.
//! - A staking-rewards mechanism. `pallet-validator-rewards` already
//!   handles validator payouts.
//! - An on-chain misbehavior verifier. v0.1 records an `evidence_hash`
//!   and trusts the `ConvictionOrigin` to have read the off-chain
//!   bundle. v0.2 introduces per-`MisbehaviorKind` verifiers.

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
    use frame_support::{
        pallet_prelude::*,
        traits::{Currency, ReservableCurrency, EnsureOrigin},
        sp_runtime::{Permill, Saturating},
    };
    use frame_system::pallet_prelude::*;
    use types::{ConvictionRecord, MisbehaviorKind};

    pub const LOG_TARGET: &str = "runtime::thin-slasher";

    pub type BalanceOf<T> =
        <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>>
            + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Reservable currency used for the validator deposit.
        type Currency: ReservableCurrency<Self::AccountId>;

        /// Minimum deposit a validator must post to participate.
        /// Larger deposits are allowed; smaller are rejected. Tuned
        /// at runtime upgrade time.
        #[pallet::constant]
        type MinimumDeposit: Get<BalanceOf<Self>>;

        /// Fraction of a target's deposit that is slashed on a
        /// confirmed conviction. `Permill::from_percent(50)` = 50%.
        /// Setting to `Permill::one()` slashes the full deposit.
        #[pallet::constant]
        type SlashFraction: Get<Permill>;

        /// Origin that can confirm or dismiss a pending conviction.
        /// Wire this to a `pallet-collective` majority or
        /// `pallet-dev-governance` track on mainnet so an individual
        /// reporter cannot unilaterally slash.
        type ConvictionOrigin: EnsureOrigin<Self::RuntimeOrigin>;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    /// Reserved deposit per validator. A row exists iff the validator
    /// currently has stake at risk.
    #[pallet::storage]
    pub type Deposits<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        BalanceOf<T>,
        OptionQuery,
    >;

    /// Next conviction id; monotonic.
    #[pallet::storage]
    pub type NextConvictionId<T: Config> = StorageValue<_, u64, ValueQuery>;

    /// Pending misbehavior reports awaiting governance review.
    #[pallet::storage]
    pub type PendingConvictions<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        u64,
        ConvictionRecord<T::AccountId, BlockNumberFor<T>>,
        OptionQuery,
    >;

    /// Number of pending convictions per target. A validator with at
    /// least one pending conviction cannot `withdraw_deposit()` until
    /// every conviction has been confirmed or dismissed.
    #[pallet::storage]
    pub type PendingByTarget<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        u32,
        ValueQuery,
    >;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A validator posted (or topped up) their deposit.
        DepositPosted {
            who: T::AccountId,
            amount: BalanceOf<T>,
            total: BalanceOf<T>,
        },
        /// A validator withdrew their deposit.
        DepositWithdrawn {
            who: T::AccountId,
            amount: BalanceOf<T>,
        },
        /// A misbehavior report was filed and queued for governance
        /// review.
        Reported {
            conviction_id: u64,
            target: T::AccountId,
            reporter: T::AccountId,
            kind: MisbehaviorKind,
        },
        /// A pending conviction was confirmed and the target's
        /// deposit was slashed.
        Convicted {
            conviction_id: u64,
            target: T::AccountId,
            slashed: BalanceOf<T>,
        },
        /// A pending conviction was dismissed (no slash).
        Dismissed {
            conviction_id: u64,
            target: T::AccountId,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Deposit is below `MinimumDeposit`.
        DepositTooSmall,
        /// Caller has no deposit on record.
        NoDeposit,
        /// Deposit cannot be withdrawn while pending convictions
        /// exist against this validator.
        DepositLocked,
        /// Reservation failed (insufficient balance).
        ReserveFailed,
        /// No pending conviction with this id.
        UnknownConviction,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Post (or top up) the caller's slashable deposit. The
        /// `amount` is reserved from the caller's free balance and
        /// added to any existing deposit.
        ///
        /// Initial post must meet `MinimumDeposit`. Top-ups have no
        /// floor — any positive `amount` is accepted.
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(50_000_000, 0))]
        pub fn post_deposit(
            origin: OriginFor<T>,
            amount: BalanceOf<T>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let existing = Deposits::<T>::get(&who).unwrap_or_else(Zero::zero);
            if existing.is_zero() {
                ensure!(amount >= T::MinimumDeposit::get(), Error::<T>::DepositTooSmall);
            }
            T::Currency::reserve(&who, amount).map_err(|_| Error::<T>::ReserveFailed)?;
            let total = existing.saturating_add(amount);
            Deposits::<T>::insert(&who, total);
            log::info!(
                target: LOG_TARGET,
                "post_deposit by {:?} amount={:?} total={:?}",
                who, amount, total,
            );
            Self::deposit_event(Event::DepositPosted { who, amount, total });
            Ok(())
        }

        /// Withdraw the caller's deposit. Refuses while any pending
        /// conviction is open against the caller — governance must
        /// resolve every report before stake can exit.
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(40_000_000, 0))]
        pub fn withdraw_deposit(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let amount = Deposits::<T>::get(&who).ok_or(Error::<T>::NoDeposit)?;
            ensure!(
                PendingByTarget::<T>::get(&who) == 0,
                Error::<T>::DepositLocked
            );
            T::Currency::unreserve(&who, amount);
            Deposits::<T>::remove(&who);
            log::info!(
                target: LOG_TARGET,
                "withdraw_deposit by {:?} amount={:?}",
                who, amount,
            );
            Self::deposit_event(Event::DepositWithdrawn { who, amount });
            Ok(())
        }

        /// File a misbehavior report against `target`. Any signed
        /// origin may file — the gas fee is the bar. The report
        /// queues a `ConvictionRecord` for `ConvictionOrigin`
        /// review; nothing is slashed at report time.
        #[pallet::call_index(2)]
        #[pallet::weight(Weight::from_parts(45_000_000, 0))]
        pub fn report(
            origin: OriginFor<T>,
            target: T::AccountId,
            kind: MisbehaviorKind,
            evidence_hash: [u8; 32],
        ) -> DispatchResult {
            let reporter = ensure_signed(origin)?;
            let conviction_id = NextConvictionId::<T>::get();
            let next = conviction_id.saturating_add(1);
            NextConvictionId::<T>::put(next);
            let reported_at = frame_system::Pallet::<T>::block_number();
            let record = ConvictionRecord {
                target: target.clone(),
                reporter: reporter.clone(),
                kind,
                evidence_hash,
                reported_at,
            };
            PendingConvictions::<T>::insert(conviction_id, record);
            PendingByTarget::<T>::mutate(&target, |n| *n = n.saturating_add(1));
            log::info!(
                target: LOG_TARGET,
                "report {} target={:?} reporter={:?} kind={:?}",
                conviction_id, target, reporter, kind,
            );
            Self::deposit_event(Event::Reported {
                conviction_id,
                target,
                reporter,
                kind,
            });
            Ok(())
        }

        /// Confirm a pending conviction. Gated by `ConvictionOrigin`.
        /// Slashes `SlashFraction` of the target's deposit (rounded
        /// down via `Permill::mul_floor`). If the target has no
        /// deposit on record the conviction still resolves — the
        /// event records `slashed = 0` so auditors can see the
        /// resolution.
        #[pallet::call_index(3)]
        #[pallet::weight(Weight::from_parts(55_000_000, 0))]
        pub fn confirm(
            origin: OriginFor<T>,
            conviction_id: u64,
        ) -> DispatchResult {
            T::ConvictionOrigin::ensure_origin(origin)?;
            let record = PendingConvictions::<T>::take(conviction_id)
                .ok_or(Error::<T>::UnknownConviction)?;
            let target = record.target.clone();
            PendingByTarget::<T>::mutate(&target, |n| *n = n.saturating_sub(1));

            let deposit = Deposits::<T>::get(&target).unwrap_or_else(Zero::zero);
            let slash_amount = T::SlashFraction::get().mul_floor(deposit);
            let actually_slashed = if slash_amount.is_zero() {
                Zero::zero()
            } else {
                let (imbalance, _) = T::Currency::slash_reserved(&target, slash_amount);
                drop(imbalance);
                // Reduce the on-record deposit by what was actually slashed.
                let remaining = deposit.saturating_sub(slash_amount);
                if remaining.is_zero() {
                    Deposits::<T>::remove(&target);
                } else {
                    Deposits::<T>::insert(&target, remaining);
                }
                slash_amount
            };
            log::warn!(
                target: LOG_TARGET,
                "confirm {} target={:?} slashed={:?}",
                conviction_id, target, actually_slashed,
            );
            Self::deposit_event(Event::Convicted {
                conviction_id,
                target,
                slashed: actually_slashed,
            });
            Ok(())
        }

        /// Dismiss a pending conviction without slashing. Gated by
        /// `ConvictionOrigin`. Used when the off-chain evidence
        /// bundle didn't hold up to governance review.
        #[pallet::call_index(4)]
        #[pallet::weight(Weight::from_parts(35_000_000, 0))]
        pub fn dismiss(
            origin: OriginFor<T>,
            conviction_id: u64,
        ) -> DispatchResult {
            T::ConvictionOrigin::ensure_origin(origin)?;
            let record = PendingConvictions::<T>::take(conviction_id)
                .ok_or(Error::<T>::UnknownConviction)?;
            let target = record.target.clone();
            PendingByTarget::<T>::mutate(&target, |n| *n = n.saturating_sub(1));
            log::info!(
                target: LOG_TARGET,
                "dismiss {} target={:?}",
                conviction_id, target,
            );
            Self::deposit_event(Event::Dismissed { conviction_id, target });
            Ok(())
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        #[cfg(feature = "try-runtime")]
        fn try_state(_n: BlockNumberFor<T>) -> Result<(), sp_runtime::TryRuntimeError> {
            // Invariant: PendingByTarget[t] == count of PendingConvictions
            // where record.target == t.
            for (target, stored_count) in PendingByTarget::<T>::iter() {
                let actual = PendingConvictions::<T>::iter()
                    .filter(|(_, r)| r.target == target)
                    .count() as u32;
                if stored_count != actual {
                    log::error!(
                        target: LOG_TARGET,
                        "try_state: PendingByTarget for {:?} mismatch (stored={}, actual={})",
                        target, stored_count, actual,
                    );
                    return Err(sp_runtime::TryRuntimeError::Other(
                        "PendingByTarget out of sync",
                    ));
                }
            }
            Ok(())
        }
    }

    // Local zero-balance helper so we don't need to import a
    // higher-level numeric prelude.
    use frame_support::sp_runtime::traits::Zero;
}
