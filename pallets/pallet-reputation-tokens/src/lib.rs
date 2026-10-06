//! # Pallet Reputation Tokens
//!
//! Per-identity reputation accounting on multiple verifier axes.
//! Specified in *Identity as Accountability Chain*, §11.6, and tracked
//! as roadmap item #5 in the treatise's §14 implementation plan
//! (Paraxiom/quantumharmony#34).
//!
//! ## Model
//!
//! - **Identities** are `u64`s. We don't reach into
//!   `pallet_identity_registry` because reputation must remain
//!   meaningful even if the identity-registry shape changes — the
//!   accounting layer stays decoupled from the schema layer.
//! - **Axes** are a closed enum (see `types::Axis`). Each axis tracks
//!   a distinct kind of verifier event. They deliberately mirror
//!   `pallet_axiom_attestation::VerifierKind` so the gov-app
//!   subscriber (#34 item 7) can translate between them by SCALE
//!   discriminant.
//! - **Scores** are `u64` per `(identity, axis)`. Monotonic except
//!   for explicit debits (revocations) and decay.
//! - **Issuance is permissioned.** Each axis has a single registered
//!   `Issuer` account, managed by sudo. The issuer is the only
//!   account that can `credit` or `debit` against that axis. For
//!   bootstrap, sudo can also delegate the issuer to itself.
//!
//! ## What this pallet does NOT decide
//!
//! - Who deserves a credit. That's the issuer's policy, off-chain or
//!   in another pallet. Reputation-tokens is the accounting layer.
//! - How scores translate to slot weight / consensus participation /
//!   payouts. That's downstream consumer policy.
//! - Whether decay is exponential or linear or staircase. We
//!   implement multiplicative-per-step (cheap, simple, sufficient
//!   for v0.1). Future versions can hook a `T::DecayKernel` trait
//!   without storage migration.
//!
//! ## Extrinsics
//!
//! - `set_issuer(axis, who)` — sudo only. Replaces the current
//!   issuer for `axis`. Required to bootstrap each axis before any
//!   credit/debit can happen.
//! - `set_decay_params(params)` — sudo only. Overwrites decay
//!   configuration.
//! - `credit(identity_id, axis, amount)` — registered issuer only.
//! - `debit(identity_id, axis, amount)` — registered issuer only.
//!   Saturating-subtract; can't go below zero.
//! - `decay_step()` — permissionless. Applies multiplicative decay
//!   to every score above `min_score`. Anyone can poke; the
//!   `cooldown_blocks` config guards against too-frequent sweeps.

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
    use frame_support::pallet_prelude::*;
    use frame_support::sp_runtime::Saturating;
    use frame_system::pallet_prelude::*;
    use types::{Axis, DecayParams};

    pub const LOG_TARGET: &str = "runtime::reputation-tokens";

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>>
            + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Minimum block delta between successive `decay_step` calls.
        /// Permissionless extrinsic so we need a cooldown to make
        /// griefing uneconomic.
        #[pallet::constant]
        type DecayCooldownBlocks: Get<BlockNumberFor<Self>>;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    /// Per-axis authorized issuer. `None` means the axis is dormant —
    /// no one can credit or debit against it. Sudo registers
    /// (or replaces) an issuer via `set_issuer`.
    #[pallet::storage]
    pub type Issuer<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        Axis,
        T::AccountId,
        OptionQuery,
    >;

    /// Per-(identity, axis) reputation score. `ValueQuery` = 0
    /// default so reads on never-credited slots return zero without
    /// extra plumbing.
    #[pallet::storage]
    pub type Score<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat, u64,    // identity_id
        Blake2_128Concat, Axis,
        u64,
        ValueQuery,
    >;

    /// Aggregated stats per axis so consumers can read "total
    /// outstanding reputation in this axis" in O(1) without
    /// iterating `Score`.
    #[pallet::storage]
    pub type AxisTotal<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        Axis,
        u128,         // u128 so a sum-of-u64s can't overflow
        ValueQuery,
    >;

    /// Last block at which `decay_step` ran.
    #[pallet::storage]
    pub type LastDecayAt<T: Config> = StorageValue<_, BlockNumberFor<T>, OptionQuery>;

    /// Decay configuration. Single shared value; per-axis decay
    /// would be a v0.2 extension if the policy diverges.
    #[pallet::storage]
    pub type Decay<T: Config> = StorageValue<_, DecayParams, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Sudo set (or replaced) the issuer for an axis.
        IssuerSet {
            axis: Axis,
            who: T::AccountId,
        },
        /// Issuer credited an identity on an axis.
        Credited {
            id: u64,
            axis: Axis,
            amount: u64,
            new_total: u64,
        },
        /// Issuer debited an identity on an axis.
        Debited {
            id: u64,
            axis: Axis,
            amount: u64,
            new_total: u64,
        },
        /// Decay swept all scores. `at` is the block; `applied_ppm`
        /// is the per-step decay used. The total burned across all
        /// (id, axis) slots is also reported so external watchers can
        /// reconcile.
        Decayed {
            at: BlockNumberFor<T>,
            applied_ppm: u32,
            total_burned: u128,
        },
        /// Sudo updated decay parameters.
        DecayParamsSet {
            params: DecayParams,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// No registered issuer for this axis.
        AxisDormant,
        /// Caller is not the registered issuer for this axis.
        NotIssuer,
        /// Credit would overflow u64.
        Overflow,
        /// Decay cooldown has not elapsed yet.
        DecayCooldown,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Register (or replace) the authorized issuer for an axis.
        /// Sudo only. The previous issuer's authority is revoked
        /// immediately; in-flight calls from them fail with
        /// `NotIssuer` from the next block.
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(20_000_000, 0))]
        pub fn set_issuer(
            origin: OriginFor<T>,
            axis: Axis,
            who: T::AccountId,
        ) -> DispatchResult {
            ensure_root(origin)?;
            Issuer::<T>::insert(axis, who.clone());
            log::info!(target: LOG_TARGET,
                "set_issuer axis={:?} who={:?}", axis, who);
            Self::deposit_event(Event::IssuerSet { axis, who });
            Ok(())
        }

        /// Overwrite decay parameters. Sudo only.
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(15_000_000, 0))]
        pub fn set_decay_params(
            origin: OriginFor<T>,
            params: DecayParams,
        ) -> DispatchResult {
            ensure_root(origin)?;
            Decay::<T>::put(params.clone());
            Self::deposit_event(Event::DecayParamsSet { params });
            Ok(())
        }

        /// Credit an identity on an axis. Only the registered issuer
        /// for `axis` may call this. Overflow is a hard error — the
        /// issuer is expected to keep scores bounded, not rely on
        /// saturation as a feature.
        #[pallet::call_index(2)]
        #[pallet::weight(Weight::from_parts(35_000_000, 0))]
        pub fn credit(
            origin: OriginFor<T>,
            identity_id: u64,
            axis: Axis,
            amount: u64,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let issuer = Issuer::<T>::get(axis).ok_or(Error::<T>::AxisDormant)?;
            ensure!(issuer == who, Error::<T>::NotIssuer);

            let new_total = Score::<T>::try_mutate(
                identity_id,
                axis,
                |s| -> Result<u64, DispatchError> {
                    *s = s.checked_add(amount).ok_or(Error::<T>::Overflow)?;
                    Ok(*s)
                },
            )?;

            AxisTotal::<T>::mutate(axis, |t| *t = t.saturating_add(amount as u128));

            Self::deposit_event(Event::Credited {
                id: identity_id,
                axis,
                amount,
                new_total,
            });
            Ok(())
        }

        /// Debit an identity on an axis. Saturating: a debit larger
        /// than current score sets the score to zero and reports
        /// `new_total = 0`. This is the revocation path; treating
        /// over-debit as an error would let an attacker who reverses
        /// the credit/debit ordering brick a revocation flow.
        #[pallet::call_index(3)]
        #[pallet::weight(Weight::from_parts(30_000_000, 0))]
        pub fn debit(
            origin: OriginFor<T>,
            identity_id: u64,
            axis: Axis,
            amount: u64,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let issuer = Issuer::<T>::get(axis).ok_or(Error::<T>::AxisDormant)?;
            ensure!(issuer == who, Error::<T>::NotIssuer);

            let (actually_burned, new_total) = Score::<T>::mutate(
                identity_id,
                axis,
                |s| {
                    let burned = (*s).min(amount);
                    *s = s.saturating_sub(amount);
                    (burned, *s)
                },
            );

            if actually_burned > 0 {
                AxisTotal::<T>::mutate(axis, |t| *t = t.saturating_sub(actually_burned as u128));
            }

            Self::deposit_event(Event::Debited {
                id: identity_id,
                axis,
                amount,
                new_total,
            });
            Ok(())
        }

        /// Permissionless decay sweep. Anyone may call but the
        /// `DecayCooldownBlocks` constant prevents griefing by
        /// requiring at least that many blocks between sweeps.
        ///
        /// Implementation: applies multiplicative decay
        /// `new = old * (1 - decay_per_step_ppm / 1_000_000)` to
        /// every score above `min_score`. Scores at or below
        /// `min_score` are untouched (avoid round-to-zero churn).
        ///
        /// The total burned across all slots is emitted in the
        /// event so external watchers can reconcile balance sheets.
        #[pallet::call_index(4)]
        #[pallet::weight(Weight::from_parts(80_000_000, 0))]
        pub fn decay_step(origin: OriginFor<T>) -> DispatchResult {
            ensure_signed(origin)?;
            let now: BlockNumberFor<T> = frame_system::Pallet::<T>::block_number();
            let cooldown: BlockNumberFor<T> = T::DecayCooldownBlocks::get();
            if let Some(last) = LastDecayAt::<T>::get() {
                ensure!(now.saturating_sub(last) >= cooldown, Error::<T>::DecayCooldown);
            }
            let params = Decay::<T>::get();
            if params.decay_per_step_ppm == 0 {
                LastDecayAt::<T>::put(now);
                Self::deposit_event(Event::Decayed {
                    at: now,
                    applied_ppm: 0,
                    total_burned: 0,
                });
                return Ok(());
            }

            // Multiplier as ppm-survivors: e.g. ppm=50_000 → 95% survives.
            let survives_ppm: u64 = 1_000_000u64
                .saturating_sub(params.decay_per_step_ppm as u64);

            let mut total_burned: u128 = 0;
            for (id, axis, old) in Score::<T>::iter() {
                if old <= params.min_score {
                    continue;
                }
                // (old * survives_ppm) / 1_000_000, in u128 to avoid overflow
                let new = ((old as u128) * (survives_ppm as u128) / 1_000_000u128) as u64;
                if new < old {
                    let burned = old - new;
                    total_burned = total_burned.saturating_add(burned as u128);
                    AxisTotal::<T>::mutate(axis, |t| *t = t.saturating_sub(burned as u128));
                    Score::<T>::insert(id, axis, new);
                }
            }

            LastDecayAt::<T>::put(now);
            Self::deposit_event(Event::Decayed {
                at: now,
                applied_ppm: params.decay_per_step_ppm,
                total_burned,
            });
            Ok(())
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        #[cfg(feature = "try-runtime")]
        fn try_state(_n: BlockNumberFor<T>) -> Result<(), sp_runtime::TryRuntimeError> {
            // Invariant: AxisTotal[axis] == Σ Score[*, axis].
            // O(scores) per check — debug-only so acceptable.
            for axis in Axis::ALL {
                let stored = AxisTotal::<T>::get(axis);
                let actual: u128 = Score::<T>::iter()
                    .filter(|(_, a, _)| *a == axis)
                    .map(|(_, _, s)| s as u128)
                    .sum();
                if stored != actual {
                    log::error!(
                        target: LOG_TARGET,
                        "try_state: axis {:?} total mismatch (stored={}, actual={})",
                        axis, stored, actual
                    );
                    return Err(sp_runtime::TryRuntimeError::Other(
                        "axis total mismatch",
                    ));
                }
            }
            Ok(())
        }
    }
}
