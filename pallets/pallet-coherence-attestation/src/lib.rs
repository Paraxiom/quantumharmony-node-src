//! # Coherence Attestation Pallet
//!
//! On-chain interface for the Coherence Beacon. A validator submits a certified
//! `(L, S)` attestation; the pallet gates it and, if admitted, credits stake =
//! secure key length `L`, weighted by distinct counterparties. This instantiates
//! the stake of Proof of Coherence v2/v3 and supersedes the QBER-as-score
//! framing (QBER is a distance proxy, not the stake).
//!
//! Interface schema: `docs/coherence-attestation-schema.md`.
//! Reference binding / twin: `qnt-lattice-optics/coherence-beacon-sim`.
//!
//! ## Security
//! - Keys never touch the chain: only `l_block` (the key *length* in bits).
//! - The transaction is signed by the validator's account (SPHINCS+ at the
//!   tx layer on the QH fork), so the body's authenticity is the tx signature.
//! - Replay protection: strictly increasing per-validator `nonce` + a bounded
//!   `round` window.
//! - Deterministic: all witness math is integer fixed-point (no floats on chain).
//! - The GATE slashes a positive key claimed with `S <= 2` (no Bell witness),
//!   and refuses a `DeviceIndependent` tier without a loophole certificate.

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

pub mod weights;
pub use weights::WeightInfo;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

/// Handler the runtime wires to its slasher (e.g. pallet-thin-slasher).
pub trait CoherenceSlasher<AccountId> {
    fn on_offense(validator: &AccountId, round: u64);
}

impl<AccountId> CoherenceSlasher<AccountId> for () {
    fn on_offense(_validator: &AccountId, _round: u64) {}
}

#[frame_support::pallet]
pub mod pallet {
    use crate::weights::WeightInfo;
    use crate::CoherenceSlasher;
    use frame_support::pallet_prelude::*;
    use frame_support::BoundedBTreeSet;
    use frame_system::pallet_prelude::*;
    use scale_codec::DecodeWithMemTracking;
    use sp_std::prelude::*;

    /// Trust tier the attestation claims (SCALE discriminant = the value).
    #[derive(Encode, Decode, Clone, Copy, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    pub enum Tier {
        TrustedDevice,
        FiberEdge,
        DeviceIndependent,
    }
    impl Default for Tier {
        fn default() -> Self {
            Self::TrustedDevice
        }
    }
    impl DecodeWithMemTracking for Tier {}

    /// Why an attestation was not admitted (recorded, not an error).
    #[derive(Encode, Decode, Clone, Copy, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    pub enum RejectReason {
        SBelowWitnessThreshold,
        QberTooHigh,
        NoSecureKey,
        UnearnedTier,
    }
    impl DecodeWithMemTracking for RejectReason {}

    /// Recorded outcome of a submitted attestation.
    #[derive(Encode, Decode, Clone, Copy, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    pub enum Outcome {
        Admitted,
        Rejected(RejectReason),
        Slashed,
    }
    impl DecodeWithMemTracking for Outcome {}

    /// The submitted body. The validator is the (signed) origin, so it is not a
    /// field here; the tx signature binds authenticity. Witness quantities are
    /// integer fixed-point: `s_milli = S*1000`, `qber_ppm = QBER*1e6`.
    #[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    #[scale_info(skip_type_params(T))]
    pub struct AttestationInput<AccountId> {
        pub counterparty: Option<AccountId>,
        pub round: u64,
        pub nonce: u64,
        pub l_block: u64,
        pub s_milli: u32,
        pub qber_ppm: u32,
        pub eps_log2_neg: u8,
        pub tier: Tier,
        pub commitment: [u8; 32],
        pub loophole_cert: bool,
    }
    impl<AccountId: DecodeWithMemTracking> DecodeWithMemTracking for AttestationInput<AccountId> {}

    /// Stored witness for the audit trail.
    #[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    pub struct StoredAttestation<AccountId> {
        pub counterparty: Option<AccountId>,
        pub l_block: u64,
        pub s_milli: u32,
        pub qber_ppm: u32,
        pub tier: Tier,
        pub commitment: [u8; 32],
        pub outcome: Outcome,
    }

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// The overarching event type.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Witness threshold in milli-units: `s_milli` must exceed this (2000 = S>2).
        #[pallet::constant]
        type SMilliMin: Get<u32>;

        /// QBER cutoff in ppm for a positive key (95_000 = 9.5%).
        #[pallet::constant]
        type QberPpmMax: Get<u32>;

        /// How many rounds in the past an attestation may reference.
        #[pallet::constant]
        type RoundWindow: Get<u64>;

        /// Maximum distinct counterparties tracked per validator.
        #[pallet::constant]
        type MaxCounterparties: Get<u32>;

        /// Slashing handler (wired to the runtime's slasher).
        type Slasher: CoherenceSlasher<Self::AccountId>;

        /// Weight information.
        type WeightInfo: crate::WeightInfo;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    /// Strictly-increasing nonce last seen per validator (replay protection).
    #[pallet::storage]
    pub type LastNonce<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, u64, ValueQuery>;

    /// Audit trail: (round, validator) -> stored witness.
    #[pallet::storage]
    pub type RoundAttestations<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        u64,
        Blake2_128Concat,
        T::AccountId,
        StoredAttestation<T::AccountId>,
        OptionQuery,
    >;

    /// Admitted-weight coherence stake per validator (epoch-decayed by the runtime).
    #[pallet::storage]
    pub type CoherenceStake<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, u128, ValueQuery>;

    /// Distinct counterparties a validator has held an admitted edge with.
    #[pallet::storage]
    pub type Counterparties<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        BoundedBTreeSet<T::AccountId, T::MaxCounterparties>,
        ValueQuery,
    >;

    /// Slash count per validator (traceability).
    #[pallet::storage]
    pub type Slashes<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, u32, ValueQuery>;

    /// Current consensus round (advanced by the runtime / ops).
    #[pallet::storage]
    pub type CurrentRound<T: Config> = StorageValue<_, u64, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// An attestation was admitted with the given stake weight (= L).
        AttestationAdmitted {
            validator: T::AccountId,
            counterparty: Option<T::AccountId>,
            round: u64,
            weight: u64,
        },
        /// An attestation was rejected (no stake, no penalty).
        AttestationRejected {
            validator: T::AccountId,
            round: u64,
            reason: RejectReason,
        },
        /// A validator was slashed for an inconsistent (L,S) (key claimed, S<=2).
        ValidatorSlashed { validator: T::AccountId, round: u64 },
        /// The current round was advanced.
        RoundAdvanced { round: u64 },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// `nonce` was not strictly greater than the last seen value.
        ReplayedNonce,
        /// `round` is outside the accepted window of the current round.
        StaleRound,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Submit a coherence attestation. Once nonce/round validation passes,
        /// the GATE always records an outcome (admit / reject / slash) and the
        /// nonce advances, so every well-formed submission is traceable.
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::submit_attestation())]
        pub fn submit_attestation(
            origin: OriginFor<T>,
            input: AttestationInput<T::AccountId>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            // Replay protection.
            ensure!(
                input.nonce > LastNonce::<T>::get(&who),
                Error::<T>::ReplayedNonce
            );
            // Round window: must reference the current or a recent past round.
            let current = CurrentRound::<T>::get();
            ensure!(
                input.round <= current
                    && current.saturating_sub(input.round) <= T::RoundWindow::get(),
                Error::<T>::StaleRound
            );

            // The GATE.
            let outcome = Self::gate(&input);

            // Apply effects.
            match outcome {
                Outcome::Admitted => {
                    CoherenceStake::<T>::mutate(&who, |s| {
                        *s = s.saturating_add(input.l_block as u128)
                    });
                    if let Some(cp) = &input.counterparty {
                        Counterparties::<T>::mutate(&who, |set| {
                            let _ = set.try_insert(cp.clone());
                        });
                    }
                    Self::deposit_event(Event::AttestationAdmitted {
                        validator: who.clone(),
                        counterparty: input.counterparty.clone(),
                        round: input.round,
                        weight: input.l_block,
                    });
                }
                Outcome::Slashed => {
                    Slashes::<T>::mutate(&who, |n| *n = n.saturating_add(1));
                    T::Slasher::on_offense(&who, input.round);
                    Self::deposit_event(Event::ValidatorSlashed {
                        validator: who.clone(),
                        round: input.round,
                    });
                }
                Outcome::Rejected(reason) => {
                    Self::deposit_event(Event::AttestationRejected {
                        validator: who.clone(),
                        round: input.round,
                        reason,
                    });
                }
            }

            // Record for audit and advance nonce.
            RoundAttestations::<T>::insert(
                input.round,
                &who,
                StoredAttestation {
                    counterparty: input.counterparty,
                    l_block: input.l_block,
                    s_milli: input.s_milli,
                    qber_ppm: input.qber_ppm,
                    tier: input.tier,
                    commitment: input.commitment,
                    outcome,
                },
            );
            LastNonce::<T>::insert(&who, input.nonce);

            Ok(())
        }

        /// Advance the current round (ops/root). In production the runtime drives
        /// this from its epoch logic.
        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::force_advance_round())]
        pub fn force_advance_round(origin: OriginFor<T>, round: u64) -> DispatchResult {
            ensure_root(origin)?;
            CurrentRound::<T>::put(round);
            Self::deposit_event(Event::RoundAdvanced { round });
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        /// The integer GATE. Mirrors the twin's `attestation::gate`.
        pub fn gate(input: &AttestationInput<T::AccountId>) -> Outcome {
            let s_min = T::SMilliMin::get();
            // Forgery: positive key with no Bell witness -> unconditional slash.
            if input.l_block > 0 && input.s_milli <= s_min {
                return Outcome::Slashed;
            }
            if input.s_milli <= s_min {
                return Outcome::Rejected(RejectReason::SBelowWitnessThreshold);
            }
            if input.qber_ppm > T::QberPpmMax::get() {
                return Outcome::Rejected(RejectReason::QberTooHigh);
            }
            if input.l_block == 0 {
                return Outcome::Rejected(RejectReason::NoSecureKey);
            }
            if input.tier == Tier::DeviceIndependent && !input.loophole_cert {
                return Outcome::Rejected(RejectReason::UnearnedTier);
            }
            Outcome::Admitted
        }
    }
}
