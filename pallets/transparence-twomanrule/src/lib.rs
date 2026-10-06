//! # Transparence Two-Man Rule Pallet
//!
//! Implements the Two-Man Rule (Coffre MPC) from Transparence, requiring both a
//! human signature (Fragment A) and a machine/oracle signature (Fragment B) before
//! authorizing payment events on-chain.
//!
//! ## Overview
//!
//! This is the core anti-corruption mechanism for public contract payments:
//!
//! 1. A payment ceremony is initiated for a contract milestone
//! 2. A human decision-maker (decideur public) provides Fragment A
//! 3. An authorized oracle (automated test/validation engine) provides Fragment B
//! 4. Only when BOTH fragments are present is a `PaymentAuthorized` event emitted
//! 5. The off-chain Fiat Bridge listens for `PaymentAuthorized` to release funds
//!
//! If the oracle detects test failures or validation issues, it can reject the
//! ceremony via `reject_machine`, permanently blocking that payment. This ensures
//! no public money flows without both human approval AND machine validation.
//!
//! ## Security
//!
//! - Oracles must be whitelisted via governance (`ForceOrigin`)
//! - Ceremonies expire after `CeremonyExpiryBlocks` (default ~24h at 6s blocks)
//! - Payment amounts are stored as hashes for privacy
//! - Lazy expiry checking on sign attempts (no on_initialize overhead)
//! - Each fragment can only be provided once per ceremony

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use codec::DecodeWithMemTracking;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_runtime::traits::Saturating;
    use sp_std::prelude::*;

    // ==================== CONSTANTS ====================

    /// Maximum ceremonies per contract
    pub const MAX_CEREMONIES_PER_CONTRACT: u32 = 1000;

    /// Default ceremony expiry in blocks (~24h at 6s blocks)
    pub const CEREMONY_EXPIRY_BLOCKS: u64 = 14400;

    // ==================== DATA STRUCTURES ====================

    /// Status of a payment ceremony
    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, Eq, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen, Default)]
    pub enum PaymentStatus {
        /// Waiting for both fragments
        #[default]
        Pending,
        /// Fragment A received, waiting for Fragment B
        HumanSigned,
        /// Fragment B received, waiting for Fragment A
        MachineSigned,
        /// Both fragments received — payment authorized
        Authorized,
        /// Machine rejected (tests failed)
        Rejected,
        /// Timed out without both signatures
        Expired,
    }

    /// A payment ceremony requiring dual authorization
    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, Eq, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    #[scale_info(skip_type_params(T))]
    pub struct PaymentCeremony<T: Config> {
        /// Unique ceremony ID
        pub id: u64,
        /// Associated contract ID
        pub contract_id: u64,
        /// Associated milestone ID
        pub milestone_id: u64,
        /// Hash of payment amount (privacy)
        pub amount_hash: [u8; 32],
        /// Fragment A provider (human decideur public)
        pub human_signer: Option<T::AccountId>,
        /// Fragment B provider (oracle/machine)
        pub machine_signer: Option<T::AccountId>,
        /// Current ceremony status
        pub status: PaymentStatus,
        /// Block when ceremony was initiated
        pub initiated_at: BlockNumberFor<T>,
        /// Block when both fragments were received
        pub authorized_at: Option<BlockNumberFor<T>>,
        /// Hash linking to oracle validation evidence
        pub evidence_hash: [u8; 32],
        /// Block after which ceremony expires
        pub expires_at: BlockNumberFor<T>,
    }

    // ==================== PALLET CONFIG ====================

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// The overarching event type
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Number of blocks before a ceremony expires
        #[pallet::constant]
        type CeremonyExpiryBlocks: Get<BlockNumberFor<Self>>;

        /// Origin that can manage the oracle whitelist (governance/sudo)
        type ForceOrigin: EnsureOrigin<Self::RuntimeOrigin>;
    }

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    // ==================== STORAGE ====================

    /// All payment ceremonies by ID
    #[pallet::storage]
    #[pallet::getter(fn ceremonies)]
    pub type Ceremonies<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        u64,
        PaymentCeremony<T>,
        OptionQuery,
    >;

    /// Next ceremony ID counter
    #[pallet::storage]
    #[pallet::getter(fn next_ceremony_id)]
    pub type NextCeremonyId<T: Config> = StorageValue<_, u64, ValueQuery>;

    /// Ceremony IDs grouped by contract
    #[pallet::storage]
    #[pallet::getter(fn ceremonies_by_contract)]
    pub type CeremoniesByContract<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        u64,
        BoundedVec<u64, ConstU32<MAX_CEREMONIES_PER_CONTRACT>>,
        ValueQuery,
    >;

    /// Whitelist of authorized oracle accounts (machine signers)
    #[pallet::storage]
    #[pallet::getter(fn authorized_oracles)]
    pub type AuthorizedOracles<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        bool,
        ValueQuery,
    >;

    // ==================== EVENTS ====================

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A new payment ceremony was initiated
        CeremonyInitiated {
            ceremony_id: u64,
            contract_id: u64,
            milestone_id: u64,
        },
        /// Human decision-maker provided Fragment A
        HumanSigned {
            ceremony_id: u64,
            signer: T::AccountId,
        },
        /// Oracle provided Fragment B
        MachineSigned {
            ceremony_id: u64,
            oracle: T::AccountId,
        },
        /// CRITICAL: Both fragments received — payment authorized
        /// The off-chain Fiat Bridge listens for this event
        PaymentAuthorized {
            ceremony_id: u64,
            contract_id: u64,
            milestone_id: u64,
            amount_hash: [u8; 32],
        },
        /// Oracle rejected the payment (tests failed)
        PaymentRejected {
            ceremony_id: u64,
            contract_id: u64,
            milestone_id: u64,
            oracle: T::AccountId,
        },
        /// Ceremony expired without both signatures
        CeremonyExpired {
            ceremony_id: u64,
        },
        /// Oracle account added to whitelist
        OracleRegistered {
            oracle: T::AccountId,
        },
        /// Oracle account removed from whitelist
        OracleRemoved {
            oracle: T::AccountId,
        },
    }

    // ==================== ERRORS ====================

    #[pallet::error]
    pub enum Error<T> {
        /// Ceremony not found
        CeremonyNotFound,
        /// Caller is not an authorized oracle
        NotAuthorizedOracle,
        /// This fragment has already been signed for this ceremony
        AlreadySigned,
        /// Ceremony has expired
        CeremonyExpired,
        /// Ceremony is not in a signable state
        CeremonyNotPending,
        /// Ceremony status does not allow this operation
        InvalidStatus,
        /// Arithmetic overflow
        Overflow,
    }

    // ==================== HOOKS ====================

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

    // ==================== DISPATCHABLES ====================

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Initiate a new payment ceremony for a contract milestone.
        ///
        /// Any signed account can initiate a ceremony. The ceremony starts in
        /// `Pending` status and requires both Fragment A (human) and Fragment B
        /// (machine) before the payment is authorized.
        ///
        /// ## Parameters
        /// - `contract_id`: ID of the associated contract
        /// - `milestone_id`: ID of the milestone being paid
        /// - `amount_hash`: Blake2 hash of the payment amount (privacy)
        /// - `evidence_hash`: Hash linking to oracle validation evidence
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn initiate_ceremony(
            origin: OriginFor<T>,
            contract_id: u64,
            milestone_id: u64,
            amount_hash: [u8; 32],
            evidence_hash: [u8; 32],
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;

            let current_block = frame_system::Pallet::<T>::block_number();

            // Generate ceremony ID
            let ceremony_id = NextCeremonyId::<T>::get();
            let next_id = ceremony_id.checked_add(1).ok_or(Error::<T>::Overflow)?;
            NextCeremonyId::<T>::put(next_id);

            // Calculate expiry block
            let expires_at = current_block.saturating_add(T::CeremonyExpiryBlocks::get());

            // Create ceremony
            let ceremony = PaymentCeremony::<T> {
                id: ceremony_id,
                contract_id,
                milestone_id,
                amount_hash,
                human_signer: None,
                machine_signer: None,
                status: PaymentStatus::Pending,
                initiated_at: current_block,
                authorized_at: None,
                evidence_hash,
                expires_at,
            };

            // Store ceremony
            Ceremonies::<T>::insert(ceremony_id, ceremony);

            // Update contract index
            CeremoniesByContract::<T>::try_mutate(contract_id, |ids| {
                ids.try_push(ceremony_id).map_err(|_| Error::<T>::Overflow)
            })?;

            Self::deposit_event(Event::CeremonyInitiated {
                ceremony_id,
                contract_id,
                milestone_id,
            });

            Ok(())
        }

        /// Provide Fragment A (human signature) for a payment ceremony.
        ///
        /// The human decideur public signs to confirm they approve the payment.
        /// If the oracle has already provided Fragment B, this call transitions
        /// the ceremony to `Authorized` and emits `PaymentAuthorized`.
        ///
        /// ## Parameters
        /// - `ceremony_id`: ID of the ceremony to sign
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn sign_human(
            origin: OriginFor<T>,
            ceremony_id: u64,
        ) -> DispatchResult {
            let signer = ensure_signed(origin)?;

            let mut ceremony = Ceremonies::<T>::get(ceremony_id)
                .ok_or(Error::<T>::CeremonyNotFound)?;

            // Lazy expiry check
            let current_block = frame_system::Pallet::<T>::block_number();
            if current_block > ceremony.expires_at {
                ceremony.status = PaymentStatus::Expired;
                Ceremonies::<T>::insert(ceremony_id, &ceremony);
                Self::deposit_event(Event::CeremonyExpired { ceremony_id });
                return Err(Error::<T>::CeremonyExpired.into());
            }

            // Check status allows human signing
            ensure!(
                ceremony.status == PaymentStatus::Pending ||
                ceremony.status == PaymentStatus::MachineSigned,
                Error::<T>::InvalidStatus
            );

            // Check not already signed by a human
            ensure!(ceremony.human_signer.is_none(), Error::<T>::AlreadySigned);

            // Record Fragment A
            ceremony.human_signer = Some(signer.clone());

            Self::deposit_event(Event::HumanSigned {
                ceremony_id,
                signer,
            });

            // Determine new status
            match ceremony.status {
                PaymentStatus::Pending => {
                    // Only human signed so far
                    ceremony.status = PaymentStatus::HumanSigned;
                },
                PaymentStatus::MachineSigned => {
                    // Machine already signed — BOTH fragments present
                    ceremony.status = PaymentStatus::Authorized;
                    ceremony.authorized_at = Some(current_block);

                    Self::deposit_event(Event::PaymentAuthorized {
                        ceremony_id,
                        contract_id: ceremony.contract_id,
                        milestone_id: ceremony.milestone_id,
                        amount_hash: ceremony.amount_hash,
                    });
                },
                _ => {
                    // Should not reach here due to ensure! above
                    return Err(Error::<T>::InvalidStatus.into());
                },
            }

            Ceremonies::<T>::insert(ceremony_id, ceremony);

            Ok(())
        }

        /// Provide Fragment B (machine/oracle signature) for a payment ceremony.
        ///
        /// Only authorized oracle accounts can call this. The oracle confirms
        /// that automated validation (tests, audits, compliance checks) passed.
        /// If the human has already provided Fragment A, this call transitions
        /// the ceremony to `Authorized` and emits `PaymentAuthorized`.
        ///
        /// ## Parameters
        /// - `ceremony_id`: ID of the ceremony to sign
        #[pallet::call_index(2)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn sign_machine(
            origin: OriginFor<T>,
            ceremony_id: u64,
        ) -> DispatchResult {
            let oracle = ensure_signed(origin)?;

            // Verify oracle is authorized
            ensure!(
                AuthorizedOracles::<T>::get(&oracle),
                Error::<T>::NotAuthorizedOracle
            );

            let mut ceremony = Ceremonies::<T>::get(ceremony_id)
                .ok_or(Error::<T>::CeremonyNotFound)?;

            // Lazy expiry check
            let current_block = frame_system::Pallet::<T>::block_number();
            if current_block > ceremony.expires_at {
                ceremony.status = PaymentStatus::Expired;
                Ceremonies::<T>::insert(ceremony_id, &ceremony);
                Self::deposit_event(Event::CeremonyExpired { ceremony_id });
                return Err(Error::<T>::CeremonyExpired.into());
            }

            // Check status allows machine signing
            ensure!(
                ceremony.status == PaymentStatus::Pending ||
                ceremony.status == PaymentStatus::HumanSigned,
                Error::<T>::InvalidStatus
            );

            // Check not already signed by a machine
            ensure!(ceremony.machine_signer.is_none(), Error::<T>::AlreadySigned);

            // Record Fragment B
            ceremony.machine_signer = Some(oracle.clone());

            Self::deposit_event(Event::MachineSigned {
                ceremony_id,
                oracle,
            });

            // Determine new status
            match ceremony.status {
                PaymentStatus::Pending => {
                    // Only machine signed so far
                    ceremony.status = PaymentStatus::MachineSigned;
                },
                PaymentStatus::HumanSigned => {
                    // Human already signed — BOTH fragments present
                    ceremony.status = PaymentStatus::Authorized;
                    ceremony.authorized_at = Some(current_block);

                    Self::deposit_event(Event::PaymentAuthorized {
                        ceremony_id,
                        contract_id: ceremony.contract_id,
                        milestone_id: ceremony.milestone_id,
                        amount_hash: ceremony.amount_hash,
                    });
                },
                _ => {
                    // Should not reach here due to ensure! above
                    return Err(Error::<T>::InvalidStatus.into());
                },
            }

            Ceremonies::<T>::insert(ceremony_id, ceremony);

            Ok(())
        }

        /// Reject a payment ceremony as an oracle.
        ///
        /// This is CRITICAL to the Two-Man Rule: when automated tests fail or
        /// validation does not pass, the oracle rejects the ceremony, permanently
        /// blocking that payment. This is how the system prevents corruption —
        /// no public money flows when tests are red.
        ///
        /// ## Parameters
        /// - `ceremony_id`: ID of the ceremony to reject
        #[pallet::call_index(3)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn reject_machine(
            origin: OriginFor<T>,
            ceremony_id: u64,
        ) -> DispatchResult {
            let oracle = ensure_signed(origin)?;

            // Verify oracle is authorized
            ensure!(
                AuthorizedOracles::<T>::get(&oracle),
                Error::<T>::NotAuthorizedOracle
            );

            let mut ceremony = Ceremonies::<T>::get(ceremony_id)
                .ok_or(Error::<T>::CeremonyNotFound)?;

            // Can only reject ceremonies that are not yet Authorized, Rejected, or Expired
            ensure!(
                ceremony.status == PaymentStatus::Pending ||
                ceremony.status == PaymentStatus::HumanSigned ||
                ceremony.status == PaymentStatus::MachineSigned,
                Error::<T>::InvalidStatus
            );

            // Transition to Rejected — permanently blocks this payment
            ceremony.status = PaymentStatus::Rejected;
            ceremony.machine_signer = Some(oracle.clone());

            Ceremonies::<T>::insert(ceremony_id, &ceremony);

            Self::deposit_event(Event::PaymentRejected {
                ceremony_id,
                contract_id: ceremony.contract_id,
                milestone_id: ceremony.milestone_id,
                oracle,
            });

            Ok(())
        }

        /// Register an oracle account to the authorized whitelist.
        ///
        /// Only callable by `ForceOrigin` (governance/sudo). Oracles are the
        /// automated validation engines that provide Fragment B.
        ///
        /// ## Parameters
        /// - `oracle_account`: Account to authorize as an oracle
        #[pallet::call_index(4)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn register_oracle(
            origin: OriginFor<T>,
            oracle_account: T::AccountId,
        ) -> DispatchResult {
            T::ForceOrigin::ensure_origin(origin)?;

            AuthorizedOracles::<T>::insert(&oracle_account, true);

            Self::deposit_event(Event::OracleRegistered {
                oracle: oracle_account,
            });

            Ok(())
        }

        /// Remove an oracle account from the authorized whitelist.
        ///
        /// Only callable by `ForceOrigin` (governance/sudo).
        ///
        /// ## Parameters
        /// - `oracle_account`: Account to deauthorize
        #[pallet::call_index(5)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn remove_oracle(
            origin: OriginFor<T>,
            oracle_account: T::AccountId,
        ) -> DispatchResult {
            T::ForceOrigin::ensure_origin(origin)?;

            AuthorizedOracles::<T>::remove(&oracle_account);

            Self::deposit_event(Event::OracleRemoved {
                oracle: oracle_account,
            });

            Ok(())
        }
    }

    // ==================== HELPER FUNCTIONS ====================

    impl<T: Config> Pallet<T> {
        /// Check if a ceremony has been fully authorized (both fragments present).
        pub fn is_authorized(ceremony_id: u64) -> bool {
            Ceremonies::<T>::get(ceremony_id)
                .map(|c| c.status == PaymentStatus::Authorized)
                .unwrap_or(false)
        }

        /// Get a ceremony by ID.
        pub fn get_ceremony(id: u64) -> Option<PaymentCeremony<T>> {
            Ceremonies::<T>::get(id)
        }
    }
}
