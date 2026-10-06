//! # Transparence Deliverables Pallet
//!
//! Tracks contract milestones and deliverables for the Transparence governance platform.
//!
//! ## Overview
//!
//! This pallet links governance contracts to their milestones and tracks completion
//! state based on oracle validations. It implements the full lifecycle from contract
//! creation through milestone delivery, oracle validation, and payment authorization
//! via the Two-Man Rule ceremony.
//!
//! ## Contract Lifecycle
//!
//! 1. **Draft**: Contract created by décideur public (owner)
//! 2. **Active**: Owner activates contract, milestones can be added
//! 3. **InExecution**: Supplier submits deliverables against milestones
//! 4. **Completed**: All milestones validated and payments authorized
//! 5. **Terminated**: Contract cancelled by owner
//!
//! ## Milestone Lifecycle
//!
//! 1. **Pending**: Milestone created
//! 2. **InProgress**: Work underway
//! 3. **ValidationPending**: Supplier submitted evidence, awaiting oracle review
//! 4. **Validated**: Oracle checks passed
//! 5. **Rejected**: Oracle checks failed
//! 6. **PaymentAuthorized**: Two-Man Rule ceremony completed
//! 7. **Paid**: Payment confirmed
//!
//! ## Integration Points
//!
//! - **transparence-oracle**: Provides validation results for deliverables
//! - **Two-Man Rule pallet**: Authorizes payments via dual-signature ceremony

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
    use sp_std::vec::Vec;

    /// Maximum milestones per contract
    pub const MAX_MILESTONES_PER_CONTRACT: u32 = 50;
    /// Maximum deliverables per milestone
    pub const MAX_DELIVERABLES_PER_MILESTONE: u32 = 20;
    /// Maximum description length
    pub const MAX_DESCRIPTION_LENGTH: u32 = 512;
    /// Maximum contracts per account (owner or supplier)
    pub const MAX_CONTRACTS_PER_ACCOUNT: u32 = 100;

    // ==================== DATA STRUCTURES ====================

    /// Phase of a governance contract
    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, Eq, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen, Default)]
    pub enum ContractPhase {
        /// Contract is in draft, not yet activated
        #[default]
        Draft,
        /// Contract is active, milestones can be added
        Active,
        /// Supplier is executing against milestones
        InExecution,
        /// All milestones completed and payments authorized
        Completed,
        /// Contract terminated by owner
        Terminated,
    }

    /// Status of a milestone within a contract
    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, Eq, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen, Default)]
    pub enum MilestoneStatus {
        /// Milestone created, no work submitted
        #[default]
        Pending,
        /// Work underway
        InProgress,
        /// Submitted for oracle review
        ValidationPending,
        /// All oracle checks passed
        Validated,
        /// Oracle checks failed
        Rejected,
        /// Two-Man Rule ceremony completed
        PaymentAuthorized,
        /// Payment confirmed
        Paid,
    }

    /// A governance contract linking a décideur public to a fournisseur privé
    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, Eq, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    #[scale_info(skip_type_params(T))]
    pub struct GovernanceContract<T: Config> {
        /// Unique contract ID
        pub id: u64,
        /// Hash of the contract title
        pub title_hash: [u8; 32],
        /// Hash of the technical specification (devis technique)
        pub devis_hash: [u8; 32],
        /// Décideur public who owns the contract
        pub owner: T::AccountId,
        /// Fournisseur privé executing the contract
        pub supplier: T::AccountId,
        /// Current phase of the contract
        pub phase: ContractPhase,
        /// Block number when the contract was created
        pub created_at: BlockNumberFor<T>,
        /// Total number of milestones in this contract
        pub milestone_count: u32,
        /// Number of milestones that are PaymentAuthorized or Paid
        pub completed_milestones: u32,
    }

    /// A milestone within a governance contract
    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, Eq, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    #[scale_info(skip_type_params(T))]
    pub struct Milestone<T: Config> {
        /// Unique milestone ID
        pub id: u64,
        /// Parent contract ID
        pub contract_id: u64,
        /// Order within the contract
        pub sequence: u32,
        /// Hash of the milestone description
        pub description_hash: [u8; 32],
        /// Current status
        pub status: MilestoneStatus,
        /// Hash of oracle evidence (set when deliverable submitted)
        pub evidence_hash: Option<[u8; 32]>,
        /// Block number when the milestone was created
        pub created_at: BlockNumberFor<T>,
        /// Block number when the milestone was validated
        pub validated_at: Option<BlockNumberFor<T>>,
        /// Links to the Two-Man Rule pallet ceremony
        pub payment_ceremony_id: Option<u64>,
    }

    // ==================== PALLET CONFIG ====================

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// The overarching event type
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    // ==================== STORAGE ====================

    /// The only account allowed to record milestone verdicts and payment
    /// authorisations: the Transparence writer (the node's `trsp` key). Set by
    /// root. `None` means nobody can, so a fresh chain fails closed.
    #[pallet::storage]
    #[pallet::getter(fn recorder)]
    pub type Recorder<T: Config> = StorageValue<_, T::AccountId, OptionQuery>;

    /// All governance contracts by ID
    #[pallet::storage]
    #[pallet::getter(fn contracts)]
    pub type Contracts<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        u64,
        GovernanceContract<T>,
        OptionQuery,
    >;

    /// Next contract ID counter
    #[pallet::storage]
    #[pallet::getter(fn next_contract_id)]
    pub type NextContractId<T: Config> = StorageValue<_, u64, ValueQuery>;

    /// All milestones by ID
    #[pallet::storage]
    #[pallet::getter(fn milestones)]
    pub type Milestones<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        u64,
        Milestone<T>,
        OptionQuery,
    >;

    /// Next milestone ID counter
    #[pallet::storage]
    #[pallet::getter(fn next_milestone_id)]
    pub type NextMilestoneId<T: Config> = StorageValue<_, u64, ValueQuery>;

    /// Milestone IDs by contract (contract_id -> list of milestone IDs)
    #[pallet::storage]
    #[pallet::getter(fn milestones_by_contract)]
    pub type MilestonesByContract<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        u64,
        BoundedVec<u64, ConstU32<MAX_MILESTONES_PER_CONTRACT>>,
        ValueQuery,
    >;

    /// Contract IDs by owner (décideur public -> list of contract IDs)
    #[pallet::storage]
    #[pallet::getter(fn contracts_by_owner)]
    pub type ContractsByOwner<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        BoundedVec<u64, ConstU32<MAX_CONTRACTS_PER_ACCOUNT>>,
        ValueQuery,
    >;

    /// Contract IDs by supplier (fournisseur privé -> list of contract IDs)
    #[pallet::storage]
    #[pallet::getter(fn contracts_by_supplier)]
    pub type ContractsBySupplier<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        BoundedVec<u64, ConstU32<MAX_CONTRACTS_PER_ACCOUNT>>,
        ValueQuery,
    >;

    // ==================== EVENTS ====================

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A new governance contract was created
        ContractCreated {
            contract_id: u64,
            owner: T::AccountId,
            supplier: T::AccountId,
        },
        /// A contract was activated (Draft -> Active)
        ContractActivated {
            contract_id: u64,
        },
        /// A milestone was added to a contract
        MilestoneAdded {
            contract_id: u64,
            milestone_id: u64,
            sequence: u32,
        },
        /// A deliverable was submitted for a milestone
        DeliverableSubmitted {
            contract_id: u64,
            milestone_id: u64,
            supplier: T::AccountId,
            evidence_hash: [u8; 32],
        },
        /// A milestone passed oracle validation
        MilestoneValidated {
            contract_id: u64,
            milestone_id: u64,
        },
        /// A milestone failed oracle validation
        MilestoneRejected {
            contract_id: u64,
            milestone_id: u64,
        },
        /// Payment was authorized via Two-Man Rule ceremony
        PaymentRecorded {
            contract_id: u64,
            milestone_id: u64,
            ceremony_id: u64,
        },
        /// All milestones completed, contract finished
        ContractCompleted {
            contract_id: u64,
        },
        /// Contract was terminated by owner
        ContractTerminated {
            contract_id: u64,
        },
        /// Root changed the authorised recorder (`None` = nobody)
        RecorderSet {
            recorder: Option<T::AccountId>,
        },
    }

    // ==================== ERRORS ====================

    #[pallet::error]
    pub enum Error<T> {
        /// The specified contract does not exist
        ContractNotFound,
        /// The specified milestone does not exist
        MilestoneNotFound,
        /// Caller is not the contract owner (décideur public)
        NotOwner,
        /// Caller is not the contract supplier (fournisseur privé)
        NotSupplier,
        /// Contract is not in the required phase for this operation
        InvalidPhase,
        /// Milestone is not in the required status for this operation
        InvalidMilestoneStatus,
        /// Maximum milestones per contract reached
        MaxMilestonesReached,
        /// Arithmetic overflow
        Overflow,
        /// Caller is not the authorised recorder, or none is set
        NotRecorder,
    }

    // ==================== DISPATCHABLES ====================

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Create a new governance contract.
        ///
        /// The caller becomes the owner (décideur public). The contract starts
        /// in Draft phase and must be activated before milestones can be added.
        ///
        /// ## Parameters
        /// - `title_hash`: Hash of the contract title
        /// - `devis_hash`: Hash of the technical specification (devis technique)
        /// - `supplier`: Account of the fournisseur privé
        #[pallet::call_index(0)]
        #[pallet::weight(10_000)]
        pub fn create_contract(
            origin: OriginFor<T>,
            title_hash: [u8; 32],
            devis_hash: [u8; 32],
            supplier: T::AccountId,
        ) -> DispatchResult {
            let owner = ensure_signed(origin)?;

            let contract_id = NextContractId::<T>::get();
            let next_id = contract_id.checked_add(1).ok_or(Error::<T>::Overflow)?;
            NextContractId::<T>::put(next_id);

            let current_block = frame_system::Pallet::<T>::block_number();

            let contract = GovernanceContract {
                id: contract_id,
                title_hash,
                devis_hash,
                owner: owner.clone(),
                supplier: supplier.clone(),
                phase: ContractPhase::Draft,
                created_at: current_block,
                milestone_count: 0,
                completed_milestones: 0,
            };

            Contracts::<T>::insert(contract_id, contract);

            // Update owner index
            ContractsByOwner::<T>::try_mutate(&owner, |contracts| {
                contracts.try_push(contract_id).map_err(|_| Error::<T>::Overflow)
            })?;

            // Update supplier index
            ContractsBySupplier::<T>::try_mutate(&supplier, |contracts| {
                contracts.try_push(contract_id).map_err(|_| Error::<T>::Overflow)
            })?;

            Self::deposit_event(Event::ContractCreated {
                contract_id,
                owner,
                supplier,
            });

            Ok(())
        }

        /// Activate a contract, transitioning it from Draft to Active.
        ///
        /// Only the contract owner (décideur public) can activate. Once active,
        /// milestones can be added to the contract.
        ///
        /// ## Parameters
        /// - `contract_id`: ID of the contract to activate
        #[pallet::call_index(1)]
        #[pallet::weight(10_000)]
        pub fn activate_contract(
            origin: OriginFor<T>,
            contract_id: u64,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let mut contract = Contracts::<T>::get(contract_id)
                .ok_or(Error::<T>::ContractNotFound)?;

            ensure!(contract.owner == who, Error::<T>::NotOwner);
            ensure!(contract.phase == ContractPhase::Draft, Error::<T>::InvalidPhase);

            contract.phase = ContractPhase::Active;
            Contracts::<T>::insert(contract_id, contract);

            Self::deposit_event(Event::ContractActivated { contract_id });

            Ok(())
        }

        /// Add a milestone to an active contract.
        ///
        /// Only the contract owner (décideur public) can add milestones. The
        /// contract must be in Active phase. The milestone starts in Pending status.
        ///
        /// ## Parameters
        /// - `contract_id`: ID of the parent contract
        /// - `sequence`: Order of this milestone within the contract
        /// - `description_hash`: Hash of the milestone description
        #[pallet::call_index(2)]
        #[pallet::weight(10_000)]
        pub fn add_milestone(
            origin: OriginFor<T>,
            contract_id: u64,
            sequence: u32,
            description_hash: [u8; 32],
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let mut contract = Contracts::<T>::get(contract_id)
                .ok_or(Error::<T>::ContractNotFound)?;

            ensure!(contract.owner == who, Error::<T>::NotOwner);
            ensure!(contract.phase == ContractPhase::Active, Error::<T>::InvalidPhase);

            // Allocate milestone ID
            let milestone_id = NextMilestoneId::<T>::get();
            let next_id = milestone_id.checked_add(1).ok_or(Error::<T>::Overflow)?;
            NextMilestoneId::<T>::put(next_id);

            let current_block = frame_system::Pallet::<T>::block_number();

            let milestone = Milestone {
                id: milestone_id,
                contract_id,
                sequence,
                description_hash,
                status: MilestoneStatus::Pending,
                evidence_hash: None,
                created_at: current_block,
                validated_at: None,
                payment_ceremony_id: None,
            };

            Milestones::<T>::insert(milestone_id, milestone);

            // Add to contract's milestone list
            MilestonesByContract::<T>::try_mutate(contract_id, |milestone_ids| {
                milestone_ids.try_push(milestone_id).map_err(|_| Error::<T>::MaxMilestonesReached)
            })?;

            // Update contract milestone count
            contract.milestone_count = contract.milestone_count
                .checked_add(1)
                .ok_or(Error::<T>::Overflow)?;
            Contracts::<T>::insert(contract_id, contract);

            Self::deposit_event(Event::MilestoneAdded {
                contract_id,
                milestone_id,
                sequence,
            });

            Ok(())
        }

        /// Submit a deliverable for a milestone.
        ///
        /// Only the contract supplier (fournisseur privé) can submit. The milestone
        /// must be in Pending or InProgress status. Transitions the milestone to
        /// ValidationPending and records the evidence hash. Also transitions the
        /// contract to InExecution if it was Active.
        ///
        /// ## Parameters
        /// - `contract_id`: ID of the parent contract
        /// - `milestone_id`: ID of the milestone to submit against
        /// - `evidence_hash`: Hash of the deliverable evidence
        #[pallet::call_index(3)]
        #[pallet::weight(10_000)]
        pub fn submit_deliverable(
            origin: OriginFor<T>,
            contract_id: u64,
            milestone_id: u64,
            evidence_hash: [u8; 32],
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let mut contract = Contracts::<T>::get(contract_id)
                .ok_or(Error::<T>::ContractNotFound)?;

            ensure!(contract.supplier == who, Error::<T>::NotSupplier);

            let mut milestone = Milestones::<T>::get(milestone_id)
                .ok_or(Error::<T>::MilestoneNotFound)?;

            // Verify milestone belongs to this contract
            ensure!(milestone.contract_id == contract_id, Error::<T>::MilestoneNotFound);

            // Milestone must be Pending or InProgress
            ensure!(
                milestone.status == MilestoneStatus::Pending ||
                milestone.status == MilestoneStatus::InProgress,
                Error::<T>::InvalidMilestoneStatus
            );

            milestone.status = MilestoneStatus::ValidationPending;
            milestone.evidence_hash = Some(evidence_hash);
            Milestones::<T>::insert(milestone_id, milestone);

            // Transition contract to InExecution if currently Active
            if contract.phase == ContractPhase::Active {
                contract.phase = ContractPhase::InExecution;
                Contracts::<T>::insert(contract_id, contract);
            }

            Self::deposit_event(Event::DeliverableSubmitted {
                contract_id,
                milestone_id,
                supplier: who,
                evidence_hash,
            });

            Ok(())
        }

        /// Record an oracle validation result for a milestone.
        ///
        /// Only the authorised `Recorder` may call this. If passed is true, the
        /// milestone transitions to Validated. If false, it transitions to Rejected.
        ///
        /// ## Parameters
        /// - `milestone_id`: ID of the milestone being validated
        /// - `passed`: Whether the oracle validation passed
        #[pallet::call_index(4)]
        #[pallet::weight(10_000)]
        pub fn record_validation_result(
            origin: OriginFor<T>,
            milestone_id: u64,
            passed: bool,
        ) -> DispatchResult {
            Self::ensure_recorder(origin)?;

            let mut milestone = Milestones::<T>::get(milestone_id)
                .ok_or(Error::<T>::MilestoneNotFound)?;

            ensure!(
                milestone.status == MilestoneStatus::ValidationPending,
                Error::<T>::InvalidMilestoneStatus
            );

            let contract_id = milestone.contract_id;

            if passed {
                milestone.status = MilestoneStatus::Validated;
                milestone.validated_at = Some(frame_system::Pallet::<T>::block_number());
                Milestones::<T>::insert(milestone_id, milestone);

                Self::deposit_event(Event::MilestoneValidated {
                    contract_id,
                    milestone_id,
                });
            } else {
                milestone.status = MilestoneStatus::Rejected;
                Milestones::<T>::insert(milestone_id, milestone);

                Self::deposit_event(Event::MilestoneRejected {
                    contract_id,
                    milestone_id,
                });
            }

            Ok(())
        }

        /// Record that the Two-Man Rule payment ceremony has been completed.
        ///
        /// Only the authorised `Recorder` may call this.
        ///
        /// Transitions the milestone from Validated to PaymentAuthorized and
        /// increments the contract's completed milestone count. If all milestones
        /// in the contract are PaymentAuthorized or Paid, the contract transitions
        /// to Completed.
        ///
        /// ## Parameters
        /// - `milestone_id`: ID of the validated milestone
        /// - `ceremony_id`: ID from the Two-Man Rule pallet
        #[pallet::call_index(5)]
        #[pallet::weight(10_000)]
        pub fn record_payment_authorized(
            origin: OriginFor<T>,
            milestone_id: u64,
            ceremony_id: u64,
        ) -> DispatchResult {
            Self::ensure_recorder(origin)?;

            let mut milestone = Milestones::<T>::get(milestone_id)
                .ok_or(Error::<T>::MilestoneNotFound)?;

            ensure!(
                milestone.status == MilestoneStatus::Validated,
                Error::<T>::InvalidMilestoneStatus
            );

            let contract_id = milestone.contract_id;

            milestone.status = MilestoneStatus::PaymentAuthorized;
            milestone.payment_ceremony_id = Some(ceremony_id);
            Milestones::<T>::insert(milestone_id, milestone);

            // Increment completed milestones on the contract
            let mut contract = Contracts::<T>::get(contract_id)
                .ok_or(Error::<T>::ContractNotFound)?;

            contract.completed_milestones = contract.completed_milestones
                .checked_add(1)
                .ok_or(Error::<T>::Overflow)?;

            Self::deposit_event(Event::PaymentRecorded {
                contract_id,
                milestone_id,
                ceremony_id,
            });

            // Check if all milestones are PaymentAuthorized or Paid
            let milestone_ids = MilestonesByContract::<T>::get(contract_id);
            let all_done = contract.milestone_count > 0 && milestone_ids.iter().all(|mid| {
                Milestones::<T>::get(mid)
                    .map(|m| {
                        m.status == MilestoneStatus::PaymentAuthorized ||
                        m.status == MilestoneStatus::Paid
                    })
                    .unwrap_or(false)
            });

            if all_done {
                contract.phase = ContractPhase::Completed;
                Self::deposit_event(Event::ContractCompleted { contract_id });
            }

            Contracts::<T>::insert(contract_id, contract);

            Ok(())
        }

        /// Terminate a contract.
        ///
        /// Only the contract owner (décideur public) can terminate. Transitions
        /// the contract to Terminated phase regardless of current phase.
        ///
        /// ## Parameters
        /// - `contract_id`: ID of the contract to terminate
        #[pallet::call_index(6)]
        #[pallet::weight(10_000)]
        pub fn terminate_contract(
            origin: OriginFor<T>,
            contract_id: u64,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let mut contract = Contracts::<T>::get(contract_id)
                .ok_or(Error::<T>::ContractNotFound)?;

            ensure!(contract.owner == who, Error::<T>::NotOwner);

            contract.phase = ContractPhase::Terminated;
            Contracts::<T>::insert(contract_id, contract);

            Self::deposit_event(Event::ContractTerminated { contract_id });

            Ok(())
        }

        /// Set or clear the authorised recorder. Root only.
        ///
        /// ## Parameters
        /// - `recorder`: the Transparence writer account, or `None` to stop
        ///   all recording
        #[pallet::call_index(7)]
        #[pallet::weight(10_000)]
        pub fn set_recorder(
            origin: OriginFor<T>,
            recorder: Option<T::AccountId>,
        ) -> DispatchResult {
            ensure_root(origin)?;
            match &recorder {
                Some(who) => Recorder::<T>::put(who),
                None => Recorder::<T>::kill(),
            }
            Self::deposit_event(Event::RecorderSet { recorder });
            Ok(())
        }
    }

    // ==================== HELPER FUNCTIONS ====================

    impl<T: Config> Pallet<T> {
        /// Signed by the authorised recorder, or `NotRecorder`.
        fn ensure_recorder(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(Recorder::<T>::get() == Some(who), Error::<T>::NotRecorder);
            Ok(())
        }

        /// Get a governance contract by ID
        pub fn get_contract(id: u64) -> Option<GovernanceContract<T>> {
            Contracts::<T>::get(id)
        }

        /// Get a milestone by ID
        pub fn get_milestone(id: u64) -> Option<Milestone<T>> {
            Milestones::<T>::get(id)
        }

        /// Get the progress of a contract as (completed_milestones, total_milestones)
        pub fn contract_progress(contract_id: u64) -> Option<(u32, u32)> {
            Contracts::<T>::get(contract_id)
                .map(|c| (c.completed_milestones, c.milestone_count))
        }
    }
}
