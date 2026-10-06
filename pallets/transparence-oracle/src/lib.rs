//! # Transparence Oracle Pallet
//!
//! Anchors oracle validation results from Transparence's verification engine
//! onto the QuantumHarmony blockchain.
//!
//! ## Overview
//!
//! This pallet provides on-chain anchoring for Transparence's 6 oracle
//! validation plugins:
//! - **Endpoint**: API endpoint health verification
//! - **Coverage**: Code coverage threshold checks
//! - **CodeAnalysis**: Static analysis (SonarQube) results
//! - **Deploy**: Deployment verification
//! - **Visual**: Visual regression testing
//! - **Performance**: Load/latency benchmarks
//!
//! ## Validation Lifecycle
//!
//! 1. Oracle service submits validation results per plugin
//! 2. Results are stored with evidence hashes and quality scores
//! 3. When all 6 plugins pass for a milestone, it is marked complete
//! 4. Validations can be revoked by the original validator (sets verdict to Error)
//!
//! ## Rate Limiting
//!
//! A configurable per-block rate limit prevents spam. The counter resets
//! each block via `on_initialize`.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use codec::DecodeWithMemTracking;
    use frame_support::{
        pallet_prelude::*,
        traits::Get,
    };
    use frame_system::pallet_prelude::*;
    use sp_std::vec::Vec;

    // ==================== TYPES ====================

    /// Validation plugin types matching Transparence's 6 oracle plugins.
    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, Eq, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen, Default)]
    pub enum ValidationPlugin {
        /// API endpoint health
        #[default]
        Endpoint,
        /// Code coverage threshold
        Coverage,
        /// Static analysis (SonarQube)
        CodeAnalysis,
        /// Deployment verification
        Deploy,
        /// Visual regression
        Visual,
        /// Load/latency benchmarks
        Performance,
    }

    /// Total number of plugin variants (used for milestone completion check).
    const PLUGIN_COUNT: usize = 6;

    /// All plugin variants in order, for iteration during milestone status computation.
    const ALL_PLUGINS: [ValidationPlugin; PLUGIN_COUNT] = [
        ValidationPlugin::Endpoint,
        ValidationPlugin::Coverage,
        ValidationPlugin::CodeAnalysis,
        ValidationPlugin::Deploy,
        ValidationPlugin::Visual,
        ValidationPlugin::Performance,
    ];

    /// Verdict of a validation run.
    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, Eq, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen, Default)]
    pub enum ValidationVerdict {
        /// Awaiting result
        #[default]
        Pending,
        /// Validation passed
        Pass,
        /// Validation failed
        Fail,
        /// Validation encountered an error (also used for revocation)
        Error,
    }

    /// An oracle validation record anchored on-chain.
    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, Eq, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    #[scale_info(skip_type_params(T))]
    pub struct OracleValidation<T: Config> {
        /// Unique validation ID
        pub id: u64,
        /// Links to Transparence contract
        pub contract_id: u64,
        /// Which milestone/deliverable
        pub milestone_id: u64,
        /// Which plugin produced this validation
        pub plugin: ValidationPlugin,
        /// SHA-256 of the raw evidence
        pub evidence_hash: [u8; 32],
        /// Pass / Fail / Error / Pending
        pub verdict: ValidationVerdict,
        /// Quality score 0-100
        pub score: u8,
        /// Who submitted (oracle service account)
        pub validator: T::AccountId,
        /// Block at which validation was anchored
        pub validated_at: BlockNumberFor<T>,
        /// Git commit SHA (up to 40 hex chars)
        pub ci_commit_hash: BoundedVec<u8, ConstU32<40>>,
        /// Arbitrary JSON metadata
        pub metadata: BoundedVec<u8, ConstU32<256>>,
    }

    // ==================== CONFIG ====================

    /// Configure the pallet.
    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// The overarching event type.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Maximum number of validations allowed per block (rate limit).
        #[pallet::constant]
        type MaxValidationsPerBlock: Get<u32>;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    // ==================== STORAGE ====================

    /// All validation records, keyed by validation ID.
    #[pallet::storage]
    #[pallet::getter(fn validations)]
    pub type Validations<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        u64, // validation_id
        OracleValidation<T>,
        OptionQuery,
    >;

    /// Auto-incrementing validation ID counter.
    #[pallet::storage]
    #[pallet::getter(fn next_validation_id)]
    pub type NextValidationId<T: Config> = StorageValue<_, u64, ValueQuery>;

    /// Index: contract_id -> list of validation IDs belonging to that contract.
    #[pallet::storage]
    #[pallet::getter(fn validations_by_contract)]
    pub type ValidationsByContract<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        u64, // contract_id
        BoundedVec<u64, ConstU32<10000>>,
        ValueQuery,
    >;

    /// Index: (contract_id, milestone_id) -> list of validation IDs for that milestone.
    #[pallet::storage]
    #[pallet::getter(fn validations_by_milestone)]
    pub type ValidationsByMilestone<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        u64, // contract_id
        Blake2_128Concat,
        u64, // milestone_id
        BoundedVec<u64, ConstU32<1000>>,
        ValueQuery,
    >;

    /// Number of validations submitted in the current block (rate limiting).
    #[pallet::storage]
    #[pallet::getter(fn validations_in_block)]
    pub type ValidationsInBlock<T: Config> = StorageValue<_, u32, ValueQuery>;

    /// Milestone completion status: (contract_id, milestone_id) -> all 6 plugins passed.
    #[pallet::storage]
    #[pallet::getter(fn milestone_status)]
    pub type MilestoneStatus<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        u64, // contract_id
        Blake2_128Concat,
        u64, // milestone_id
        bool,
        ValueQuery,
    >;

    // ==================== EVENTS ====================

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A validation result was submitted and anchored on-chain.
        ValidationSubmitted {
            validation_id: u64,
            contract_id: u64,
            milestone_id: u64,
            plugin: ValidationPlugin,
            verdict: ValidationVerdict,
            validator: T::AccountId,
        },
        /// A validation was revoked (verdict set to Error).
        ValidationRevoked {
            validation_id: u64,
            validator: T::AccountId,
        },
        /// All 6 plugins passed for a milestone — milestone is now complete.
        MilestoneCompleted {
            contract_id: u64,
            milestone_id: u64,
        },
    }

    // ==================== ERRORS ====================

    #[pallet::error]
    pub enum Error<T> {
        /// The requested validation ID does not exist.
        ValidationNotFound,
        /// Caller is not the original validator of this record.
        NotValidator,
        /// Per-block validation rate limit exceeded.
        RateLimitExceeded,
        /// Score must be 0-100.
        InvalidScore,
        /// Arithmetic overflow.
        Overflow,
        /// This milestone has already been marked as completed.
        MilestoneAlreadyCompleted,
    }

    // ==================== HOOKS ====================

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(_block: BlockNumberFor<T>) -> Weight {
            // Reset the per-block rate limit counter at the start of every block.
            ValidationsInBlock::<T>::put(0u32);
            Weight::from_parts(1_000, 0)
        }
    }

    // ==================== CALLS ====================

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Submit a validation result from Transparence's verification engine.
        ///
        /// Validates rate limits and score bounds, stores the record, updates
        /// contract/milestone indices, and auto-computes milestone completion
        /// (all 6 plugins must have a Pass verdict).
        #[pallet::call_index(0)]
        #[pallet::weight(10_000)]
        pub fn submit_validation(
            origin: OriginFor<T>,
            contract_id: u64,
            milestone_id: u64,
            plugin: ValidationPlugin,
            evidence_hash: [u8; 32],
            verdict: ValidationVerdict,
            score: u8,
            ci_commit_hash: Vec<u8>,
            metadata: Vec<u8>,
        ) -> DispatchResult {
            let validator = ensure_signed(origin)?;

            // --- Rate limit check ---
            let current_count = ValidationsInBlock::<T>::get();
            ensure!(
                current_count < T::MaxValidationsPerBlock::get(),
                Error::<T>::RateLimitExceeded
            );

            // --- Score validation ---
            ensure!(score <= 100, Error::<T>::InvalidScore);

            // --- Milestone guard ---
            ensure!(
                !MilestoneStatus::<T>::get(contract_id, milestone_id),
                Error::<T>::MilestoneAlreadyCompleted
            );

            // --- Convert bounded vecs ---
            let ci_commit_hash_bounded: BoundedVec<u8, ConstU32<40>> =
                ci_commit_hash.try_into().map_err(|_| Error::<T>::Overflow)?;
            let metadata_bounded: BoundedVec<u8, ConstU32<256>> =
                metadata.try_into().map_err(|_| Error::<T>::Overflow)?;

            // --- Allocate ID ---
            let validation_id = NextValidationId::<T>::get();
            let next_id = validation_id.checked_add(1).ok_or(Error::<T>::Overflow)?;
            NextValidationId::<T>::put(next_id);

            // --- Increment block counter ---
            ValidationsInBlock::<T>::put(
                current_count.checked_add(1).ok_or(Error::<T>::Overflow)?
            );

            let current_block = frame_system::Pallet::<T>::block_number();

            // --- Build record ---
            let validation = OracleValidation::<T> {
                id: validation_id,
                contract_id,
                milestone_id,
                plugin: plugin.clone(),
                evidence_hash,
                verdict: verdict.clone(),
                score,
                validator: validator.clone(),
                validated_at: current_block,
                ci_commit_hash: ci_commit_hash_bounded,
                metadata: metadata_bounded,
            };

            // --- Store validation ---
            Validations::<T>::insert(validation_id, validation);

            // --- Update contract index ---
            ValidationsByContract::<T>::try_mutate(contract_id, |ids| {
                ids.try_push(validation_id).map_err(|_| Error::<T>::Overflow)
            })?;

            // --- Update milestone index ---
            ValidationsByMilestone::<T>::try_mutate(contract_id, milestone_id, |ids| {
                ids.try_push(validation_id).map_err(|_| Error::<T>::Overflow)
            })?;

            // --- Emit submission event ---
            Self::deposit_event(Event::ValidationSubmitted {
                validation_id,
                contract_id,
                milestone_id,
                plugin,
                verdict,
                validator,
            });

            // --- Auto-compute milestone status ---
            // A milestone is complete when all 6 plugins have at least one Pass verdict.
            Self::recompute_milestone_status(contract_id, milestone_id);

            Ok(())
        }

        /// Revoke a previously submitted validation.
        ///
        /// Only the original validator can revoke. Sets the verdict to Error.
        /// Triggers recomputation of milestone status.
        #[pallet::call_index(1)]
        #[pallet::weight(10_000)]
        pub fn revoke_validation(
            origin: OriginFor<T>,
            validation_id: u64,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            // --- Fetch and validate ---
            let mut validation = Validations::<T>::get(validation_id)
                .ok_or(Error::<T>::ValidationNotFound)?;

            ensure!(validation.validator == who, Error::<T>::NotValidator);

            let contract_id = validation.contract_id;
            let milestone_id = validation.milestone_id;

            // --- Set verdict to Error ---
            validation.verdict = ValidationVerdict::Error;
            Validations::<T>::insert(validation_id, validation);

            // --- Emit revocation event ---
            Self::deposit_event(Event::ValidationRevoked {
                validation_id,
                validator: who,
            });

            // --- Recompute milestone status (may flip from true to false) ---
            Self::recompute_milestone_status(contract_id, milestone_id);

            Ok(())
        }
    }

    // ==================== HELPER FUNCTIONS ====================

    impl<T: Config> Pallet<T> {
        /// Check whether a milestone is complete (all 6 plugins have a Pass verdict).
        pub fn is_milestone_complete(contract_id: u64, milestone_id: u64) -> bool {
            MilestoneStatus::<T>::get(contract_id, milestone_id)
        }

        /// Retrieve a validation record by ID.
        pub fn get_validation(id: u64) -> Option<OracleValidation<T>> {
            Validations::<T>::get(id)
        }

        /// Recompute and store milestone status.
        ///
        /// Iterates over all validation IDs for (contract_id, milestone_id),
        /// checks whether each of the 6 plugins has at least one Pass verdict,
        /// and updates MilestoneStatus accordingly. Emits MilestoneCompleted
        /// when transitioning from incomplete to complete.
        fn recompute_milestone_status(contract_id: u64, milestone_id: u64) {
            let was_complete = MilestoneStatus::<T>::get(contract_id, milestone_id);

            let validation_ids = ValidationsByMilestone::<T>::get(contract_id, milestone_id);

            let all_pass = ALL_PLUGINS.iter().all(|required_plugin| {
                validation_ids.iter().any(|vid| {
                    if let Some(v) = Validations::<T>::get(vid) {
                        v.plugin == *required_plugin && v.verdict == ValidationVerdict::Pass
                    } else {
                        false
                    }
                })
            });

            MilestoneStatus::<T>::insert(contract_id, milestone_id, all_pass);

            // Emit event only on transition from incomplete to complete
            if all_pass && !was_complete {
                Self::deposit_event(Event::MilestoneCompleted {
                    contract_id,
                    milestone_id,
                });
            }
        }
    }
}
