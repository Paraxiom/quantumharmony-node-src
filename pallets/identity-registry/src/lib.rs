//! # Identity Registry Pallet
//!
//! Unified post-quantum identity management for all services, agents, oracles,
//! shields, and users in the QuantumHarmony ecosystem.
//!
//! ## Overview
//!
//! This pallet provides a soulbound (non-transferable), evolving identity system
//! inspired by the Kylin Network dynamic NFT concept. Each identity carries:
//!
//! - **Role**: Shield, Agent, OracleReporter, Validator, Citizen, Decideur,
//!   Fournisseur, or Service
//! - **PQ key material**: Algorithm identifier, public key hash, and fingerprint
//! - **Reputation**: Dynamic score (0-10000 basis points) adjusted by governance
//! - **Activity tracking**: Attestation count and last-active block, updated by
//!   other pallets (Coherence Shield, oracle, etc.)
//!
//! ## Key Rotation
//!
//! Identities support key rotation without losing history. The `rotate_key`
//! extrinsic updates key material while preserving the identity ID, reputation,
//! attestation count, and all other fields.
//!
//! ## Lookup
//!
//! Identities can be looked up by:
//! - Identity ID (primary key)
//! - Public key hash (SHA-256 of full public key)
//! - Fingerprint (e.g. "58:72:ac:47:...")
//! - Owner account (returns all identities for that account)
//! - Role (returns all identities with a given role)

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

#[frame_support::pallet]
pub mod pallet {
    use codec::DecodeWithMemTracking;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_runtime::traits::Saturating;
    use sp_std::vec::Vec;

    // ==================== CONSTANTS ====================

    /// Maximum identities a single account can register.
    pub const MAX_IDENTITIES_PER_ACCOUNT: u32 = 10;

    /// Maximum length of the metadata field (bytes).
    pub const MAX_METADATA_LENGTH: u32 = 256;

    /// Maximum length of a key fingerprint (bytes).
    pub const MAX_FINGERPRINT_LENGTH: u32 = 48;

    // ==================== DATA STRUCTURES ====================

    /// Role of an identity within the QuantumHarmony ecosystem.
    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, Eq, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen, Default)]
    pub enum IdentityRole {
        /// Coherence Shield instance
        #[default]
        Shield,
        /// Axiom agent / qh-agent
        Agent,
        /// Oracle data feeder
        OracleReporter,
        /// QH validator node
        Validator,
        /// Democratie Augmentee participant
        Citizen,
        /// Municipal decision-maker (Transparence)
        Decideur,
        /// Supplier (Transparence)
        Fournisseur,
        /// Generic service identity
        Service,
    }

    /// Lifecycle status of an identity.
    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, Eq, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen, Default)]
    pub enum IdentityStatus {
        /// Identity is active and valid
        #[default]
        Active,
        /// Temporarily suspended by governance
        Suspended,
        /// Permanently revoked (irreversible)
        Revoked,
    }

    /// Post-quantum key algorithm used by the identity.
    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, Eq, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen, Default)]
    pub enum KeyAlgorithm {
        /// FALCON-512 lattice signature
        #[default]
        Falcon512,
        /// FALCON-1024 lattice signature
        Falcon1024,
        /// SPHINCS+ hash-based signature
        SphincsPlus,
        /// ML-KEM-1024 key encapsulation
        MlKem1024,
    }

    /// Oracle reporter status — tracks reporting lifecycle.
    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, Eq, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen, Default)]
    pub enum ReporterStatus {
        /// Not an oracle reporter
        #[default]
        Unregistered,
        /// Applied, awaiting approval
        Pending,
        /// Approved, can submit oracle data
        Active,
        /// Submitted bad data, staked tokens lost
        Slashed,
    }

    /// Identity stratum per the *Identity as Accountability Chain*
    /// treatise (§3, §2.7 hypergraph). The chain treats every
    /// identity as belonging to exactly one stratum; stratum
    /// determines which accountability operations are even
    /// possible (e.g. `delegate_to_scope` only makes sense for an
    /// S1Person delegating). The S3 stratum (group/collective) is
    /// reserved but intentionally not modelled in v0.1 — it
    /// requires a separate governance attachment.
    ///
    /// The variant order is meaningful for the
    /// stratum-well-foundedness property (Theorem 3 in the
    /// treatise): every S2/S4/S5 identity must trace upward to an
    /// S1 root in finite steps.
    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, Eq, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen, Default)]
    pub enum Stratum {
        /// Natural person / sovereign founding identity. Always a
        /// root; never has a `parent_identity`.
        #[default]
        S1Person,
        /// Scoped delegate (e.g. a supplier's named procurement
        /// contact, a service-role under a parent organization).
        /// Must have `parent_identity` set.
        S2Scoped,
        /// AI-agent instance. Must have `parent_identity` set and
        /// `instance_anchor` populated (the cryptographic hash that
        /// pins this instance to a specific deployment).
        S4AgentInstance,
        /// Cross-tenant identity (e.g. a supplier verified by two
        /// procurement bodies). Must have `parent_identity` set and
        /// at least one `tenant_id`.
        S5CrossTenant,
    }

    /// Who actually holds the signing key for this identity. Crucial
    /// for the credential-vault integration: revocation of a
    /// `TenantCustodial` credential needs the tenant's signing
    /// authority, whereas `SelfSovereign` requires the holder's.
    ///
    /// `NcCustodial` is the "non-custodial co-signer" variant where
    /// the keys are held by an N-of-M holder quorum off-chain; the
    /// pallet-credential-vault commitments referenced by such an
    /// identity carry the quorum policy in their `service_name`
    /// metadata.
    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, Eq, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen, Default)]
    pub enum CustodyMode {
        /// Holder holds the signing key directly.
        SelfSovereign,
        /// Non-custodial co-signed (threshold quorum off-chain).
        NcCustodial,
        /// Tenant/operator holds the signing key on the holder's
        /// behalf. Default for v1 identities migrated forward, since
        /// the testnet today is tenant-custodial throughout
        /// (Transparence, Contributor AI, etc.).
        #[default]
        TenantCustodial,
    }

    /// Hardware deployment tier — classifies the physical infrastructure.
    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, Eq, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen, Default)]
    pub enum HardwareTier {
        /// Unknown or unspecified
        #[default]
        Unknown,
        /// Jetson Nano, RPi — $100-200
        Edge,
        /// NUC, Mac Mini, basic server — $2-5K
        Municipal,
        /// Dual 4090 workstation — $7-15K
        Enterprise,
        /// Air-gapped rack + FPGA + QKD — $50K+
        Defence,
        /// VPS validator node — $40/mo
        Cloud,
    }

    /// A post-quantum identity record (soulbound, non-transferable).
    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, Eq, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    #[scale_info(skip_type_params(T))]
    pub struct PqIdentity<T: Config> {
        /// Unique identity ID
        pub id: u64,
        /// Account that owns this identity
        pub owner: T::AccountId,
        /// Role within the ecosystem
        pub role: IdentityRole,
        /// PQ algorithm for the associated key
        pub algorithm: KeyAlgorithm,
        /// SHA-256 of the full public key
        pub public_key_hash: [u8; 32],
        /// Human-readable key fingerprint (e.g. "58:72:ac:47:...")
        pub fingerprint: BoundedVec<u8, ConstU32<MAX_FINGERPRINT_LENGTH>>,
        /// Label for this identity (e.g. "shield-alice-main")
        pub label: BoundedVec<u8, ConstU32<64>>,
        /// Current lifecycle status
        pub status: IdentityStatus,
        /// Block at which the identity was registered
        pub registered_at: BlockNumberFor<T>,
        /// Block of most recent attestation/activity
        pub last_active: BlockNumberFor<T>,
        /// Total attestations signed by this identity
        pub attestation_count: u64,
        /// Dynamic reputation score (0-10000 basis points)
        pub reputation_score: u32,
        /// Arbitrary JSON metadata
        pub metadata: BoundedVec<u8, ConstU32<MAX_METADATA_LENGTH>>,
        /// Oracle reporter status (for OracleReporter role)
        pub reporter_status: ReporterStatus,
        /// Hardware deployment tier
        pub hardware_tier: HardwareTier,
    }

    // ==================== PALLET CONFIG ====================

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// The overarching event type.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Origin that can perform admin operations (suspend, reactivate, update reputation).
        type ForceOrigin: EnsureOrigin<Self::RuntimeOrigin>;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    // ==================== STORAGE ====================

    /// All identity records, keyed by identity ID.
    #[pallet::storage]
    #[pallet::getter(fn identities)]
    pub type Identities<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        u64,
        PqIdentity<T>,
        OptionQuery,
    >;

    /// Auto-incrementing identity ID counter.
    #[pallet::storage]
    #[pallet::getter(fn next_identity_id)]
    pub type NextIdentityId<T: Config> = StorageValue<_, u64, ValueQuery>;

    /// Index: fingerprint -> identity ID (for lookup by fingerprint).
    #[pallet::storage]
    #[pallet::getter(fn identity_by_fingerprint)]
    pub type IdentityByFingerprint<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        BoundedVec<u8, ConstU32<MAX_FINGERPRINT_LENGTH>>,
        u64,
        OptionQuery,
    >;

    /// Index: public key hash -> identity ID (for lookup by pubkey).
    #[pallet::storage]
    #[pallet::getter(fn identity_by_public_key_hash)]
    pub type IdentityByPublicKeyHash<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        [u8; 32],
        u64,
        OptionQuery,
    >;

    /// Index: owner account -> list of identity IDs owned by that account.
    #[pallet::storage]
    #[pallet::getter(fn identities_by_owner)]
    pub type IdentitiesByOwner<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        BoundedVec<u64, ConstU32<MAX_IDENTITIES_PER_ACCOUNT>>,
        ValueQuery,
    >;

    /// Index: role -> list of identity IDs with that role.
    #[pallet::storage]
    #[pallet::getter(fn identities_by_role)]
    pub type IdentitiesByRole<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        IdentityRole,
        BoundedVec<u64, ConstU32<10000>>,
        ValueQuery,
    >;

    // ==================== TREATISE EXTENSIONS (App. B.1) ====================
    //
    // These maps layer the Stratum / CustodyMode / parent_identity /
    // tenant_id / kyc_bundle_hash / instance_anchor fields onto the
    // existing PqIdentity rows *without* touching the on-chain
    // schema of the struct itself. The pre-existing identities
    // (#0-#5 on chain at time of merge) keep decoding correctly;
    // their extension fields read as defaults until set explicitly
    // via `set_extended_metadata`.

    /// Stratum per identity. Defaults to S1Person — that's the
    /// canonical assumption for every identity that registered
    /// before this extension landed.
    #[pallet::storage]
    pub type IdentityStratum<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        u64,
        Stratum,
        ValueQuery,
    >;

    /// Custody mode per identity. Defaults to TenantCustodial —
    /// matches the testnet's current operational reality.
    #[pallet::storage]
    pub type IdentityCustody<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        u64,
        CustodyMode,
        ValueQuery,
    >;

    /// For S2/S4/S5 identities, the id of the parent identity they
    /// descend from. Stratum-well-foundedness (Theorem 3) requires
    /// the parent chain to terminate at an S1 root in finite steps.
    #[pallet::storage]
    pub type IdentityParent<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        u64,
        u64,
        OptionQuery,
    >;

    /// For S2/S5 identities, the tenant identifier this identity is
    /// scoped under. Free-form bytes; the chain does not interpret
    /// them.
    #[pallet::storage]
    pub type IdentityTenant<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        u64,
        BoundedVec<u8, ConstU32<64>>,
        OptionQuery,
    >;

    /// For S1 identities that elect to anchor a KYC bundle on
    /// chain, the hash of that bundle (the bundle itself lives
    /// off-chain, typically pallet-credential-vault-committed).
    /// Set only with the holder's consent; defaults to None.
    #[pallet::storage]
    pub type IdentityKycBundle<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        u64,
        [u8; 32],
        OptionQuery,
    >;

    /// For S4 (agent-instance) identities, the cryptographic anchor
    /// that pins this instance to a specific deployment artifact
    /// (e.g. weights hash, container digest, code commit). Required
    /// for the instance-non-identity theorem to be meaningful.
    #[pallet::storage]
    pub type IdentityInstanceAnchor<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        u64,
        [u8; 32],
        OptionQuery,
    >;

    // ==================== EVENTS ====================

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A new PQ identity was registered on-chain.
        IdentityRegistered {
            identity_id: u64,
            owner: T::AccountId,
            role: IdentityRole,
            algorithm: KeyAlgorithm,
            label: BoundedVec<u8, ConstU32<64>>,
        },
        /// Identity metadata was updated.
        MetadataUpdated {
            identity_id: u64,
        },
        /// An attestation/activity was recorded for this identity.
        ActivityRecorded {
            identity_id: u64,
            attestation_count: u64,
        },
        /// Reputation score was adjusted by governance.
        ReputationUpdated {
            identity_id: u64,
            old_score: u32,
            new_score: u32,
        },
        /// Identity was suspended by governance.
        IdentitySuspended {
            identity_id: u64,
        },
        /// Identity was reactivated from suspension by governance.
        IdentityReactivated {
            identity_id: u64,
        },
        /// Identity was permanently revoked (irreversible).
        IdentityRevoked {
            identity_id: u64,
        },
        /// Key material was rotated for an identity.
        KeyRotated {
            identity_id: u64,
            new_fingerprint: BoundedVec<u8, ConstU32<MAX_FINGERPRINT_LENGTH>>,
        },
        /// Treatise-extension metadata was set on an identity (any
        /// subset of stratum / custody / parent / tenant / KYC /
        /// instance anchor).
        ExtendedMetadataSet {
            identity_id: u64,
            stratum: Stratum,
            custody: CustodyMode,
        },
    }

    // ==================== ERRORS ====================

    #[pallet::error]
    pub enum Error<T> {
        /// The requested identity ID does not exist.
        IdentityNotFound,
        /// Caller is not the owner of this identity.
        NotOwner,
        /// Identity has already been permanently revoked.
        AlreadyRevoked,
        /// Identity is already suspended.
        AlreadySuspended,
        /// Identity is not currently suspended (cannot reactivate).
        NotSuspended,
        /// Another identity already uses this fingerprint.
        DuplicateFingerprint,
        /// Another identity already uses this public key hash.
        DuplicatePublicKey,
        /// Account has reached the maximum number of identities.
        MaxIdentitiesReached,
        /// Arithmetic overflow.
        Overflow,
        /// Stratum/parent combination is inconsistent with
        /// well-foundedness: S2/S4/S5 require a parent, S1 must not
        /// have one, and an S4 must carry an instance_anchor.
        InvalidStratumLineage,
        /// Tenant identifier exceeds the 64-byte bound.
        TenantIdTooLong,
        /// Parent identity referenced does not exist.
        ParentIdentityNotFound,
    }

    // ==================== HOOKS ====================

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

    // ==================== DISPATCHABLES ====================

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Register a new PQ identity for the calling account.
        ///
        /// Any signed account can register their own identity. The identity starts
        /// in `Active` status with a neutral reputation of 5000 (50%). Creates all
        /// necessary index entries for lookup by fingerprint, pubkey hash, owner,
        /// and role.
        ///
        /// ## Parameters
        /// - `role`: Role of this identity in the ecosystem
        /// - `algorithm`: PQ algorithm used for the key
        /// - `public_key_hash`: SHA-256 hash of the full public key
        /// - `fingerprint`: Human-readable key fingerprint
        /// - `label`: Short label for this identity
        /// - `metadata`: Arbitrary JSON metadata
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn register_identity(
            origin: OriginFor<T>,
            role: IdentityRole,
            algorithm: KeyAlgorithm,
            public_key_hash: [u8; 32],
            fingerprint: Vec<u8>,
            label: Vec<u8>,
            metadata: Vec<u8>,
            hardware_tier: HardwareTier,
        ) -> DispatchResult {
            let owner = ensure_signed(origin)?;

            // --- Convert bounded vecs ---
            let fingerprint_bounded: BoundedVec<u8, ConstU32<MAX_FINGERPRINT_LENGTH>> =
                fingerprint.try_into().map_err(|_| Error::<T>::Overflow)?;
            let label_bounded: BoundedVec<u8, ConstU32<64>> =
                label.try_into().map_err(|_| Error::<T>::Overflow)?;
            let metadata_bounded: BoundedVec<u8, ConstU32<MAX_METADATA_LENGTH>> =
                metadata.try_into().map_err(|_| Error::<T>::Overflow)?;

            // --- Uniqueness checks ---
            ensure!(
                !IdentityByFingerprint::<T>::contains_key(&fingerprint_bounded),
                Error::<T>::DuplicateFingerprint
            );
            ensure!(
                !IdentityByPublicKeyHash::<T>::contains_key(&public_key_hash),
                Error::<T>::DuplicatePublicKey
            );

            // --- Owner capacity check ---
            let owner_ids = IdentitiesByOwner::<T>::get(&owner);
            ensure!(
                (owner_ids.len() as u32) < MAX_IDENTITIES_PER_ACCOUNT,
                Error::<T>::MaxIdentitiesReached
            );

            // --- Allocate ID ---
            let identity_id = NextIdentityId::<T>::get();
            let next_id = identity_id.checked_add(1).ok_or(Error::<T>::Overflow)?;
            NextIdentityId::<T>::put(next_id);

            let current_block = frame_system::Pallet::<T>::block_number();

            // --- Build record ---
            let identity = PqIdentity::<T> {
                id: identity_id,
                owner: owner.clone(),
                role: role.clone(),
                algorithm: algorithm.clone(),
                public_key_hash,
                fingerprint: fingerprint_bounded.clone(),
                label: label_bounded.clone(),
                status: IdentityStatus::Active,
                registered_at: current_block,
                last_active: current_block,
                attestation_count: 0,
                reputation_score: 5000, // neutral
                metadata: metadata_bounded,
                reporter_status: if role == IdentityRole::OracleReporter {
                    ReporterStatus::Pending
                } else {
                    ReporterStatus::Unregistered
                },
                hardware_tier,
            };

            // --- Store identity ---
            Identities::<T>::insert(identity_id, identity);

            // --- Update indices ---
            IdentityByFingerprint::<T>::insert(&fingerprint_bounded, identity_id);
            IdentityByPublicKeyHash::<T>::insert(&public_key_hash, identity_id);

            IdentitiesByOwner::<T>::try_mutate(&owner, |ids| {
                ids.try_push(identity_id).map_err(|_| Error::<T>::MaxIdentitiesReached)
            })?;

            IdentitiesByRole::<T>::try_mutate(&role, |ids| {
                ids.try_push(identity_id).map_err(|_| Error::<T>::Overflow)
            })?;

            // --- Emit event ---
            Self::deposit_event(Event::IdentityRegistered {
                identity_id,
                owner,
                role,
                algorithm,
                label: label_bounded,
            });

            Ok(())
        }

        /// Update the metadata field of an identity.
        ///
        /// Only the owner of the identity can update its metadata.
        ///
        /// ## Parameters
        /// - `identity_id`: ID of the identity to update
        /// - `new_metadata`: New JSON metadata
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn update_metadata(
            origin: OriginFor<T>,
            identity_id: u64,
            new_metadata: Vec<u8>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let mut identity = Identities::<T>::get(identity_id)
                .ok_or(Error::<T>::IdentityNotFound)?;

            ensure!(identity.owner == who, Error::<T>::NotOwner);
            ensure!(identity.status != IdentityStatus::Revoked, Error::<T>::AlreadyRevoked);

            let metadata_bounded: BoundedVec<u8, ConstU32<MAX_METADATA_LENGTH>> =
                new_metadata.try_into().map_err(|_| Error::<T>::Overflow)?;

            identity.metadata = metadata_bounded;
            Identities::<T>::insert(identity_id, identity);

            Self::deposit_event(Event::MetadataUpdated { identity_id });

            Ok(())
        }

        /// Record an attestation/activity for an identity.
        ///
        /// Updates `last_active` to the current block and increments
        /// `attestation_count`. Intended for use by other pallets (Coherence
        /// Shield, oracle, etc.) to track identity activity.
        ///
        /// ## Parameters
        /// - `identity_id`: ID of the identity to update
        #[pallet::call_index(2)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn record_activity(
            origin: OriginFor<T>,
            identity_id: u64,
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;

            let mut identity = Identities::<T>::get(identity_id)
                .ok_or(Error::<T>::IdentityNotFound)?;

            ensure!(identity.status != IdentityStatus::Revoked, Error::<T>::AlreadyRevoked);

            let current_block = frame_system::Pallet::<T>::block_number();
            identity.last_active = current_block;
            identity.attestation_count = identity.attestation_count
                .checked_add(1)
                .ok_or(Error::<T>::Overflow)?;

            let count = identity.attestation_count;
            Identities::<T>::insert(identity_id, identity);

            Self::deposit_event(Event::ActivityRecorded {
                identity_id,
                attestation_count: count,
            });

            Ok(())
        }

        /// Adjust the reputation score of an identity.
        ///
        /// ForceOrigin only. The delta is added to the current score, clamped
        /// to the range 0-10000.
        ///
        /// ## Parameters
        /// - `identity_id`: ID of the identity to adjust
        /// - `delta`: Signed adjustment to reputation score
        #[pallet::call_index(3)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn update_reputation(
            origin: OriginFor<T>,
            identity_id: u64,
            delta: i32,
        ) -> DispatchResult {
            T::ForceOrigin::ensure_origin(origin)?;

            let mut identity = Identities::<T>::get(identity_id)
                .ok_or(Error::<T>::IdentityNotFound)?;

            ensure!(identity.status != IdentityStatus::Revoked, Error::<T>::AlreadyRevoked);

            let old_score = identity.reputation_score;

            // Apply delta with clamping to 0-10000
            let new_score = if delta >= 0 {
                old_score.saturating_add(delta as u32).min(10000)
            } else {
                let abs_delta = delta.unsigned_abs();
                old_score.saturating_sub(abs_delta)
            };

            identity.reputation_score = new_score;
            Identities::<T>::insert(identity_id, identity);

            Self::deposit_event(Event::ReputationUpdated {
                identity_id,
                old_score,
                new_score,
            });

            Ok(())
        }

        /// Suspend an identity.
        ///
        /// ForceOrigin only. Sets the identity status to `Suspended`. Only
        /// active identities can be suspended.
        ///
        /// ## Parameters
        /// - `identity_id`: ID of the identity to suspend
        #[pallet::call_index(4)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn suspend_identity(
            origin: OriginFor<T>,
            identity_id: u64,
        ) -> DispatchResult {
            T::ForceOrigin::ensure_origin(origin)?;

            let mut identity = Identities::<T>::get(identity_id)
                .ok_or(Error::<T>::IdentityNotFound)?;

            ensure!(identity.status != IdentityStatus::Revoked, Error::<T>::AlreadyRevoked);
            ensure!(identity.status != IdentityStatus::Suspended, Error::<T>::AlreadySuspended);

            identity.status = IdentityStatus::Suspended;
            Identities::<T>::insert(identity_id, identity);

            Self::deposit_event(Event::IdentitySuspended { identity_id });

            Ok(())
        }

        /// Reactivate a suspended identity.
        ///
        /// ForceOrigin only. Sets the identity status back to `Active`. Only
        /// suspended identities can be reactivated.
        ///
        /// ## Parameters
        /// - `identity_id`: ID of the identity to reactivate
        #[pallet::call_index(5)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn reactivate_identity(
            origin: OriginFor<T>,
            identity_id: u64,
        ) -> DispatchResult {
            T::ForceOrigin::ensure_origin(origin)?;

            let mut identity = Identities::<T>::get(identity_id)
                .ok_or(Error::<T>::IdentityNotFound)?;

            ensure!(identity.status != IdentityStatus::Revoked, Error::<T>::AlreadyRevoked);
            ensure!(identity.status == IdentityStatus::Suspended, Error::<T>::NotSuspended);

            identity.status = IdentityStatus::Active;
            Identities::<T>::insert(identity_id, identity);

            Self::deposit_event(Event::IdentityReactivated { identity_id });

            Ok(())
        }

        /// Permanently revoke an identity.
        ///
        /// Can be called by the owner OR by ForceOrigin. Once revoked, an
        /// identity cannot be reactivated. This is irreversible.
        ///
        /// ## Parameters
        /// - `identity_id`: ID of the identity to revoke
        #[pallet::call_index(6)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn revoke_identity(
            origin: OriginFor<T>,
            identity_id: u64,
        ) -> DispatchResult {
            // Allow either owner or ForceOrigin
            let is_force = T::ForceOrigin::ensure_origin(origin.clone()).is_ok();

            let mut identity = Identities::<T>::get(identity_id)
                .ok_or(Error::<T>::IdentityNotFound)?;

            ensure!(identity.status != IdentityStatus::Revoked, Error::<T>::AlreadyRevoked);

            if !is_force {
                let who = ensure_signed(origin)?;
                ensure!(identity.owner == who, Error::<T>::NotOwner);
            }

            identity.status = IdentityStatus::Revoked;
            Identities::<T>::insert(identity_id, identity);

            Self::deposit_event(Event::IdentityRevoked { identity_id });

            Ok(())
        }

        /// Rotate key material for an existing identity.
        ///
        /// Owner only. Updates the public key hash and fingerprint while
        /// preserving the identity ID, reputation score, attestation count,
        /// and all other fields. This allows PQ key rotation without losing
        /// on-chain history.
        ///
        /// ## Parameters
        /// - `identity_id`: ID of the identity to rotate keys for
        /// - `new_public_key_hash`: SHA-256 of the new public key
        /// - `new_fingerprint`: New human-readable fingerprint
        #[pallet::call_index(7)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn rotate_key(
            origin: OriginFor<T>,
            identity_id: u64,
            new_public_key_hash: [u8; 32],
            new_fingerprint: Vec<u8>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let mut identity = Identities::<T>::get(identity_id)
                .ok_or(Error::<T>::IdentityNotFound)?;

            ensure!(identity.owner == who, Error::<T>::NotOwner);
            ensure!(identity.status != IdentityStatus::Revoked, Error::<T>::AlreadyRevoked);

            let new_fingerprint_bounded: BoundedVec<u8, ConstU32<MAX_FINGERPRINT_LENGTH>> =
                new_fingerprint.try_into().map_err(|_| Error::<T>::Overflow)?;

            // --- Uniqueness checks for new key material ---
            // Allow if the new fingerprint is the same as the old one (no-op rotation
            // of fingerprint), otherwise ensure no duplicate
            if new_fingerprint_bounded != identity.fingerprint {
                ensure!(
                    !IdentityByFingerprint::<T>::contains_key(&new_fingerprint_bounded),
                    Error::<T>::DuplicateFingerprint
                );
            }
            if new_public_key_hash != identity.public_key_hash {
                ensure!(
                    !IdentityByPublicKeyHash::<T>::contains_key(&new_public_key_hash),
                    Error::<T>::DuplicatePublicKey
                );
            }

            // --- Remove old index entries ---
            IdentityByFingerprint::<T>::remove(&identity.fingerprint);
            IdentityByPublicKeyHash::<T>::remove(&identity.public_key_hash);

            // --- Update identity ---
            identity.public_key_hash = new_public_key_hash;
            identity.fingerprint = new_fingerprint_bounded.clone();

            // --- Insert new index entries ---
            IdentityByFingerprint::<T>::insert(&new_fingerprint_bounded, identity_id);
            IdentityByPublicKeyHash::<T>::insert(&new_public_key_hash, identity_id);

            Identities::<T>::insert(identity_id, identity);

            Self::deposit_event(Event::KeyRotated {
                identity_id,
                new_fingerprint: new_fingerprint_bounded,
            });

            Ok(())
        }

        /// Set the treatise-extension metadata (Stratum, CustodyMode,
        /// optional parent_identity / tenant_id / kyc_bundle_hash /
        /// instance_anchor) on an existing identity.
        ///
        /// Caller must own the identity (matches `update_metadata`'s
        /// authorization model).
        ///
        /// Enforces stratum-well-foundedness at write time:
        /// - S1Person: parent_identity MUST be None
        /// - S2Scoped: parent_identity MUST be Some(_) AND that
        ///   parent must exist
        /// - S4AgentInstance: parent + instance_anchor BOTH required
        /// - S5CrossTenant: parent + tenant_id BOTH required
        ///
        /// Idempotent: re-setting the same values is a no-op
        /// (mod event emission).
        #[pallet::call_index(8)]
        #[pallet::weight(Weight::from_parts(50_000_000, 0))]
        pub fn set_extended_metadata(
            origin: OriginFor<T>,
            identity_id: u64,
            stratum: Stratum,
            custody: CustodyMode,
            parent_identity: Option<u64>,
            tenant_id: Option<sp_std::vec::Vec<u8>>,
            kyc_bundle_hash: Option<[u8; 32]>,
            instance_anchor: Option<[u8; 32]>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            // Owner check, matches the rest of the pallet's pattern.
            let identity = Identities::<T>::get(identity_id)
                .ok_or(Error::<T>::IdentityNotFound)?;
            ensure!(identity.owner == who, Error::<T>::NotOwner);

            // Stratum-well-foundedness invariants.
            match stratum {
                Stratum::S1Person => {
                    ensure!(parent_identity.is_none(),
                        Error::<T>::InvalidStratumLineage);
                }
                Stratum::S2Scoped => {
                    ensure!(parent_identity.is_some(),
                        Error::<T>::InvalidStratumLineage);
                }
                Stratum::S4AgentInstance => {
                    ensure!(parent_identity.is_some()
                            && instance_anchor.is_some(),
                        Error::<T>::InvalidStratumLineage);
                }
                Stratum::S5CrossTenant => {
                    ensure!(parent_identity.is_some()
                            && tenant_id.is_some(),
                        Error::<T>::InvalidStratumLineage);
                }
            }

            // Parent existence check (avoids dangling references).
            if let Some(pid) = parent_identity {
                ensure!(
                    Identities::<T>::contains_key(pid),
                    Error::<T>::ParentIdentityNotFound
                );
            }

            // Tenant length check before any storage write.
            let tenant_bounded: Option<BoundedVec<u8, ConstU32<64>>> =
                match tenant_id {
                    None => None,
                    Some(raw) => Some(
                        BoundedVec::try_from(raw)
                            .map_err(|_| Error::<T>::TenantIdTooLong)?,
                    ),
                };

            // Writes — all idempotent, take None as "remove this".
            IdentityStratum::<T>::insert(identity_id, stratum.clone());
            IdentityCustody::<T>::insert(identity_id, custody.clone());
            match parent_identity {
                Some(p) => IdentityParent::<T>::insert(identity_id, p),
                None => IdentityParent::<T>::remove(identity_id),
            }
            match tenant_bounded {
                Some(t) => IdentityTenant::<T>::insert(identity_id, t),
                None => IdentityTenant::<T>::remove(identity_id),
            }
            match kyc_bundle_hash {
                Some(h) => IdentityKycBundle::<T>::insert(identity_id, h),
                None => IdentityKycBundle::<T>::remove(identity_id),
            }
            match instance_anchor {
                Some(h) => IdentityInstanceAnchor::<T>::insert(identity_id, h),
                None => IdentityInstanceAnchor::<T>::remove(identity_id),
            }

            Self::deposit_event(Event::ExtendedMetadataSet {
                identity_id,
                stratum,
                custody,
            });

            Ok(())
        }
    }

    // ==================== HELPER FUNCTIONS ====================

    impl<T: Config> Pallet<T> {
        /// Retrieve an identity record by ID.
        pub fn get_identity(id: u64) -> Option<PqIdentity<T>> {
            Identities::<T>::get(id)
        }

        /// Look up an identity ID by fingerprint.
        pub fn lookup_by_fingerprint(fingerprint: &[u8]) -> Option<u64> {
            let bounded: BoundedVec<u8, ConstU32<MAX_FINGERPRINT_LENGTH>> =
                fingerprint.to_vec().try_into().ok()?;
            IdentityByFingerprint::<T>::get(&bounded)
        }

        /// Look up an identity ID by public key hash.
        pub fn lookup_by_pubkey_hash(hash: [u8; 32]) -> Option<u64> {
            IdentityByPublicKeyHash::<T>::get(&hash)
        }

        /// Check whether an identity exists and is currently active.
        pub fn is_active(id: u64) -> bool {
            Identities::<T>::get(id)
                .map(|i| i.status == IdentityStatus::Active)
                .unwrap_or(false)
        }
    }
}
