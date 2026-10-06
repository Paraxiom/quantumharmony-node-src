//! Tests for the Identity Registry pallet
//!
//! Comprehensive test coverage for PQ identity registration, metadata updates,
//! activity tracking, reputation management, suspension, revocation, key
//! rotation, and lookup helpers.

use crate::{mock::*, pallet::*, Error, Event};
use frame_support::{assert_noop, assert_ok, BoundedVec};

// ==================== HELPERS ====================

/// Create a unique public key hash from a seed byte.
fn pubkey_hash(seed: u8) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash[0] = seed;
    hash[31] = seed;
    hash
}

/// Create a fingerprint byte vec from a seed byte.
fn fingerprint(seed: u8) -> Vec<u8> {
    vec![seed; 16]
}

/// A short label.
fn label(seed: u8) -> Vec<u8> {
    vec![b'I', b'D', seed]
}

/// Empty metadata.
fn empty_metadata() -> Vec<u8> {
    vec![]
}

/// Register a default identity for `account` using the given seed for
/// unique key material. Returns the identity ID assigned.
fn register_default(account: u64, seed: u8) -> u64 {
    let id_before = IdentityRegistry::next_identity_id();
    assert_ok!(IdentityRegistry::register_identity(
        RuntimeOrigin::signed(account),
        IdentityRole::Shield,
        KeyAlgorithm::Falcon512,
        pubkey_hash(seed),
        fingerprint(seed),
        label(seed),
        empty_metadata(),
        HardwareTier::Cloud,
    ));
    id_before
}

// ==================== REGISTRATION TESTS ====================

#[test]
fn register_identity_works() {
    new_test_ext().execute_with(|| {
        let id = register_default(ALICE, 1);
        assert_eq!(id, 0);

        // Storage: identity exists and has correct fields
        let identity = IdentityRegistry::identities(id).expect("identity should exist");
        assert_eq!(identity.id, 0);
        assert_eq!(identity.owner, ALICE);
        assert_eq!(identity.role, IdentityRole::Shield);
        assert_eq!(identity.algorithm, KeyAlgorithm::Falcon512);
        assert_eq!(identity.public_key_hash, pubkey_hash(1));
        assert_eq!(identity.status, IdentityStatus::Active);
        assert_eq!(identity.attestation_count, 0);
        assert_eq!(identity.registered_at, 1);
        assert_eq!(identity.last_active, 1);

        // Index: fingerprint -> id
        let fp_bounded: BoundedVec<u8, frame_support::traits::ConstU32<MAX_FINGERPRINT_LENGTH>> =
            fingerprint(1).try_into().unwrap();
        assert_eq!(IdentityRegistry::identity_by_fingerprint(&fp_bounded), Some(0));

        // Index: pubkey hash -> id
        assert_eq!(IdentityRegistry::identity_by_public_key_hash(pubkey_hash(1)), Some(0));

        // Index: owner -> ids
        let owner_ids = IdentityRegistry::identities_by_owner(ALICE);
        assert!(owner_ids.contains(&0));

        // Index: role -> ids
        let role_ids = IdentityRegistry::identities_by_role(IdentityRole::Shield);
        assert!(role_ids.contains(&0));

        // Next ID incremented
        assert_eq!(IdentityRegistry::next_identity_id(), 1);

        // Event
        System::assert_last_event(
            Event::IdentityRegistered {
                identity_id: 0,
                owner: ALICE,
                role: IdentityRole::Shield,
                algorithm: KeyAlgorithm::Falcon512,
                label: label(1).try_into().unwrap(),
            }
            .into(),
        );
    });
}

#[test]
fn register_identity_default_reputation() {
    new_test_ext().execute_with(|| {
        let id = register_default(ALICE, 1);
        let identity = IdentityRegistry::identities(id).expect("identity should exist");
        assert_eq!(identity.reputation_score, 5000);
    });
}

#[test]
fn register_duplicate_fingerprint_fails() {
    new_test_ext().execute_with(|| {
        register_default(ALICE, 1);

        // Same fingerprint, different pubkey
        assert_noop!(
            IdentityRegistry::register_identity(
                RuntimeOrigin::signed(BOB),
                IdentityRole::Agent,
                KeyAlgorithm::Falcon1024,
                pubkey_hash(2),     // different pubkey
                fingerprint(1),     // SAME fingerprint
                label(2),
                empty_metadata(),
                HardwareTier::Cloud,
            ),
            Error::<Test>::DuplicateFingerprint
        );
    });
}

#[test]
fn register_duplicate_pubkey_fails() {
    new_test_ext().execute_with(|| {
        register_default(ALICE, 1);

        // Same pubkey hash, different fingerprint
        assert_noop!(
            IdentityRegistry::register_identity(
                RuntimeOrigin::signed(BOB),
                IdentityRole::Agent,
                KeyAlgorithm::Falcon1024,
                pubkey_hash(1),     // SAME pubkey
                fingerprint(2),     // different fingerprint
                label(2),
                empty_metadata(),
                HardwareTier::Cloud,
            ),
            Error::<Test>::DuplicatePublicKey
        );
    });
}

#[test]
fn register_max_identities_per_account() {
    new_test_ext().execute_with(|| {
        // Register 10 identities for ALICE (the max)
        for seed in 0..10u8 {
            register_default(ALICE, seed);
        }

        // The 11th should fail
        assert_noop!(
            IdentityRegistry::register_identity(
                RuntimeOrigin::signed(ALICE),
                IdentityRole::Citizen,
                KeyAlgorithm::SphincsPlus,
                pubkey_hash(10),
                fingerprint(10),
                label(10),
                empty_metadata(),
                HardwareTier::Municipal,
            ),
            Error::<Test>::MaxIdentitiesReached
        );

        // But another account can still register
        register_default(BOB, 100);
        assert!(IdentityRegistry::identities(10).is_some());
    });
}

// ==================== METADATA UPDATE TESTS ====================

#[test]
fn update_metadata_owner_only() {
    new_test_ext().execute_with(|| {
        let id = register_default(ALICE, 1);

        // BOB is not the owner
        assert_noop!(
            IdentityRegistry::update_metadata(
                RuntimeOrigin::signed(BOB),
                id,
                b"new metadata".to_vec(),
            ),
            Error::<Test>::NotOwner
        );
    });
}

#[test]
fn update_metadata_works() {
    new_test_ext().execute_with(|| {
        let id = register_default(ALICE, 1);
        let new_meta = b"{\"version\":2}".to_vec();

        assert_ok!(IdentityRegistry::update_metadata(
            RuntimeOrigin::signed(ALICE),
            id,
            new_meta.clone(),
        ));

        let identity = IdentityRegistry::identities(id).expect("identity should exist");
        let meta_bounded: BoundedVec<u8, frame_support::traits::ConstU32<MAX_METADATA_LENGTH>> =
            new_meta.try_into().unwrap();
        assert_eq!(identity.metadata, meta_bounded);

        System::assert_last_event(Event::MetadataUpdated { identity_id: id }.into());
    });
}

// ==================== ACTIVITY RECORDING TESTS ====================

#[test]
fn record_activity_increments_count() {
    new_test_ext().execute_with(|| {
        let id = register_default(ALICE, 1);

        // Initial state
        let identity = IdentityRegistry::identities(id).unwrap();
        assert_eq!(identity.attestation_count, 0);
        assert_eq!(identity.last_active, 1);

        // Record first activity at block 5
        System::set_block_number(5);
        assert_ok!(IdentityRegistry::record_activity(
            RuntimeOrigin::signed(ALICE),
            id,
        ));

        let identity = IdentityRegistry::identities(id).unwrap();
        assert_eq!(identity.attestation_count, 1);
        assert_eq!(identity.last_active, 5);

        System::assert_last_event(
            Event::ActivityRecorded {
                identity_id: id,
                attestation_count: 1,
            }
            .into(),
        );

        // Record second activity at block 10
        System::set_block_number(10);
        assert_ok!(IdentityRegistry::record_activity(
            RuntimeOrigin::signed(BOB), // any signed origin can record
            id,
        ));

        let identity = IdentityRegistry::identities(id).unwrap();
        assert_eq!(identity.attestation_count, 2);
        assert_eq!(identity.last_active, 10);
    });
}

// ==================== REPUTATION TESTS ====================

#[test]
fn update_reputation_force_origin_only() {
    new_test_ext().execute_with(|| {
        let id = register_default(ALICE, 1);

        // Signed origin cannot update reputation
        assert_noop!(
            IdentityRegistry::update_reputation(
                RuntimeOrigin::signed(ALICE),
                id,
                500,
            ),
            sp_runtime::DispatchError::BadOrigin
        );

        // Root can
        assert_ok!(IdentityRegistry::update_reputation(
            RuntimeOrigin::root(),
            id,
            500,
        ));
    });
}

#[test]
fn update_reputation_clamped() {
    new_test_ext().execute_with(|| {
        let id = register_default(ALICE, 1);
        // Default is 5000

        // Push above 10000 — should clamp to 10000
        assert_ok!(IdentityRegistry::update_reputation(
            RuntimeOrigin::root(),
            id,
            6000,
        ));
        let identity = IdentityRegistry::identities(id).unwrap();
        assert_eq!(identity.reputation_score, 10000);

        System::assert_last_event(
            Event::ReputationUpdated {
                identity_id: id,
                old_score: 5000,
                new_score: 10000,
            }
            .into(),
        );

        // Push below 0 — should clamp to 0
        assert_ok!(IdentityRegistry::update_reputation(
            RuntimeOrigin::root(),
            id,
            -20000,
        ));
        let identity = IdentityRegistry::identities(id).unwrap();
        assert_eq!(identity.reputation_score, 0);

        System::assert_last_event(
            Event::ReputationUpdated {
                identity_id: id,
                old_score: 10000,
                new_score: 0,
            }
            .into(),
        );
    });
}

// ==================== SUSPENSION TESTS ====================

#[test]
fn suspend_identity_works() {
    new_test_ext().execute_with(|| {
        let id = register_default(ALICE, 1);

        assert_ok!(IdentityRegistry::suspend_identity(
            RuntimeOrigin::root(),
            id,
        ));

        let identity = IdentityRegistry::identities(id).unwrap();
        assert_eq!(identity.status, IdentityStatus::Suspended);

        System::assert_last_event(Event::IdentitySuspended { identity_id: id }.into());

        // Cannot suspend again
        assert_noop!(
            IdentityRegistry::suspend_identity(RuntimeOrigin::root(), id),
            Error::<Test>::AlreadySuspended
        );
    });
}

#[test]
fn reactivate_identity_works() {
    new_test_ext().execute_with(|| {
        let id = register_default(ALICE, 1);

        // Suspend first
        assert_ok!(IdentityRegistry::suspend_identity(RuntimeOrigin::root(), id));
        assert_eq!(
            IdentityRegistry::identities(id).unwrap().status,
            IdentityStatus::Suspended,
        );

        // Reactivate
        assert_ok!(IdentityRegistry::reactivate_identity(
            RuntimeOrigin::root(),
            id,
        ));

        let identity = IdentityRegistry::identities(id).unwrap();
        assert_eq!(identity.status, IdentityStatus::Active);

        System::assert_last_event(Event::IdentityReactivated { identity_id: id }.into());
    });
}

#[test]
fn reactivate_not_suspended_fails() {
    new_test_ext().execute_with(|| {
        let id = register_default(ALICE, 1);

        // Identity is Active, not Suspended
        assert_noop!(
            IdentityRegistry::reactivate_identity(RuntimeOrigin::root(), id),
            Error::<Test>::NotSuspended
        );
    });
}

// ==================== REVOCATION TESTS ====================

#[test]
fn revoke_identity_permanent() {
    new_test_ext().execute_with(|| {
        let id = register_default(ALICE, 1);

        // Revoke
        assert_ok!(IdentityRegistry::revoke_identity(
            RuntimeOrigin::signed(ALICE),
            id,
        ));

        let identity = IdentityRegistry::identities(id).unwrap();
        assert_eq!(identity.status, IdentityStatus::Revoked);

        System::assert_last_event(Event::IdentityRevoked { identity_id: id }.into());

        // Cannot reactivate a revoked identity
        assert_noop!(
            IdentityRegistry::reactivate_identity(RuntimeOrigin::root(), id),
            Error::<Test>::AlreadyRevoked
        );

        // Cannot update metadata on a revoked identity
        assert_noop!(
            IdentityRegistry::update_metadata(
                RuntimeOrigin::signed(ALICE),
                id,
                b"new".to_vec(),
            ),
            Error::<Test>::AlreadyRevoked
        );

        // Cannot record activity on a revoked identity
        assert_noop!(
            IdentityRegistry::record_activity(RuntimeOrigin::signed(ALICE), id),
            Error::<Test>::AlreadyRevoked
        );

        // Cannot suspend a revoked identity
        assert_noop!(
            IdentityRegistry::suspend_identity(RuntimeOrigin::root(), id),
            Error::<Test>::AlreadyRevoked
        );

        // Cannot update reputation on a revoked identity
        assert_noop!(
            IdentityRegistry::update_reputation(RuntimeOrigin::root(), id, 100),
            Error::<Test>::AlreadyRevoked
        );

        // Cannot revoke again
        assert_noop!(
            IdentityRegistry::revoke_identity(RuntimeOrigin::signed(ALICE), id),
            Error::<Test>::AlreadyRevoked
        );
    });
}

#[test]
fn revoke_by_owner_works() {
    new_test_ext().execute_with(|| {
        let id = register_default(ALICE, 1);

        // Owner can revoke
        assert_ok!(IdentityRegistry::revoke_identity(
            RuntimeOrigin::signed(ALICE),
            id,
        ));

        let identity = IdentityRegistry::identities(id).unwrap();
        assert_eq!(identity.status, IdentityStatus::Revoked);

        // Non-owner cannot revoke someone else's identity
        let id2 = register_default(BOB, 2);
        assert_noop!(
            IdentityRegistry::revoke_identity(RuntimeOrigin::signed(ALICE), id2),
            Error::<Test>::NotOwner
        );
    });
}

#[test]
fn revoke_by_force_origin_works() {
    new_test_ext().execute_with(|| {
        let id = register_default(ALICE, 1);

        // Root (ForceOrigin) can revoke anyone's identity
        assert_ok!(IdentityRegistry::revoke_identity(
            RuntimeOrigin::root(),
            id,
        ));

        let identity = IdentityRegistry::identities(id).unwrap();
        assert_eq!(identity.status, IdentityStatus::Revoked);

        System::assert_last_event(Event::IdentityRevoked { identity_id: id }.into());
    });
}

// ==================== KEY ROTATION TESTS ====================

#[test]
fn rotate_key_works() {
    new_test_ext().execute_with(|| {
        let id = register_default(ALICE, 1);

        // Set some reputation and attestations first
        assert_ok!(IdentityRegistry::update_reputation(RuntimeOrigin::root(), id, 1000));
        assert_ok!(IdentityRegistry::record_activity(RuntimeOrigin::signed(ALICE), id));

        let identity_before = IdentityRegistry::identities(id).unwrap();
        assert_eq!(identity_before.reputation_score, 6000);
        assert_eq!(identity_before.attestation_count, 1);

        // Rotate key
        let new_pk = pubkey_hash(99);
        let new_fp = fingerprint(99);

        assert_ok!(IdentityRegistry::rotate_key(
            RuntimeOrigin::signed(ALICE),
            id,
            new_pk,
            new_fp.clone(),
        ));

        let identity_after = IdentityRegistry::identities(id).unwrap();

        // Key material changed
        assert_eq!(identity_after.public_key_hash, new_pk);
        let new_fp_bounded: BoundedVec<u8, frame_support::traits::ConstU32<MAX_FINGERPRINT_LENGTH>> =
            new_fp.clone().try_into().unwrap();
        assert_eq!(identity_after.fingerprint, new_fp_bounded);

        // Identity ID, reputation, attestation count preserved
        assert_eq!(identity_after.id, id);
        assert_eq!(identity_after.reputation_score, 6000);
        assert_eq!(identity_after.attestation_count, 1);
        assert_eq!(identity_after.owner, ALICE);

        // Old indices removed, new indices present
        let old_fp_bounded: BoundedVec<u8, frame_support::traits::ConstU32<MAX_FINGERPRINT_LENGTH>> =
            fingerprint(1).try_into().unwrap();
        assert_eq!(IdentityRegistry::identity_by_fingerprint(&old_fp_bounded), None);
        assert_eq!(IdentityRegistry::identity_by_public_key_hash(pubkey_hash(1)), None);

        assert_eq!(IdentityRegistry::identity_by_fingerprint(&new_fp_bounded), Some(id));
        assert_eq!(IdentityRegistry::identity_by_public_key_hash(new_pk), Some(id));

        // Event
        System::assert_last_event(
            Event::KeyRotated {
                identity_id: id,
                new_fingerprint: new_fp.try_into().unwrap(),
            }
            .into(),
        );
    });
}

#[test]
fn rotate_key_not_owner_fails() {
    new_test_ext().execute_with(|| {
        let id = register_default(ALICE, 1);

        assert_noop!(
            IdentityRegistry::rotate_key(
                RuntimeOrigin::signed(BOB),
                id,
                pubkey_hash(50),
                fingerprint(50),
            ),
            Error::<Test>::NotOwner
        );
    });
}

// ==================== LOOKUP HELPER TESTS ====================

#[test]
fn lookup_by_fingerprint_works() {
    new_test_ext().execute_with(|| {
        let id = register_default(ALICE, 42);

        // Found
        let result = IdentityRegistry::lookup_by_fingerprint(&fingerprint(42));
        assert_eq!(result, Some(id));

        // Not found
        let result = IdentityRegistry::lookup_by_fingerprint(&fingerprint(99));
        assert_eq!(result, None);
    });
}

#[test]
fn lookup_by_pubkey_hash_works() {
    new_test_ext().execute_with(|| {
        let id = register_default(ALICE, 42);

        // Found
        let result = IdentityRegistry::lookup_by_pubkey_hash(pubkey_hash(42));
        assert_eq!(result, Some(id));

        // Not found
        let result = IdentityRegistry::lookup_by_pubkey_hash(pubkey_hash(99));
        assert_eq!(result, None);
    });
}

// ============================================================================
// set_extended_metadata — treatise extensions (App. B.1, GH #34)
// ============================================================================

#[test]
fn set_extended_metadata_owner_can_set_basics() {
    new_test_ext().execute_with(|| {
        let id = register_default(ALICE, 1);
        // Defaults read clean for an identity that hasn't called the extension.
        assert_eq!(IdentityStratum::<Test>::get(id), Stratum::S1Person);
        assert_eq!(IdentityCustody::<Test>::get(id), CustodyMode::TenantCustodial);
        assert!(IdentityParent::<Test>::get(id).is_none());

        // Owner sets a self-sovereign S1 with a KYC bundle hash.
        assert_ok!(IdentityRegistry::set_extended_metadata(
            RuntimeOrigin::signed(ALICE),
            id,
            Stratum::S1Person,
            CustodyMode::SelfSovereign,
            None,
            None,
            Some([0xAB; 32]),
            None,
        ));
        assert_eq!(IdentityStratum::<Test>::get(id), Stratum::S1Person);
        assert_eq!(IdentityCustody::<Test>::get(id), CustodyMode::SelfSovereign);
        assert_eq!(IdentityKycBundle::<Test>::get(id), Some([0xAB; 32]));
    });
}

#[test]
fn set_extended_metadata_rejects_non_owner() {
    new_test_ext().execute_with(|| {
        let id = register_default(ALICE, 1);
        assert_noop!(
            IdentityRegistry::set_extended_metadata(
                RuntimeOrigin::signed(BOB),
                id,
                Stratum::S1Person,
                CustodyMode::SelfSovereign,
                None, None, None, None,
            ),
            Error::<Test>::NotOwner,
        );
    });
}

#[test]
fn s1_with_parent_is_rejected() {
    new_test_ext().execute_with(|| {
        let parent = register_default(ALICE, 1);
        let child = register_default(ALICE, 2);
        assert_noop!(
            IdentityRegistry::set_extended_metadata(
                RuntimeOrigin::signed(ALICE),
                child,
                Stratum::S1Person,
                CustodyMode::SelfSovereign,
                Some(parent),  // ← S1 cannot have a parent
                None, None, None,
            ),
            Error::<Test>::InvalidStratumLineage,
        );
    });
}

#[test]
fn s2_without_parent_is_rejected() {
    new_test_ext().execute_with(|| {
        let id = register_default(ALICE, 1);
        assert_noop!(
            IdentityRegistry::set_extended_metadata(
                RuntimeOrigin::signed(ALICE),
                id,
                Stratum::S2Scoped,
                CustodyMode::TenantCustodial,
                None,  // ← required
                None, None, None,
            ),
            Error::<Test>::InvalidStratumLineage,
        );
    });
}

#[test]
fn s4_without_anchor_is_rejected() {
    new_test_ext().execute_with(|| {
        let parent = register_default(ALICE, 1);
        let agent = register_default(ALICE, 2);
        assert_noop!(
            IdentityRegistry::set_extended_metadata(
                RuntimeOrigin::signed(ALICE),
                agent,
                Stratum::S4AgentInstance,
                CustodyMode::TenantCustodial,
                Some(parent),
                None,
                None,
                None,  // ← anchor required
            ),
            Error::<Test>::InvalidStratumLineage,
        );
    });
}

#[test]
fn s5_without_tenant_is_rejected() {
    new_test_ext().execute_with(|| {
        let parent = register_default(ALICE, 1);
        let cross = register_default(ALICE, 2);
        assert_noop!(
            IdentityRegistry::set_extended_metadata(
                RuntimeOrigin::signed(ALICE),
                cross,
                Stratum::S5CrossTenant,
                CustodyMode::TenantCustodial,
                Some(parent),
                None,  // ← tenant required
                None,
                None,
            ),
            Error::<Test>::InvalidStratumLineage,
        );
    });
}

#[test]
fn parent_must_exist() {
    new_test_ext().execute_with(|| {
        let id = register_default(ALICE, 1);
        assert_noop!(
            IdentityRegistry::set_extended_metadata(
                RuntimeOrigin::signed(ALICE),
                id,
                Stratum::S2Scoped,
                CustodyMode::TenantCustodial,
                Some(9999),  // never registered
                None, None, None,
            ),
            Error::<Test>::ParentIdentityNotFound,
        );
    });
}

#[test]
fn s4_with_parent_and_anchor_succeeds() {
    new_test_ext().execute_with(|| {
        let parent = register_default(ALICE, 1);
        let agent  = register_default(ALICE, 2);
        let anchor = [0xCD; 32];
        assert_ok!(IdentityRegistry::set_extended_metadata(
            RuntimeOrigin::signed(ALICE),
            agent,
            Stratum::S4AgentInstance,
            CustodyMode::NcCustodial,
            Some(parent),
            None,
            None,
            Some(anchor),
        ));
        assert_eq!(IdentityStratum::<Test>::get(agent), Stratum::S4AgentInstance);
        assert_eq!(IdentityParent::<Test>::get(agent), Some(parent));
        assert_eq!(IdentityInstanceAnchor::<Test>::get(agent), Some(anchor));
    });
}

#[test]
fn s5_with_tenant_succeeds_and_round_trips() {
    new_test_ext().execute_with(|| {
        let parent = register_default(ALICE, 1);
        let cross  = register_default(ALICE, 2);
        let tenant = b"ville-de-levis".to_vec();
        assert_ok!(IdentityRegistry::set_extended_metadata(
            RuntimeOrigin::signed(ALICE),
            cross,
            Stratum::S5CrossTenant,
            CustodyMode::TenantCustodial,
            Some(parent),
            Some(tenant.clone()),
            None,
            None,
        ));
        assert_eq!(
            IdentityTenant::<Test>::get(cross).map(|b| b.to_vec()),
            Some(tenant),
        );
    });
}

#[test]
fn tenant_too_long_is_rejected() {
    new_test_ext().execute_with(|| {
        let parent = register_default(ALICE, 1);
        let cross  = register_default(ALICE, 2);
        let too_long = vec![b'x'; 65];
        assert_noop!(
            IdentityRegistry::set_extended_metadata(
                RuntimeOrigin::signed(ALICE),
                cross,
                Stratum::S5CrossTenant,
                CustodyMode::TenantCustodial,
                Some(parent),
                Some(too_long),
                None, None,
            ),
            Error::<Test>::TenantIdTooLong,
        );
    });
}

#[test]
fn re_set_removes_fields_when_none_passed() {
    new_test_ext().execute_with(|| {
        let parent = register_default(ALICE, 1);
        let child  = register_default(ALICE, 2);
        // First, set as S2 with a tenant.
        assert_ok!(IdentityRegistry::set_extended_metadata(
            RuntimeOrigin::signed(ALICE),
            child,
            Stratum::S2Scoped,
            CustodyMode::TenantCustodial,
            Some(parent),
            Some(b"t1".to_vec()),
            Some([1; 32]),
            None,
        ));
        assert!(IdentityTenant::<Test>::get(child).is_some());
        assert!(IdentityKycBundle::<Test>::get(child).is_some());

        // Re-set as S1 with no optional fields → all optionals cleared.
        assert_ok!(IdentityRegistry::set_extended_metadata(
            RuntimeOrigin::signed(ALICE),
            child,
            Stratum::S1Person,
            CustodyMode::SelfSovereign,
            None, None, None, None,
        ));
        assert_eq!(IdentityStratum::<Test>::get(child), Stratum::S1Person);
        assert!(IdentityParent::<Test>::get(child).is_none());
        assert!(IdentityTenant::<Test>::get(child).is_none());
        assert!(IdentityKycBundle::<Test>::get(child).is_none());
    });
}
