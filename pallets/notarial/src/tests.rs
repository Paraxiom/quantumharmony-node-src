//! Tests for the Notarial pallet
//!
//! Comprehensive test coverage for document attestation, witnessing,
//! revocation, certification, and tag management.

use crate::{mock::*, Error, Event, AttestationStatus, DocumentCategory};
use frame_support::{assert_noop, assert_ok};

/// Helper to create a document hash
fn document_hash(seed: u8) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash[0] = seed;
    hash[31] = seed;
    hash
}

/// Helper to create description bytes
fn description(text: &str) -> Vec<u8> {
    text.as_bytes().to_vec()
}

// ==================== ATTEST DOCUMENT TESTS ====================

#[test]
fn attest_document_works() {
    new_test_ext().execute_with(|| {
        let hash = document_hash(1);
        let desc = description("Test document");

        assert_ok!(Notarial::attest_document(
            RuntimeOrigin::signed(ALICE),
            hash,
            0, // AcademicCredential
            desc.clone(),
            None, // permanent
            None,
            None,
        ));

        // Verify attestation was created
        let attestation = Notarial::attestations(0).expect("Attestation should exist");
        assert_eq!(attestation.document_hash, hash);
        assert_eq!(attestation.attester, ALICE);
        assert_eq!(attestation.category, DocumentCategory::AcademicCredential);
        assert_eq!(attestation.status, AttestationStatus::Active);
        assert_eq!(attestation.witness_count, 0);
        assert!(!attestation.certified);

        // Verify lookup by hash works
        assert_eq!(Notarial::attestation_by_hash(hash), Some(0));

        // Verify owner tracking
        let owner_attestations = Notarial::attestations_by_owner(ALICE);
        assert!(owner_attestations.contains(&0));

        // Verify event
        System::assert_has_event(Event::DocumentAttested {
            attestation_id: 0,
            document_hash: hash,
            attester: ALICE,
            category_id: 0,
        }.into());
    });
}

#[test]
fn attest_document_with_validity_period() {
    new_test_ext().execute_with(|| {
        let hash = document_hash(2);

        assert_ok!(Notarial::attest_document(
            RuntimeOrigin::signed(ALICE),
            hash,
            1, // LegalDocument
            description("Legal doc"),
            Some(100), // expires in 100 blocks
            None,
            None,
        ));

        let attestation = Notarial::attestations(0).expect("Attestation should exist");
        assert_eq!(attestation.expires_at, Some(101)); // starts at block 1 + 100 = 101
    });
}

#[test]
fn attest_document_with_contract_reference() {
    new_test_ext().execute_with(|| {
        let hash = document_hash(3);

        assert_ok!(Notarial::attest_document(
            RuntimeOrigin::signed(ALICE),
            hash,
            2, // Contract
            description("Contract attestation"),
            None,
            Some(42), // contract_id
            None,
        ));

        let attestation = Notarial::attestations(0).expect("Attestation should exist");
        assert_eq!(attestation.contract_id, Some(42));
        assert_eq!(attestation.category, DocumentCategory::Contract);
    });
}

#[test]
fn attest_document_fails_duplicate() {
    new_test_ext().execute_with(|| {
        let hash = document_hash(4);

        assert_ok!(Notarial::attest_document(
            RuntimeOrigin::signed(ALICE),
            hash,
            0,
            description("First"),
            None,
            None,
            None,
        ));

        // Try to attest same document again
        assert_noop!(
            Notarial::attest_document(
                RuntimeOrigin::signed(BOB),
                hash,
                0,
                description("Duplicate"),
                None,
                None,
                None,
            ),
            Error::<Test>::AlreadyAttested
        );
    });
}

#[test]
fn attest_document_fails_description_too_long() {
    new_test_ext().execute_with(|| {
        let hash = document_hash(5);
        let long_desc = vec![b'x'; 600]; // > MAX_DESCRIPTION_LENGTH (512)

        assert_noop!(
            Notarial::attest_document(
                RuntimeOrigin::signed(ALICE),
                hash,
                0,
                long_desc,
                None,
                None,
                None,
            ),
            Error::<Test>::DescriptionTooLong
        );
    });
}

#[test]
fn attest_document_all_categories() {
    new_test_ext().execute_with(|| {
        for cat_id in 0u8..8u8 {
            let hash = document_hash(10 + cat_id);

            assert_ok!(Notarial::attest_document(
                RuntimeOrigin::signed(ALICE),
                hash,
                cat_id,
                description(&format!("Category {}", cat_id)),
                None,
                None,
                None,
            ));

            let attestation = Notarial::attestations(cat_id as u64).expect("Attestation should exist");
            assert_eq!(attestation.category, DocumentCategory::from(cat_id));
        }
    });
}

// ==================== WITNESS ATTESTATION TESTS ====================

#[test]
fn witness_attestation_works() {
    new_test_ext().execute_with(|| {
        let hash = document_hash(20);

        // Create attestation
        assert_ok!(Notarial::attest_document(
            RuntimeOrigin::signed(ALICE),
            hash,
            0,
            description("Witnessable doc"),
            None,
            None,
            None,
        ));

        // Witness it
        assert_ok!(Notarial::witness_attestation(
            RuntimeOrigin::signed(BOB),
            0,
            None,
        ));

        // Verify witness count
        let attestation = Notarial::attestations(0).expect("Attestation should exist");
        assert_eq!(attestation.witness_count, 1);

        // Verify witness record
        let witnesses = Notarial::witnesses(0);
        assert_eq!(witnesses.len(), 1);
        assert_eq!(witnesses[0].account, BOB);

        // Verify event
        System::assert_has_event(Event::AttestationWitnessed {
            attestation_id: 0,
            witness: BOB,
            witness_count: 1,
        }.into());
    });
}

#[test]
fn witness_attestation_with_note() {
    new_test_ext().execute_with(|| {
        let hash = document_hash(21);
        let note = document_hash(99); // Use as note hash

        assert_ok!(Notarial::attest_document(
            RuntimeOrigin::signed(ALICE),
            hash,
            0,
            description("Doc with note"),
            None,
            None,
            None,
        ));

        assert_ok!(Notarial::witness_attestation(
            RuntimeOrigin::signed(BOB),
            0,
            Some(note),
        ));

        let witnesses = Notarial::witnesses(0);
        assert_eq!(witnesses[0].note_hash, Some(note));
    });
}

#[test]
fn witness_attestation_certification() {
    new_test_ext().execute_with(|| {
        let hash = document_hash(22);

        assert_ok!(Notarial::attest_document(
            RuntimeOrigin::signed(ALICE),
            hash,
            0,
            description("To be certified"),
            None,
            None,
            None,
        ));

        // Add enough witnesses for certification (MinWitnesses = 2)
        assert_ok!(Notarial::witness_attestation(RuntimeOrigin::signed(BOB), 0, None));
        assert_ok!(Notarial::witness_attestation(RuntimeOrigin::signed(CHARLIE), 0, None));

        let attestation = Notarial::attestations(0).expect("Attestation should exist");
        assert!(attestation.certified);
        assert_eq!(attestation.status, AttestationStatus::Certified);
        assert_eq!(attestation.witness_count, 2);

        // Verify certification event
        System::assert_has_event(Event::AttestationCertified {
            attestation_id: 0,
            witness_count: 2,
        }.into());
    });
}

#[test]
fn witness_attestation_fails_self_witness() {
    new_test_ext().execute_with(|| {
        let hash = document_hash(23);

        assert_ok!(Notarial::attest_document(
            RuntimeOrigin::signed(ALICE),
            hash,
            0,
            description("No self-witness"),
            None,
            None,
            None,
        ));

        assert_noop!(
            Notarial::witness_attestation(RuntimeOrigin::signed(ALICE), 0, None),
            Error::<Test>::CannotWitnessOwn
        );
    });
}

#[test]
fn witness_attestation_fails_duplicate() {
    new_test_ext().execute_with(|| {
        let hash = document_hash(24);

        assert_ok!(Notarial::attest_document(
            RuntimeOrigin::signed(ALICE),
            hash,
            0,
            description("No duplicate witness"),
            None,
            None,
            None,
        ));

        assert_ok!(Notarial::witness_attestation(RuntimeOrigin::signed(BOB), 0, None));

        assert_noop!(
            Notarial::witness_attestation(RuntimeOrigin::signed(BOB), 0, None),
            Error::<Test>::AlreadyWitnessed
        );
    });
}

#[test]
fn witness_attestation_fails_not_found() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            Notarial::witness_attestation(RuntimeOrigin::signed(BOB), 999, None),
            Error::<Test>::AttestationNotFound
        );
    });
}

#[test]
fn witness_attestation_fails_revoked() {
    new_test_ext().execute_with(|| {
        let hash = document_hash(25);

        assert_ok!(Notarial::attest_document(
            RuntimeOrigin::signed(ALICE),
            hash,
            0,
            description("Will be revoked"),
            None,
            None,
            None,
        ));

        assert_ok!(Notarial::revoke_attestation(
            RuntimeOrigin::signed(ALICE),
            0,
            description("Revoking"),
        ));

        assert_noop!(
            Notarial::witness_attestation(RuntimeOrigin::signed(BOB), 0, None),
            Error::<Test>::AttestationRevoked
        );
    });
}

// ==================== REVOKE ATTESTATION TESTS ====================

#[test]
fn revoke_attestation_works() {
    new_test_ext().execute_with(|| {
        let hash = document_hash(30);

        assert_ok!(Notarial::attest_document(
            RuntimeOrigin::signed(ALICE),
            hash,
            0,
            description("To revoke"),
            None,
            None,
            None,
        ));

        assert_ok!(Notarial::revoke_attestation(
            RuntimeOrigin::signed(ALICE),
            0,
            description("Reason for revocation"),
        ));

        let attestation = Notarial::attestations(0).expect("Attestation should exist");
        assert_eq!(attestation.status, AttestationStatus::Revoked);

        System::assert_has_event(Event::AttestationRevoked {
            attestation_id: 0,
            reason: description("Reason for revocation"),
        }.into());
    });
}

#[test]
fn revoke_attestation_fails_not_owner() {
    new_test_ext().execute_with(|| {
        let hash = document_hash(31);

        assert_ok!(Notarial::attest_document(
            RuntimeOrigin::signed(ALICE),
            hash,
            0,
            description("Only owner can revoke"),
            None,
            None,
            None,
        ));

        assert_noop!(
            Notarial::revoke_attestation(
                RuntimeOrigin::signed(BOB),
                0,
                description("Unauthorized"),
            ),
            Error::<Test>::NotOwner
        );
    });
}

#[test]
fn revoke_attestation_fails_not_found() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            Notarial::revoke_attestation(
                RuntimeOrigin::signed(ALICE),
                999,
                description("Not found"),
            ),
            Error::<Test>::AttestationNotFound
        );
    });
}

// ==================== CERTIFICATE TESTS ====================

#[test]
fn generate_certificate_works() {
    new_test_ext().execute_with(|| {
        let hash = document_hash(40);

        assert_ok!(Notarial::attest_document(
            RuntimeOrigin::signed(ALICE),
            hash,
            0,
            description("For certificate"),
            None,
            None,
            None,
        ));

        // Add witnesses to certify
        assert_ok!(Notarial::witness_attestation(RuntimeOrigin::signed(BOB), 0, None));
        assert_ok!(Notarial::witness_attestation(RuntimeOrigin::signed(CHARLIE), 0, None));

        // Generate certificate
        assert_ok!(Notarial::generate_certificate(
            RuntimeOrigin::signed(ALICE),
            0,
        ));

        // Verify certificate exists
        let cert = Notarial::certificates(0).expect("Certificate should exist");
        assert_eq!(cert.attestation_id, 0);
        assert_eq!(cert.issuer, ALICE);

        // Verify next ID incremented
        assert_eq!(Notarial::next_certificate_id(), 1);
    });
}

#[test]
fn generate_certificate_fails_not_certified() {
    new_test_ext().execute_with(|| {
        let hash = document_hash(41);

        assert_ok!(Notarial::attest_document(
            RuntimeOrigin::signed(ALICE),
            hash,
            0,
            description("Not enough witnesses"),
            None,
            None,
            None,
        ));

        // Only 1 witness - not enough for certification
        assert_ok!(Notarial::witness_attestation(RuntimeOrigin::signed(BOB), 0, None));

        assert_noop!(
            Notarial::generate_certificate(RuntimeOrigin::signed(ALICE), 0),
            Error::<Test>::NotCertified
        );
    });
}

#[test]
fn generate_certificate_fails_revoked() {
    new_test_ext().execute_with(|| {
        let hash = document_hash(42);

        assert_ok!(Notarial::attest_document(
            RuntimeOrigin::signed(ALICE),
            hash,
            0,
            description("Will certify then revoke"),
            None,
            None,
            None,
        ));

        // Certify
        assert_ok!(Notarial::witness_attestation(RuntimeOrigin::signed(BOB), 0, None));
        assert_ok!(Notarial::witness_attestation(RuntimeOrigin::signed(CHARLIE), 0, None));

        // Revoke
        assert_ok!(Notarial::revoke_attestation(
            RuntimeOrigin::signed(ALICE),
            0,
            description("Changed mind"),
        ));

        // Cannot generate certificate for revoked
        assert_noop!(
            Notarial::generate_certificate(RuntimeOrigin::signed(ALICE), 0),
            Error::<Test>::AttestationRevoked
        );
    });
}

// ==================== TAG TESTS ====================

#[test]
fn add_tags_works() {
    new_test_ext().execute_with(|| {
        let hash = document_hash(50);

        assert_ok!(Notarial::attest_document(
            RuntimeOrigin::signed(ALICE),
            hash,
            0,
            description("Taggable"),
            None,
            None,
            None,
        ));

        let tags = vec![
            b"legal".to_vec(),
            b"contract".to_vec(),
            b"2024".to_vec(),
        ];

        assert_ok!(Notarial::add_tags(
            RuntimeOrigin::signed(ALICE),
            0,
            tags.clone(),
        ));

        let stored_tags = Notarial::tags(0);
        assert_eq!(stored_tags.len(), 3);

        System::assert_has_event(Event::TagsAdded {
            attestation_id: 0,
            tags,
        }.into());
    });
}

#[test]
fn add_tags_fails_not_owner() {
    new_test_ext().execute_with(|| {
        let hash = document_hash(51);

        assert_ok!(Notarial::attest_document(
            RuntimeOrigin::signed(ALICE),
            hash,
            0,
            description("Only owner tags"),
            None,
            None,
            None,
        ));

        assert_noop!(
            Notarial::add_tags(
                RuntimeOrigin::signed(BOB),
                0,
                vec![b"unauthorized".to_vec()],
            ),
            Error::<Test>::NotOwner
        );
    });
}

#[test]
fn add_tags_fails_tag_too_long() {
    new_test_ext().execute_with(|| {
        let hash = document_hash(52);

        assert_ok!(Notarial::attest_document(
            RuntimeOrigin::signed(ALICE),
            hash,
            0,
            description("Tag limit test"),
            None,
            None,
            None,
        ));

        let long_tag = vec![b'x'; 50]; // > MAX_TAG_LENGTH (32)

        assert_noop!(
            Notarial::add_tags(RuntimeOrigin::signed(ALICE), 0, vec![long_tag]),
            Error::<Test>::TagTooLong
        );
    });
}

// ==================== TRUSTED WITNESS TESTS ====================

#[test]
fn add_trusted_witness_works() {
    new_test_ext().execute_with(|| {
        assert_ok!(Notarial::add_trusted_witness(
            RuntimeOrigin::signed(ALICE),
            BOB,
        ));

        assert!(Notarial::is_trusted_witness(&BOB));

        System::assert_has_event(Event::TrustedWitnessAdded {
            witness: BOB,
        }.into());
    });
}

#[test]
fn remove_trusted_witness_works() {
    new_test_ext().execute_with(|| {
        assert_ok!(Notarial::add_trusted_witness(RuntimeOrigin::signed(ALICE), BOB));
        assert!(Notarial::is_trusted_witness(&BOB));

        assert_ok!(Notarial::remove_trusted_witness(RuntimeOrigin::signed(ALICE), BOB));
        assert!(!Notarial::is_trusted_witness(&BOB));

        System::assert_has_event(Event::TrustedWitnessRemoved {
            witness: BOB,
        }.into());
    });
}

// ==================== HELPER FUNCTION TESTS ====================

#[test]
fn verify_document_works() {
    new_test_ext().execute_with(|| {
        let hash = document_hash(60);

        assert_ok!(Notarial::attest_document(
            RuntimeOrigin::signed(ALICE),
            hash,
            0,
            description("Verifiable"),
            None,
            None,
            None,
        ));

        let result = Notarial::verify_document(hash);
        assert!(result.is_some());

        let (id, block) = result.unwrap();
        assert_eq!(id, 0);
        assert_eq!(block, 1); // Attested at block 1

        // Non-existent document
        assert!(Notarial::verify_document(document_hash(99)).is_none());
    });
}

#[test]
fn is_valid_works() {
    new_test_ext().execute_with(|| {
        let hash = document_hash(61);

        assert_ok!(Notarial::attest_document(
            RuntimeOrigin::signed(ALICE),
            hash,
            0,
            description("Validity check"),
            None,
            None,
            None,
        ));

        assert!(Notarial::is_valid(0));

        // Revoke and check
        assert_ok!(Notarial::revoke_attestation(
            RuntimeOrigin::signed(ALICE),
            0,
            description("Revoked"),
        ));

        assert!(!Notarial::is_valid(0));

        // Non-existent
        assert!(!Notarial::is_valid(999));
    });
}

#[test]
fn get_attestation_for_document_works() {
    new_test_ext().execute_with(|| {
        let hash = document_hash(62);

        assert_ok!(Notarial::attest_document(
            RuntimeOrigin::signed(ALICE),
            hash,
            3, // IntellectualProperty
            description("IP doc"),
            None,
            None,
            None,
        ));

        let attestation = Notarial::get_attestation_for_document(hash);
        assert!(attestation.is_some());

        let att = attestation.unwrap();
        assert_eq!(att.document_hash, hash);
        assert_eq!(att.category, DocumentCategory::IntellectualProperty);

        // Non-existent
        assert!(Notarial::get_attestation_for_document(document_hash(99)).is_none());
    });
}

// ==================== EDGE CASES ====================

#[test]
fn multiple_attestations_different_users() {
    new_test_ext().execute_with(|| {
        // Different users can attest different documents
        let hash1 = document_hash(70);
        let hash2 = document_hash(71);

        assert_ok!(Notarial::attest_document(
            RuntimeOrigin::signed(ALICE),
            hash1,
            0,
            description("Alice's doc"),
            None,
            None,
            None,
        ));

        assert_ok!(Notarial::attest_document(
            RuntimeOrigin::signed(BOB),
            hash2,
            0,
            description("Bob's doc"),
            None,
            None,
            None,
        ));

        assert_eq!(Notarial::attestations_by_owner(ALICE).len(), 1);
        assert_eq!(Notarial::attestations_by_owner(BOB).len(), 1);
    });
}

#[test]
fn attestation_id_increments() {
    new_test_ext().execute_with(|| {
        for i in 0..5 {
            let hash = document_hash(80 + i as u8);

            assert_ok!(Notarial::attest_document(
                RuntimeOrigin::signed(ALICE),
                hash,
                0,
                description(&format!("Doc {}", i)),
                None,
                None,
                None,
            ));

            assert_eq!(Notarial::next_attestation_id(), i + 1);
        }
    });
}

// ==================== NOTARIZE / ANCHORING TESTS ====================

/// AuditAnchor category id (see `DocumentCategory::AuditAnchor = 8`).
const AUDIT_ANCHOR: u8 = 8;

#[test]
fn notarize_with_requester_proof_works() {
    new_test_ext().execute_with(|| {
        let hash = document_hash(40);
        let fingerprint = vec![0xAB, 0xCD, 0xEF];
        let signature = vec![0x11; 690]; // Falcon-512 ~690 bytes

        assert_ok!(Notarial::notarize(
            RuntimeOrigin::signed(ALICE),
            hash,
            AUDIT_ANCHOR,
            description("audit:tenant-x"),
            None,
            Some(fingerprint.clone()),
            Some(signature.clone()),
        ));

        let attestation = Notarial::attestations(0).expect("Attestation should exist");
        assert_eq!(attestation.attester, ALICE); // the notary
        assert_eq!(attestation.category, DocumentCategory::AuditAnchor);
        assert_eq!(
            attestation.requester_fingerprint.map(|f| f.into_inner()),
            Some(fingerprint)
        );
        assert_eq!(
            attestation.requester_signature.map(|s| s.into_inner()),
            Some(signature)
        );
        assert_eq!(Notarial::attestation_by_hash(hash), Some(0));

        System::assert_has_event(Event::DocumentAttested {
            attestation_id: 0,
            document_hash: hash,
            attester: ALICE,
            category_id: AUDIT_ANCHOR,
        }.into());
    });
}

#[test]
fn notarize_without_requester_proof_works() {
    new_test_ext().execute_with(|| {
        let hash = document_hash(41);

        assert_ok!(Notarial::notarize(
            RuntimeOrigin::signed(ALICE),
            hash,
            2, // Contract
            description("contract:42"),
            None,
            None,
            None,
        ));

        let attestation = Notarial::attestations(0).expect("Attestation should exist");
        assert_eq!(attestation.category, DocumentCategory::Contract);
        assert!(attestation.requester_fingerprint.is_none());
        assert!(attestation.requester_signature.is_none());
    });
}

#[test]
fn notarize_rejects_duplicate_hash() {
    new_test_ext().execute_with(|| {
        let hash = document_hash(42);

        assert_ok!(Notarial::notarize(
            RuntimeOrigin::signed(ALICE),
            hash,
            AUDIT_ANCHOR,
            description("first"),
            None,
            None,
            None,
        ));

        // Re-notarising the same hash is rejected (idempotency guard); the RPC
        // layer surfaces the existing record instead of erroring.
        assert_noop!(
            Notarial::notarize(
                RuntimeOrigin::signed(BOB),
                hash,
                AUDIT_ANCHOR,
                description("second"),
                None,
                None,
                None,
            ),
            Error::<Test>::AlreadyAttested
        );
    });
}

#[test]
fn notarize_rejects_oversized_fingerprint() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            Notarial::notarize(
                RuntimeOrigin::signed(ALICE),
                document_hash(43),
                AUDIT_ANCHOR,
                description("x"),
                None,
                Some(vec![0u8; 49]), // > MAX_FINGERPRINT_LENGTH (48)
                None,
            ),
            Error::<Test>::FingerprintTooLong
        );
    });
}

#[test]
fn notarize_rejects_oversized_signature() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            Notarial::notarize(
                RuntimeOrigin::signed(ALICE),
                document_hash(44),
                AUDIT_ANCHOR,
                description("x"),
                None,
                None,
                Some(vec![0u8; 1401]), // > MAX_SIGNATURE_LENGTH (1400)
            ),
            Error::<Test>::SignatureTooLong
        );
    });
}

#[test]
fn attest_document_leaves_requester_fields_none() {
    new_test_ext().execute_with(|| {
        let hash = document_hash(45);
        assert_ok!(Notarial::attest_document(
            RuntimeOrigin::signed(ALICE),
            hash,
            2,
            description("contract"),
            None,
            None,
            None,
        ));
        let attestation = Notarial::attestations(0).expect("Attestation should exist");
        assert!(attestation.requester_fingerprint.is_none());
        assert!(attestation.requester_signature.is_none());
    });
}

#[test]
fn document_category_audit_anchor_round_trips_from_u8() {
    assert_eq!(DocumentCategory::from(8u8), DocumentCategory::AuditAnchor);
    assert_eq!(DocumentCategory::from(2u8), DocumentCategory::Contract);
    // 7 and unknown discriminants fall back to Other.
    assert_eq!(DocumentCategory::from(7u8), DocumentCategory::Other);
    assert_eq!(DocumentCategory::from(99u8), DocumentCategory::Other);
}

// ==================== MIGRATION TESTS ====================

#[test]
fn migration_v0_to_v1_bumps_version_and_is_idempotent() {
    use frame_support::traits::{GetStorageVersion, OnRuntimeUpgrade, StorageVersion};

    new_test_ext().execute_with(|| {
        // Simulate a pre-v1 chain: force the on-chain version back to 0.
        StorageVersion::new(0).put::<Notarial>();
        assert_eq!(Notarial::on_chain_storage_version(), StorageVersion::new(0));

        // First run bumps to v1 (translate over the — here empty — map is a no-op).
        let _ = crate::migrations::v1::MigrateV0ToV1::<Test>::on_runtime_upgrade();
        assert_eq!(Notarial::on_chain_storage_version(), StorageVersion::new(1));

        // Second run is a no-op (idempotent short-circuit).
        let _ = crate::migrations::v1::MigrateV0ToV1::<Test>::on_runtime_upgrade();
        assert_eq!(Notarial::on_chain_storage_version(), StorageVersion::new(1));
    });
}

// NOTE: a byte-level translate test (insert a v0-encoded `Attestation`, run the
// migration, assert the row gains `requester_*: None`) is recommended via a
// storage fixture or `try-runtime` against chain state. Left for the reviewer to
// add with a real v0 snapshot since the mock genesis already starts at v1.

// ==================== MIGRATION v0 -> v1 ====================

#[test]
fn migrate_v0_to_v1_preserves_rows_and_is_idempotent() {
    use crate::{Attestations, Pallet};
    use crate::migrations::v1::{v0, MigrateV0ToV1};
    use frame_support::traits::{GetStorageVersion, OnRuntimeUpgrade, StorageVersion};
    use frame_support::storage::unhashed;
    use frame_support::BoundedVec;

    new_test_ext().execute_with(|| {
        // simulate a pre-upgrade (v0) chain
        StorageVersion::new(0).put::<Pallet<Test>>();
        assert_eq!(Pallet::<Test>::on_chain_storage_version(), 0);

        // seed two v0-format rows (the 12 pre-v1 fields, no requester proof)
        for id in 0u64..2 {
            let v0_att = v0::Attestation::<Test> {
                id,
                document_hash: [id as u8; 32],
                category: DocumentCategory::Contract,
                description: BoundedVec::try_from(b"legacy".to_vec()).unwrap(),
                attester: ALICE,
                attested_at: 1,
                expires_at: None,
                status: AttestationStatus::Active,
                witness_count: 0,
                certified: false,
                contract_id: Some(42),
                academic_id: None,
            };
            let key = Attestations::<Test>::hashed_key_for(id);
            unhashed::put(&key, &v0_att);
        }

        // run the migration
        let _ = MigrateV0ToV1::<Test>::on_runtime_upgrade();

        // storage version bumped to 1
        assert_eq!(Pallet::<Test>::on_chain_storage_version(), 1);

        // every row survived, decodes as v1, new fields = None, old fields intact
        for id in 0u64..2 {
            let a = Attestations::<Test>::get(id).expect("row survived migration");
            assert_eq!(a.id, id);
            assert_eq!(a.contract_id, Some(42));
            assert_eq!(a.category, DocumentCategory::Contract);
            assert_eq!(a.requester_fingerprint, None);
            assert_eq!(a.requester_signature, None);
        }

        // idempotent: re-running short-circuits and loses nothing
        let _ = MigrateV0ToV1::<Test>::on_runtime_upgrade();
        assert_eq!(Pallet::<Test>::on_chain_storage_version(), 1);
        assert!(Attestations::<Test>::get(0u64).is_some());
    });
}
