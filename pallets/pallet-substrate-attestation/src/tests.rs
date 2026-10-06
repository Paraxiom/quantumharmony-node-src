//! Tests for `pallet-substrate-attestation`. Cover the three
//! extrinsics, parent-link discipline, the lineage graph, and every
//! error path.

use crate::mock::*;
use crate::{
    types::ArtifactKind, AttesterModelCount, DescendantCount, ModelOwner,
    Models, NextModelId,
};
use frame_support::{assert_noop, assert_ok};

const ALICE: AccountId = 1;
const BOB: AccountId = 2;
const ATTESTER_A: u64 = 100;
const ATTESTER_B: u64 = 200;

fn cid(s: &[u8]) -> Vec<u8> { s.to_vec() }

fn commit_base(who: AccountId, attester: u64, weights: [u8; 32]) -> u64 {
    let id = NextModelId::<Test>::get();
    assert_ok!(SubstrateAttestation::commit_weights(
        RuntimeOrigin::signed(who),
        attester,
        ArtifactKind::BaseModel,
        weights,
        None,
        cid(b"bafy..base"),
        None,
    ));
    id
}

// ── commit_weights() ───────────────────────────────────────────────────────

#[test]
fn commit_base_assigns_id_and_stores_row() {
    new_test_ext().execute_with(|| {
        assert_eq!(NextModelId::<Test>::get(), 0);
        let id = commit_base(ALICE, ATTESTER_A, [7u8; 32]);
        assert_eq!(id, 0);

        let m = Models::<Test>::get(0).expect("stored");
        assert_eq!(m.attester_identity, ATTESTER_A);
        assert_eq!(m.kind, ArtifactKind::BaseModel);
        assert_eq!(m.weights_hash, [7u8; 32]);
        assert_eq!(m.parent_model, None);
        assert_eq!(m.ipfs_cid.to_vec(), b"bafy..base".to_vec());
        assert_eq!(m.training_attestation_id, None);
        assert_eq!(m.created_at, 1);
        assert!(m.revoked_at.is_none());

        assert_eq!(ModelOwner::<Test>::get(0), Some(ALICE));
        assert_eq!(AttesterModelCount::<Test>::get(ATTESTER_A), 1);
        assert_eq!(NextModelId::<Test>::get(), 1);
    });
}

#[test]
fn commit_base_rejects_parent_argument() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            SubstrateAttestation::commit_weights(
                RuntimeOrigin::signed(ALICE),
                ATTESTER_A,
                ArtifactKind::BaseModel,
                [1u8; 32],
                Some(999), // base must not carry parent
                cid(b"bafy"),
                None,
            ),
            crate::Error::<Test>::BaseModelMustNotHaveParent,
        );
    });
}

#[test]
fn commit_finetune_requires_parent() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            SubstrateAttestation::commit_weights(
                RuntimeOrigin::signed(ALICE),
                ATTESTER_A,
                ArtifactKind::FineTune,
                [2u8; 32],
                None,
                cid(b"bafy"),
                None,
            ),
            crate::Error::<Test>::DerivedModelRequiresParent,
        );
    });
}

#[test]
fn commit_finetune_rejects_unknown_parent() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            SubstrateAttestation::commit_weights(
                RuntimeOrigin::signed(ALICE),
                ATTESTER_A,
                ArtifactKind::FineTune,
                [2u8; 32],
                Some(42),
                cid(b"bafy"),
                None,
            ),
            crate::Error::<Test>::ParentModelNotFound,
        );
    });
}

#[test]
fn commit_finetune_with_valid_parent_links_descendant_count() {
    new_test_ext().execute_with(|| {
        let base = commit_base(ALICE, ATTESTER_A, [7u8; 32]);
        assert_eq!(DescendantCount::<Test>::get(base), 0);

        assert_ok!(SubstrateAttestation::commit_weights(
            RuntimeOrigin::signed(ALICE),
            ATTESTER_A,
            ArtifactKind::FineTune,
            [8u8; 32],
            Some(base),
            cid(b"bafy..ft"),
            Some(42), // arbitrary axiom-attestation pointer
        ));

        let child = Models::<Test>::get(1).expect("child stored");
        assert_eq!(child.parent_model, Some(base));
        assert_eq!(child.training_attestation_id, Some(42));
        assert_eq!(DescendantCount::<Test>::get(base), 1);
    });
}

#[test]
fn commit_adapter_with_valid_parent_works() {
    new_test_ext().execute_with(|| {
        let base = commit_base(ALICE, ATTESTER_A, [7u8; 32]);
        assert_ok!(SubstrateAttestation::commit_weights(
            RuntimeOrigin::signed(BOB),
            ATTESTER_B,
            ArtifactKind::Adapter,
            [9u8; 32],
            Some(base),
            cid(b"bafy..lora"),
            None,
        ));
        let child = Models::<Test>::get(1).expect("adapter stored");
        assert_eq!(child.kind, ArtifactKind::Adapter);
        assert_eq!(DescendantCount::<Test>::get(base), 1);
    });
}

#[test]
fn commit_rejects_oversize_cid() {
    new_test_ext().execute_with(|| {
        let too_long = vec![b'a'; 129];
        assert_noop!(
            SubstrateAttestation::commit_weights(
                RuntimeOrigin::signed(ALICE),
                ATTESTER_A,
                ArtifactKind::BaseModel,
                [0u8; 32],
                None,
                too_long,
                None,
            ),
            crate::Error::<Test>::CidTooLong,
        );
    });
}

#[test]
fn commit_enforces_attester_limit() {
    new_test_ext().execute_with(|| {
        // TestMaxModelsPerAttester = 3.
        for i in 0..3 {
            let mut w = [0u8; 32];
            w[0] = i as u8;
            commit_base(ALICE, ATTESTER_A, w);
        }
        assert_noop!(
            SubstrateAttestation::commit_weights(
                RuntimeOrigin::signed(ALICE),
                ATTESTER_A,
                ArtifactKind::BaseModel,
                [4u8; 32],
                None,
                cid(b"bafy"),
                None,
            ),
            crate::Error::<Test>::ModelLimitReached,
        );
    });
}

#[test]
fn commit_rejects_revoked_parent() {
    new_test_ext().execute_with(|| {
        let base = commit_base(ALICE, ATTESTER_A, [7u8; 32]);
        assert_ok!(SubstrateAttestation::revoke(RuntimeOrigin::signed(ALICE), base));
        assert_noop!(
            SubstrateAttestation::commit_weights(
                RuntimeOrigin::signed(BOB),
                ATTESTER_B,
                ArtifactKind::FineTune,
                [8u8; 32],
                Some(base),
                cid(b"bafy..ft"),
                None,
            ),
            crate::Error::<Test>::ParentModelRevoked,
        );
    });
}

// ── revoke() ────────────────────────────────────────────────────────────────

#[test]
fn revoke_sets_revoked_at_and_blocks_attest_use() {
    new_test_ext().execute_with(|| {
        let base = commit_base(ALICE, ATTESTER_A, [7u8; 32]);
        assert_ok!(SubstrateAttestation::revoke(RuntimeOrigin::signed(ALICE), base));

        let m = Models::<Test>::get(base).expect("still present");
        assert!(!m.is_active());
        assert_eq!(m.revoked_at, Some(1));

        assert_noop!(
            SubstrateAttestation::attest_use(
                RuntimeOrigin::signed(ALICE),
                base,
                b"agent-x ran fine-tune".to_vec(),
            ),
            crate::Error::<Test>::ModelRevoked,
        );
    });
}

#[test]
fn revoke_rejects_unknown_id() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            SubstrateAttestation::revoke(RuntimeOrigin::signed(ALICE), 999),
            crate::Error::<Test>::UnknownModel,
        );
    });
}

#[test]
fn revoke_rejects_non_committer() {
    new_test_ext().execute_with(|| {
        let base = commit_base(ALICE, ATTESTER_A, [7u8; 32]);
        assert_noop!(
            SubstrateAttestation::revoke(RuntimeOrigin::signed(BOB), base),
            crate::Error::<Test>::NotCommitter,
        );
    });
}

#[test]
fn revoke_twice_fails() {
    new_test_ext().execute_with(|| {
        let base = commit_base(ALICE, ATTESTER_A, [7u8; 32]);
        assert_ok!(SubstrateAttestation::revoke(RuntimeOrigin::signed(ALICE), base));
        assert_noop!(
            SubstrateAttestation::revoke(RuntimeOrigin::signed(ALICE), base),
            crate::Error::<Test>::AlreadyRevoked,
        );
    });
}

// ── attest_use() ───────────────────────────────────────────────────────────

#[test]
fn attest_use_on_active_model_succeeds() {
    new_test_ext().execute_with(|| {
        let base = commit_base(ALICE, ATTESTER_A, [7u8; 32]);
        assert_ok!(SubstrateAttestation::attest_use(
            RuntimeOrigin::signed(BOB),
            base,
            b"karmonic-mistral-7b-v2".to_vec(),
        ));
    });
}

#[test]
fn attest_use_rejects_unknown_id() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            SubstrateAttestation::attest_use(
                RuntimeOrigin::signed(ALICE),
                999,
                b"ctx".to_vec(),
            ),
            crate::Error::<Test>::UnknownModel,
        );
    });
}
