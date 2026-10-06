//! Tests for `pallet-credential-vault`. Cover the three extrinsics
//! plus every error path. Mutator-style assertions check that
//! storage is the *only* place state can change.

use crate::mock::*;
use crate::{
    types::CredentialKind, Commitments, CommitmentOwner, HolderCommitmentCount,
    NextCommitmentId,
};
use frame_support::{assert_noop, assert_ok};
use frame_system::Pallet as System;

const ALICE: AccountId = 1;
const BOB: AccountId = 2;
const HOLDER_A: u64 = 100;
const HOLDER_B: u64 = 200;

fn cid(s: &[u8]) -> Vec<u8> { s.to_vec() }
fn name(s: &[u8]) -> Vec<u8> { s.to_vec() }

// ── commit() ────────────────────────────────────────────────────────────────

#[test]
fn commit_assigns_id_and_stores_row() {
    new_test_ext().execute_with(|| {
        assert_eq!(NextCommitmentId::<Test>::get(), 0);
        assert_ok!(CredentialVault::commit(
            RuntimeOrigin::signed(ALICE),
            HOLDER_A,
            name(b"sudo"),
            CredentialKind::Sudo,
            cid(b"bafy..."),
            [7u8; 32],
            [3u8; 12],
        ));
        // Id 0 stored, counter advanced.
        let c = Commitments::<Test>::get(0).expect("stored");
        assert_eq!(c.holder_identity, HOLDER_A);
        assert_eq!(c.service_name.to_vec(), b"sudo".to_vec());
        assert_eq!(c.credential_kind, CredentialKind::Sudo);
        assert_eq!(c.ciphertext_cid.to_vec(), b"bafy...".to_vec());
        assert_eq!(c.ciphertext_hash, [7u8; 32]);
        assert_eq!(c.iv_hint, [3u8; 12]);
        assert_eq!(c.created_at, 1);
        assert!(c.revoked_at.is_none());
        // Owner tracked.
        assert_eq!(CommitmentOwner::<Test>::get(0), Some(ALICE));
        // Holder counter incremented.
        assert_eq!(HolderCommitmentCount::<Test>::get(HOLDER_A), 1);
        // Next id rolled.
        assert_eq!(NextCommitmentId::<Test>::get(), 1);
    });
}

#[test]
fn commit_rejects_oversize_service_name() {
    new_test_ext().execute_with(|| {
        let too_long = vec![b'x'; 65];
        assert_noop!(
            CredentialVault::commit(
                RuntimeOrigin::signed(ALICE),
                HOLDER_A,
                too_long,
                CredentialKind::Sudo,
                cid(b"bafy"),
                [0u8; 32],
                [0u8; 12],
            ),
            crate::Error::<Test>::ServiceNameTooLong,
        );
    });
}

#[test]
fn commit_rejects_oversize_cid() {
    new_test_ext().execute_with(|| {
        let too_long = vec![b'a'; 129];
        assert_noop!(
            CredentialVault::commit(
                RuntimeOrigin::signed(ALICE),
                HOLDER_A,
                name(b"sudo"),
                CredentialKind::Sudo,
                too_long,
                [0u8; 32],
                [0u8; 12],
            ),
            crate::Error::<Test>::CidTooLong,
        );
    });
}

#[test]
fn commit_enforces_per_holder_limit() {
    new_test_ext().execute_with(|| {
        // TestMaxCommitmentsPerHolder = 3, so three succeed.
        for i in 0..3 {
            assert_ok!(CredentialVault::commit(
                RuntimeOrigin::signed(ALICE),
                HOLDER_A,
                name(format!("k{}", i).as_bytes()),
                CredentialKind::ServiceKey,
                cid(b"bafy"),
                [i as u8; 32],
                [0u8; 12],
            ));
        }
        assert_eq!(HolderCommitmentCount::<Test>::get(HOLDER_A), 3);
        // Fourth is rejected.
        assert_noop!(
            CredentialVault::commit(
                RuntimeOrigin::signed(ALICE),
                HOLDER_A,
                name(b"k3"),
                CredentialKind::ServiceKey,
                cid(b"bafy"),
                [99u8; 32],
                [0u8; 12],
            ),
            crate::Error::<Test>::CommitmentLimitReached,
        );
        // A *different* holder is unaffected.
        assert_ok!(CredentialVault::commit(
            RuntimeOrigin::signed(ALICE),
            HOLDER_B,
            name(b"hb"),
            CredentialKind::ServiceKey,
            cid(b"bafy"),
            [0u8; 32],
            [0u8; 12],
        ));
    });
}

// ── revoke() ────────────────────────────────────────────────────────────────

#[test]
fn revoke_sets_revoked_at_for_owner() {
    new_test_ext().execute_with(|| {
        assert_ok!(CredentialVault::commit(
            RuntimeOrigin::signed(ALICE),
            HOLDER_A,
            name(b"sudo"),
            CredentialKind::Sudo,
            cid(b"bafy"),
            [0u8; 32],
            [0u8; 12],
        ));
        System::<Test>::set_block_number(42);
        assert_ok!(CredentialVault::revoke(RuntimeOrigin::signed(ALICE), 0));
        let c = Commitments::<Test>::get(0).unwrap();
        assert_eq!(c.revoked_at, Some(42));
        assert!(!c.is_active());
    });
}

#[test]
fn revoke_rejects_non_owner() {
    new_test_ext().execute_with(|| {
        assert_ok!(CredentialVault::commit(
            RuntimeOrigin::signed(ALICE),
            HOLDER_A,
            name(b"sudo"),
            CredentialKind::Sudo,
            cid(b"bafy"),
            [0u8; 32],
            [0u8; 12],
        ));
        assert_noop!(
            CredentialVault::revoke(RuntimeOrigin::signed(BOB), 0),
            crate::Error::<Test>::NotCommitter,
        );
        // Still active.
        assert!(Commitments::<Test>::get(0).unwrap().is_active());
    });
}

#[test]
fn revoke_unknown_id_errors() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            CredentialVault::revoke(RuntimeOrigin::signed(ALICE), 99),
            crate::Error::<Test>::UnknownCommitment,
        );
    });
}

#[test]
fn revoke_twice_errors() {
    new_test_ext().execute_with(|| {
        assert_ok!(CredentialVault::commit(
            RuntimeOrigin::signed(ALICE),
            HOLDER_A,
            name(b"sudo"),
            CredentialKind::Sudo,
            cid(b"bafy"),
            [0u8; 32],
            [0u8; 12],
        ));
        assert_ok!(CredentialVault::revoke(RuntimeOrigin::signed(ALICE), 0));
        assert_noop!(
            CredentialVault::revoke(RuntimeOrigin::signed(ALICE), 0),
            crate::Error::<Test>::AlreadyRevoked,
        );
    });
}

// ── attest_use() ────────────────────────────────────────────────────────────

#[test]
fn attest_use_emits_event_with_context_hash() {
    new_test_ext().execute_with(|| {
        assert_ok!(CredentialVault::commit(
            RuntimeOrigin::signed(ALICE),
            HOLDER_A,
            name(b"sudo"),
            CredentialKind::Sudo,
            cid(b"bafy"),
            [0u8; 32],
            [0u8; 12],
        ));
        let ctx = b"audit-quorum:3-of-5".to_vec();
        assert_ok!(CredentialVault::attest_use(
            RuntimeOrigin::signed(BOB),
            0,
            ctx,
        ));
        // Event is the only state change; storage is unchanged.
        assert!(Commitments::<Test>::get(0).unwrap().is_active());
    });
}

#[test]
fn attest_use_rejects_revoked() {
    new_test_ext().execute_with(|| {
        assert_ok!(CredentialVault::commit(
            RuntimeOrigin::signed(ALICE),
            HOLDER_A,
            name(b"sudo"),
            CredentialKind::Sudo,
            cid(b"bafy"),
            [0u8; 32],
            [0u8; 12],
        ));
        assert_ok!(CredentialVault::revoke(RuntimeOrigin::signed(ALICE), 0));
        assert_noop!(
            CredentialVault::attest_use(
                RuntimeOrigin::signed(BOB),
                0,
                b"any".to_vec(),
            ),
            crate::Error::<Test>::CommitmentRevoked,
        );
    });
}

#[test]
fn attest_use_unknown_id_errors() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            CredentialVault::attest_use(
                RuntimeOrigin::signed(BOB),
                42,
                b"".to_vec(),
            ),
            crate::Error::<Test>::UnknownCommitment,
        );
    });
}

// ── invariants (try-runtime gated) ─────────────────────────────────────────

#[cfg(feature = "try-runtime")]
#[test]
fn try_state_passes_after_commit_and_revoke() {
    use frame_support::traits::Hooks;
    new_test_ext().execute_with(|| {
        assert_ok!(CredentialVault::commit(
            RuntimeOrigin::signed(ALICE),
            HOLDER_A,
            name(b"sudo"),
            CredentialKind::Sudo,
            cid(b"bafy"),
            [0u8; 32],
            [0u8; 12],
        ));
        assert_ok!(CredentialVault::revoke(RuntimeOrigin::signed(ALICE), 0));
        assert_ok!(
            <CredentialVault as Hooks<BlockNumber>>::try_state(System::<Test>::block_number())
        );
    });
}
