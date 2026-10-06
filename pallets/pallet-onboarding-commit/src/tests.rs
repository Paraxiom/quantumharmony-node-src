//! Tests for `pallet-onboarding-commit`. Cover the three extrinsics and
//! every error variant. The mutator-call assertions are critical: a passing
//! reveal MUST invoke `add_validator`; every failure path MUST NOT.

use crate::mock::*;
use crate::types::OnboardingKind;
use crate::{CommitKind, Commits, Event, RevealedPubkeys};
use codec::Encode;
use frame_support::{assert_noop, assert_ok};
use frame_system::Pallet as System;
use sp_io::hashing::blake2_256;

/// Helper: build a commit_hash + the reveal args that produce it.
fn make_commit(
    aura_pubkey: &[u8],
    account_id: AccountId,
    nonce: [u8; 32],
) -> [u8; 32] {
    let mut payload = Vec::with_capacity(aura_pubkey.len() + 32 + 32);
    payload.extend_from_slice(aura_pubkey);
    payload.extend_from_slice(&account_id.encode());
    payload.extend_from_slice(&nonce);
    blake2_256(&payload)
}

fn advance_blocks(n: BlockNumber) {
    let now = System::<Test>::block_number();
    System::<Test>::set_block_number(now + n);
}

// ─── commit() ────────────────────────────────────────────────────────────────

#[test]
fn commit_reserves_bond_and_emits_event() {
    new_test_ext().execute_with(|| {
        let hash = [1u8; 32];
        let bond_before = Balances::reserved_balance(1);
        assert_eq!(bond_before, 0);

        assert_ok!(OnboardingCommit::commit(
            RuntimeOrigin::signed(1),
            hash,
        ));

        // Bond actually reserved.
        assert_eq!(Balances::reserved_balance(1), 1_000);

        // Storage entry written.
        let info = Commits::<Test>::get(&hash).expect("commit recorded");
        assert_eq!(info.committer, 1);
        assert_eq!(info.bond, 1_000);
        assert!(!info.revealed);

        // Mutator NOT yet called (only reveal triggers add_validator).
        assert!(mutator_calls::take().is_empty());

        // Event emitted with the right window_ends.
        let events = System::<Test>::events();
        let evt = events
            .iter()
            .find_map(|e| match &e.event {
                RuntimeEvent::OnboardingCommit(inner) => Some(inner.clone()),
                _ => None,
            })
            .expect("commit event");
        match evt {
            Event::Committed { who, commit_hash, bond, window_ends } => {
                assert_eq!(who, 1);
                assert_eq!(commit_hash, hash);
                assert_eq!(bond, 1_000);
                assert_eq!(window_ends, 1 + 10);
            }
            other => panic!("expected Committed, got {:?}", other),
        }
    });
}

#[test]
fn commit_rejects_duplicate_hash() {
    new_test_ext().execute_with(|| {
        let hash = [2u8; 32];
        assert_ok!(OnboardingCommit::commit(RuntimeOrigin::signed(1), hash));
        assert_noop!(
            OnboardingCommit::commit(RuntimeOrigin::signed(2), hash),
            crate::Error::<Test>::DuplicateCommit,
        );
        // Account 2's bond was NOT reserved.
        assert_eq!(Balances::reserved_balance(2), 0);
    });
}

#[test]
fn commit_rejects_when_bond_unaffordable() {
    new_test_ext().execute_with(|| {
        // Account 99 is unseeded → balance 0.
        assert_noop!(
            OnboardingCommit::commit(RuntimeOrigin::signed(99), [3u8; 32]),
            crate::Error::<Test>::BondFailed,
        );
    });
}

// ─── reveal() ────────────────────────────────────────────────────────────────

#[test]
fn reveal_after_window_releases_bond_and_calls_mutator() {
    new_test_ext().execute_with(|| {
        let aura_pubkey = vec![0xAAu8; 64];
        let account_id: AccountId = 1;
        let nonce = [0x42u8; 32];
        let hash = make_commit(&aura_pubkey, account_id, nonce);

        assert_ok!(OnboardingCommit::commit(RuntimeOrigin::signed(1), hash));
        assert_eq!(Balances::reserved_balance(1), 1_000);

        // Inside the window: reveal must fail.
        assert_noop!(
            OnboardingCommit::reveal(
                RuntimeOrigin::signed(1),
                aura_pubkey.clone(),
                account_id,
                nonce,
            ),
            crate::Error::<Test>::DisputeWindowOpen,
        );

        advance_blocks(10);

        // After window: reveal succeeds.
        assert_ok!(OnboardingCommit::reveal(
            RuntimeOrigin::signed(1),
            aura_pubkey.clone(),
            account_id,
            nonce,
        ));

        // Bond unreserved.
        assert_eq!(Balances::reserved_balance(1), 0);
        // Mutator called with the right account.
        assert_eq!(mutator_calls::take(), vec![1]);
        // Pubkey hash recorded.
        let pkh = blake2_256(&aura_pubkey);
        assert_eq!(RevealedPubkeys::<Test>::get(&pkh), Some(1));
        // Commit flagged revealed.
        let info = Commits::<Test>::get(&hash).unwrap();
        assert!(info.revealed);
    });
}

#[test]
fn reveal_rejects_hash_mismatch_via_unknown_commit() {
    new_test_ext().execute_with(|| {
        let aura_pubkey = vec![0xBBu8; 64];
        let nonce = [0x11u8; 32];
        let hash = make_commit(&aura_pubkey, 1, nonce);
        assert_ok!(OnboardingCommit::commit(RuntimeOrigin::signed(1), hash));
        advance_blocks(10);
        // Tamper with the nonce — the recomputed hash won't match any stored
        // commit, so the pallet surfaces UnknownCommit (which is what
        // operators see for both "no such commit" and "wrong reveal args" —
        // intentional: revealing tampered values must look identical to a
        // never-committed pubkey to deny side-channel learning).
        let bad_nonce = [0x99u8; 32];
        assert_noop!(
            OnboardingCommit::reveal(
                RuntimeOrigin::signed(1),
                aura_pubkey,
                1,
                bad_nonce,
            ),
            crate::Error::<Test>::UnknownCommit,
        );
        // Mutator not called.
        assert!(mutator_calls::take().is_empty());
    });
}

#[test]
fn reveal_rejects_wrong_committer() {
    new_test_ext().execute_with(|| {
        let aura_pubkey = vec![0xCCu8; 64];
        let nonce = [0x22u8; 32];
        let hash = make_commit(&aura_pubkey, 1, nonce);
        assert_ok!(OnboardingCommit::commit(RuntimeOrigin::signed(1), hash));
        advance_blocks(10);
        assert_noop!(
            OnboardingCommit::reveal(
                RuntimeOrigin::signed(2), // wrong committer
                aura_pubkey,
                1,
                nonce,
            ),
            crate::Error::<Test>::NotCommitter,
        );
        assert!(mutator_calls::take().is_empty());
    });
}

#[test]
fn reveal_rejects_duplicate_pubkey() {
    new_test_ext().execute_with(|| {
        let aura_pubkey = vec![0xDDu8; 64];
        let nonce_a = [0x01u8; 32];
        let nonce_b = [0x02u8; 32];
        let hash_a = make_commit(&aura_pubkey, 1, nonce_a);
        let hash_b = make_commit(&aura_pubkey, 2, nonce_b);

        // First operator commits + reveals successfully.
        assert_ok!(OnboardingCommit::commit(RuntimeOrigin::signed(1), hash_a));
        assert_ok!(OnboardingCommit::commit(RuntimeOrigin::signed(2), hash_b));
        advance_blocks(10);
        assert_ok!(OnboardingCommit::reveal(
            RuntimeOrigin::signed(1),
            aura_pubkey.clone(),
            1,
            nonce_a,
        ));
        // Second operator (same pubkey, different account) — must be blocked.
        assert_noop!(
            OnboardingCommit::reveal(
                RuntimeOrigin::signed(2),
                aura_pubkey,
                2,
                nonce_b,
            ),
            crate::Error::<Test>::PubkeyAlreadyRevealed,
        );
        // Only the first mutator call was made.
        assert_eq!(mutator_calls::take(), vec![1]);
    });
}

#[test]
fn reveal_rejects_wrong_length_pubkey() {
    new_test_ext().execute_with(|| {
        let bad_pubkey = vec![0xAB; 32]; // wrong length — should be 64
        let nonce = [0x77u8; 32];
        // We compute a hash using the bad-length pubkey so commit + reveal
        // would normally pair up. The pallet must reject pre-hash on length.
        let hash = make_commit(&bad_pubkey, 1, nonce);
        assert_ok!(OnboardingCommit::commit(RuntimeOrigin::signed(1), hash));
        advance_blocks(10);
        assert_noop!(
            OnboardingCommit::reveal(
                RuntimeOrigin::signed(1),
                bad_pubkey,
                1,
                nonce,
            ),
            crate::Error::<Test>::InvalidPubkeyLength,
        );
        // Mutator never invoked with a malformed key.
        assert!(mutator_calls::take().is_empty());
    });
}

#[test]
fn reveal_rejects_double_reveal() {
    new_test_ext().execute_with(|| {
        let aura_pubkey = vec![0xEEu8; 64];
        let nonce = [0x33u8; 32];
        let hash = make_commit(&aura_pubkey, 1, nonce);
        assert_ok!(OnboardingCommit::commit(RuntimeOrigin::signed(1), hash));
        advance_blocks(10);
        assert_ok!(OnboardingCommit::reveal(
            RuntimeOrigin::signed(1),
            aura_pubkey.clone(),
            1,
            nonce,
        ));
        // Second reveal of the same commit must fail.
        assert_noop!(
            OnboardingCommit::reveal(
                RuntimeOrigin::signed(1),
                aura_pubkey,
                1,
                nonce,
            ),
            crate::Error::<Test>::AlreadyRevealed,
        );
        // add_validator called exactly once, not twice.
        assert_eq!(mutator_calls::take(), vec![1]);
    });
}

// ─── challenge() ─────────────────────────────────────────────────────────────

#[test]
fn challenge_slashes_bond_for_duplicate_pubkey_attempt() {
    new_test_ext().execute_with(|| {
        let aura_pubkey = vec![0xFFu8; 64];
        let nonce_a = [0x55u8; 32];
        let nonce_b = [0x66u8; 32];
        let hash_a = make_commit(&aura_pubkey, 1, nonce_a);
        let hash_b = make_commit(&aura_pubkey, 2, nonce_b);

        // Operator 1 commits + reveals legitimately.
        assert_ok!(OnboardingCommit::commit(RuntimeOrigin::signed(1), hash_a));
        // Operator 2 commits the same pubkey under their own account
        // (attempted key-takeover). Their bond is reserved.
        assert_ok!(OnboardingCommit::commit(RuntimeOrigin::signed(2), hash_b));
        advance_blocks(10);
        assert_ok!(OnboardingCommit::reveal(
            RuntimeOrigin::signed(1),
            aura_pubkey.clone(),
            1,
            nonce_a,
        ));

        // Now operator 2's commit is bad-faith and visible.
        // But the dispute window for hash_b has already expired (10 blocks
        // elapsed since both commits). Re-commit hash_b at a later block to
        // simulate a fresh bad-faith commit inside its own window.
        let nonce_c = [0x77u8; 32];
        let hash_c = make_commit(&aura_pubkey, 3, nonce_c);
        assert_ok!(OnboardingCommit::commit(RuntimeOrigin::signed(3), hash_c));
        let bond_before = Balances::reserved_balance(3);
        assert_eq!(bond_before, 1_000);
        // Challenger (account 1) surfaces the duplicate pubkey.
        assert_ok!(OnboardingCommit::challenge(
            RuntimeOrigin::signed(1),
            hash_c,
            aura_pubkey,
        ));
        // Operator 3's bond is slashed (reserved went to 0 and free didn't
        // grow → funds destroyed, not refunded).
        assert_eq!(Balances::reserved_balance(3), 0);
        assert!(Balances::free_balance(3) < 100_000);
        // Commit removed.
        assert!(Commits::<Test>::get(&hash_c).is_none());
        // Mutator was called for operator 1's reveal, not for operator 3.
        assert_eq!(mutator_calls::take(), vec![1]);
    });
}

// ─── invariants ──────────────────────────────────────────────────────────────

#[cfg(feature = "try-runtime")]
#[test]
fn try_state_passes_after_clean_commit_reveal() {
    use frame_support::traits::Hooks;
    new_test_ext().execute_with(|| {
        let aura_pubkey = vec![0xA1u8; 64];
        let nonce = [0xA2u8; 32];
        let hash = make_commit(&aura_pubkey, 1, nonce);
        assert_ok!(OnboardingCommit::commit(RuntimeOrigin::signed(1), hash));
        advance_blocks(10);
        assert_ok!(OnboardingCommit::reveal(
            RuntimeOrigin::signed(1),
            aura_pubkey,
            1,
            nonce,
        ));
        assert_ok!(
            <OnboardingCommit as Hooks<BlockNumber>>::try_state(System::<Test>::block_number())
        );
    });
}

// ── v43 generalization: kind-aware commit + reveal_generic ─────────────

/// Helper: build a generic-kind commit_hash from (payload || nonce).
fn make_generic_commit(payload: &[u8], nonce: [u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(payload.len() + 32);
    buf.extend_from_slice(payload);
    buf.extend_from_slice(&nonce);
    blake2_256(&buf)
}

#[test]
fn legacy_commit_defaults_kind_to_validator() {
    new_test_ext().execute_with(|| {
        let pk = vec![0x42u8; 64];
        let n = [0x10u8; 32];
        let hash = make_commit(&pk, 1, n);
        assert_ok!(OnboardingCommit::commit(RuntimeOrigin::signed(1), hash));
        // ValueQuery default — never written, reads as Validator.
        assert_eq!(CommitKind::<Test>::get(&hash), OnboardingKind::Validator);
        // …and the existing reveal flow keeps working.
        advance_blocks(10);
        assert_ok!(OnboardingCommit::reveal(
            RuntimeOrigin::signed(1), pk, 1, n,
        ));
    });
}

#[test]
fn commit_with_kind_writes_kind_and_reserves_bond() {
    new_test_ext().execute_with(|| {
        let payload = b"any-encoded-thing".to_vec();
        let n = [0x77u8; 32];
        let hash = make_generic_commit(&payload, n);

        assert_ok!(OnboardingCommit::commit_with_kind(
            RuntimeOrigin::signed(1), hash, OnboardingKind::Generic,
        ));
        assert!(Commits::<Test>::contains_key(&hash));
        assert_eq!(CommitKind::<Test>::get(&hash), OnboardingKind::Generic);
    });
}

#[test]
fn reveal_rejects_generic_commit() {
    new_test_ext().execute_with(|| {
        // Use the validator-style commit hash (pubkey||account||nonce) so
        // that the recomputed hash in reveal() actually matches — that
        // way the kind-check is exercised, not the hash-match check.
        let pk = vec![0x42u8; 64];
        let n = [0x33u8; 32];
        let hash = make_commit(&pk, 1, n);
        assert_ok!(OnboardingCommit::commit_with_kind(
            RuntimeOrigin::signed(1), hash, OnboardingKind::Generic,
        ));
        advance_blocks(10);
        assert_noop!(
            OnboardingCommit::reveal(RuntimeOrigin::signed(1), pk, 1, n),
            crate::Error::<Test>::WrongOnboardingKind,
        );
    });
}

#[test]
fn reveal_generic_rejects_validator_commit() {
    new_test_ext().execute_with(|| {
        let pk = vec![0x42u8; 64];
        let n = [0x55u8; 32];
        let hash = make_commit(&pk, 1, n);
        assert_ok!(OnboardingCommit::commit(RuntimeOrigin::signed(1), hash));
        advance_blocks(10);
        assert_noop!(
            OnboardingCommit::reveal_generic(
                RuntimeOrigin::signed(1), hash, b"x".to_vec(), n,
            ),
            crate::Error::<Test>::WrongOnboardingKind,
        );
    });
}

#[test]
fn reveal_generic_succeeds_and_emits_event_with_payload_hash() {
    new_test_ext().execute_with(|| {
        let payload = b"gov-app-payload".to_vec();
        let n = [0xCCu8; 32];
        let hash = make_generic_commit(&payload, n);
        assert_ok!(OnboardingCommit::commit_with_kind(
            RuntimeOrigin::signed(1), hash, OnboardingKind::Generic,
        ));
        advance_blocks(10);
        assert_ok!(OnboardingCommit::reveal_generic(
            RuntimeOrigin::signed(1), hash, payload.clone(), n,
        ));
        let expected_payload_hash = blake2_256(&payload);
        System::<Test>::assert_has_event(Event::GenericRevealed {
            who: 1,
            commit_hash: hash,
            payload_hash: expected_payload_hash,
        }.into());
        // Bond released — no on-chain mutator was called, so
        // RevealedPubkeys remains empty.
        assert!(RevealedPubkeys::<Test>::iter().next().is_none());
    });
}

#[test]
fn reveal_generic_rejects_hash_mismatch() {
    new_test_ext().execute_with(|| {
        let payload = b"intended".to_vec();
        let n = [0xDDu8; 32];
        let hash = make_generic_commit(&payload, n);
        assert_ok!(OnboardingCommit::commit_with_kind(
            RuntimeOrigin::signed(1), hash, OnboardingKind::Generic,
        ));
        advance_blocks(10);
        assert_noop!(
            OnboardingCommit::reveal_generic(
                RuntimeOrigin::signed(1), hash, b"different".to_vec(), n,
            ),
            crate::Error::<Test>::HashMismatch,
        );
    });
}

#[test]
fn reveal_generic_requires_committer() {
    new_test_ext().execute_with(|| {
        let payload = b"x".to_vec();
        let n = [0xEEu8; 32];
        let hash = make_generic_commit(&payload, n);
        assert_ok!(OnboardingCommit::commit_with_kind(
            RuntimeOrigin::signed(1), hash, OnboardingKind::Generic,
        ));
        advance_blocks(10);
        assert_noop!(
            OnboardingCommit::reveal_generic(
                RuntimeOrigin::signed(2), hash, payload, n,
            ),
            crate::Error::<Test>::NotCommitter,
        );
    });
}
