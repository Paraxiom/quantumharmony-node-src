//! Tests for the Transparence Two-Man Rule pallet
//!
//! Comprehensive test coverage for ceremony initiation, dual-signature
//! authorization, oracle whitelist management, rejection, expiry, and events.

use crate::{mock::*, pallet::*, Error, Event};
use frame_support::{assert_err, assert_noop, assert_ok};

/// Helper: create an amount hash from a seed
fn amount_hash(seed: u8) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash[0] = seed;
    hash[31] = seed;
    hash
}

/// Helper: create an evidence hash from a seed
fn evidence_hash(seed: u8) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash[0] = seed;
    hash[1] = 0xEE;
    hash
}

/// Helper: register BOB as an authorized oracle via root
fn register_bob_as_oracle() {
    assert_ok!(TwoManRule::register_oracle(
        RuntimeOrigin::root(),
        BOB,
    ));
}

/// Helper: initiate a ceremony and return ceremony_id (always 0 for first)
fn initiate_default_ceremony() -> u64 {
    assert_ok!(TwoManRule::initiate_ceremony(
        RuntimeOrigin::signed(ALICE),
        1,  // contract_id
        1,  // milestone_id
        amount_hash(1),
        evidence_hash(1),
    ));
    0 // first ceremony ID
}

// ==================== INITIATE CEREMONY TESTS ====================

#[test]
fn initiate_ceremony_works() {
    new_test_ext().execute_with(|| {
        assert_ok!(TwoManRule::initiate_ceremony(
            RuntimeOrigin::signed(ALICE),
            1,  // contract_id
            1,  // milestone_id
            amount_hash(1),
            evidence_hash(1),
        ));

        // Verify ceremony was created
        let ceremony = TwoManRule::ceremonies(0).expect("Should exist");
        assert_eq!(ceremony.id, 0);
        assert_eq!(ceremony.contract_id, 1);
        assert_eq!(ceremony.milestone_id, 1);
        assert_eq!(ceremony.amount_hash, amount_hash(1));
        assert_eq!(ceremony.evidence_hash, evidence_hash(1));
        assert_eq!(ceremony.status, PaymentStatus::Pending);
        assert_eq!(ceremony.human_signer, None);
        assert_eq!(ceremony.machine_signer, None);
        assert_eq!(ceremony.initiated_at, 1);
        assert_eq!(ceremony.authorized_at, None);
        // Expiry = block 1 + 100 = 101
        assert_eq!(ceremony.expires_at, 101);

        // Verify next ID incremented
        assert_eq!(TwoManRule::next_ceremony_id(), 1);

        // Verify contract index
        let contract_ceremonies = TwoManRule::ceremonies_by_contract(1);
        assert!(contract_ceremonies.contains(&0));

        // Verify event
        System::assert_has_event(Event::CeremonyInitiated {
            ceremony_id: 0,
            contract_id: 1,
            milestone_id: 1,
        }.into());
    });
}

// ==================== DUAL SIGNATURE TESTS ====================

#[test]
fn sign_human_then_machine_authorizes() {
    new_test_ext().execute_with(|| {
        register_bob_as_oracle();
        let ceremony_id = initiate_default_ceremony();

        // Fragment A: human signs
        assert_ok!(TwoManRule::sign_human(
            RuntimeOrigin::signed(ALICE),
            ceremony_id,
        ));

        let ceremony = TwoManRule::ceremonies(ceremony_id).expect("Should exist");
        assert_eq!(ceremony.status, PaymentStatus::HumanSigned);
        assert_eq!(ceremony.human_signer, Some(ALICE));

        System::assert_has_event(Event::HumanSigned {
            ceremony_id,
            signer: ALICE,
        }.into());

        // Fragment B: machine signs
        assert_ok!(TwoManRule::sign_machine(
            RuntimeOrigin::signed(BOB),
            ceremony_id,
        ));

        let ceremony = TwoManRule::ceremonies(ceremony_id).expect("Should exist");
        assert_eq!(ceremony.status, PaymentStatus::Authorized);
        assert_eq!(ceremony.machine_signer, Some(BOB));
        assert!(ceremony.authorized_at.is_some());
        assert_eq!(ceremony.authorized_at, Some(1));

        System::assert_has_event(Event::MachineSigned {
            ceremony_id,
            oracle: BOB,
        }.into());

        // Verify PaymentAuthorized event
        System::assert_has_event(Event::PaymentAuthorized {
            ceremony_id,
            contract_id: 1,
            milestone_id: 1,
            amount_hash: amount_hash(1),
        }.into());
    });
}

#[test]
fn sign_machine_then_human_authorizes() {
    new_test_ext().execute_with(|| {
        register_bob_as_oracle();
        let ceremony_id = initiate_default_ceremony();

        // Fragment B first: machine signs
        assert_ok!(TwoManRule::sign_machine(
            RuntimeOrigin::signed(BOB),
            ceremony_id,
        ));

        let ceremony = TwoManRule::ceremonies(ceremony_id).expect("Should exist");
        assert_eq!(ceremony.status, PaymentStatus::MachineSigned);
        assert_eq!(ceremony.machine_signer, Some(BOB));

        // Fragment A: human signs
        assert_ok!(TwoManRule::sign_human(
            RuntimeOrigin::signed(ALICE),
            ceremony_id,
        ));

        let ceremony = TwoManRule::ceremonies(ceremony_id).expect("Should exist");
        assert_eq!(ceremony.status, PaymentStatus::Authorized);
        assert_eq!(ceremony.human_signer, Some(ALICE));
        assert!(ceremony.authorized_at.is_some());

        // Verify PaymentAuthorized event
        System::assert_has_event(Event::PaymentAuthorized {
            ceremony_id,
            contract_id: 1,
            milestone_id: 1,
            amount_hash: amount_hash(1),
        }.into());
    });
}

// ==================== ORACLE WHITELIST TESTS ====================

#[test]
fn sign_machine_not_oracle_fails() {
    new_test_ext().execute_with(|| {
        let ceremony_id = initiate_default_ceremony();

        // CHARLIE is not whitelisted
        assert_noop!(
            TwoManRule::sign_machine(
                RuntimeOrigin::signed(CHARLIE),
                ceremony_id,
            ),
            Error::<Test>::NotAuthorizedOracle
        );
    });
}

#[test]
fn register_oracle_works() {
    new_test_ext().execute_with(|| {
        // ForceOrigin (root) can register
        assert_ok!(TwoManRule::register_oracle(
            RuntimeOrigin::root(),
            BOB,
        ));

        assert!(TwoManRule::authorized_oracles(BOB));

        System::assert_has_event(Event::OracleRegistered {
            oracle: BOB,
        }.into());

        // Non-root cannot register
        assert_noop!(
            TwoManRule::register_oracle(
                RuntimeOrigin::signed(ALICE),
                CHARLIE,
            ),
            sp_runtime::DispatchError::BadOrigin
        );
    });
}

#[test]
fn remove_oracle_works() {
    new_test_ext().execute_with(|| {
        // Register then remove
        assert_ok!(TwoManRule::register_oracle(RuntimeOrigin::root(), BOB));
        assert!(TwoManRule::authorized_oracles(BOB));

        assert_ok!(TwoManRule::remove_oracle(RuntimeOrigin::root(), BOB));
        assert!(!TwoManRule::authorized_oracles(BOB));

        System::assert_has_event(Event::OracleRemoved {
            oracle: BOB,
        }.into());

        // Non-root cannot remove
        assert_noop!(
            TwoManRule::remove_oracle(
                RuntimeOrigin::signed(ALICE),
                CHARLIE,
            ),
            sp_runtime::DispatchError::BadOrigin
        );
    });
}

// ==================== REJECTION TESTS ====================

#[test]
fn reject_machine_blocks_payment() {
    new_test_ext().execute_with(|| {
        register_bob_as_oracle();
        let ceremony_id = initiate_default_ceremony();

        // Human signs first
        assert_ok!(TwoManRule::sign_human(
            RuntimeOrigin::signed(ALICE),
            ceremony_id,
        ));

        // Oracle rejects (tests failed)
        assert_ok!(TwoManRule::reject_machine(
            RuntimeOrigin::signed(BOB),
            ceremony_id,
        ));

        let ceremony = TwoManRule::ceremonies(ceremony_id).expect("Should exist");
        assert_eq!(ceremony.status, PaymentStatus::Rejected);
        assert_eq!(ceremony.machine_signer, Some(BOB));

        // Verify rejection event
        System::assert_has_event(Event::PaymentRejected {
            ceremony_id,
            contract_id: 1,
            milestone_id: 1,
            oracle: BOB,
        }.into());

        // Cannot sign after rejection
        assert_noop!(
            TwoManRule::sign_machine(
                RuntimeOrigin::signed(BOB),
                ceremony_id,
            ),
            Error::<Test>::InvalidStatus
        );
    });
}

// ==================== DOUBLE SIGN TESTS ====================

#[test]
fn double_sign_human_fails() {
    new_test_ext().execute_with(|| {
        let ceremony_id = initiate_default_ceremony();

        // First human sign — transitions to HumanSigned
        assert_ok!(TwoManRule::sign_human(
            RuntimeOrigin::signed(ALICE),
            ceremony_id,
        ));

        // Second human sign should fail — status is HumanSigned, which
        // is not Pending or MachineSigned, so InvalidStatus fires
        assert_noop!(
            TwoManRule::sign_human(
                RuntimeOrigin::signed(CHARLIE),
                ceremony_id,
            ),
            Error::<Test>::InvalidStatus
        );
    });
}

#[test]
fn double_sign_machine_fails() {
    new_test_ext().execute_with(|| {
        register_bob_as_oracle();
        assert_ok!(TwoManRule::register_oracle(RuntimeOrigin::root(), DAVE));

        let ceremony_id = initiate_default_ceremony();

        // First machine sign — transitions to MachineSigned
        assert_ok!(TwoManRule::sign_machine(
            RuntimeOrigin::signed(BOB),
            ceremony_id,
        ));

        // Second machine sign should fail — status is MachineSigned, which
        // is not Pending or HumanSigned, so InvalidStatus fires
        assert_noop!(
            TwoManRule::sign_machine(
                RuntimeOrigin::signed(DAVE),
                ceremony_id,
            ),
            Error::<Test>::InvalidStatus
        );
    });
}

// ==================== EXPIRY TESTS ====================

#[test]
fn expired_ceremony_fails() {
    new_test_ext().execute_with(|| {
        register_bob_as_oracle();
        let ceremony_id = initiate_default_ceremony();

        // Verify ceremony was created with correct expiry
        let ceremony = TwoManRule::ceremonies(ceremony_id).expect("Should exist");
        assert_eq!(ceremony.expires_at, 101); // block 1 + 100

        // Advance past expiry
        System::set_block_number(102);

        // Human sign should fail with CeremonyExpired
        // Note: the lazy expiry sets status to Expired and returns error,
        // but since dispatch is transactional, the storage change is reverted
        assert_noop!(
            TwoManRule::sign_human(
                RuntimeOrigin::signed(ALICE),
                ceremony_id,
            ),
            Error::<Test>::CeremonyExpired
        );

        // Machine sign should also fail with CeremonyExpired
        assert_noop!(
            TwoManRule::sign_machine(
                RuntimeOrigin::signed(BOB),
                ceremony_id,
            ),
            Error::<Test>::CeremonyExpired
        );

        // Ceremony remains Pending in storage (transactional revert)
        // but it is effectively expired — any sign attempt will fail
        let ceremony = TwoManRule::ceremonies(ceremony_id).expect("Should exist");
        assert_eq!(ceremony.status, PaymentStatus::Pending);

        // Signing at a non-expired block still works
        System::set_block_number(50);
        assert_ok!(TwoManRule::sign_human(
            RuntimeOrigin::signed(ALICE),
            ceremony_id,
        ));
    });
}

// ==================== THE CRITICAL TEST ====================

#[test]
fn payment_authorized_event_emitted() {
    new_test_ext().execute_with(|| {
        register_bob_as_oracle();

        // Create ceremony
        assert_ok!(TwoManRule::initiate_ceremony(
            RuntimeOrigin::signed(ALICE),
            42,  // contract_id
            7,   // milestone_id
            amount_hash(99),
            evidence_hash(99),
        ));

        let ceremony_id = 0;

        // Both fragments
        assert_ok!(TwoManRule::sign_human(
            RuntimeOrigin::signed(ALICE),
            ceremony_id,
        ));
        assert_ok!(TwoManRule::sign_machine(
            RuntimeOrigin::signed(BOB),
            ceremony_id,
        ));

        // THE critical assertion: PaymentAuthorized is the event
        // the off-chain Fiat Bridge listens for
        System::assert_last_event(Event::PaymentAuthorized {
            ceremony_id,
            contract_id: 42,
            milestone_id: 7,
            amount_hash: amount_hash(99),
        }.into());

        // Also verify via helper
        assert!(TwoManRule::is_authorized(ceremony_id));
    });
}

// ==================== EDGE CASES ====================

#[test]
fn ceremony_not_found() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            TwoManRule::sign_human(
                RuntimeOrigin::signed(ALICE),
                999,
            ),
            Error::<Test>::CeremonyNotFound
        );
    });
}

#[test]
fn reject_non_oracle_fails() {
    new_test_ext().execute_with(|| {
        let ceremony_id = initiate_default_ceremony();

        // CHARLIE is not an oracle
        assert_noop!(
            TwoManRule::reject_machine(
                RuntimeOrigin::signed(CHARLIE),
                ceremony_id,
            ),
            Error::<Test>::NotAuthorizedOracle
        );
    });
}

#[test]
fn reject_already_authorized_fails() {
    new_test_ext().execute_with(|| {
        register_bob_as_oracle();
        let ceremony_id = initiate_default_ceremony();

        // Authorize the ceremony
        assert_ok!(TwoManRule::sign_human(RuntimeOrigin::signed(ALICE), ceremony_id));
        assert_ok!(TwoManRule::sign_machine(RuntimeOrigin::signed(BOB), ceremony_id));

        // Cannot reject after authorization
        assert_noop!(
            TwoManRule::reject_machine(
                RuntimeOrigin::signed(BOB),
                ceremony_id,
            ),
            Error::<Test>::InvalidStatus
        );
    });
}

#[test]
fn multiple_ceremonies_independent() {
    new_test_ext().execute_with(|| {
        register_bob_as_oracle();

        // Create two ceremonies
        assert_ok!(TwoManRule::initiate_ceremony(
            RuntimeOrigin::signed(ALICE),
            1, 1, amount_hash(1), evidence_hash(1),
        ));
        assert_ok!(TwoManRule::initiate_ceremony(
            RuntimeOrigin::signed(ALICE),
            1, 2, amount_hash(2), evidence_hash(2),
        ));

        // Authorize first only
        assert_ok!(TwoManRule::sign_human(RuntimeOrigin::signed(ALICE), 0));
        assert_ok!(TwoManRule::sign_machine(RuntimeOrigin::signed(BOB), 0));

        assert!(TwoManRule::is_authorized(0));
        assert!(!TwoManRule::is_authorized(1));

        // Second is still pending
        let ceremony = TwoManRule::ceremonies(1).expect("Should exist");
        assert_eq!(ceremony.status, PaymentStatus::Pending);
    });
}
