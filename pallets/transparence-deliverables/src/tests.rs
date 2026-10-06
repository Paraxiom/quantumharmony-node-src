//! Tests for the Transparence Deliverables pallet
//!
//! Comprehensive test coverage for the full contract lifecycle: creation,
//! activation, milestone management, deliverable submission, oracle validation,
//! payment authorization, completion, and termination.

use crate::{mock::*, pallet::*, Error, Event};
use frame_support::{assert_noop, assert_ok};

/// Helper: create a title hash from a seed
fn title_hash(seed: u8) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash[0] = seed;
    hash[31] = seed;
    hash
}

/// Helper: create a devis hash from a seed
fn devis_hash(seed: u8) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash[0] = seed;
    hash[1] = 0xDE;
    hash
}

/// Helper: create a description hash from a seed
fn desc_hash(seed: u8) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash[0] = seed;
    hash[2] = 0xDD;
    hash
}

/// Helper: create an evidence hash from a seed
fn evidence_hash(seed: u8) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash[0] = seed;
    hash[3] = 0xEE;
    hash
}

/// Helper: create a contract in Draft phase and return contract_id
fn create_draft_contract() -> u64 {
    assert_ok!(Deliverables::create_contract(
        RuntimeOrigin::signed(OWNER),
        title_hash(1),
        devis_hash(1),
        SUPPLIER,
    ));
    0 // first contract ID
}

/// Helper: create and activate a contract, return contract_id
fn create_active_contract() -> u64 {
    let id = create_draft_contract();
    assert_ok!(Deliverables::activate_contract(
        RuntimeOrigin::signed(OWNER),
        id,
    ));
    id
}

/// Helper: create active contract with one milestone, return (contract_id, milestone_id)
fn create_contract_with_milestone() -> (u64, u64) {
    let contract_id = create_active_contract();
    assert_ok!(Deliverables::add_milestone(
        RuntimeOrigin::signed(OWNER),
        contract_id,
        1, // sequence
        desc_hash(1),
    ));
    (contract_id, 0) // first milestone ID
}

// ==================== CREATE CONTRACT TESTS ====================

#[test]
fn create_contract_works() {
    new_test_ext().execute_with(|| {
        assert_ok!(Deliverables::create_contract(
            RuntimeOrigin::signed(OWNER),
            title_hash(1),
            devis_hash(1),
            SUPPLIER,
        ));

        // Verify contract was created
        let contract = Deliverables::contracts(0).expect("Should exist");
        assert_eq!(contract.id, 0);
        assert_eq!(contract.title_hash, title_hash(1));
        assert_eq!(contract.devis_hash, devis_hash(1));
        assert_eq!(contract.owner, OWNER);
        assert_eq!(contract.supplier, SUPPLIER);
        assert_eq!(contract.phase, ContractPhase::Draft);
        assert_eq!(contract.created_at, 1);
        assert_eq!(contract.milestone_count, 0);
        assert_eq!(contract.completed_milestones, 0);

        // Verify next ID incremented
        assert_eq!(Deliverables::next_contract_id(), 1);

        // Verify owner index
        let owner_contracts = Deliverables::contracts_by_owner(OWNER);
        assert!(owner_contracts.contains(&0));

        // Verify supplier index
        let supplier_contracts = Deliverables::contracts_by_supplier(SUPPLIER);
        assert!(supplier_contracts.contains(&0));

        // Verify event
        System::assert_has_event(Event::ContractCreated {
            contract_id: 0,
            owner: OWNER,
            supplier: SUPPLIER,
        }.into());
    });
}

// ==================== ACTIVATE CONTRACT TESTS ====================

#[test]
fn activate_contract_works() {
    new_test_ext().execute_with(|| {
        let contract_id = create_draft_contract();

        assert_ok!(Deliverables::activate_contract(
            RuntimeOrigin::signed(OWNER),
            contract_id,
        ));

        let contract = Deliverables::contracts(contract_id).expect("Should exist");
        assert_eq!(contract.phase, ContractPhase::Active);

        System::assert_has_event(Event::ContractActivated {
            contract_id,
        }.into());
    });
}

#[test]
fn activate_not_owner_fails() {
    new_test_ext().execute_with(|| {
        let contract_id = create_draft_contract();

        // Supplier cannot activate
        assert_noop!(
            Deliverables::activate_contract(
                RuntimeOrigin::signed(SUPPLIER),
                contract_id,
            ),
            Error::<Test>::NotOwner
        );

        // Random outsider cannot activate
        assert_noop!(
            Deliverables::activate_contract(
                RuntimeOrigin::signed(OUTSIDER),
                contract_id,
            ),
            Error::<Test>::NotOwner
        );
    });
}

#[test]
fn activate_already_active_fails() {
    new_test_ext().execute_with(|| {
        let contract_id = create_active_contract();

        // Cannot activate an already active contract
        assert_noop!(
            Deliverables::activate_contract(
                RuntimeOrigin::signed(OWNER),
                contract_id,
            ),
            Error::<Test>::InvalidPhase
        );
    });
}

// ==================== ADD MILESTONE TESTS ====================

#[test]
fn add_milestone_works() {
    new_test_ext().execute_with(|| {
        let contract_id = create_active_contract();

        assert_ok!(Deliverables::add_milestone(
            RuntimeOrigin::signed(OWNER),
            contract_id,
            1, // sequence
            desc_hash(1),
        ));

        // Verify milestone was created
        let milestone = Deliverables::milestones(0).expect("Should exist");
        assert_eq!(milestone.id, 0);
        assert_eq!(milestone.contract_id, contract_id);
        assert_eq!(milestone.sequence, 1);
        assert_eq!(milestone.description_hash, desc_hash(1));
        assert_eq!(milestone.status, MilestoneStatus::Pending);
        assert_eq!(milestone.evidence_hash, None);
        assert_eq!(milestone.created_at, 1);
        assert_eq!(milestone.validated_at, None);
        assert_eq!(milestone.payment_ceremony_id, None);

        // Verify next milestone ID
        assert_eq!(Deliverables::next_milestone_id(), 1);

        // Verify contract milestone count updated
        let contract = Deliverables::contracts(contract_id).expect("Should exist");
        assert_eq!(contract.milestone_count, 1);

        // Verify milestone index
        let milestone_ids = Deliverables::milestones_by_contract(contract_id);
        assert!(milestone_ids.contains(&0));

        // Verify event
        System::assert_has_event(Event::MilestoneAdded {
            contract_id,
            milestone_id: 0,
            sequence: 1,
        }.into());
    });
}

#[test]
fn add_milestone_draft_fails() {
    new_test_ext().execute_with(|| {
        let contract_id = create_draft_contract();

        // Contract is in Draft, not Active
        assert_noop!(
            Deliverables::add_milestone(
                RuntimeOrigin::signed(OWNER),
                contract_id,
                1,
                desc_hash(1),
            ),
            Error::<Test>::InvalidPhase
        );
    });
}

#[test]
fn add_milestone_not_owner_fails() {
    new_test_ext().execute_with(|| {
        let contract_id = create_active_contract();

        assert_noop!(
            Deliverables::add_milestone(
                RuntimeOrigin::signed(SUPPLIER),
                contract_id,
                1,
                desc_hash(1),
            ),
            Error::<Test>::NotOwner
        );
    });
}

// ==================== SUBMIT DELIVERABLE TESTS ====================

#[test]
fn submit_deliverable_supplier_only() {
    new_test_ext().execute_with(|| {
        let (contract_id, milestone_id) = create_contract_with_milestone();

        // Owner cannot submit deliverable
        assert_noop!(
            Deliverables::submit_deliverable(
                RuntimeOrigin::signed(OWNER),
                contract_id,
                milestone_id,
                evidence_hash(1),
            ),
            Error::<Test>::NotSupplier
        );

        // Outsider cannot submit deliverable
        assert_noop!(
            Deliverables::submit_deliverable(
                RuntimeOrigin::signed(OUTSIDER),
                contract_id,
                milestone_id,
                evidence_hash(1),
            ),
            Error::<Test>::NotSupplier
        );

        // Supplier CAN submit
        assert_ok!(Deliverables::submit_deliverable(
            RuntimeOrigin::signed(SUPPLIER),
            contract_id,
            milestone_id,
            evidence_hash(1),
        ));
    });
}

#[test]
fn submit_deliverable_transitions_contract() {
    new_test_ext().execute_with(|| {
        let (contract_id, milestone_id) = create_contract_with_milestone();

        // Contract should be Active before submission
        let contract = Deliverables::contracts(contract_id).expect("Should exist");
        assert_eq!(contract.phase, ContractPhase::Active);

        assert_ok!(Deliverables::submit_deliverable(
            RuntimeOrigin::signed(SUPPLIER),
            contract_id,
            milestone_id,
            evidence_hash(1),
        ));

        // Contract should now be InExecution
        let contract = Deliverables::contracts(contract_id).expect("Should exist");
        assert_eq!(contract.phase, ContractPhase::InExecution);

        // Milestone should be ValidationPending
        let milestone = Deliverables::milestones(milestone_id).expect("Should exist");
        assert_eq!(milestone.status, MilestoneStatus::ValidationPending);
        assert_eq!(milestone.evidence_hash, Some(evidence_hash(1)));

        // Verify event
        System::assert_has_event(Event::DeliverableSubmitted {
            contract_id,
            milestone_id,
            supplier: SUPPLIER,
            evidence_hash: evidence_hash(1),
        }.into());
    });
}

// ==================== RECORD VALIDATION TESTS ====================

#[test]
fn record_validation_pass() {
    new_test_ext().execute_with(|| {
        let (contract_id, milestone_id) = create_contract_with_milestone();

        // Submit deliverable first
        assert_ok!(Deliverables::submit_deliverable(
            RuntimeOrigin::signed(SUPPLIER),
            contract_id,
            milestone_id,
            evidence_hash(1),
        ));

        // Oracle records pass
        assert_ok!(Deliverables::record_validation_result(
            RuntimeOrigin::signed(ORACLE),
            milestone_id,
            true,
        ));

        let milestone = Deliverables::milestones(milestone_id).expect("Should exist");
        assert_eq!(milestone.status, MilestoneStatus::Validated);
        assert!(milestone.validated_at.is_some());

        System::assert_has_event(Event::MilestoneValidated {
            contract_id,
            milestone_id,
        }.into());
    });
}

#[test]
fn record_validation_fail() {
    new_test_ext().execute_with(|| {
        let (contract_id, milestone_id) = create_contract_with_milestone();

        // Submit deliverable first
        assert_ok!(Deliverables::submit_deliverable(
            RuntimeOrigin::signed(SUPPLIER),
            contract_id,
            milestone_id,
            evidence_hash(1),
        ));

        // Oracle records fail
        assert_ok!(Deliverables::record_validation_result(
            RuntimeOrigin::signed(ORACLE),
            milestone_id,
            false,
        ));

        let milestone = Deliverables::milestones(milestone_id).expect("Should exist");
        assert_eq!(milestone.status, MilestoneStatus::Rejected);
        assert_eq!(milestone.validated_at, None);

        System::assert_has_event(Event::MilestoneRejected {
            contract_id,
            milestone_id,
        }.into());
    });
}

#[test]
fn record_validation_wrong_status_fails() {
    new_test_ext().execute_with(|| {
        let (contract_id, milestone_id) = create_contract_with_milestone();

        // Milestone is Pending, not ValidationPending
        assert_noop!(
            Deliverables::record_validation_result(
                RuntimeOrigin::signed(ORACLE),
                milestone_id,
                true,
            ),
            Error::<Test>::InvalidMilestoneStatus
        );
    });
}

// ==================== PAYMENT RECORDING TESTS ====================

#[test]
fn record_payment_completes_contract() {
    new_test_ext().execute_with(|| {
        let contract_id = create_active_contract();

        // Add two milestones
        assert_ok!(Deliverables::add_milestone(
            RuntimeOrigin::signed(OWNER),
            contract_id, 1, desc_hash(1),
        ));
        assert_ok!(Deliverables::add_milestone(
            RuntimeOrigin::signed(OWNER),
            contract_id, 2, desc_hash(2),
        ));

        let ms1_id = 0u64;
        let ms2_id = 1u64;

        // Process milestone 1: submit -> validate -> payment
        assert_ok!(Deliverables::submit_deliverable(
            RuntimeOrigin::signed(SUPPLIER),
            contract_id, ms1_id, evidence_hash(1),
        ));
        assert_ok!(Deliverables::record_validation_result(
            RuntimeOrigin::signed(ORACLE),
            ms1_id, true,
        ));
        assert_ok!(Deliverables::record_payment_authorized(
            RuntimeOrigin::signed(ORACLE),
            ms1_id, 100, // ceremony_id
        ));

        // Contract not yet complete (second milestone still pending)
        let contract = Deliverables::contracts(contract_id).expect("Should exist");
        assert_eq!(contract.completed_milestones, 1);
        assert_eq!(contract.phase, ContractPhase::InExecution);

        // Verify PaymentRecorded event
        System::assert_has_event(Event::PaymentRecorded {
            contract_id,
            milestone_id: ms1_id,
            ceremony_id: 100,
        }.into());

        // Verify milestone has ceremony ID
        let ms1 = Deliverables::milestones(ms1_id).expect("Should exist");
        assert_eq!(ms1.status, MilestoneStatus::PaymentAuthorized);
        assert_eq!(ms1.payment_ceremony_id, Some(100));

        // Process milestone 2: submit -> validate -> payment
        assert_ok!(Deliverables::submit_deliverable(
            RuntimeOrigin::signed(SUPPLIER),
            contract_id, ms2_id, evidence_hash(2),
        ));
        assert_ok!(Deliverables::record_validation_result(
            RuntimeOrigin::signed(ORACLE),
            ms2_id, true,
        ));
        assert_ok!(Deliverables::record_payment_authorized(
            RuntimeOrigin::signed(ORACLE),
            ms2_id, 101, // ceremony_id
        ));

        // Now contract should be Completed
        let contract = Deliverables::contracts(contract_id).expect("Should exist");
        assert_eq!(contract.completed_milestones, 2);
        assert_eq!(contract.phase, ContractPhase::Completed);

        // Verify ContractCompleted event
        System::assert_has_event(Event::ContractCompleted {
            contract_id,
        }.into());
    });
}

#[test]
fn record_payment_wrong_status_fails() {
    new_test_ext().execute_with(|| {
        let (contract_id, milestone_id) = create_contract_with_milestone();

        // Submit deliverable (milestone is now ValidationPending, not Validated)
        assert_ok!(Deliverables::submit_deliverable(
            RuntimeOrigin::signed(SUPPLIER),
            contract_id,
            milestone_id,
            evidence_hash(1),
        ));

        // Try to record payment without validation
        assert_noop!(
            Deliverables::record_payment_authorized(
                RuntimeOrigin::signed(ORACLE),
                milestone_id,
                100,
            ),
            Error::<Test>::InvalidMilestoneStatus
        );
    });
}

// ==================== TERMINATE CONTRACT TESTS ====================

#[test]
fn terminate_contract_works() {
    new_test_ext().execute_with(|| {
        let contract_id = create_active_contract();

        assert_ok!(Deliverables::terminate_contract(
            RuntimeOrigin::signed(OWNER),
            contract_id,
        ));

        let contract = Deliverables::contracts(contract_id).expect("Should exist");
        assert_eq!(contract.phase, ContractPhase::Terminated);

        System::assert_has_event(Event::ContractTerminated {
            contract_id,
        }.into());
    });
}

#[test]
fn terminate_contract_not_owner_fails() {
    new_test_ext().execute_with(|| {
        let contract_id = create_active_contract();

        assert_noop!(
            Deliverables::terminate_contract(
                RuntimeOrigin::signed(SUPPLIER),
                contract_id,
            ),
            Error::<Test>::NotOwner
        );

        assert_noop!(
            Deliverables::terminate_contract(
                RuntimeOrigin::signed(OUTSIDER),
                contract_id,
            ),
            Error::<Test>::NotOwner
        );
    });
}

// ==================== MAX MILESTONES TESTS ====================

#[test]
fn max_milestones_enforced() {
    new_test_ext().execute_with(|| {
        let contract_id = create_active_contract();

        // Add MAX_MILESTONES_PER_CONTRACT milestones
        for i in 0..MAX_MILESTONES_PER_CONTRACT {
            assert_ok!(Deliverables::add_milestone(
                RuntimeOrigin::signed(OWNER),
                contract_id,
                i + 1,
                desc_hash(i as u8),
            ));
        }

        // Next one should fail
        assert_noop!(
            Deliverables::add_milestone(
                RuntimeOrigin::signed(OWNER),
                contract_id,
                MAX_MILESTONES_PER_CONTRACT + 1,
                desc_hash(255),
            ),
            Error::<Test>::MaxMilestonesReached
        );

        // Verify contract milestone count
        let contract = Deliverables::contracts(contract_id).expect("Should exist");
        assert_eq!(contract.milestone_count, MAX_MILESTONES_PER_CONTRACT);
    });
}

// ==================== EDGE CASES ====================

#[test]
fn contract_not_found() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            Deliverables::activate_contract(
                RuntimeOrigin::signed(OWNER),
                999,
            ),
            Error::<Test>::ContractNotFound
        );
    });
}

#[test]
fn milestone_not_found() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            Deliverables::record_validation_result(
                RuntimeOrigin::signed(ORACLE),
                999,
                true,
            ),
            Error::<Test>::MilestoneNotFound
        );
    });
}

#[test]
fn helper_contract_progress() {
    new_test_ext().execute_with(|| {
        let contract_id = create_active_contract();

        // No milestones yet
        let progress = Deliverables::contract_progress(contract_id);
        assert_eq!(progress, Some((0, 0)));

        // Add a milestone
        assert_ok!(Deliverables::add_milestone(
            RuntimeOrigin::signed(OWNER),
            contract_id, 1, desc_hash(1),
        ));

        let progress = Deliverables::contract_progress(contract_id);
        assert_eq!(progress, Some((0, 1)));

        // Non-existent contract
        assert_eq!(Deliverables::contract_progress(999), None);
    });
}

#[test]
fn multiple_contracts_independent() {
    new_test_ext().execute_with(|| {
        // Create two contracts
        assert_ok!(Deliverables::create_contract(
            RuntimeOrigin::signed(OWNER),
            title_hash(1), devis_hash(1), SUPPLIER,
        ));
        assert_ok!(Deliverables::create_contract(
            RuntimeOrigin::signed(OWNER),
            title_hash(2), devis_hash(2), SUPPLIER,
        ));

        // Activate first only
        assert_ok!(Deliverables::activate_contract(RuntimeOrigin::signed(OWNER), 0));

        let c0 = Deliverables::contracts(0).expect("Should exist");
        let c1 = Deliverables::contracts(1).expect("Should exist");
        assert_eq!(c0.phase, ContractPhase::Active);
        assert_eq!(c1.phase, ContractPhase::Draft);

        // Owner and supplier indices should have both
        assert_eq!(Deliverables::contracts_by_owner(OWNER).len(), 2);
        assert_eq!(Deliverables::contracts_by_supplier(SUPPLIER).len(), 2);
    });
}

// ==================== RECORDER AUTHORISATION ====================

/// Helper: a milestone in ValidationPending
fn pending_milestone() -> u64 {
    let (contract_id, milestone_id) = create_contract_with_milestone();
    assert_ok!(Deliverables::submit_deliverable(
        RuntimeOrigin::signed(SUPPLIER),
        contract_id,
        milestone_id,
        evidence_hash(1),
    ));
    milestone_id
}

#[test]
fn record_validation_not_recorder_fails() {
    new_test_ext().execute_with(|| {
        let milestone_id = pending_milestone();
        for who in [OWNER, SUPPLIER, OUTSIDER] {
            assert_noop!(
                Deliverables::record_validation_result(RuntimeOrigin::signed(who), milestone_id, true),
                Error::<Test>::NotRecorder
            );
        }
    });
}

#[test]
fn record_payment_not_recorder_fails() {
    new_test_ext().execute_with(|| {
        let milestone_id = pending_milestone();
        assert_ok!(Deliverables::record_validation_result(
            RuntimeOrigin::signed(ORACLE),
            milestone_id,
            true,
        ));
        for who in [OWNER, SUPPLIER, OUTSIDER] {
            assert_noop!(
                Deliverables::record_payment_authorized(RuntimeOrigin::signed(who), milestone_id, 99),
                Error::<Test>::NotRecorder
            );
        }
    });
}

#[test]
fn no_recorder_set_refuses_everyone() {
    new_test_ext().execute_with(|| {
        let milestone_id = pending_milestone();
        assert_ok!(Deliverables::set_recorder(RuntimeOrigin::root(), None));
        assert_eq!(Deliverables::recorder(), None);
        assert_noop!(
            Deliverables::record_validation_result(RuntimeOrigin::signed(ORACLE), milestone_id, true),
            Error::<Test>::NotRecorder
        );
    });
}

#[test]
fn set_recorder_root_only() {
    new_test_ext().execute_with(|| {
        for who in [OWNER, ORACLE, OUTSIDER] {
            assert_noop!(
                Deliverables::set_recorder(RuntimeOrigin::signed(who), Some(who)),
                sp_runtime::DispatchError::BadOrigin
            );
        }
        assert_ok!(Deliverables::set_recorder(RuntimeOrigin::root(), Some(OUTSIDER)));
        assert_eq!(Deliverables::recorder(), Some(OUTSIDER));
        System::assert_last_event(Event::RecorderSet { recorder: Some(OUTSIDER) }.into());
    });
}

#[test]
fn new_recorder_takes_over() {
    new_test_ext().execute_with(|| {
        let milestone_id = pending_milestone();
        assert_ok!(Deliverables::set_recorder(RuntimeOrigin::root(), Some(OUTSIDER)));
        assert_noop!(
            Deliverables::record_validation_result(RuntimeOrigin::signed(ORACLE), milestone_id, true),
            Error::<Test>::NotRecorder
        );
        assert_ok!(Deliverables::record_validation_result(
            RuntimeOrigin::signed(OUTSIDER),
            milestone_id,
            true,
        ));
    });
}
