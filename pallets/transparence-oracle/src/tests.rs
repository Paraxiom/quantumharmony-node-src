//! Tests for the Transparence Oracle pallet
//!
//! Comprehensive test coverage for oracle validation submission, rate limiting,
//! score bounds, revocation, milestone completion, and edge cases.

use crate::{mock::*, pallet::*, Error, Event};
use frame_support::{assert_noop, assert_ok, traits::Hooks};

/// Helper: create an evidence hash from a seed
fn evidence_hash(seed: u8) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash[0] = seed;
    hash[31] = seed;
    hash
}

/// Helper: a valid CI commit hash
fn ci_commit() -> Vec<u8> {
    b"abc123def456".to_vec()
}

/// Helper: valid metadata
fn metadata() -> Vec<u8> {
    b"{}".to_vec()
}

/// Helper: submit a passing validation for a specific plugin
fn submit_pass(
    who: u64,
    contract_id: u64,
    milestone_id: u64,
    plugin: ValidationPlugin,
    seed: u8,
) {
    assert_ok!(TransparenceOracle::submit_validation(
        RuntimeOrigin::signed(who),
        contract_id,
        milestone_id,
        plugin,
        evidence_hash(seed),
        ValidationVerdict::Pass,
        90,
        ci_commit(),
        metadata(),
    ));
}

/// Helper: submit all 6 plugin passes for a milestone
fn submit_all_six_passes(who: u64, contract_id: u64, milestone_id: u64) {
    submit_pass(who, contract_id, milestone_id, ValidationPlugin::Endpoint, 10);
    submit_pass(who, contract_id, milestone_id, ValidationPlugin::Coverage, 11);
    submit_pass(who, contract_id, milestone_id, ValidationPlugin::CodeAnalysis, 12);
    submit_pass(who, contract_id, milestone_id, ValidationPlugin::Deploy, 13);
    // Need to reset block counter since MaxValidationsPerBlock = 5
    // Advance block to reset the per-block rate limit counter
    TransparenceOracle::on_initialize(2);
    submit_pass(who, contract_id, milestone_id, ValidationPlugin::Visual, 14);
    submit_pass(who, contract_id, milestone_id, ValidationPlugin::Performance, 15);
}

// ==================== SUBMIT VALIDATION TESTS ====================

#[test]
fn submit_validation_works() {
    new_test_ext().execute_with(|| {
        assert_ok!(TransparenceOracle::submit_validation(
            RuntimeOrigin::signed(ALICE),
            1,  // contract_id
            1,  // milestone_id
            ValidationPlugin::Endpoint,
            evidence_hash(1),
            ValidationVerdict::Pass,
            95,
            ci_commit(),
            metadata(),
        ));

        // Verify validation was stored
        let validation = TransparenceOracle::validations(0).expect("Should exist");
        assert_eq!(validation.id, 0);
        assert_eq!(validation.contract_id, 1);
        assert_eq!(validation.milestone_id, 1);
        assert_eq!(validation.plugin, ValidationPlugin::Endpoint);
        assert_eq!(validation.verdict, ValidationVerdict::Pass);
        assert_eq!(validation.score, 95);
        assert_eq!(validation.validator, ALICE);
        assert_eq!(validation.validated_at, 1);

        // Verify next ID incremented
        assert_eq!(TransparenceOracle::next_validation_id(), 1);

        // Verify contract index
        let contract_validations = TransparenceOracle::validations_by_contract(1);
        assert!(contract_validations.contains(&0));

        // Verify milestone index
        let milestone_validations = TransparenceOracle::validations_by_milestone(1, 1);
        assert!(milestone_validations.contains(&0));

        // Verify event
        System::assert_has_event(Event::ValidationSubmitted {
            validation_id: 0,
            contract_id: 1,
            milestone_id: 1,
            plugin: ValidationPlugin::Endpoint,
            verdict: ValidationVerdict::Pass,
            validator: ALICE,
        }.into());
    });
}

#[test]
fn submit_validation_rate_limit() {
    new_test_ext().execute_with(|| {
        // MaxValidationsPerBlock = 5
        for i in 0u8..5 {
            assert_ok!(TransparenceOracle::submit_validation(
                RuntimeOrigin::signed(ALICE),
                1,
                1,
                ValidationPlugin::Endpoint,
                evidence_hash(i),
                ValidationVerdict::Pass,
                80,
                ci_commit(),
                metadata(),
            ));
        }

        // 6th should fail
        assert_noop!(
            TransparenceOracle::submit_validation(
                RuntimeOrigin::signed(ALICE),
                1,
                1,
                ValidationPlugin::Coverage,
                evidence_hash(99),
                ValidationVerdict::Pass,
                80,
                ci_commit(),
                metadata(),
            ),
            Error::<Test>::RateLimitExceeded
        );
    });
}

#[test]
fn submit_validation_invalid_score() {
    new_test_ext().execute_with(|| {
        // Score > 100 should fail
        assert_noop!(
            TransparenceOracle::submit_validation(
                RuntimeOrigin::signed(ALICE),
                1,
                1,
                ValidationPlugin::Endpoint,
                evidence_hash(1),
                ValidationVerdict::Pass,
                101,
                ci_commit(),
                metadata(),
            ),
            Error::<Test>::InvalidScore
        );

        // Score = 255 should also fail
        assert_noop!(
            TransparenceOracle::submit_validation(
                RuntimeOrigin::signed(ALICE),
                1,
                1,
                ValidationPlugin::Endpoint,
                evidence_hash(2),
                ValidationVerdict::Pass,
                255,
                ci_commit(),
                metadata(),
            ),
            Error::<Test>::InvalidScore
        );

        // Score = 100 is valid (boundary)
        assert_ok!(TransparenceOracle::submit_validation(
            RuntimeOrigin::signed(ALICE),
            1,
            1,
            ValidationPlugin::Endpoint,
            evidence_hash(3),
            ValidationVerdict::Pass,
            100,
            ci_commit(),
            metadata(),
        ));

        // Score = 0 is valid (boundary)
        assert_ok!(TransparenceOracle::submit_validation(
            RuntimeOrigin::signed(ALICE),
            1,
            2,
            ValidationPlugin::Endpoint,
            evidence_hash(4),
            ValidationVerdict::Fail,
            0,
            ci_commit(),
            metadata(),
        ));
    });
}

// ==================== REVOKE VALIDATION TESTS ====================

#[test]
fn revoke_validation_works() {
    new_test_ext().execute_with(|| {
        assert_ok!(TransparenceOracle::submit_validation(
            RuntimeOrigin::signed(ALICE),
            1, 1,
            ValidationPlugin::Endpoint,
            evidence_hash(1),
            ValidationVerdict::Pass,
            90,
            ci_commit(),
            metadata(),
        ));

        assert_ok!(TransparenceOracle::revoke_validation(
            RuntimeOrigin::signed(ALICE),
            0,
        ));

        // Verify verdict changed to Error
        let validation = TransparenceOracle::validations(0).expect("Should exist");
        assert_eq!(validation.verdict, ValidationVerdict::Error);

        // Verify event
        System::assert_has_event(Event::ValidationRevoked {
            validation_id: 0,
            validator: ALICE,
        }.into());
    });
}

#[test]
fn revoke_validation_not_owner() {
    new_test_ext().execute_with(|| {
        assert_ok!(TransparenceOracle::submit_validation(
            RuntimeOrigin::signed(ALICE),
            1, 1,
            ValidationPlugin::Endpoint,
            evidence_hash(1),
            ValidationVerdict::Pass,
            90,
            ci_commit(),
            metadata(),
        ));

        // BOB cannot revoke ALICE's validation
        assert_noop!(
            TransparenceOracle::revoke_validation(
                RuntimeOrigin::signed(BOB),
                0,
            ),
            Error::<Test>::NotValidator
        );
    });
}

#[test]
fn validation_not_found() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            TransparenceOracle::revoke_validation(
                RuntimeOrigin::signed(ALICE),
                999,
            ),
            Error::<Test>::ValidationNotFound
        );
    });
}

// ==================== MILESTONE COMPLETION TESTS ====================

#[test]
fn milestone_completion_auto() {
    new_test_ext().execute_with(|| {
        let contract_id = 1u64;
        let milestone_id = 1u64;

        // Submit all 6 plugin passes
        submit_all_six_passes(ALICE, contract_id, milestone_id);

        // Milestone should now be complete
        assert!(TransparenceOracle::is_milestone_complete(contract_id, milestone_id));
        assert!(TransparenceOracle::milestone_status(contract_id, milestone_id));

        // Verify MilestoneCompleted event was emitted
        System::assert_has_event(Event::MilestoneCompleted {
            contract_id,
            milestone_id,
        }.into());
    });
}

#[test]
fn milestone_partial_no_completion() {
    new_test_ext().execute_with(|| {
        let contract_id = 1u64;
        let milestone_id = 1u64;

        // Submit only 5 of 6 plugins
        submit_pass(ALICE, contract_id, milestone_id, ValidationPlugin::Endpoint, 10);
        submit_pass(ALICE, contract_id, milestone_id, ValidationPlugin::Coverage, 11);
        submit_pass(ALICE, contract_id, milestone_id, ValidationPlugin::CodeAnalysis, 12);
        submit_pass(ALICE, contract_id, milestone_id, ValidationPlugin::Deploy, 13);
        // Reset block counter
        TransparenceOracle::on_initialize(2);
        submit_pass(ALICE, contract_id, milestone_id, ValidationPlugin::Visual, 14);
        // Performance NOT submitted

        // Milestone should NOT be complete
        assert!(!TransparenceOracle::is_milestone_complete(contract_id, milestone_id));
        assert!(!TransparenceOracle::milestone_status(contract_id, milestone_id));
    });
}

#[test]
fn revoke_recomputes_milestone() {
    new_test_ext().execute_with(|| {
        let contract_id = 1u64;
        let milestone_id = 1u64;

        // Complete the milestone
        submit_all_six_passes(ALICE, contract_id, milestone_id);
        assert!(TransparenceOracle::is_milestone_complete(contract_id, milestone_id));

        // Revoke the Endpoint validation (validation_id = 0)
        assert_ok!(TransparenceOracle::revoke_validation(
            RuntimeOrigin::signed(ALICE),
            0,
        ));

        // Milestone should no longer be complete (Endpoint now has Error verdict)
        assert!(!TransparenceOracle::is_milestone_complete(contract_id, milestone_id));
    });
}

#[test]
fn duplicate_plugin_overwrites() {
    new_test_ext().execute_with(|| {
        let contract_id = 1u64;
        let milestone_id = 1u64;

        // Submit a Fail for Endpoint
        assert_ok!(TransparenceOracle::submit_validation(
            RuntimeOrigin::signed(ALICE),
            contract_id,
            milestone_id,
            ValidationPlugin::Endpoint,
            evidence_hash(1),
            ValidationVerdict::Fail,
            30,
            ci_commit(),
            metadata(),
        ));

        // Milestone should not be complete
        assert!(!TransparenceOracle::is_milestone_complete(contract_id, milestone_id));

        // Submit a Pass for Endpoint (second submission)
        assert_ok!(TransparenceOracle::submit_validation(
            RuntimeOrigin::signed(ALICE),
            contract_id,
            milestone_id,
            ValidationPlugin::Endpoint,
            evidence_hash(2),
            ValidationVerdict::Pass,
            95,
            ci_commit(),
            metadata(),
        ));

        // Both validations exist in milestone index
        let milestone_validations = TransparenceOracle::validations_by_milestone(contract_id, milestone_id);
        assert_eq!(milestone_validations.len(), 2);

        // First is Fail, second is Pass — recompute checks for ANY Pass per plugin
        // Still not complete because only Endpoint has a Pass (5 other plugins missing)
        assert!(!TransparenceOracle::is_milestone_complete(contract_id, milestone_id));

        // Now complete the other 5 plugins
        submit_pass(ALICE, contract_id, milestone_id, ValidationPlugin::Coverage, 11);
        submit_pass(ALICE, contract_id, milestone_id, ValidationPlugin::CodeAnalysis, 12);
        // Reset rate limit
        TransparenceOracle::on_initialize(2);
        submit_pass(ALICE, contract_id, milestone_id, ValidationPlugin::Deploy, 13);
        submit_pass(ALICE, contract_id, milestone_id, ValidationPlugin::Visual, 14);
        submit_pass(ALICE, contract_id, milestone_id, ValidationPlugin::Performance, 15);

        // Now milestone should be complete (Endpoint has at least one Pass)
        assert!(TransparenceOracle::is_milestone_complete(contract_id, milestone_id));
    });
}

// ==================== EDGE CASES ====================

#[test]
fn submit_validation_fail_verdict_does_not_complete_milestone() {
    new_test_ext().execute_with(|| {
        // Submit all 6 plugins but with Fail verdict for one
        submit_pass(ALICE, 1, 1, ValidationPlugin::Endpoint, 10);
        submit_pass(ALICE, 1, 1, ValidationPlugin::Coverage, 11);
        submit_pass(ALICE, 1, 1, ValidationPlugin::CodeAnalysis, 12);
        submit_pass(ALICE, 1, 1, ValidationPlugin::Deploy, 13);
        TransparenceOracle::on_initialize(2);
        submit_pass(ALICE, 1, 1, ValidationPlugin::Visual, 14);

        // Performance with Fail verdict
        assert_ok!(TransparenceOracle::submit_validation(
            RuntimeOrigin::signed(ALICE),
            1, 1,
            ValidationPlugin::Performance,
            evidence_hash(15),
            ValidationVerdict::Fail,
            20,
            ci_commit(),
            metadata(),
        ));

        assert!(!TransparenceOracle::is_milestone_complete(1, 1));
    });
}

#[test]
fn rate_limit_resets_on_new_block() {
    new_test_ext().execute_with(|| {
        // Fill up the block
        for i in 0u8..5 {
            assert_ok!(TransparenceOracle::submit_validation(
                RuntimeOrigin::signed(ALICE),
                1, 1,
                ValidationPlugin::Endpoint,
                evidence_hash(i),
                ValidationVerdict::Pass,
                80,
                ci_commit(),
                metadata(),
            ));
        }

        // Should be at limit
        assert_eq!(TransparenceOracle::validations_in_block(), 5);

        // New block resets counter
        TransparenceOracle::on_initialize(2);
        assert_eq!(TransparenceOracle::validations_in_block(), 0);

        // Can submit again
        assert_ok!(TransparenceOracle::submit_validation(
            RuntimeOrigin::signed(ALICE),
            1, 1,
            ValidationPlugin::Endpoint,
            evidence_hash(50),
            ValidationVerdict::Pass,
            80,
            ci_commit(),
            metadata(),
        ));
    });
}

#[test]
fn milestone_already_completed_blocks_further_submissions() {
    new_test_ext().execute_with(|| {
        let contract_id = 1u64;
        let milestone_id = 1u64;

        // Complete the milestone
        submit_all_six_passes(ALICE, contract_id, milestone_id);
        assert!(TransparenceOracle::is_milestone_complete(contract_id, milestone_id));

        // Try to submit another validation for the same milestone
        assert_noop!(
            TransparenceOracle::submit_validation(
                RuntimeOrigin::signed(ALICE),
                contract_id,
                milestone_id,
                ValidationPlugin::Endpoint,
                evidence_hash(99),
                ValidationVerdict::Pass,
                100,
                ci_commit(),
                metadata(),
            ),
            Error::<Test>::MilestoneAlreadyCompleted
        );
    });
}
