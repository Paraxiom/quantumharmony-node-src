//! Tests for `pallet-reputation-tokens`. Cover issuer registration,
//! credit/debit/decay paths, every error path, and the
//! AxisTotal-stays-in-sync invariant.

use crate::mock::*;
use crate::{
    types::{Axis, DecayParams},
    AxisTotal, Decay, Issuer, LastDecayAt, Score,
};
use frame_support::{assert_noop, assert_ok};

const ALICE: AccountId = 1;     // sudo target / random caller
const ISSUER_AXIOM: AccountId = 100;
const ISSUER_REVIEW: AccountId = 101;
const NOT_ISSUER: AccountId = 999;

const ID_A: u64 = 7;
const ID_B: u64 = 8;

fn root() -> RuntimeOrigin {
    RuntimeOrigin::root()
}

fn signed(who: AccountId) -> RuntimeOrigin {
    RuntimeOrigin::signed(who)
}

// ── set_issuer ─────────────────────────────────────────────────────────────

#[test]
fn set_issuer_stores_and_emits() {
    new_test_ext().execute_with(|| {
        assert!(Issuer::<Test>::get(Axis::AxiomTask).is_none());
        assert_ok!(ReputationTokens::set_issuer(root(), Axis::AxiomTask, ISSUER_AXIOM));
        assert_eq!(Issuer::<Test>::get(Axis::AxiomTask), Some(ISSUER_AXIOM));
        System::assert_has_event(crate::Event::IssuerSet {
            axis: Axis::AxiomTask,
            who: ISSUER_AXIOM,
        }.into());
    });
}

#[test]
fn set_issuer_replaces_previous() {
    new_test_ext().execute_with(|| {
        assert_ok!(ReputationTokens::set_issuer(root(), Axis::AxiomTask, ISSUER_AXIOM));
        assert_ok!(ReputationTokens::set_issuer(root(), Axis::AxiomTask, ISSUER_REVIEW));
        assert_eq!(Issuer::<Test>::get(Axis::AxiomTask), Some(ISSUER_REVIEW));
    });
}

#[test]
fn set_issuer_requires_root() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            ReputationTokens::set_issuer(signed(ALICE), Axis::AxiomTask, ISSUER_AXIOM),
            sp_runtime::DispatchError::BadOrigin,
        );
    });
}

// ── credit ─────────────────────────────────────────────────────────────────

#[test]
fn credit_fails_when_axis_dormant() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            ReputationTokens::credit(signed(ISSUER_AXIOM), ID_A, Axis::AxiomTask, 10),
            crate::Error::<Test>::AxisDormant,
        );
    });
}

#[test]
fn credit_fails_when_not_issuer() {
    new_test_ext().execute_with(|| {
        assert_ok!(ReputationTokens::set_issuer(root(), Axis::AxiomTask, ISSUER_AXIOM));
        assert_noop!(
            ReputationTokens::credit(signed(NOT_ISSUER), ID_A, Axis::AxiomTask, 10),
            crate::Error::<Test>::NotIssuer,
        );
    });
}

#[test]
fn credit_stores_score_and_updates_axis_total() {
    new_test_ext().execute_with(|| {
        assert_ok!(ReputationTokens::set_issuer(root(), Axis::AxiomTask, ISSUER_AXIOM));
        assert_ok!(ReputationTokens::credit(
            signed(ISSUER_AXIOM), ID_A, Axis::AxiomTask, 10,
        ));
        assert_eq!(Score::<Test>::get(ID_A, Axis::AxiomTask), 10);
        assert_eq!(AxisTotal::<Test>::get(Axis::AxiomTask), 10);

        assert_ok!(ReputationTokens::credit(
            signed(ISSUER_AXIOM), ID_A, Axis::AxiomTask, 5,
        ));
        assert_eq!(Score::<Test>::get(ID_A, Axis::AxiomTask), 15);
        assert_eq!(AxisTotal::<Test>::get(Axis::AxiomTask), 15);

        System::assert_has_event(crate::Event::Credited {
            id: ID_A,
            axis: Axis::AxiomTask,
            amount: 5,
            new_total: 15,
        }.into());
    });
}

#[test]
fn credit_overflow_is_a_hard_error() {
    new_test_ext().execute_with(|| {
        assert_ok!(ReputationTokens::set_issuer(root(), Axis::AxiomTask, ISSUER_AXIOM));
        assert_ok!(ReputationTokens::credit(
            signed(ISSUER_AXIOM), ID_A, Axis::AxiomTask, u64::MAX,
        ));
        assert_noop!(
            ReputationTokens::credit(signed(ISSUER_AXIOM), ID_A, Axis::AxiomTask, 1),
            crate::Error::<Test>::Overflow,
        );
        assert_eq!(Score::<Test>::get(ID_A, Axis::AxiomTask), u64::MAX);
    });
}

// ── debit ──────────────────────────────────────────────────────────────────

#[test]
fn debit_saturates_at_zero_and_updates_axis_total() {
    new_test_ext().execute_with(|| {
        assert_ok!(ReputationTokens::set_issuer(root(), Axis::AxiomTask, ISSUER_AXIOM));
        assert_ok!(ReputationTokens::credit(
            signed(ISSUER_AXIOM), ID_A, Axis::AxiomTask, 12,
        ));
        // Debit larger than current — saturates to zero.
        assert_ok!(ReputationTokens::debit(
            signed(ISSUER_AXIOM), ID_A, Axis::AxiomTask, 100,
        ));
        assert_eq!(Score::<Test>::get(ID_A, Axis::AxiomTask), 0);
        assert_eq!(AxisTotal::<Test>::get(Axis::AxiomTask), 0);
        System::assert_has_event(crate::Event::Debited {
            id: ID_A,
            axis: Axis::AxiomTask,
            amount: 100,
            new_total: 0,
        }.into());
    });
}

#[test]
fn debit_fails_when_not_issuer() {
    new_test_ext().execute_with(|| {
        assert_ok!(ReputationTokens::set_issuer(root(), Axis::AxiomTask, ISSUER_AXIOM));
        assert_noop!(
            ReputationTokens::debit(signed(NOT_ISSUER), ID_A, Axis::AxiomTask, 1),
            crate::Error::<Test>::NotIssuer,
        );
    });
}

// ── decay_step ─────────────────────────────────────────────────────────────

#[test]
fn decay_step_skips_min_score_slots() {
    new_test_ext().execute_with(|| {
        assert_ok!(ReputationTokens::set_decay_params(
            root(),
            DecayParams { half_life_blocks: 100, decay_per_step_ppm: 100_000, min_score: 50 },
        ));
        assert_ok!(ReputationTokens::set_issuer(root(), Axis::AxiomTask, ISSUER_AXIOM));
        // Below the floor — should be left alone.
        assert_ok!(ReputationTokens::credit(signed(ISSUER_AXIOM), ID_A, Axis::AxiomTask, 30));
        // Above the floor — should be decayed by 10%.
        assert_ok!(ReputationTokens::credit(signed(ISSUER_AXIOM), ID_B, Axis::AxiomTask, 1_000));

        System::set_block_number(20);
        assert_ok!(ReputationTokens::decay_step(signed(ALICE)));

        assert_eq!(Score::<Test>::get(ID_A, Axis::AxiomTask), 30, "below min_score: untouched");
        assert_eq!(Score::<Test>::get(ID_B, Axis::AxiomTask), 900, "above min_score: -10%");
        // AxisTotal reflects only the burn for ID_B.
        assert_eq!(AxisTotal::<Test>::get(Axis::AxiomTask), 30 + 900);
    });
}

#[test]
fn decay_step_enforces_cooldown() {
    new_test_ext().execute_with(|| {
        assert_ok!(ReputationTokens::set_decay_params(
            root(),
            DecayParams { half_life_blocks: 100, decay_per_step_ppm: 50_000, min_score: 0 },
        ));
        assert_ok!(ReputationTokens::set_issuer(root(), Axis::AxiomTask, ISSUER_AXIOM));
        assert_ok!(ReputationTokens::credit(signed(ISSUER_AXIOM), ID_A, Axis::AxiomTask, 1_000));

        System::set_block_number(10);
        assert_ok!(ReputationTokens::decay_step(signed(ALICE)));

        // Cooldown is 5 blocks — second call too soon should fail.
        System::set_block_number(12);
        assert_noop!(
            ReputationTokens::decay_step(signed(ALICE)),
            crate::Error::<Test>::DecayCooldown,
        );

        // After cooldown — succeeds again.
        System::set_block_number(20);
        assert_ok!(ReputationTokens::decay_step(signed(ALICE)));
    });
}

#[test]
fn decay_step_with_zero_ppm_is_a_noop_but_resets_lastdecay() {
    new_test_ext().execute_with(|| {
        assert_ok!(ReputationTokens::set_decay_params(
            root(),
            DecayParams { half_life_blocks: 0, decay_per_step_ppm: 0, min_score: 0 },
        ));
        assert_ok!(ReputationTokens::set_issuer(root(), Axis::AxiomTask, ISSUER_AXIOM));
        assert_ok!(ReputationTokens::credit(signed(ISSUER_AXIOM), ID_A, Axis::AxiomTask, 500));

        System::set_block_number(10);
        assert_ok!(ReputationTokens::decay_step(signed(ALICE)));
        assert_eq!(Score::<Test>::get(ID_A, Axis::AxiomTask), 500, "ppm=0 → unchanged");
        assert_eq!(LastDecayAt::<Test>::get(), Some(10));
    });
}

#[test]
fn set_decay_params_requires_root() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            ReputationTokens::set_decay_params(
                signed(ALICE),
                DecayParams { half_life_blocks: 1, decay_per_step_ppm: 1, min_score: 0 },
            ),
            sp_runtime::DispatchError::BadOrigin,
        );
    });
}

#[test]
fn cross_axis_isolation() {
    // Crediting on AxiomTask must not touch PrCodeReview totals.
    new_test_ext().execute_with(|| {
        assert_ok!(ReputationTokens::set_issuer(root(), Axis::AxiomTask, ISSUER_AXIOM));
        assert_ok!(ReputationTokens::set_issuer(root(), Axis::PrCodeReview, ISSUER_REVIEW));

        assert_ok!(ReputationTokens::credit(signed(ISSUER_AXIOM), ID_A, Axis::AxiomTask, 100));
        assert_ok!(ReputationTokens::credit(signed(ISSUER_REVIEW), ID_A, Axis::PrCodeReview, 5));

        assert_eq!(AxisTotal::<Test>::get(Axis::AxiomTask), 100);
        assert_eq!(AxisTotal::<Test>::get(Axis::PrCodeReview), 5);
        assert_eq!(AxisTotal::<Test>::get(Axis::QuestionGen), 0);

        // The AxiomTask issuer can't touch the PrCodeReview axis.
        assert_noop!(
            ReputationTokens::credit(signed(ISSUER_AXIOM), ID_A, Axis::PrCodeReview, 1),
            crate::Error::<Test>::NotIssuer,
        );
    });
}
