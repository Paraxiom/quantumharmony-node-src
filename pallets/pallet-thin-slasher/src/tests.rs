//! Tests for `pallet-thin-slasher`. Cover all five extrinsics, every
//! error path, the deposit-locked-while-pending invariant, and slash
//! amount arithmetic.

use crate::mock::*;
use crate::{
    types::MisbehaviorKind,
    Deposits, NextConvictionId, PendingByTarget, PendingConvictions,
};
use frame_support::{assert_noop, assert_ok};

const ALICE: AccountId = 1;
const BOB: AccountId = 2;
const CHARLIE: AccountId = 3;
const GOV: AccountId = 99;

fn signed(who: AccountId) -> RuntimeOrigin {
    RuntimeOrigin::signed(who)
}

// ── post_deposit ────────────────────────────────────────────────────────────

#[test]
fn post_deposit_initial_reserves_funds_and_records_total() {
    new_test_ext().execute_with(|| {
        assert_eq!(Deposits::<Test>::get(ALICE), None);
        assert_eq!(Balances::reserved_balance(ALICE), 0);

        assert_ok!(ThinSlasher::post_deposit(signed(ALICE), 2_000));

        assert_eq!(Deposits::<Test>::get(ALICE), Some(2_000));
        assert_eq!(Balances::reserved_balance(ALICE), 2_000);
        assert_eq!(Balances::free_balance(ALICE), 8_000);
        System::assert_has_event(crate::Event::DepositPosted {
            who: ALICE,
            amount: 2_000,
            total: 2_000,
        }.into());
    });
}

#[test]
fn post_deposit_initial_below_minimum_fails() {
    new_test_ext().execute_with(|| {
        // CHARLIE only has 500; MinimumDeposit = 1_000.
        assert_noop!(
            ThinSlasher::post_deposit(signed(CHARLIE), 500),
            crate::Error::<Test>::DepositTooSmall,
        );
        assert_eq!(Balances::reserved_balance(CHARLIE), 0);
    });
}

#[test]
fn post_deposit_topup_has_no_minimum() {
    new_test_ext().execute_with(|| {
        assert_ok!(ThinSlasher::post_deposit(signed(ALICE), 1_000));
        // Top-up of 1 is fine even though MinimumDeposit = 1_000.
        assert_ok!(ThinSlasher::post_deposit(signed(ALICE), 1));
        assert_eq!(Deposits::<Test>::get(ALICE), Some(1_001));
    });
}

#[test]
fn post_deposit_reserve_failure_returns_error() {
    new_test_ext().execute_with(|| {
        // CHARLIE has 500, MinimumDeposit = 1_000 — fails the
        // minimum check before reserve is attempted, so this path
        // hits when someone with > min tries to over-reserve. Use
        // ALICE asking for 20_000 (she only has 10_000).
        assert_noop!(
            ThinSlasher::post_deposit(signed(ALICE), 20_000),
            crate::Error::<Test>::ReserveFailed,
        );
    });
}

// ── withdraw_deposit ────────────────────────────────────────────────────────

#[test]
fn withdraw_deposit_clears_record_and_unreserves_funds() {
    new_test_ext().execute_with(|| {
        assert_ok!(ThinSlasher::post_deposit(signed(ALICE), 2_000));
        assert_ok!(ThinSlasher::withdraw_deposit(signed(ALICE)));
        assert_eq!(Deposits::<Test>::get(ALICE), None);
        assert_eq!(Balances::reserved_balance(ALICE), 0);
        assert_eq!(Balances::free_balance(ALICE), 10_000);
    });
}

#[test]
fn withdraw_deposit_fails_without_record() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            ThinSlasher::withdraw_deposit(signed(ALICE)),
            crate::Error::<Test>::NoDeposit,
        );
    });
}

#[test]
fn withdraw_deposit_locked_while_pending_conviction() {
    new_test_ext().execute_with(|| {
        assert_ok!(ThinSlasher::post_deposit(signed(ALICE), 2_000));
        assert_ok!(ThinSlasher::report(
            signed(BOB),
            ALICE,
            MisbehaviorKind::AuraEquivocation,
            [9u8; 32],
        ));
        assert_noop!(
            ThinSlasher::withdraw_deposit(signed(ALICE)),
            crate::Error::<Test>::DepositLocked,
        );
    });
}

// ── report ─────────────────────────────────────────────────────────────────

#[test]
fn report_enqueues_record_and_increments_counter() {
    new_test_ext().execute_with(|| {
        assert_eq!(NextConvictionId::<Test>::get(), 0);
        assert_ok!(ThinSlasher::report(
            signed(BOB),
            ALICE,
            MisbehaviorKind::PocDivergence { observed_at: 500_000 },
            [1u8; 32],
        ));
        assert_eq!(NextConvictionId::<Test>::get(), 1);
        let record = PendingConvictions::<Test>::get(0).expect("queued");
        assert_eq!(record.target, ALICE);
        assert_eq!(record.reporter, BOB);
        assert_eq!(record.evidence_hash, [1u8; 32]);
        assert_eq!(PendingByTarget::<Test>::get(ALICE), 1);
    });
}

#[test]
fn report_open_to_any_signed_origin() {
    new_test_ext().execute_with(|| {
        // CHARLIE has only 500 — still allowed to file a report
        // (governance reviews; spam economics handled by tx fees).
        assert_ok!(ThinSlasher::report(
            signed(CHARLIE),
            ALICE,
            MisbehaviorKind::AuraEquivocation,
            [2u8; 32],
        ));
        assert_eq!(PendingByTarget::<Test>::get(ALICE), 1);
    });
}

// ── confirm ────────────────────────────────────────────────────────────────

#[test]
fn confirm_slashes_correct_fraction() {
    new_test_ext().execute_with(|| {
        assert_ok!(ThinSlasher::post_deposit(signed(ALICE), 2_000));
        assert_ok!(ThinSlasher::report(
            signed(BOB),
            ALICE,
            MisbehaviorKind::AuraEquivocation,
            [3u8; 32],
        ));
        assert_ok!(ThinSlasher::confirm(signed(GOV), 0));
        // SlashFraction = 50% of 2_000 = 1_000.
        assert_eq!(Deposits::<Test>::get(ALICE), Some(1_000));
        assert_eq!(Balances::reserved_balance(ALICE), 1_000);
        // Free balance untouched (slash burns reserved).
        assert_eq!(Balances::free_balance(ALICE), 8_000);
        assert_eq!(PendingByTarget::<Test>::get(ALICE), 0);
        assert!(PendingConvictions::<Test>::get(0).is_none());
        System::assert_has_event(crate::Event::Convicted {
            conviction_id: 0,
            target: ALICE,
            slashed: 1_000,
        }.into());
    });
}

#[test]
fn confirm_with_no_deposit_records_zero_slash() {
    new_test_ext().execute_with(|| {
        // Report against ALICE without a deposit on record.
        assert_ok!(ThinSlasher::report(
            signed(BOB),
            ALICE,
            MisbehaviorKind::AuraEquivocation,
            [4u8; 32],
        ));
        assert_ok!(ThinSlasher::confirm(signed(GOV), 0));
        System::assert_has_event(crate::Event::Convicted {
            conviction_id: 0,
            target: ALICE,
            slashed: 0,
        }.into());
    });
}

#[test]
fn confirm_rejects_non_governance_origin() {
    new_test_ext().execute_with(|| {
        assert_ok!(ThinSlasher::post_deposit(signed(ALICE), 2_000));
        assert_ok!(ThinSlasher::report(
            signed(BOB),
            ALICE,
            MisbehaviorKind::AuraEquivocation,
            [5u8; 32],
        ));
        assert_noop!(
            ThinSlasher::confirm(signed(BOB), 0),
            sp_runtime::DispatchError::BadOrigin,
        );
    });
}

#[test]
fn confirm_unknown_conviction_fails() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            ThinSlasher::confirm(signed(GOV), 999),
            crate::Error::<Test>::UnknownConviction,
        );
    });
}

// ── dismiss ────────────────────────────────────────────────────────────────

#[test]
fn dismiss_drops_record_without_slashing() {
    new_test_ext().execute_with(|| {
        assert_ok!(ThinSlasher::post_deposit(signed(ALICE), 2_000));
        assert_ok!(ThinSlasher::report(
            signed(BOB),
            ALICE,
            MisbehaviorKind::AuraEquivocation,
            [6u8; 32],
        ));
        assert_ok!(ThinSlasher::dismiss(signed(GOV), 0));
        assert_eq!(Deposits::<Test>::get(ALICE), Some(2_000));
        assert_eq!(Balances::reserved_balance(ALICE), 2_000);
        assert_eq!(PendingByTarget::<Test>::get(ALICE), 0);
        assert!(PendingConvictions::<Test>::get(0).is_none());
        // After dismissal the validator can withdraw freely.
        assert_ok!(ThinSlasher::withdraw_deposit(signed(ALICE)));
    });
}

#[test]
fn dismiss_rejects_non_governance_origin() {
    new_test_ext().execute_with(|| {
        assert_ok!(ThinSlasher::report(
            signed(BOB),
            ALICE,
            MisbehaviorKind::AuraEquivocation,
            [7u8; 32],
        ));
        assert_noop!(
            ThinSlasher::dismiss(signed(BOB), 0),
            sp_runtime::DispatchError::BadOrigin,
        );
    });
}

// ── multi-conviction interaction ───────────────────────────────────────────

#[test]
fn two_pending_blocks_withdrawal_until_both_resolved() {
    new_test_ext().execute_with(|| {
        assert_ok!(ThinSlasher::post_deposit(signed(ALICE), 2_000));
        assert_ok!(ThinSlasher::report(
            signed(BOB),
            ALICE,
            MisbehaviorKind::AuraEquivocation,
            [8u8; 32],
        ));
        assert_ok!(ThinSlasher::report(
            signed(BOB),
            ALICE,
            MisbehaviorKind::PocDivergence { observed_at: 600_000 },
            [9u8; 32],
        ));
        assert_eq!(PendingByTarget::<Test>::get(ALICE), 2);
        assert_noop!(
            ThinSlasher::withdraw_deposit(signed(ALICE)),
            crate::Error::<Test>::DepositLocked,
        );
        // Resolve one — still blocked.
        assert_ok!(ThinSlasher::dismiss(signed(GOV), 0));
        assert_eq!(PendingByTarget::<Test>::get(ALICE), 1);
        assert_noop!(
            ThinSlasher::withdraw_deposit(signed(ALICE)),
            crate::Error::<Test>::DepositLocked,
        );
        // Resolve the second — now free.
        assert_ok!(ThinSlasher::confirm(signed(GOV), 1));
        assert_ok!(ThinSlasher::withdraw_deposit(signed(ALICE)));
    });
}
