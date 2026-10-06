//! Tests for pallet-coherence-attestation.

use crate::mock::*;
use crate::pallet::{
    AttestationInput, CoherenceStake, Counterparties, Event, LastNonce, Outcome, RejectReason,
    RoundAttestations, Slashes, Tier,
};
use crate::Error;
use frame_support::{assert_noop, assert_ok};

const V0: u64 = 10;
const V1: u64 = 11;

fn input(round: u64, nonce: u64, l: u64, s_milli: u32, qber_ppm: u32) -> AttestationInput<u64> {
    AttestationInput {
        counterparty: Some(V1),
        round,
        nonce,
        l_block: l,
        s_milli,
        qber_ppm,
        eps_log2_neg: 30,
        tier: Tier::TrustedDevice,
        commitment: [7u8; 32],
        loophole_cert: false,
    }
}

fn set_round(r: u64) {
    assert_ok!(CoherenceAttestation::force_advance_round(
        RuntimeOrigin::root(),
        r
    ));
}

#[test]
fn honest_attestation_admitted_and_staked() {
    new_test_ext().execute_with(|| {
        set_round(5);
        assert_ok!(CoherenceAttestation::submit_attestation(
            RuntimeOrigin::signed(V0),
            input(5, 1, 180_000, 2750, 11_000),
        ));
        assert_eq!(CoherenceStake::<Test>::get(V0), 180_000);
        assert_eq!(LastNonce::<Test>::get(V0), 1);
        assert!(Counterparties::<Test>::get(V0).contains(&V1));
        System::assert_last_event(
            Event::AttestationAdmitted {
                validator: V0,
                counterparty: Some(V1),
                round: 5,
                weight: 180_000,
            }
            .into(),
        );
        let stored = RoundAttestations::<Test>::get(5, V0).unwrap();
        assert_eq!(stored.outcome, Outcome::Admitted);
    });
}

#[test]
fn forger_is_slashed() {
    new_test_ext().execute_with(|| {
        set_round(5);
        // Positive key with S <= 2: no Bell witness.
        assert_ok!(CoherenceAttestation::submit_attestation(
            RuntimeOrigin::signed(V0),
            input(5, 1, 50_000, 1900, 0),
        ));
        assert_eq!(Slashes::<Test>::get(V0), 1);
        assert_eq!(CoherenceStake::<Test>::get(V0), 0);
        System::assert_last_event(Event::ValidatorSlashed { validator: V0, round: 5 }.into());
    });
}

#[test]
fn replayed_nonce_rejected() {
    new_test_ext().execute_with(|| {
        set_round(5);
        assert_ok!(CoherenceAttestation::submit_attestation(
            RuntimeOrigin::signed(V0),
            input(5, 2, 180_000, 2750, 11_000),
        ));
        assert_noop!(
            CoherenceAttestation::submit_attestation(
                RuntimeOrigin::signed(V0),
                input(5, 2, 180_000, 2750, 11_000),
            ),
            Error::<Test>::ReplayedNonce
        );
    });
}

#[test]
fn stale_round_rejected() {
    new_test_ext().execute_with(|| {
        set_round(20);
        // round 5 is more than RoundWindow (8) behind 20.
        assert_noop!(
            CoherenceAttestation::submit_attestation(
                RuntimeOrigin::signed(V0),
                input(5, 1, 180_000, 2750, 11_000),
            ),
            Error::<Test>::StaleRound
        );
    });
}

#[test]
fn high_qber_rejected_without_penalty() {
    new_test_ext().execute_with(|| {
        set_round(5);
        assert_ok!(CoherenceAttestation::submit_attestation(
            RuntimeOrigin::signed(V0),
            input(5, 1, 0, 2750, 120_000), // 12% QBER, no key
        ));
        assert_eq!(CoherenceStake::<Test>::get(V0), 0);
        assert_eq!(Slashes::<Test>::get(V0), 0);
        // S>2 so the first rejection reason hit is the high QBER... but l=0 here,
        // and qber check precedes the no-key check, so QberTooHigh is recorded.
        let stored = RoundAttestations::<Test>::get(5, V0).unwrap();
        assert_eq!(stored.outcome, Outcome::Rejected(RejectReason::QberTooHigh));
    });
}

#[test]
fn device_independent_tier_requires_certificate() {
    new_test_ext().execute_with(|| {
        set_round(5);
        let mut di = input(5, 1, 180_000, 2750, 11_000);
        di.tier = Tier::DeviceIndependent;
        di.loophole_cert = false;
        assert_ok!(CoherenceAttestation::submit_attestation(
            RuntimeOrigin::signed(V0),
            di.clone(),
        ));
        let stored = RoundAttestations::<Test>::get(5, V0).unwrap();
        assert_eq!(stored.outcome, Outcome::Rejected(RejectReason::UnearnedTier));

        // With the certificate, the same attestation is admitted.
        let mut ok = di;
        ok.nonce = 2;
        ok.loophole_cert = true;
        assert_ok!(CoherenceAttestation::submit_attestation(
            RuntimeOrigin::signed(V0),
            ok,
        ));
        assert_eq!(CoherenceStake::<Test>::get(V0), 180_000);
    });
}
