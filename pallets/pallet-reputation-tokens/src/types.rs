use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::pallet_prelude::*;
use scale_info::TypeInfo;

/// Per-axis identity reputation. Each axis tracks a distinct kind of
/// verifier event — keep them separate so a noisy automated axis
/// (e.g. `AxiomTask`) can't drown out a slow-moving human-judged
/// axis (e.g. `PrCodeReview`).
///
/// The axis set deliberately mirrors `pallet_axiom_attestation`'s
/// `VerifierKind`, but we don't import that enum across pallets:
/// reputation-tokens needs to stay usable without axiom-attestation,
/// and the SCALE-encoded discriminants line up by position when the
/// gov-app subscriber (#34 item 7) translates between the two.
#[derive(Clone, Copy, Encode, Decode, DecodeWithMemTracking, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen, Default)]
pub enum Axis {
    #[default]
    AxiomTask,
    QuestionGen,
    PrCodeReview,
    VaultCommitment,
    PersonaAttestation,
}

impl Axis {
    /// Stable iteration order over all axes. Used by `decay_step` to
    /// sweep without depending on `strum` or similar crates.
    pub const ALL: [Axis; 5] = [
        Axis::AxiomTask,
        Axis::QuestionGen,
        Axis::PrCodeReview,
        Axis::VaultCommitment,
        Axis::PersonaAttestation,
    ];
}

/// Decay parameters. Stored as a single `StorageValue` so a sudo can
/// change them via one extrinsic without per-axis bookkeeping.
///
/// `half_life_blocks`: number of blocks for any score to halve, when
/// `decay_step` is called. The actual decay is multiplicative on each
/// `decay_step` invocation; the half-life is a documentation
/// reference — the on-chain calculation is `new = old * (1 -
/// decay_per_step_ppm / 1_000_000)`.
///
/// `decay_per_step_ppm`: parts-per-million decay applied each call.
/// Mainnet default tuned so that one daily `decay_step` (~7,200 blocks
/// at 12s) gives a ~30-day half-life.
///
/// `min_score`: scores below this are not decayed (saves storage on
/// rounding-to-zero accounts).
#[derive(Clone, Encode, Decode, DecodeWithMemTracking, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen, Default)]
pub struct DecayParams {
    pub half_life_blocks: u32,
    pub decay_per_step_ppm: u32,
    pub min_score: u64,
}
