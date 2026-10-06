use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::pallet_prelude::*;
use scale_info::TypeInfo;

/// What a validator is being accused of. Open enum so future
/// misbehavior categories (DA-unavailability, light-client-bridge
/// equivocation, …) can land without breaking the existing on-chain
/// layout, since SCALE-encoded enums are forward-compatible when
/// consumers ignore unknown variants.
///
/// v0.1 covers the two categories the BGFL justice architecture
/// explicitly enumerates as on-chain provable:
///
/// - `PocDivergence`: the validator's Proof-of-Coherence reading
///   stayed outside the gadget's tolerance band past the recovery
///   window. Reporter supplies the block height the divergence was
///   observed at; the gadget's local trace + the on-chain header at
///   that height is the off-chain audit trail.
/// - `AuraEquivocation`: classic double-sign. Two distinct headers
///   signed by the same Aura authority at the same slot. v0.1
///   records only the evidence hash; an on-chain verifier that
///   decodes both headers and re-checks the signatures is v0.2 work.
#[derive(Clone, Copy, Encode, Decode, DecodeWithMemTracking, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
pub enum MisbehaviorKind {
    PocDivergence { observed_at: u32 },
    AuraEquivocation,
}

/// A pending misbehavior report awaiting governance confirmation.
/// Holds enough to (a) identify the accusation, (b) refund the
/// reporter's gas-only contribution if it was honest, (c) credit the
/// slash to the right target if confirmed.
///
/// `evidence_hash` is the off-chain audit anchor: a blake2_256 of the
/// canonical evidence bundle the reporter constructed. It is NOT
/// re-verified on chain in v0.1 — the chain trusts the governance
/// `ConvictionOrigin` to have looked at the off-chain bundle before
/// confirming. v0.2 work introduces on-chain verifiers for each
/// `MisbehaviorKind`.
#[derive(Clone, Encode, Decode, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
pub struct ConvictionRecord<AccountId, BlockNumber> {
    pub target: AccountId,
    pub reporter: AccountId,
    pub kind: MisbehaviorKind,
    pub evidence_hash: [u8; 32],
    pub reported_at: BlockNumber,
}
