use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::pallet_prelude::*;
use scale_info::TypeInfo;
use sp_std::vec::Vec;

/// What kind of artifact a `WeightCommitment` refers to. Open-ended;
/// new variants can land in follow-up runtime upgrades since
/// SCALE-encoded enums are forward-compatible when consumers ignore
/// unknown variants. For v0.1 we cover the cases we actually run
/// today on Paraxiom infra:
///
/// - `BaseModel` — a from-scratch pretrained model (Mistral-7B,
///   Qwen-7B, etc., or any in-house base).
/// - `FineTune` — a derived model whose parent must point at an
///   existing on-chain commitment. The parent link is what makes
///   provenance enforceable instead of advisory.
/// - `Adapter` — a LoRA / IA³ / prompt-tuning artifact riding on
///   top of a parent model. Same parent-link discipline as
///   `FineTune`.
/// - `Distilled` — a student model derived from a teacher.
///   `parent_model` references the teacher.
#[derive(Clone, Encode, Decode, DecodeWithMemTracking, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen, Default)]
pub enum ArtifactKind {
    #[default]
    BaseModel,
    FineTune,
    Adapter,
    Distilled,
}

/// A commitment to a set of LLM weights. The chain records *what*
/// exists, *what it descends from*, and *who attested it*. Weights
/// themselves live off-chain (IPFS), since they're public artifacts
/// — the security property here is provenance, not secrecy.
///
/// Mirrors identity-architecture treatise §11.5 (substrate
/// attestation). Field semantics:
///
/// - `attester_identity` — `pallet_identity_registry` id that
///   attested this commitment. Lets `pallet_axiom_attestation` and
///   downstream auditors trace weights back to a named identity.
/// - `kind` — see `ArtifactKind`. The parent-link discipline is
///   enforced by extrinsic-level checks, not the type system.
/// - `weights_hash` — Blake2-256 of the canonical serialized weight
///   tensor manifest. Whatever format the team commits to has to
///   commit to the same canonicalization that produced this hash.
/// - `parent_model` — the model id this artifact derives from.
///   Required for `FineTune`, `Adapter`, `Distilled`; forbidden for
///   `BaseModel` (a base model has no parent by definition).
/// - `ipfs_cid` — IPFS CID of the artifact manifest (which itself
///   points at weights + training config + dataset hashes).
/// - `training_attestation_id` — optional pointer to a
///   `pallet_axiom_attestation` row that captured the training run.
///   Lets a verifier chase: weights → training run → agent task →
///   audit chain.
/// - `created_at` — block of the `commit_weights` extrinsic.
/// - `revoked_at` — block of the `revoke` extrinsic. Once set, the
///   commitment is considered withdrawn; later supersession or
///   re-attestation needs a new model id.
#[derive(Clone, Encode, Decode, DecodeWithMemTracking, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
pub struct WeightCommitment<BlockNumber> {
    pub attester_identity: u64,
    pub kind: ArtifactKind,
    pub weights_hash: [u8; 32],
    pub parent_model: Option<u64>,
    pub ipfs_cid: BoundedVec<u8, ConstU32<128>>,
    pub training_attestation_id: Option<u64>,
    pub created_at: BlockNumber,
    pub revoked_at: Option<BlockNumber>,
}

impl<BlockNumber: Copy> WeightCommitment<BlockNumber> {
    /// A commitment is `Active` until revoked; supersession is
    /// handled by registering a new commitment with this one as the
    /// parent. Used by `revoke` and `attest_use` to reject
    /// operations on already-withdrawn artifacts.
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }
}

/// Helper used by extrinsic-arg checkers; keeps the caller-facing
/// API as raw `Vec<u8>` while storage stays bounded.
pub fn bound_cid(
    s: Vec<u8>,
) -> Result<BoundedVec<u8, ConstU32<128>>, ()> {
    BoundedVec::try_from(s).map_err(|_| ())
}
