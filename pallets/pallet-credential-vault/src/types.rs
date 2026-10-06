use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::pallet_prelude::*;
use scale_info::TypeInfo;
use sp_std::vec::Vec;

/// What a `Commitment` is referring to. Open-ended on purpose — new
/// kinds can land in follow-up runtime upgrades without breaking the
/// on-chain layout, since SCALE-encoded enums are
/// forward-compatible if the consumer ignores unknown variants. For
/// the v0.1 ship, three variants cover the cases that bit us in
/// the 2026-05-28 incident:
///
/// - `Sudo` — the chain's sudo signer, the one that we hunted for
///   in `~/secrets` and finally extracted from the keystore file.
/// - `ValidatorStash` — a validator's stash signer, scoped to the
///   identity it operates under.
/// - `ServiceKey` — anything else operationally needed (issuer
///   keys for the credential vault itself, oracle signing keys,
///   notarial keys, …).
#[derive(Clone, Encode, Decode, DecodeWithMemTracking, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
pub enum CredentialKind {
    Sudo,
    ValidatorStash,
    ServiceKey,
}

/// A commitment to an encrypted credential held off-chain (IPFS in
/// the canonical deployment). The chain records *what* exists and
/// the master-key destruction event (`revoked_at`) that makes a
/// later recovery infeasible; the ciphertext lives outside the
/// chain.
///
/// Mirrors identity-architecture treatise App. B.3. Field semantics:
///
/// - `holder_identity` — `pallet_identity_registry` id this
///   commitment belongs to. The vault never holds credentials that
///   aren't traceable to an on-chain identity.
/// - `service_name` — operator-meaningful tag (`"sudo"`,
///   `"alice-validator"`, `"transparence-issuer"`). Free-form
///   bytes; the chain doesn't interpret it.
/// - `credential_kind` — see `CredentialKind`.
/// - `ciphertext_cid` — IPFS CID (or any other content-addressed
///   identifier; we don't require a specific multicodec at the
///   chain layer).
/// - `ciphertext_hash` — Blake2-256 of the ciphertext bytes. Lets
///   anyone fetching from IPFS verify integrity without trusting
///   the gateway.
/// - `iv_hint` — the symmetric-cipher IV used. 12 bytes is the
///   ChaCha20-Poly1305 / AES-GCM convention; we don't enforce
///   either at the chain layer.
/// - `created_at` — block of the `commit` extrinsic.
/// - `revoked_at` — block of the `revoke` extrinsic (Theorem 11
///   activation: once set, decryption is provably infeasible).
#[derive(Clone, Encode, Decode, DecodeWithMemTracking, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
pub struct Commitment<BlockNumber> {
    pub holder_identity: u64,
    pub service_name: BoundedVec<u8, ConstU32<64>>,
    pub credential_kind: CredentialKind,
    pub ciphertext_cid: BoundedVec<u8, ConstU32<128>>,
    pub ciphertext_hash: [u8; 32],
    pub iv_hint: [u8; 12],
    pub created_at: BlockNumber,
    pub revoked_at: Option<BlockNumber>,
}

impl<BlockNumber: Copy> Commitment<BlockNumber> {
    /// A commitment is `Active` from `commit` until `revoke`. Used by
    /// `attest_use` to reject audit attempts on already-revoked
    /// credentials.
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }
}

/// Helper used by the extrinsic-arg checkers; lets the pallet keep
/// the caller-facing API as raw `Vec<u8>` while the storage type is
/// bounded.
pub fn bound_service_name(
    s: Vec<u8>,
) -> Result<BoundedVec<u8, ConstU32<64>>, ()> {
    BoundedVec::try_from(s).map_err(|_| ())
}

pub fn bound_cid(
    s: Vec<u8>,
) -> Result<BoundedVec<u8, ConstU32<128>>, ()> {
    BoundedVec::try_from(s).map_err(|_| ())
}
