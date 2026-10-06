use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::pallet_prelude::*;
use scale_info::TypeInfo;

#[derive(Clone, Encode, Decode, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
pub struct CommitInfo<AccountId, BlockNumber, Balance> {
    pub committer: AccountId,
    pub block: BlockNumber,
    pub bond: Balance,
    pub revealed: bool,
}

#[derive(Clone, Encode, Decode, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
pub enum ChallengeKind {
    DuplicatePubkey,
    StaleCommit,
}

/// What an outstanding commit is for. The pallet started life as a
/// validator-onboarding primitive (#33 fallout); this enum lifts it
/// into a general-purpose commit-reveal substrate that other
/// pallets — gov-app event subscriber (#34 item 7), credential
/// issuance flows, future identity-rotation paths — can reuse
/// without duplicating the dispute-window + bond machinery.
///
/// Defaults to `Validator` so that any `CommitKind` storage entry
/// missing for a pre-v43 `Commits` row decodes as the original
/// validator-onboarding shape — keeps the on-chain layout
/// backwards-compatible without a storage migration.
#[derive(Clone, Copy, Encode, Decode, DecodeWithMemTracking, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen, Default)]
pub enum OnboardingKind {
    /// Validator onboarding (legacy default). Reveal MUST go through
    /// `reveal()` and bind an aura pubkey to an account via the
    /// `ValidatorMutator` hook.
    #[default]
    Validator,
    /// Generic commit-reveal. Reveal goes through `reveal_generic()`,
    /// which performs the hash check, releases the bond, and emits
    /// a `GenericRevealed` event without calling any on-chain mutator.
    /// Downstream pallets (gov-app, identity rotation, …) subscribe
    /// to the event and act on it themselves.
    Generic,
}
