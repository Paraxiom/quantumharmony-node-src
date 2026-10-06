//! Storage migrations for the notarial pallet.

use frame_support::{
    pallet_prelude::*,
    traits::{Get, GetStorageVersion, OnRuntimeUpgrade},
    weights::Weight,
};

/// v0 → v1: add the optional `requester_fingerprint` / `requester_signature`
/// fields to every stored `Attestation` (set to `None` for pre-existing rows).
///
/// SCALE-encoded structs are positional, so appending two fields makes the old
/// bytes undecodable without an explicit `translate`. This migration reads each
/// row as the v0 layout and rewrites it in the v1 layout.
pub mod v1 {
    use super::*;
    use crate::{
        Attestation, AttestationStatus, Attestations, Config, DocumentCategory, Pallet,
        MAX_DESCRIPTION_LENGTH,
    };
    use frame_system::pallet_prelude::BlockNumberFor;

    /// Pre-migration (`v0`) layout of `Attestation` — must match the on-chain
    /// encoding byte-for-byte (the 12 fields that existed before v1).
    pub mod v0 {
        use super::*;

        #[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
        #[scale_info(skip_type_params(T))]
        pub struct Attestation<T: Config> {
            pub id: u64,
            pub document_hash: [u8; 32],
            pub category: DocumentCategory,
            pub description: BoundedVec<u8, ConstU32<MAX_DESCRIPTION_LENGTH>>,
            pub attester: T::AccountId,
            pub attested_at: BlockNumberFor<T>,
            pub expires_at: Option<BlockNumberFor<T>>,
            pub status: AttestationStatus,
            pub witness_count: u32,
            pub certified: bool,
            pub contract_id: Option<u32>,
            pub academic_id: Option<u32>,
        }
    }

    /// One-shot migration. Idempotent: it short-circuits once the on-chain
    /// storage version is already ≥ 1.
    pub struct MigrateV0ToV1<T>(core::marker::PhantomData<T>);

    impl<T: Config> OnRuntimeUpgrade for MigrateV0ToV1<T> {
        fn on_runtime_upgrade() -> Weight {
            let onchain = Pallet::<T>::on_chain_storage_version();
            if onchain >= 1 {
                log::info!(
                    target: "runtime::notarial",
                    "notarial::MigrateV0ToV1 skipped — on-chain version already {onchain:?}"
                );
                return T::DbWeight::get().reads(1);
            }

            let mut migrated: u64 = 0;
            Attestations::<T>::translate::<v0::Attestation<T>, _>(|_id, old| {
                migrated = migrated.saturating_add(1);
                Some(Attestation {
                    id: old.id,
                    document_hash: old.document_hash,
                    category: old.category,
                    description: old.description,
                    attester: old.attester,
                    attested_at: old.attested_at,
                    expires_at: old.expires_at,
                    status: old.status,
                    witness_count: old.witness_count,
                    certified: old.certified,
                    contract_id: old.contract_id,
                    academic_id: old.academic_id,
                    // New v1 fields — unknown for legacy rows.
                    requester_fingerprint: None,
                    requester_signature: None,
                })
            });

            StorageVersion::new(1).put::<Pallet<T>>();
            log::info!(
                target: "runtime::notarial",
                "notarial::MigrateV0ToV1 migrated {migrated} attestation(s) to v1"
            );

            // reads+writes per row, +1 for the storage-version write.
            T::DbWeight::get().reads_writes(migrated.saturating_add(1), migrated.saturating_add(1))
        }

        #[cfg(feature = "try-runtime")]
        fn pre_upgrade() -> Result<sp_std::vec::Vec<u8>, sp_runtime::TryRuntimeError> {
            let count = Attestations::<T>::iter().count() as u64;
            Ok(count.encode())
        }

        #[cfg(feature = "try-runtime")]
        fn post_upgrade(state: sp_std::vec::Vec<u8>) -> Result<(), sp_runtime::TryRuntimeError> {
            let before: u64 = Decode::decode(&mut &state[..])
                .map_err(|_| sp_runtime::TryRuntimeError::Other("notarial: bad pre-upgrade state"))?;
            let after = Attestations::<T>::iter().count() as u64;
            if before != after {
                return Err(sp_runtime::TryRuntimeError::Other(
                    "notarial: attestation count changed during migration",
                ));
            }
            if Pallet::<T>::on_chain_storage_version() < 1 {
                return Err(sp_runtime::TryRuntimeError::Other(
                    "notarial: storage version not bumped",
                ));
            }
            Ok(())
        }
    }
}
