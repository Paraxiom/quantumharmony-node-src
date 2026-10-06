//! Storage migrations run by `frame_system::Config::SingleBlockMigrations`.

/// Spec 47: Stablecoin (QCAD, index 35) and Devonomics (index 37) leave the
/// runtime.
///
/// Stablecoin reserved each vault's QMHY collateral on the owner's account.
/// Clearing its storage alone would leave that QMHY reserved with no call
/// able to release it, so the collateral is unreserved first. `collateral`
/// is set to zero whenever a vault is closed or liquidated, so unreserving
/// it never touches a reserve made by another pallet.
///
/// Remove `Migrations` from the runtime in spec 48.
pub mod spec47 {
	use crate::{AccountId, Balance, Balances, BlockNumber, Runtime};
	use frame_support::{
		migrations::RemovePallet, parameter_types, storage_alias, traits::OnRuntimeUpgrade,
		traits::{Get, ReservableCurrency}, weights::Weight, Blake2_128Concat,
	};
	use scale_codec::{Decode, Encode};

	/// Byte-exact copy of `pallet_stablecoin::VaultStatus`.
	#[derive(Encode, Decode)]
	pub enum VaultStatus {
		Active,
		AtRisk,
		Liquidatable,
		Liquidated,
		Closed,
	}

	/// Byte-exact copy of `pallet_stablecoin::Vault<Runtime>`.
	#[derive(Encode, Decode)]
	pub struct Vault {
		pub id: u64,
		pub owner: AccountId,
		pub collateral: Balance,
		pub debt: Balance,
		pub created_at: BlockNumber,
		pub last_fee_block: BlockNumber,
		pub accumulated_fees: Balance,
		pub status: VaultStatus,
	}

	/// `Stablecoin::Vaults`, as the pallet stored it.
	#[storage_alias]
	pub type Vaults = StorageMap<Stablecoin, Blake2_128Concat, u64, Vault>;

	/// Release the QMHY collateral of every vault.
	pub struct UnreserveVaultCollateral;

	impl OnRuntimeUpgrade for UnreserveVaultCollateral {
		fn on_runtime_upgrade() -> Weight {
			let mut vaults: u64 = 0;
			let mut released: Balance = 0;
			let mut short: Balance = 0;
			for (id, vault) in Vaults::iter() {
				vaults += 1;
				if vault.collateral == 0 {
					continue;
				}
				let left = <Balances as ReservableCurrency<AccountId>>::unreserve(
					&vault.owner,
					vault.collateral,
				);
				released = released.saturating_add(vault.collateral.saturating_sub(left));
				if left != 0 {
					log::warn!(
						target: "runtime::migrations",
						"spec47: vault {id}: {left} of {} collateral was not reserved",
						vault.collateral,
					);
					short = short.saturating_add(left);
				}
			}
			log::info!(
				target: "runtime::migrations",
				"spec47: {vaults} vault(s), {released} QMHY collateral unreserved, {short} missing",
			);
			// One read per vault, and per owner a read and a write of the account.
			<Runtime as frame_system::Config>::DbWeight::get()
				.reads_writes(vaults.saturating_mul(2), vaults)
		}
	}

	parameter_types! {
		pub const StablecoinPalletName: &'static str = "Stablecoin";
		pub const DevonomicsPalletName: &'static str = "Devonomics";
	}

	type DbWeight = <Runtime as frame_system::Config>::DbWeight;

	/// In this order: unreserve, then clear both pallets' storage.
	pub type Migrations = (
		UnreserveVaultCollateral,
		RemovePallet<StablecoinPalletName, DbWeight>,
		RemovePallet<DevonomicsPalletName, DbWeight>,
	);

	#[cfg(test)]
	mod tests {
		use super::*;
		use frame_support::traits::Currency;
		use sp_core::hashing::twox_128;
		use sp_runtime::BuildStorage;

		fn prefix_is_empty(pallet: &[u8]) -> bool {
			let prefix = twox_128(pallet).to_vec();
			match sp_io::storage::next_key(&prefix) {
				Some(k) => !k.starts_with(&prefix),
				None => true,
			}
		}

		#[test]
		fn unreserves_collateral_and_clears_both_pallets() {
			let storage = frame_system::GenesisConfig::<Runtime>::default()
				.build_storage()
				.unwrap();
			sp_io::TestExternalities::new(storage).execute_with(|| {
				let owner = AccountId::new([7u8; 32]);
				let closed_owner = AccountId::new([8u8; 32]);
				let unit: Balance = <Runtime as pallet_balances::Config>::ExistentialDeposit::get();
				let _ = Balances::make_free_balance_be(&owner, 1_000 * unit);
				let _ = Balances::make_free_balance_be(&closed_owner, 1_000 * unit);

				// A reserve made by another pallet must survive.
				Balances::reserve(&owner, 5 * unit).unwrap();
				// The vault's collateral.
				Balances::reserve(&owner, 300 * unit).unwrap();
				Vaults::insert(
					0,
					Vault {
						id: 0,
						owner: owner.clone(),
						collateral: 300 * unit,
						debt: 100 * unit,
						created_at: 1,
						last_fee_block: 1,
						accumulated_fees: 0,
						status: VaultStatus::Active,
					},
				);
				// A closed vault keeps no collateral.
				Balances::reserve(&closed_owner, 7 * unit).unwrap();
				Vaults::insert(
					1,
					Vault {
						id: 1,
						owner: closed_owner.clone(),
						collateral: 0,
						debt: 0,
						created_at: 1,
						last_fee_block: 1,
						accumulated_fees: 0,
						status: VaultStatus::Closed,
					},
				);
				// Something under the Devonomics prefix.
				let mut key = twox_128(b"Devonomics").to_vec();
				key.extend_from_slice(&twox_128(b"DevScore"));
				key.extend_from_slice(&[1u8; 48]);
				sp_io::storage::set(&key, &42u32.encode());

				assert!(!prefix_is_empty(b"Stablecoin"));
				assert!(!prefix_is_empty(b"Devonomics"));

				Migrations::on_runtime_upgrade();

				assert_eq!(Balances::reserved_balance(&owner), 5 * unit);
				assert_eq!(Balances::reserved_balance(&closed_owner), 7 * unit);
				assert_eq!(Balances::free_balance(&owner), 995 * unit);
				assert!(prefix_is_empty(b"Stablecoin"));
				assert!(prefix_is_empty(b"Devonomics"));

				// A second run finds nothing to do.
				Migrations::on_runtime_upgrade();
				assert_eq!(Balances::reserved_balance(&owner), 5 * unit);
			});
		}
	}
}
