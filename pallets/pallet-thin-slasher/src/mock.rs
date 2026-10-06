//! Test runtime for `pallet-thin-slasher`.

use crate as pallet_thin_slasher;
use frame_support::{
    derive_impl, parameter_types,
    traits::EnsureOrigin,
};
use sp_core::H256;
use sp_runtime::{
    traits::{BlakeTwo256, IdentityLookup},
    BuildStorage, Permill,
};

pub type AccountId = u64;
pub type Balance = u128;
type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
    pub enum Test {
        System: frame_system,
        Balances: pallet_balances,
        ThinSlasher: pallet_thin_slasher,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig as frame_system::DefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
    type AccountId = AccountId;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountData = pallet_balances::AccountData<Balance>;
}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig as pallet_balances::DefaultConfig)]
impl pallet_balances::Config for Test {
    type Balance = Balance;
    type AccountStore = System;
    type ExistentialDeposit = ExistentialDeposit;
}

parameter_types! {
    pub const ExistentialDeposit: Balance = 1;
    pub const TestMinimumDeposit: Balance = 1_000;
    pub TestSlashFraction: Permill = Permill::from_percent(50);
}

/// Mock `ConvictionOrigin`: only AccountId 99 represents "governance"
/// in tests. Lets us exercise the gating without a real collective.
pub struct GovAccount;
impl EnsureOrigin<RuntimeOrigin> for GovAccount {
    type Success = ();
    fn try_origin(o: RuntimeOrigin) -> Result<Self::Success, RuntimeOrigin> {
        match o.clone().into() {
            Ok(frame_system::RawOrigin::Signed(99)) => Ok(()),
            _ => Err(o),
        }
    }
    #[cfg(feature = "runtime-benchmarks")]
    fn try_successful_origin() -> Result<RuntimeOrigin, ()> {
        Ok(frame_system::RawOrigin::Signed(99).into())
    }
}

impl pallet_thin_slasher::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type MinimumDeposit = TestMinimumDeposit;
    type SlashFraction = TestSlashFraction;
    type ConvictionOrigin = GovAccount;
}

/// Test ext with seeded balances:
/// - ALICE (1): 10_000 (the typical validator)
/// - BOB (2):   10_000 (another validator / reporter)
/// - CHARLIE (3): 500 (below MinimumDeposit, to test rejection)
pub fn new_test_ext() -> sp_io::TestExternalities {
    let mut storage = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .expect("frame_system genesis");
    pallet_balances::GenesisConfig::<Test> {
        balances: vec![(1, 10_000), (2, 10_000), (3, 500), (99, 10_000)],
        dev_accounts: None,
    }
    .assimilate_storage(&mut storage)
    .expect("balances genesis");
    let mut ext: sp_io::TestExternalities = storage.into();
    ext.execute_with(|| System::set_block_number(1));
    ext
}
