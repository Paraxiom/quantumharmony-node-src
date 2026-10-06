//! Mock runtime for Transparence Oracle pallet tests

use crate as pallet_transparence_oracle;
use frame_support::{
    derive_impl,
    parameter_types,
};
use sp_runtime::BuildStorage;

type Block = frame_system::mocking::MockBlock<Test>;

// Test accounts
pub const ALICE: u64 = 1;
pub const BOB: u64 = 2;
pub const CHARLIE: u64 = 3;

// Configure mock runtime
frame_support::construct_runtime!(
    pub enum Test {
        System: frame_system,
        TransparenceOracle: pallet_transparence_oracle,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
}

parameter_types! {
    pub const MaxValidationsPerBlock: u32 = 5;
}

impl pallet_transparence_oracle::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type MaxValidationsPerBlock = MaxValidationsPerBlock;
}

// Build test externalities
pub fn new_test_ext() -> sp_io::TestExternalities {
    let t = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();

    let mut ext = sp_io::TestExternalities::new(t);
    ext.execute_with(|| System::set_block_number(1));
    ext
}
