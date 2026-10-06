//! Mock runtime for Identity Registry pallet tests

use crate as pallet_identity_registry;
use frame_support::derive_impl;
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
        IdentityRegistry: pallet_identity_registry,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
}

impl pallet_identity_registry::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type ForceOrigin = frame_system::EnsureRoot<u64>;
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
