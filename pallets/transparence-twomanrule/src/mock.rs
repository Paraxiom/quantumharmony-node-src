//! Mock runtime for Transparence Two-Man Rule pallet tests

use crate as pallet_transparence_twomanrule;
use frame_support::{
    derive_impl,
    parameter_types,
};
use sp_runtime::BuildStorage;

type Block = frame_system::mocking::MockBlock<Test>;

// Test accounts
pub const ALICE: u64 = 1;   // Human decideur public
pub const BOB: u64 = 2;     // Oracle / machine signer
pub const CHARLIE: u64 = 3; // Non-whitelisted account
pub const DAVE: u64 = 4;    // Another oracle

// Configure mock runtime
frame_support::construct_runtime!(
    pub enum Test {
        System: frame_system,
        TwoManRule: pallet_transparence_twomanrule,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
}

parameter_types! {
    pub const CeremonyExpiryBlocks: u64 = 100;
}

impl pallet_transparence_twomanrule::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type CeremonyExpiryBlocks = CeremonyExpiryBlocks;
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
