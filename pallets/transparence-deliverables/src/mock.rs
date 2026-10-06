//! Mock runtime for Transparence Deliverables pallet tests

use crate as pallet_transparence_deliverables;
use frame_support::derive_impl;
use sp_runtime::BuildStorage;

type Block = frame_system::mocking::MockBlock<Test>;

// Test accounts
pub const OWNER: u64 = 1;    // Decideur public (contract owner)
pub const SUPPLIER: u64 = 2; // Fournisseur prive (contract supplier)
pub const ORACLE: u64 = 3;   // Oracle service account
pub const OUTSIDER: u64 = 4; // Unrelated account

// Configure mock runtime
frame_support::construct_runtime!(
    pub enum Test {
        System: frame_system,
        Deliverables: pallet_transparence_deliverables,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
}

impl pallet_transparence_deliverables::Config for Test {
    type RuntimeEvent = RuntimeEvent;
}

// Build test externalities
pub fn new_test_ext() -> sp_io::TestExternalities {
    let t = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();

    let mut ext = sp_io::TestExternalities::new(t);
    ext.execute_with(|| {
        System::set_block_number(1);
        crate::Recorder::<Test>::put(ORACLE);
    });
    ext
}
