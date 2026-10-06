//! Test runtime for `pallet-substrate-attestation`.

use crate as pallet_substrate_attestation;
use frame_support::{derive_impl, parameter_types};
use sp_core::H256;
use sp_runtime::{
    traits::{BlakeTwo256, IdentityLookup},
    BuildStorage,
};

pub type AccountId = u64;
pub type BlockNumber = u64;
type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
    pub enum Test {
        System: frame_system,
        SubstrateAttestation: pallet_substrate_attestation,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig as frame_system::DefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
    type AccountId = AccountId;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Hash = H256;
    type Hashing = BlakeTwo256;
}

parameter_types! {
    /// Small enough that the limit test runs without padding.
    pub const TestMaxModelsPerAttester: u32 = 3;
}

impl pallet_substrate_attestation::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type MaxModelsPerAttester = TestMaxModelsPerAttester;
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    let storage = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .expect("frame_system genesis");
    let mut ext: sp_io::TestExternalities = storage.into();
    ext.execute_with(|| System::set_block_number(1));
    ext
}
