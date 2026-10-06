//! Test runtime for `pallet-reputation-tokens`.

use crate as pallet_reputation_tokens;
use frame_support::{derive_impl, parameter_types};
use sp_core::H256;
use sp_runtime::{
    traits::{BlakeTwo256, IdentityLookup},
    BuildStorage,
};

pub type AccountId = u64;
type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
    pub enum Test {
        System: frame_system,
        ReputationTokens: pallet_reputation_tokens,
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
    /// Tight cooldown so we can exercise both cooldown rejection and
    /// successful re-decay without huge block advances in tests.
    pub const TestDecayCooldownBlocks: u64 = 5;
}

impl pallet_reputation_tokens::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type DecayCooldownBlocks = TestDecayCooldownBlocks;
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    let storage = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .expect("frame_system genesis");
    let mut ext: sp_io::TestExternalities = storage.into();
    ext.execute_with(|| System::set_block_number(1));
    ext
}
