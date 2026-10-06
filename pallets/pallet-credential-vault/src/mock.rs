//! Test runtime for `pallet-credential-vault`.

use crate as pallet_credential_vault;
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
        CredentialVault: pallet_credential_vault,
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
    pub const TestMaxCommitmentsPerHolder: u32 = 3;
}

impl pallet_credential_vault::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type MaxCommitmentsPerHolder = TestMaxCommitmentsPerHolder;
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    let storage = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .expect("frame_system genesis");
    let mut ext: sp_io::TestExternalities = storage.into();
    ext.execute_with(|| System::set_block_number(1));
    ext
}
