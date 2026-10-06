//! Mock runtime for pallet-coherence-attestation tests.

use crate as pallet_coherence_attestation;
use frame_support::{
    derive_impl, parameter_types,
    traits::{ConstU16, ConstU32, ConstU64},
};
use sp_runtime::{
    testing::H256,
    traits::{BlakeTwo256, IdentityLookup},
    BuildStorage,
};

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
    pub enum Test
    {
        System: frame_system,
        CoherenceAttestation: pallet_coherence_attestation,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type BaseCallFilter = frame_support::traits::Everything;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type RuntimeOrigin = RuntimeOrigin;
    type RuntimeCall = RuntimeCall;
    type Nonce = u64;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = u64;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Block = Block;
    type RuntimeEvent = RuntimeEvent;
    type BlockHashCount = ConstU64<250>;
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = ();
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = ConstU16<42>;
    type OnSetCode = ();
    type MaxConsumers = ConstU32<16>;
}

parameter_types! {
    pub const SMilliMin: u32 = 2000;       // S > 2
    pub const QberPpmMax: u32 = 95_000;    // 9.5%
    pub const RoundWindow: u64 = 8;
    pub const MaxCounterparties: u32 = 64;
}

impl pallet_coherence_attestation::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type SMilliMin = SMilliMin;
    type QberPpmMax = QberPpmMax;
    type RoundWindow = RoundWindow;
    type MaxCounterparties = MaxCounterparties;
    type Slasher = (); // no-op in tests; runtime wires the real slasher
    type WeightInfo = ();
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    let storage = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();
    let mut ext: sp_io::TestExternalities = storage.into();
    ext.execute_with(|| System::set_block_number(1));
    ext
}
