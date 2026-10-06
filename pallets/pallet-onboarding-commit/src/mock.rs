//! Test runtime for `pallet-onboarding-commit`. Minimal: System + Balances +
//! the pallet under test. The `ValidatorMutator` is a thread-local mock that
//! records every `add_validator` call so tests can assert on it.

use crate as pallet_onboarding_commit;
use crate::ValidatorMutator;
use frame_support::{
    derive_impl,
    parameter_types,
    traits::ConstU128,
};
use sp_core::H256;
use sp_runtime::{
    traits::{BlakeTwo256, IdentityLookup},
    BuildStorage,
};

pub type AccountId = u64;
pub type Balance = u128;
pub type BlockNumber = u64;

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
    pub enum Test {
        System: frame_system,
        Balances: pallet_balances,
        OnboardingCommit: pallet_onboarding_commit,
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
    type ExistentialDeposit = ConstU128<1>;
    type AccountStore = System;
}

parameter_types! {
    /// Bond required to publish a commit. Picked so it fits comfortably in
    /// the seeded test balances (100k) and exercises reservation accounting
    /// without overflow.
    pub const TestCommitBond: Balance = 1_000;
    /// Short window for tests — production uses ~50 blocks.
    pub const TestDisputeWindow: BlockNumber = 10;
}

/// Mock ValidatorMutator. Captures every `add_validator` call into a
/// thread-local vec so tests can assert on the sequence (and on never-called
/// in failure paths).
pub mod mutator_calls {
    use super::AccountId;
    use std::cell::RefCell;
    thread_local! {
        pub static CALLS: RefCell<Vec<AccountId>> = const { RefCell::new(Vec::new()) };
    }
    pub fn record(who: AccountId) {
        CALLS.with(|v| v.borrow_mut().push(who));
    }
    pub fn take() -> Vec<AccountId> {
        CALLS.with(|v| std::mem::take(&mut *v.borrow_mut()))
    }
}

pub struct MockValidatorMutator;
impl ValidatorMutator<AccountId> for MockValidatorMutator {
    fn add_validator(account_id: AccountId) -> frame_support::dispatch::DispatchResult {
        mutator_calls::record(account_id);
        Ok(())
    }
}

impl pallet_onboarding_commit::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type CommitBond = TestCommitBond;
    type DisputeWindow = TestDisputeWindow;
    type ValidatorMutator = MockValidatorMutator;
}

/// Standard test externalities. Seeds account 1 + 2 + 3 with 100_000 each so
/// every test has predictable balances.
pub fn new_test_ext() -> sp_io::TestExternalities {
    let mut storage = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .expect("Frame system genesis");
    pallet_balances::GenesisConfig::<Test> {
        balances: vec![(1, 100_000), (2, 100_000), (3, 100_000)],
        ..Default::default()
    }
    .assimilate_storage(&mut storage)
    .expect("Balances genesis");
    let mut ext: sp_io::TestExternalities = storage.into();
    ext.execute_with(|| {
        // Tests start at block 1 so block arithmetic doesn't underflow.
        System::set_block_number(1);
        // Clear any prior mutator calls in case tests share a process.
        let _ = mutator_calls::take();
    });
    ext
}
