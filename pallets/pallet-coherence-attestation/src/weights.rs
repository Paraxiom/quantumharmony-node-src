//! Weights for pallet_coherence_attestation.
//!
//! Placeholder estimates. Run the benchmark CLI to generate real weights.

use frame_support::{traits::Get, weights::Weight};
use sp_std::marker::PhantomData;

pub trait WeightInfo {
    fn submit_attestation() -> Weight;
    fn force_advance_round() -> Weight;
}

pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
    fn submit_attestation() -> Weight {
        Weight::from_parts(60_000_000, 0)
            .saturating_add(T::DbWeight::get().reads(3))
            .saturating_add(T::DbWeight::get().writes(4))
    }

    fn force_advance_round() -> Weight {
        Weight::from_parts(15_000_000, 0).saturating_add(T::DbWeight::get().writes(1))
    }
}

impl WeightInfo for () {
    fn submit_attestation() -> Weight {
        Weight::from_parts(60_000_000, 0)
    }
    fn force_advance_round() -> Weight {
        Weight::from_parts(15_000_000, 0)
    }
}
