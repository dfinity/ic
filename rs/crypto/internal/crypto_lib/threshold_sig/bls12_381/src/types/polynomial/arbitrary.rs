//! Random data generation for use in tests

use super::*;
use proptest::prelude::*;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

pub fn fr() -> impl Strategy<Value = Fr> {
    any::<[u8; 32]>()
        .prop_map(ChaChaRng::from_seed)
        .prop_map(|mut rng| Fr::random(&mut rng))
}

pub fn poly() -> impl Strategy<Value = Polynomial> {
    any::<([u8; 32], u8)>().prop_map(|(seed, length)| {
        let mut rng = ChaChaRng::from_seed(seed);
        Polynomial::random(length as usize, &mut rng)
    })
}
