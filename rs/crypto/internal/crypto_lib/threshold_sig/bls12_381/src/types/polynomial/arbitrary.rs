//! Random data generation for use in tests

use super::*;
use proptest::prelude::*;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

pub fn fr() -> impl Strategy<Value = Scalar> {
    any::<[u8; 32]>()
        .prop_map(ChaChaRng::from_seed)
        .prop_map(|mut rng| Scalar::random(&mut rng))
}

pub fn poly() -> impl Strategy<Value = Polynomial> {
    any::<([u8; 32], u8)>().prop_map(|(seed, length)| {
        let mut rng = ChaChaRng::from_seed(seed);
        Polynomial::random(length as usize, &mut rng)
    })
}
