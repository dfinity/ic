//! Random data generation for use in tests

use super::*;
use ic_crypto_internal_bls12381_common::random_bls12_381_scalar;
use proptest::prelude::*;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

pub fn fr() -> impl Strategy<Value = Scalar> {
    any::<[u8; 32]>()
        .prop_map(ChaChaRng::from_seed)
        .prop_map(|mut rng| random_bls12_381_scalar(&mut rng))
}

pub fn poly() -> impl Strategy<Value = Polynomial> {
    any::<([u8; 32], u8)>().prop_map(|(seed, length)| {
        let mut rng = ChaChaRng::from_seed(seed);
        Polynomial::random(length as usize, &mut rng)
    })
}
