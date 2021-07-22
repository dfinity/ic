//! Test ephemeral key generation and validation
//!
//! Generated keys should validate; changing the any validation input should
//! cause the validation to fail.
use super::{create_ephemeral, create_pop_data, verification_pop_data, verify_ephemeral, PopData};
use crate::api::dkg_errors::DkgCreateEphemeralError;
use crate::dkg::secp256k1::types::{
    EphemeralPopBytes, EphemeralPublicKeyBytes, EphemeralSecretKey, EphemeralSecretKeyBytes,
};
use ic_types::{IDkgId, Randomness};
use ic_types_test_utils::arbitrary as arbitrary_types;
use proptest::prelude::*;
use rand::{CryptoRng, Rng};
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use std::convert::TryFrom;

proptest! {
        #![proptest_config(ProptestConfig {
            max_shrink_iters: 0,
            .. ProptestConfig::default()
        })]

    /// Pop data of key generation and validation should match.
    ///
    /// Note: This should pass if and only if validation passes, however this test failure is much easier to debug.
    #[test]
    fn pop_data_should_match(
      seed:  Randomness,
      dkg_id in arbitrary_types::dkg_id(),
      sender in proptest::collection::vec(any::<u8>(), 0..100),
    ) {
        test::pop_data_should_match(seed, dkg_id, &sender);
    }

    /// Verify that keys validate if used as intended.
    #[test]
    fn honest_keys_should_validate(
      seed:  Randomness,
      dkg_id in arbitrary_types::dkg_id(),
      sender in proptest::collection::vec(any::<u8>(), 0..100),
    ) {
        test::honest_keys_should_validate(seed, dkg_id, &sender);
    }

    #[test]
    fn incorrect_dkg_should_not_validate(
      seed:  Randomness,
      dkg_id in arbitrary_types::dkg_id(),
      incorrect_dkg_id in arbitrary_types::dkg_id(),
      sender in proptest::collection::vec(any::<u8>(), 0..100),
    ) {
        prop_assume!(dkg_id != incorrect_dkg_id);
        test::incorrect_dkg_should_not_validate(seed, dkg_id, incorrect_dkg_id, &sender);
    }

    #[test]
    fn incorrect_sender_should_not_validate(
      seed:  Randomness,
      dkg_id in arbitrary_types::dkg_id(),
      sender in proptest::collection::vec(any::<u8>(), 0..100),
      incorrect_sender in proptest::collection::vec(any::<u8>(), 0..100),
    ) {
        prop_assume!(sender != incorrect_sender);
        test::incorrect_sender_should_not_validate(seed, dkg_id, &sender, &incorrect_sender);
    }
}

/// Creates a public key and PoP for a given secret key
pub fn create_ephemeral_public_key<R: Rng + CryptoRng>(
    mut rng: &mut R,
    dkg_id: IDkgId,
    secret_key_bytes: &EphemeralSecretKeyBytes,
    sender: &[u8],
) -> Result<(EphemeralPublicKeyBytes, EphemeralPopBytes), DkgCreateEphemeralError> {
    let secret_key = EphemeralSecretKey::try_from(secret_key_bytes)
        .map_err(DkgCreateEphemeralError::MalformedSecretKeyError)?;
    let PopData {
        public_key_bytes,
        pop,
        ..
    } = create_pop_data(&mut rng, dkg_id, &secret_key, sender);
    Ok((public_key_bytes, EphemeralPopBytes::from(pop)))
}

mod test {
    use super::*;

    /// By design, it is hard to determine why a PoP verification has failed.
    /// It is constituted of hashes and if a hash does not match it should
    /// not be possible to determine from the hash output which of the
    /// inputs to the hash are different.  That is great, but makes problems
    /// hard to debug. Here we compare the intermediate values so that we
    /// can diagnose problems easily.
    pub fn pop_data_should_match(seed: Randomness, dkg_id: IDkgId, sender: &[u8]) {
        let mut rng = ChaChaRng::from_seed(seed.get());
        let secret_key = EphemeralSecretKey::random(&mut rng);

        let left = create_pop_data(&mut rng, dkg_id, &secret_key, &sender);
        let right = {
            let pop_bytes = EphemeralPopBytes::from(&left.pop);
            verification_pop_data(dkg_id, sender, (left.public_key_bytes, pop_bytes))
                .expect("Verification failed")
        };

        if left != right {
            panic!("Pop data does not match:\n\n{:#?}\n\n{:#?}", left, right);
        }
    }
    pub fn honest_keys_should_validate(seed: Randomness, dkg_id: IDkgId, sender: &[u8]) {
        let mut rng = ChaChaRng::from_seed(seed.get());
        let (_secret_key_bytes, public_key_bytes, pop_bytes) =
            create_ephemeral(&mut rng, dkg_id, &sender);
        assert!(verify_ephemeral(dkg_id, sender, (public_key_bytes, pop_bytes)).is_ok())
    }
    pub fn incorrect_dkg_should_not_validate(
        seed: Randomness,
        dkg_id: IDkgId,
        incorrect_dkg_id: IDkgId,
        sender: &[u8],
    ) {
        assert_ne!(
            dkg_id, incorrect_dkg_id,
            "Invalid test: DkgIds should differ"
        );
        let mut rng = ChaChaRng::from_seed(seed.get());
        let (_secret_key_bytes, public_key_bytes, pop_bytes) =
            create_ephemeral(&mut rng, dkg_id, &sender);
        assert!(verify_ephemeral(incorrect_dkg_id, sender, (public_key_bytes, pop_bytes)).is_err())
    }
    pub fn incorrect_sender_should_not_validate(
        seed: Randomness,
        dkg_id: IDkgId,
        sender: &[u8],
        incorrect_sender: &[u8],
    ) {
        assert_ne!(
            sender, incorrect_sender,
            "Invalid test: Senders should differ"
        );
        let mut rng = ChaChaRng::from_seed(seed.get());
        let (_secret_key_bytes, public_key_bytes, pop_bytes) =
            create_ephemeral(&mut rng, dkg_id, &sender);
        assert!(verify_ephemeral(dkg_id, incorrect_sender, (public_key_bytes, pop_bytes)).is_err())
    }
}
