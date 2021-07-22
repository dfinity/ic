#![allow(clippy::unwrap_used)]
//! Signature tests

use super::super::crypto;
use super::super::test_utils::select_n;
use super::super::types::{
    polynomial::arbitrary::poly, CombinedSignature, IndividualSignature, Polynomial,
    PublicCoefficients, SecretKey,
};
use crate::crypto::hash_message_to_g1;
use crate::types::PublicKey;
use ff::Field;
use ic_crypto_internal_bls12381_common::{g1_to_bytes, hash_to_fr};
use ic_types::crypto::error::InvalidArgumentError;
use ic_types::{NodeIndex, NumberOfNodes, Randomness};
use pairing::bls12_381::Fr;
use proptest::prelude::*;
use proptest::std_facade::HashSet;
use rand::seq::IteratorRandom;
use rand::Rng;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use std::convert::TryFrom;

pub mod util {
    use super::{
        crypto, select_n, IndividualSignature, InvalidArgumentError, NodeIndex, NumberOfNodes,
        Polynomial, PublicCoefficients, Randomness, SecretKey,
    };
    use ff::Field;
    use pairing::bls12_381::Fr;

    // A public key as computed by the holder of the private key is the same as the
    // public key as computed from the public public_coefficients.
    pub fn test_individual_public_key_matches(
        public_coefficients: &PublicCoefficients,
        secret_keys: &[SecretKey],
    ) {
        for (index, secret_key) in secret_keys.iter().enumerate() {
            assert_eq!(
                crypto::individual_public_key(public_coefficients, index as NodeIndex),
                crypto::public_key_from_secret_key(secret_key),
                "Individual public key match failed for index {}",
                index
            )
        }
    }

    /// Given all the secret keys, get the combined secret key.
    /// Useful for testing with the standard dealing API that throws away the
    /// original secret polynomial.
    fn combined_secret_key(secret_keys: &[SecretKey]) -> SecretKey {
        let coordinates: Vec<(Fr, SecretKey)> = secret_keys
            .iter()
            .zip(0_u32..)
            .map(|(y, index)| (crypto::x_for_index(index), *y))
            .collect();
        Polynomial::interpolate(&coordinates)
            .coefficients
            .get(0)
            .cloned()
            .unwrap_or_else(SecretKey::zero)
    }

    /// Test for util::combined_secret_key().
    /// If the number of receivers is at least the length of the polynomial,
    /// combined_secret_key() should recover the 0'th term of the polynomial.
    /// If fewer are provided it should be practically impossible.
    pub fn test_combined_secret_key(polynomial: Polynomial, num_receivers: NumberOfNodes) {
        let combined_secret = polynomial
            .coefficients
            .get(0)
            .cloned()
            .unwrap_or_else(SecretKey::zero);
        let secret_keys: Vec<SecretKey> = (0..num_receivers.get())
            .map(|index| polynomial.evaluate_at(&crypto::x_for_index(index)))
            .collect();
        assert_eq!(
            combined_secret == combined_secret_key(&secret_keys),
            num_receivers.get() as usize >= polynomial.coefficients.len()
        );
    }

    /// Test for threshold signatures.
    /// This verifies that:
    /// * if the scheme is used correctly, signatures verify.
    /// * if incorrect values are provided, signatures fail to verify.
    fn test_threshold_signatures(
        public_coefficients: &PublicCoefficients,
        secret_keys: &[SecretKey],
        threshold: NumberOfNodes,
        seed: Randomness,
        message: &[u8],
    ) {
        let signatures: Vec<IndividualSignature> = secret_keys
            .iter()
            .map(|secret_key| crypto::sign_message(message, secret_key))
            .collect();

        // Verify each individual signature:
        for (index, signature) in signatures.iter().enumerate() {
            let public_key = crypto::individual_public_key(public_coefficients, index as NodeIndex);

            // Correct values validate:
            assert_eq!(
                crypto::verify(message, *signature, public_key),
                Ok(()),
                "Individual signature failed verification for signatory number {}/{}",
                index,
                secret_keys.len()
            );

            // Incorrect values fail to validate:
            if threshold > NumberOfNodes::from(1) {
                let wrong_index = (index + 1) % secret_keys.len();
                let wrong_public_key =
                    crypto::individual_public_key(public_coefficients, wrong_index as NodeIndex);
                assert!(
                    crypto::verify(message, *signature, wrong_public_key).is_err(),
                    "Individual signature verification accepted incorrect signatory {} instead of {}/{}",
                    wrong_index,
                    index,
                    secret_keys.len()
                );
            }
        }

        // Get the combined public key
        let public_key = crypto::combined_public_key(&public_coefficients);
        let secret_key = combined_secret_key(secret_keys);
        assert_eq!(public_key, crypto::public_key_from_secret_key(&secret_key));

        // Combine a random subset of signatures:
        let signature_selection = select_n(seed, threshold, &signatures);
        let signature = crypto::combine_signatures(&signature_selection, threshold)
            .expect("Failed to combine signatures");

        // Correct values validate:
        assert_eq!(crypto::verify(message, signature, public_key), Ok(()));

        // Incorrect values are rejected:
        if !public_coefficients.coefficients.is_empty() {
            let incorrect_message = [&b"pound of flesh"[..], message].concat();
            assert!(
                incorrect_message != message,
                "Bad test: The messages should be different"
            );
            assert!(crypto::verify(&incorrect_message, signature, public_key).is_err());
        }
        if public_coefficients.coefficients.len() > 1 {
            let some_individual_signature = signatures[0];
            assert!(
                crypto::verify(message, some_individual_signature, public_key).is_err(),
                "Signature verification passed with incorrect signature: got {:?} expected {:?}",
                some_individual_signature,
                signature
            );
        }
        if public_coefficients.coefficients.len() > 1 {
            let some_individual_public_key =
                crypto::individual_public_key(public_coefficients, 11_u32);
            assert!(crypto::verify(message, signature, some_individual_public_key).is_err());
        }
    }

    /// Test that public coefficients behave correctly relative to:
    /// * secret_keys  - specifically that public keys from secret keys match
    ///   public keys computed from the public coefficients.
    /// * threshold - specifically that threshold or more correct signatures
    ///   validate against the public coefficients whereas fewer or incorrect
    ///   signatures do not.
    pub fn test_valid_public_coefficients(
        public_coefficients: &PublicCoefficients,
        secret_keys: &[SecretKey],
        threshold: NumberOfNodes,
        seed: Randomness,
        message: &[u8],
    ) {
        test_individual_public_key_matches(public_coefficients, secret_keys);
        test_threshold_signatures(public_coefficients, secret_keys, threshold, seed, message);
    }

    // TODO(DFN-1412): Test scenarios where only some keys are generated
    pub fn keygen(
        seed: Randomness,
        threshold: NumberOfNodes,
        number_of_shares: NumberOfNodes,
    ) -> Result<(PublicCoefficients, Vec<SecretKey>), InvalidArgumentError> {
        let which_shares = vec![true; number_of_shares.get() as usize];
        crypto::keygen(seed, threshold, &which_shares).map(|(public_coefficients, keys_maybe)| {
            let keys: Vec<SecretKey> = keys_maybe.iter().cloned().flatten().collect();
            (public_coefficients, keys)
        })
    }

    /// Combining multiple key generations should yield a valid generation.
    /// TODO(DFN-1412): Extend these tests for the case where keys have gaps.
    pub fn assert_keygen_composes(
        generations: &[(PublicCoefficients, Vec<SecretKey>)],
        threshold: NumberOfNodes,
        seed: Randomness,
        message: &[u8],
    ) {
        // Sum public_coefficients and secret keys.  We treat the vector of secret keys
        // as a polynomial so that we can use polynomial addition.
        let public_coefficients = &generations
            .iter()
            .cloned()
            .map(|(public_coefficients, _)| public_coefficients)
            .sum::<PublicCoefficients>();
        let secret_keys = &generations
            .iter()
            .map(|(_, secret_keys)| secret_keys)
            .map(|coefficients| Polynomial {
                coefficients: (*coefficients).to_vec(),
            })
            .sum::<Polynomial>()
            .coefficients;
        test_valid_public_coefficients(public_coefficients, secret_keys, threshold, seed, message);
    }
}

/// Verify that x_for_index(i) == i+1 (in the field).
#[test]
fn x_for_index_is_correct() {
    // First N values:
    let mut x = Fr::one();
    for i in 0..100 {
        assert_eq!(crypto::x_for_index(i), x);
        x.add_assign(&Fr::one());
    }
    // Binary 0, 1, 11, 111, ... all the way up to the maximum NodeIndex.
    // The corresponding x values are binary 1, 10, 100, ... and the last value is
    // one greater than the maximum NodeIndex.
    let mut x = Fr::one();
    let mut i: NodeIndex = 0;
    loop {
        assert_eq!(crypto::x_for_index(i), x);
        if i == NodeIndex::max_value() {
            break;
        }
        i = i * 2 + 1;
        x.add_assign(&x.clone());
    }
}

/// Verifies that different messages yield different points on G1 when hashed,
/// with high probability
#[test]
fn test_distinct_messages_yield_distinct_hashes() {
    let number_of_messages = 100;
    let points: HashSet<_> = (0..number_of_messages as u32)
        .map(|number| {
            let g1 = hash_message_to_g1(&number.to_be_bytes()[..]);
            let bytes = g1_to_bytes(&g1);
            // It suffices to prove that the first 32 bytes are distinct.  More requires a
            // custom hash implementation.
            let mut hashable = [0u8; 32];
            hashable.copy_from_slice(&bytes[0..32]);
            hashable
        })
        .collect();
    assert_eq!(number_of_messages, points.len(), "Collisions found");
}

/// This is a happy path test for the single dealer case.
#[test]
fn omnipotent_dealer() {
    let threshold = NumberOfNodes::from(3);
    let num_shares = NumberOfNodes::from(6);
    let seed = Randomness::from([1u8; 32]);
    let message = b"foo";

    let (public_coefficients, shares) =
        util::keygen(seed, threshold, num_shares).expect("Could not generate keys");
    let public_key = PublicKey::from(&public_coefficients);

    let signature_options: Vec<Option<IndividualSignature>> = shares
        .iter()
        .enumerate()
        .map(|(index, secret_key)| {
            let signature = crypto::sign_message(message, secret_key);
            let public_key =
                crypto::individual_public_key(&public_coefficients, index as NodeIndex);
            assert!(crypto::verify(&message[..], signature, public_key).is_ok());
            Some(signature)
        })
        .collect();

    let combined_signature: CombinedSignature =
        crypto::combine_signatures(&signature_options, threshold)
            .expect("Combining signatures failed");

    assert_eq!(
        crypto::verify(&message[..], combined_signature, public_key),
        Ok(())
    );
}

#[test]
#[ignore]
/// Verifies that `verify_keygen_args` returns an error if the vector of
/// eligible nodes is too long.
///
/// The maximum length that should be accepted is `NodeIndex::max_value()`.
/// More should fail.
///
/// Note: This is a slow test and can consume a lot of RAM, depending on the
/// definition of NodeIndex.  To test quickly, change NodeIndex to u16.  If the
/// code is clean and compiles, this test will run quickly.
fn verify_keygen_args_rejects_too_many_share_indices() {
    let max_node_index = usize::try_from(NodeIndex::max_value());
    if max_node_index.is_err() {
        return; // usize is smaller than NodeIndex
    }
    let max_node_index = max_node_index.unwrap();

    if usize::max_value() > max_node_index {
        assert!(
            crypto::verify_keygen_args(NumberOfNodes::from(0), &vec![true; max_node_index]).is_ok()
        );
        assert!(crypto::verify_keygen_args(
            NumberOfNodes::from(0),
            &vec![true; max_node_index + 1]
        )
        .is_err());
    }
}

proptest! {
        #![proptest_config(ProptestConfig {
            cases: 3,
            .. ProptestConfig::default()
        })]

        #[test]
        fn single_keygen_is_valid(keygen_seed: [u8;32], test_seed: [u8;32], threshold in 0_u32..5, redundancy in (0_u32..10), message: Vec<u8>) {
            let threshold = NumberOfNodes::from(threshold);
            let num_shares = threshold + NumberOfNodes::from(redundancy);
            let (public_coefficients, secret_keys) = util::keygen(Randomness::from(keygen_seed), threshold, num_shares).expect("Failed to generate keys");
            util::test_valid_public_coefficients(&public_coefficients, &secret_keys, threshold, Randomness::from(test_seed), &message);
        }


        #[test]
        fn proptest_keygen_composes(keygen_seeds in proptest::collection::vec(any::<[u8;32]>(), 1..10), test_seed: [u8;32], threshold in 0_u32..10, redundancy in (0_u32..10), message: Vec<u8>) {
            let threshold = NumberOfNodes::from(threshold);
            let num_shares = threshold + NumberOfNodes::from(redundancy);
            let generations = keygen_seeds.into_iter().map(|seed| util::keygen(Randomness::from(seed), threshold, num_shares).expect("Could not generate keys")).collect::<Vec<_>>();
            util::assert_keygen_composes(&generations, threshold, Randomness::from(test_seed), &message)
        }

        #[test]
        fn test_combined_secret_key(polynomial in poly(), num_receivers: u8) {
            // Note: Arbitrary provides a polynomial of length 0-255, so on average
            // half the time this test will run with sufficient receivers and half
            // with insufficient.
            util::test_combined_secret_key(polynomial, NumberOfNodes::from(num_receivers as NodeIndex));
        }

        /// Verifies that verify_keygen_args returns an error if the number of eligible nodes
        /// is strictly less than the threshold.
        /// In this test the other requirements of verify_keygen_args are satisfied, so when
        /// the number of eligible nodes is greater than or equal to the threshold this checks
        /// that no error is returned.
        #[test]
        fn verify_keygen_args_rejects_insufficient_eligible_nodes(
            threshold in 0_u32..10,
            eligible in 0_u32..10,
            ineligible in 0_u32..10,
            seed: Randomness,
        ) {
            let all_nodes = vec![true;(eligible+ineligible) as usize];
            let eligible_nodes: Vec<bool> = select_n(seed, NumberOfNodes::from(eligible), &all_nodes).iter().map(|entry| entry.is_some()).collect();
            assert_eq!(crypto::verify_keygen_args(NumberOfNodes::from(threshold), &eligible_nodes).is_ok(), eligible >= threshold);
        }

        /// Keygen with secret is identical to the normal keygen except
        /// that the threshold key is specified.  here we check that the
        /// threshold key is correct by examining the threshold public
        /// key of the generated key.
        #[test]
        fn verifies_that_keygen_with_secret_has_the_correct_public_coefficient_at_zero(
            threshold in 1_u32..5,
            redundancy in 0_u32..5,
            idle_receivers in 0_u32..5,
            seed: Randomness
        ) {
            let mut rng = ChaChaRng::from_seed(seed.get());
            let receivers_size = (threshold+redundancy+idle_receivers) as usize;

            let secret_key = SecretKey::random(&mut rng);

            let eligibility = {
                let mut eligibility = vec![true;receivers_size];
                for index in (0..receivers_size).choose_multiple(&mut rng, idle_receivers as usize) {
                    eligibility[index] = false;
                }
                eligibility
            };

            let (public_coefficients, _secret_keys) = crypto::keygen_with_secret(
                            Randomness::from(rng.gen::<[u8; 32]>()),
                            NumberOfNodes::from(threshold),
                            &eligibility,
                            &secret_key,
                        )
                        .expect("Reshare keygen failed");

            let expected_public_key = crypto::public_key_from_secret_key(&secret_key);
            let actual_public_key = PublicKey::from(&public_coefficients);
            assert_eq!(expected_public_key, actual_public_key);
        }
}

mod resharing_util {
    use super::*;
    use pairing::bls12_381::G2;

    pub type ToyDealing = (PublicCoefficients, Vec<Option<SecretKey>>);

    /// For each resharing dealer, generate keys.
    ///
    /// # Arguments
    /// * `rng` is the entropy source for key generation.
    /// * `original_receiver_shares` are the pre-existing secret threshold keys
    ///   of the resharing dealers.
    /// * `new_threshold` is the minimum number of signatures that will be
    ///   needed to create a valid threshold signature in the new threshold
    ///   system.
    /// * `new_eligibility` indicates which of the new receivers should receive
    ///   keys.
    pub fn multiple_keygen(
        rng: &mut ChaChaRng,
        original_receiver_shares: &[Option<SecretKey>],
        new_threshold: NumberOfNodes,
        new_eligibility: &[bool],
    ) -> Vec<Option<ToyDealing>> {
        original_receiver_shares
            .iter()
            .map(|key_maybe| {
                key_maybe.map(|secret_key| {
                    crypto::keygen_with_secret(
                        Randomness::from(rng.gen::<[u8; 32]>()),
                        new_threshold,
                        new_eligibility,
                        &secret_key,
                    )
                    .expect("Reshare keygen failed")
                })
            })
            .collect()
    }

    /// Given multiple secret keys (y values) at different indices (which give x
    /// values) interpolate the value at zero.
    pub fn interpolate_secret_key(shares: &[Option<SecretKey>]) -> SecretKey {
        let shares: Vec<(SecretKey, SecretKey)> = shares
            .iter()
            .enumerate()
            .filter_map(|(index, share_maybe)| {
                share_maybe.map(|share| (crypto::x_for_index(index as NodeIndex), share))
            })
            .collect();
        Polynomial::interpolate(&shares).coefficients[0]
    }

    /// Given multiple public keys (y values) at different points (which give x
    /// values) interpolate the value at zero.
    pub fn interpolate_public_key(shares: &[Option<PublicKey>]) -> PublicKey {
        let shares: Vec<(SecretKey, G2)> = shares
            .iter()
            .enumerate()
            .filter_map(|(index, share_maybe)| {
                share_maybe.map(|share| (crypto::x_for_index(index as NodeIndex), share.0))
            })
            .collect();
        PublicKey(PublicCoefficients::interpolate(&shares).unwrap())
    }

    /// For each active new receiver, this provides a single encrypted secret
    /// threshold key.
    pub fn compute_combined_encrypted_shares(
        eligibility: &[bool],
        dealings: &[Option<ToyDealing>],
    ) -> Vec<Option<SecretKey>> {
        (0..)
            .zip(eligibility)
            .map(|(new_receiver_index, eligible)| {
                if *eligible {
                    Some({
                        let new_receiver_shares: Vec<Option<SecretKey>> = dealings
                            .iter()
                            .map(|dealing_maybe| {
                                dealing_maybe.as_ref().map(|dealing| {
                                    dealing.1[new_receiver_index].expect("Missing share")
                                })
                            })
                            .collect();
                        resharing_util::interpolate_secret_key(&new_receiver_shares)
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    // Computes the new public coefficients by combining the public coefficients in
    // the dealings.
    pub fn compute_new_public_coefficients(
        new_threshold: NumberOfNodes,
        dealings: &[Option<ToyDealing>],
    ) -> PublicCoefficients {
        PublicCoefficients {
            coefficients: (0..new_threshold.get() as usize)
                .map(|coefficient_index| {
                    let new_receiver_shares: Vec<Option<PublicKey>> = dealings
                        .iter()
                        .map(|dealing_maybe| {
                            dealing_maybe
                                .as_ref()
                                .map(|dealing| dealing.0.coefficients[coefficient_index])
                        })
                        .collect();
                    resharing_util::interpolate_public_key(&new_receiver_shares)
                })
                .collect(),
        }
    }
}

/// Demonstrates how resharing works from the perspective of just the threshold
/// keys.
///
/// A complication that is omitted is the encryption of the key shares.
#[test]
fn simplified_resharing_should_preserve_the_threshold_key() {
    let original_threshold = 3;
    let new_threshold = 4;
    let original_eligibility = vec![true, true, false, true, true];
    let new_eligibility = vec![true, false, true, false, true, true, true];
    let mut rng = ChaChaRng::from_seed([9u8; 32]);
    let (original_public_coefficients, original_receiver_shares) = crypto::keygen(
        Randomness::from(rng.gen::<[u8; 32]>()),
        NumberOfNodes::from(original_threshold),
        &original_eligibility,
    )
    .expect("Original keygen failed");
    let reshares: Vec<Option<resharing_util::ToyDealing>> = resharing_util::multiple_keygen(
        &mut rng,
        &original_receiver_shares,
        NumberOfNodes::from(new_threshold),
        &new_eligibility,
    );
    let new_receiver_shares: Vec<Option<SecretKey>> =
        resharing_util::compute_combined_encrypted_shares(&new_eligibility, &reshares);
    assert_eq!(
        resharing_util::interpolate_secret_key(&original_receiver_shares),
        resharing_util::interpolate_secret_key(&new_receiver_shares),
        "New secret doesn't match old"
    );
    let new_public_coefficients: PublicCoefficients =
        resharing_util::compute_new_public_coefficients(
            NumberOfNodes::from(new_threshold),
            &reshares,
        );
    assert_eq!(
        original_public_coefficients.coefficients[0], new_public_coefficients.coefficients[0],
        "New public key doesn't match old"
    );
}

/// Demonstrates how resharing works from the perspective of just the threshold
/// keys.
///
/// This adds encryption of key shares to the simpler test above.
#[test]
fn resharing_with_encryption_should_preserve_the_threshold_key() {
    /// This represents the DiffieHellman key encryption key used to encrypt key
    /// shares.
    ///
    /// Note: The original receiver is the new dealer.
    fn dh_stub(original_receiver_index: NodeIndex, new_receiver_index: NodeIndex) -> SecretKey {
        let mut hash = ic_crypto_sha256::Sha256::new();
        hash.write(&(original_receiver_index as NodeIndex).to_be_bytes()[..]);
        hash.write(&(new_receiver_index as NodeIndex).to_be_bytes()[..]);
        hash_to_fr(hash)
    }
    let original_threshold = 3;
    let new_threshold = 4;
    let original_eligibility = vec![true, true, false, true, true];
    let new_eligibility = vec![true, false, true, false, true, true, true];
    let mut rng = ChaChaRng::from_seed([9u8; 32]);
    let (original_public_coefficients, original_receiver_shares) = crypto::keygen(
        Randomness::from(rng.gen::<[u8; 32]>()),
        NumberOfNodes::from(original_threshold),
        &original_eligibility,
    )
    .expect("Original keygen failed");
    let unencrypted_reshares: Vec<Option<resharing_util::ToyDealing>> =
        resharing_util::multiple_keygen(
            &mut rng,
            &original_receiver_shares,
            NumberOfNodes::from(new_threshold),
            &new_eligibility,
        );
    let reshares = {
        let mut reshares = unencrypted_reshares;
        // Encrypt all shares with the stub DiffieHellman.
        for (original_receiver_index, dealing_maybe) in reshares.iter_mut().enumerate() {
            for dealing in dealing_maybe.iter_mut() {
                for (new_receiver_index, key_maybe) in dealing.1.iter_mut().enumerate() {
                    for key in key_maybe.iter_mut() {
                        key.add_assign(&dh_stub(
                            original_receiver_index as NodeIndex,
                            new_receiver_index as NodeIndex,
                        ))
                    }
                }
            }
        }
        reshares
    };
    let new_combined_encrypted_receiver_shares: Vec<Option<SecretKey>> =
        resharing_util::compute_combined_encrypted_shares(&new_eligibility, &reshares);
    let new_public_coefficients: PublicCoefficients =
        resharing_util::compute_new_public_coefficients(
            NumberOfNodes::from(new_threshold),
            &reshares,
        );
    assert_eq!(
        original_public_coefficients.coefficients[0], new_public_coefficients.coefficients[0],
        "New public key doesn't match old"
    );
    let new_combined_receiver_shares: Vec<Option<SecretKey>> =
        new_combined_encrypted_receiver_shares
            .iter()
            .enumerate()
            .map(|(new_receiver_index, new_share_maybe)| {
                new_share_maybe.map(|new_encrypted_share| {
                    let dh_keys: Vec<Option<SecretKey>> = original_eligibility
                        .iter()
                        .enumerate()
                        .map(|(original_receiver_index, eligible)| {
                            if *eligible {
                                Some(dh_stub(
                                    original_receiver_index as NodeIndex,
                                    new_receiver_index as NodeIndex,
                                ))
                            } else {
                                None
                            }
                        })
                        .collect();
                    let dh_key = resharing_util::interpolate_secret_key(&dh_keys);
                    let mut new_receiver_share: SecretKey = new_encrypted_share;
                    new_receiver_share.sub_assign(&dh_key);
                    new_receiver_share
                })
            })
            .collect();

    assert_eq!(
        resharing_util::interpolate_secret_key(&original_receiver_shares),
        resharing_util::interpolate_secret_key(&new_combined_receiver_shares),
        "New secret doesn't match old"
    );
}
