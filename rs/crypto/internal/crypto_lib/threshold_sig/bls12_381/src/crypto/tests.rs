//! Signature tests

use super::super::crypto;
use super::super::test_utils::select_n;
use super::super::types::{
    CombinedSignature, IndividualSignature, Polynomial, PublicCoefficients, SecretKey,
};
use crate::crypto::hash_message_to_g1;
use crate::types::PublicKey;
use ic_crypto_internal_bls12_381_type::{G2Affine, LagrangeCoefficients, NodeIndices, Scalar};
use ic_crypto_internal_seed::Seed;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_types::crypto::error::InvalidArgumentError;
use ic_types::{NodeIndex, NumberOfNodes};
use proptest::prelude::*;
use proptest::std_facade::HashSet;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

pub mod util {
    use super::*;
    use ic_crypto_internal_seed::Seed;

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
                "Individual public key match failed for index {index}"
            )
        }
    }

    /// Given all the secret keys, get the combined secret key.
    /// Useful for testing with the standard dealing API that throws away the
    /// original secret polynomial.
    pub fn combined_secret_key(secret_keys: &[SecretKey]) -> SecretKey {
        let node_ids = (0..secret_keys.len() as NodeIndex).collect::<Vec<_>>();
        let interp = LagrangeCoefficients::at_zero(&NodeIndices::from_slice(&node_ids).unwrap());
        interp.interpolate_scalar(secret_keys).unwrap()
    }

    /// Test for threshold signatures.
    /// This verifies that:
    /// * if the scheme is used correctly, signatures verify.
    /// * if incorrect values are provided, signatures fail to verify.
    fn test_threshold_signatures(
        public_coefficients: &PublicCoefficients,
        secret_keys: &[SecretKey],
        threshold: NumberOfNodes,
        seed: Seed,
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
            assert!(
                crypto::verify(message, signature, &public_key),
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
                    !crypto::verify(message, signature, &wrong_public_key),
                    "Individual signature verification accepted incorrect signatory {} instead of {}/{}",
                    wrong_index,
                    index,
                    secret_keys.len()
                );
            }
        }

        // Get the combined public key
        let public_key = crypto::combined_public_key(public_coefficients);
        let secret_key = combined_secret_key(secret_keys);
        assert_eq!(public_key, crypto::public_key_from_secret_key(&secret_key));

        // Combine a random subset of signatures:
        let signature_selection = select_n(seed, threshold, &signatures);
        let signature = crypto::combine_signatures(&signature_selection, threshold)
            .expect("Failed to combine signatures");

        // Correct values validate:
        assert!(crypto::verify(message, &signature, &public_key));

        // Incorrect values are rejected:
        if !public_coefficients.coefficients.is_empty() {
            let incorrect_message = [&b"pound of flesh"[..], message].concat();
            assert!(
                incorrect_message != message,
                "Bad test: The messages should be different"
            );
            assert!(!crypto::verify(&incorrect_message, &signature, &public_key));
        }
        if public_coefficients.coefficients.len() > 1 {
            let some_individual_signature = signatures[0].clone();
            assert!(
                !crypto::verify(message, &some_individual_signature, &public_key),
                "Signature verification passed with incorrect signature: got {some_individual_signature:?} expected {signature:?}"
            );
        }
        if public_coefficients.coefficients.len() > 1 {
            let some_individual_public_key =
                crypto::individual_public_key(public_coefficients, 11_u32);
            assert!(!crypto::verify(
                message,
                &signature,
                &some_individual_public_key
            ));
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
        seed: Seed,
        message: &[u8],
    ) {
        test_individual_public_key_matches(public_coefficients, secret_keys);
        test_threshold_signatures(public_coefficients, secret_keys, threshold, seed, message);
    }

    pub fn generate_threshold_key(
        seed: Seed,
        threshold: NumberOfNodes,
        number_of_shares: NumberOfNodes,
    ) -> Result<(PublicCoefficients, Vec<SecretKey>), InvalidArgumentError> {
        crypto::generate_threshold_key(seed, threshold, number_of_shares)
    }

    /// Combining multiple key generations should yield a valid generation.
    pub fn assert_keygen_composes(
        generations: &[(PublicCoefficients, Vec<SecretKey>)],
        threshold: NumberOfNodes,
        seed: Seed,
        message: &[u8],
    ) {
        // Sum public_coefficients and secret keys.
        let public_coefficients = &generations
            .iter()
            .cloned()
            .map(|(public_coefficients, _)| public_coefficients)
            .sum::<PublicCoefficients>();

        let mut secret_keys = Polynomial::zero();

        for g in generations {
            secret_keys = secret_keys + Polynomial::new(g.1.clone());
        }

        let secret_keys = secret_keys.coefficients().to_vec();

        test_valid_public_coefficients(public_coefficients, &secret_keys, threshold, seed, message);
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
            let bytes = g1.serialize();
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
    let seed = Seed::from_bytes(&[1u8; 32]);
    let message = b"foo";

    let (public_coefficients, shares) =
        util::generate_threshold_key(seed, threshold, num_shares).expect("Could not generate keys");
    let public_key = PublicKey::from(&public_coefficients);

    let signature_options: Vec<Option<IndividualSignature>> = shares
        .iter()
        .enumerate()
        .map(|(index, secret_key)| {
            let signature = crypto::sign_message(message, secret_key);
            let public_key =
                crypto::individual_public_key(&public_coefficients, index as NodeIndex);
            assert!(crypto::verify(&message[..], &signature, &public_key));
            Some(signature)
        })
        .collect();

    let combined_signature: CombinedSignature =
        crypto::combine_signatures(&signature_options, threshold)
            .expect("Combining signatures failed");

    assert!(crypto::verify(
        &message[..],
        &combined_signature,
        &public_key
    ));
}

#[test]
fn test_combined_secret_key() {
    let rng = &mut reproducible_rng();
    for _trial in 0..3 {
        let num_receivers = rng.gen_range::<u8, _>(1..=u8::MAX) as NodeIndex;
        let poly_degree = rng.r#gen::<u8>() as usize;

        let polynomial = Polynomial::random(poly_degree, rng);

        // If the number of receivers is at least the length of the polynomial,
        // combined_secret_key() should recover the 0'th term of the polynomial.
        // If fewer are provided it should be practically impossible.
        let combined_secret = polynomial.coeff(0).clone();
        let secret_keys: Vec<SecretKey> = (0..num_receivers)
            .map(|index| polynomial.evaluate_at(&Scalar::from_node_index(index)))
            .collect();
        assert_eq!(
            combined_secret == util::combined_secret_key(&secret_keys),
            num_receivers as usize >= polynomial.coefficients().len()
        );
    }
}

proptest! {
        #![proptest_config(ProptestConfig {
            cases: 3,
            .. ProptestConfig::default()
        })]

        #[test]
        fn single_keygen_is_valid(keygen_seed: [u8;32], test_seed: [u8;32], threshold in 1_u32..5, redundancy in (0_u32..10), message: Vec<u8>) {
            let threshold = NumberOfNodes::from(threshold);
            let num_shares = threshold + NumberOfNodes::from(redundancy);
            let (public_coefficients, secret_keys) = util::generate_threshold_key(Seed::from_bytes(&keygen_seed), threshold, num_shares).expect("Failed to generate keys");
            util::test_valid_public_coefficients(&public_coefficients, &secret_keys, threshold, Seed::from_bytes(&test_seed), &message);
        }


        #[test]
        fn proptest_keygen_composes(keygen_seeds in proptest::collection::vec(any::<[u8;32]>(), 1..10), test_seed: [u8;32], threshold in 1_u32..10, redundancy in (0_u32..10), message: Vec<u8>) {
            let threshold = NumberOfNodes::from(threshold);
            let num_shares = threshold + NumberOfNodes::from(redundancy);
            let generations = keygen_seeds.into_iter().map(|seed| util::generate_threshold_key(Seed::from_bytes(&seed), threshold, num_shares).expect("Could not generate keys")).collect::<Vec<_>>();
            util::assert_keygen_composes(&generations, threshold, Seed::from_bytes(&test_seed), &message)
        }

        /// Keygen with secret is identical to the normal keygen except
        /// that the threshold key is specified.  here we check that the
        /// threshold key is correct by examining the threshold public
        /// key of the generated key.
        #[test]
        fn verifies_that_threshold_share_secret_key_has_the_correct_public_coefficient_at_zero(
            threshold in 1_u32..5,
            redundancy in 0_u32..5,
            idle_receivers in 0_u32..5,
            seed: [u8; 32]
        ) {
            let rng = &mut ChaChaRng::from_seed(seed);
            let receivers_size = (threshold+redundancy+idle_receivers) as usize;

            let secret_key = Scalar::random(rng);

            let (public_coefficients, _secret_keys) = crypto::threshold_share_secret_key(
                Seed::from_rng(rng),
                NumberOfNodes::from(threshold),
                NumberOfNodes::from(receivers_size as u32),
                &secret_key,
            ).expect("Reshare keygen failed");

            let expected_public_key = crypto::public_key_from_secret_key(&secret_key);
            let actual_public_key = PublicKey::from(&public_coefficients);
            assert_eq!(expected_public_key, actual_public_key);
        }
}

mod resharing_util {
    use super::*;

    pub type ToyDealing = (PublicCoefficients, Vec<SecretKey>);

    /// For each resharing dealer, generate keys.
    ///
    /// # Arguments
    /// * `rng` is the entropy source for key generation.
    /// * `original_receiver_shares` are the pre-existing secret threshold keys
    ///   of the resharing dealers.
    /// * `new_threshold` is the minimum number of signatures that will be
    ///   needed to create a valid threshold signature in the new threshold
    ///   system.
    /// * `new_receivers` indicates how many receivers get a new share
    pub fn multiple_keygen(
        rng: &mut ChaChaRng,
        original_receiver_shares: &[SecretKey],
        new_threshold: NumberOfNodes,
        new_receivers: NumberOfNodes,
    ) -> Vec<ToyDealing> {
        original_receiver_shares
            .iter()
            .map(|key| {
                crypto::threshold_share_secret_key(
                    Seed::from_rng(rng),
                    new_threshold,
                    new_receivers,
                    key,
                )
                .expect("Reshare keygen failed")
            })
            .collect()
    }

    /// Given multiple secret keys (y values) at different indices (which give x
    /// values) interpolate the value at zero.
    pub fn interpolate_secret_key(shares: &[SecretKey]) -> SecretKey {
        let node_ids = (0..shares.len() as NodeIndex).collect::<Vec<_>>();
        let interp = LagrangeCoefficients::at_zero(&NodeIndices::from_slice(&node_ids).unwrap());
        interp.interpolate_scalar(shares).unwrap()
    }

    /// Given multiple public keys (y values) at different points (which give x
    /// values) interpolate the value at zero.
    pub fn interpolate_public_key(shares: &[PublicKey]) -> PublicKey {
        let shares: Vec<(NodeIndex, G2Affine)> = shares
            .iter()
            .enumerate()
            .map(|(index, share)| ((index as NodeIndex), share.0.clone()))
            .collect();
        PublicKey(
            PublicCoefficients::interpolate_g2(&shares)
                .unwrap()
                .to_affine(),
        )
    }

    /// For each active new receiver, this provides a single encrypted secret
    /// threshold key.
    pub fn compute_combined_encrypted_shares(
        receivers: NumberOfNodes,
        dealings: &[ToyDealing],
    ) -> Vec<SecretKey> {
        (0..receivers.get() as usize)
            .map(|new_receiver_index| {
                let new_receiver_shares: Vec<SecretKey> = dealings
                    .iter()
                    .map(|dealing| dealing.1[new_receiver_index].clone())
                    .collect();
                resharing_util::interpolate_secret_key(&new_receiver_shares)
            })
            .collect()
    }

    // Computes the new public coefficients by combining the public coefficients in
    // the dealings.
    pub fn compute_new_public_coefficients(
        new_threshold: NumberOfNodes,
        dealings: &[ToyDealing],
    ) -> PublicCoefficients {
        PublicCoefficients {
            coefficients: (0..new_threshold.get() as usize)
                .map(|coefficient_index| {
                    let new_receiver_shares: Vec<PublicKey> = dealings
                        .iter()
                        .map(|dealing| {
                            dealing
                                .0
                                .coefficients
                                .get(coefficient_index)
                                .cloned()
                                .unwrap()
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
    let original_threshold = NumberOfNodes::from(3);
    let original_receivers = NumberOfNodes::from(5);
    let new_threshold = NumberOfNodes::from(4);
    let new_receivers = NumberOfNodes::from(7);

    let rng = &mut ChaChaRng::from_seed([9u8; 32]);

    let (original_public_coefficients, original_receiver_shares) =
        crypto::generate_threshold_key(Seed::from_rng(rng), original_threshold, original_receivers)
            .expect("Original keygen failed");
    let reshares = resharing_util::multiple_keygen(
        rng,
        &original_receiver_shares,
        new_threshold,
        new_receivers,
    );
    let new_receiver_shares: Vec<SecretKey> =
        resharing_util::compute_combined_encrypted_shares(new_receivers, &reshares);
    assert_eq!(
        resharing_util::interpolate_secret_key(&original_receiver_shares),
        resharing_util::interpolate_secret_key(&new_receiver_shares),
        "New secret doesn't match old"
    );
    let new_public_coefficients: PublicCoefficients =
        resharing_util::compute_new_public_coefficients(new_threshold, &reshares);
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
        let mut hash = ic_crypto_sha2::Sha256::new();
        hash.write(&(original_receiver_index as NodeIndex).to_be_bytes()[..]);
        hash.write(&(new_receiver_index as NodeIndex).to_be_bytes()[..]);
        // This reduces modulo the group order which would introduce a slight bias, which
        // would be dangerous in production code but is acceptable in a test.
        SecretKey::deserialize_unchecked(&hash.finish())
    }
    let original_threshold = NumberOfNodes::from(3);
    let original_receivers = NumberOfNodes::from(5);
    let new_threshold = NumberOfNodes::from(5);
    let new_receivers = NumberOfNodes::from(7);
    let rng = &mut ChaChaRng::from_seed([9u8; 32]);
    let (original_public_coefficients, original_receiver_shares) =
        crypto::generate_threshold_key(Seed::from_rng(rng), original_threshold, original_receivers)
            .expect("Original keygen failed");
    let unencrypted_reshares = resharing_util::multiple_keygen(
        rng,
        &original_receiver_shares,
        new_threshold,
        new_receivers,
    );
    let reshares = {
        let mut reshares = unencrypted_reshares;
        // Encrypt all shares with the stub DiffieHellman.
        for (original_receiver_index, dealings) in reshares.iter_mut().enumerate() {
            for (new_receiver_index, key) in dealings.1.iter_mut().enumerate() {
                *key += dh_stub(
                    original_receiver_index as NodeIndex,
                    new_receiver_index as NodeIndex,
                );
            }
        }
        reshares
    };
    let new_combined_encrypted_receiver_shares: Vec<SecretKey> =
        resharing_util::compute_combined_encrypted_shares(new_receivers, &reshares);
    let new_public_coefficients: PublicCoefficients =
        resharing_util::compute_new_public_coefficients(new_threshold, &reshares);
    assert_eq!(
        original_public_coefficients.coefficients[0], new_public_coefficients.coefficients[0],
        "New public key doesn't match old"
    );
    let new_combined_receiver_shares: Vec<SecretKey> = new_combined_encrypted_receiver_shares
        .iter()
        .enumerate()
        .map(|(new_receiver_index, new_encrypted_share)| {
            let dh_keys: Vec<SecretKey> = (0..original_receivers.get())
                .map(|original_receiver_index| {
                    dh_stub(
                        original_receiver_index as NodeIndex,
                        new_receiver_index as NodeIndex,
                    )
                })
                .collect();
            let dh_key = resharing_util::interpolate_secret_key(&dh_keys);
            new_encrypted_share - &dh_key
        })
        .collect();

    assert_eq!(
        resharing_util::interpolate_secret_key(&original_receiver_shares),
        resharing_util::interpolate_secret_key(&new_combined_receiver_shares),
        "New secret doesn't match old"
    );
}

#[test]
fn generating_a_key_returns_expected_error_for_invalid_args() {
    let seed = [0u8; 32];
    let rng = &mut ChaChaRng::from_seed(seed);

    for threshold in 0..10 {
        for receivers in 0..10 {
            let result = crypto::generate_threshold_key(
                Seed::from_rng(rng),
                NumberOfNodes::from(threshold as u32),
                NumberOfNodes::from(receivers as u32),
            );

            match result {
                Ok((public_coeff, shares)) => {
                    assert!(threshold > 0);
                    assert!(threshold <= receivers);
                    assert_eq!(shares.len(), receivers);
                    assert_eq!(public_coeff.coefficients.len(), threshold);
                }
                Err(e) => {
                    if threshold == 0 {
                        assert!(e.message.starts_with("Threshold of zero is invalid"));
                    } else {
                        assert!(threshold > receivers);
                        assert!(e.message.starts_with("Threshold too high: "));
                    }
                }
            }
        }
    }
}
