use super::*;
use crate::dkg::secp256k1::ephemeral_key::tests::create_ephemeral_public_key;
use crate::dkg::secp256k1::types::EphemeralSecretKeyBytes;
use crate::test_utils::select_n;
use crate::types::PublicKey;
use ic_types::Randomness;
use ic_types_test_utils::arbitrary as arbitrary_types;
use proptest::prelude::*;
use rand::seq::IteratorRandom;
use rand::Rng;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use std::convert::{TryFrom, TryInto};

/// Happy path MUST succeed
fn test_honest_dealing_verifies(
    seed: Randomness,
    dealer_secret_key: EphemeralSecretKey,
    dkg_id: IDkgId,
    threshold: NumberOfNodes,
    receiver_keys: &[Option<(EphemeralPublicKeyBytes, EphemeralPopBytes)>],
) {
    let mut rng = ChaChaRng::from_seed(seed.get());
    let dealing = create_dealing(
        Randomness::from(rng.gen::<[u8; 32]>()),
        dealer_secret_key.into(),
        dkg_id,
        threshold,
        receiver_keys,
    )
    .expect("CLibDealing failed");
    verify_dealing(threshold, receiver_keys, dealing).expect("Verification failed");
}

/// If a receiver public key is malformed, dealing MUST fail.
fn test_dealing_should_fail_with_malformed_public_key(
    seed: Randomness,
    dealer_secret_key: EphemeralSecretKey,
    dkg_id: IDkgId,
    threshold: NumberOfNodes,
    receiver_keys: &[Option<(EphemeralPublicKeyBytes, EphemeralPopBytes)>],
) {
    let mut rng = ChaChaRng::from_seed(seed.get());
    let malformed_receiver_keys = {
        let mut ans = receiver_keys.to_vec();
        let receiver_index: usize = ans
            .iter()
            .enumerate()
            .filter_map(|(index, element)| element.map(|_| index))
            .choose(&mut rng)
            .expect("No record found");
        let (mut public_key_bytes, pop_bytes) = ans[receiver_index].expect("Value is not Some");
        public_key_bytes.0[0] = !public_key_bytes.0[0]; // The first byte is the elliptic curve sign byte.
        assert!(
            EphemeralPublicKey::try_from(public_key_bytes).is_err(),
            "Bad test: The public key should be malformed"
        );
        ans[receiver_index] = Some((public_key_bytes, pop_bytes));
        ans
    };
    assert_ne!(
        receiver_keys,
        &malformed_receiver_keys[..],
        "Test error; the receiver keys should have been corrupted"
    );
    let dealing = create_dealing(
        Randomness::from(rng.gen::<[u8; 32]>()),
        dealer_secret_key.into(),
        dkg_id,
        threshold,
        &malformed_receiver_keys,
    );
    assert!(dealing.is_err())
}

/// If any input fields are malformed verification MUST fail.
pub fn test_malformed_dealing_fails_verification(
    dealing: CLibDealingBytes,
    threshold: NumberOfNodes,
    receiver_keys: &[Option<(EphemeralPublicKeyBytes, EphemeralPopBytes)>],
) {
    // Every EncryptedSecretKey is potentially valid.
    // The only field that may fail parsing is a public key in public_coefficients.
    let CLibDealingBytes {
        public_coefficients,
        ..
    } = dealing.clone();
    if threshold > NumberOfNodes::from(0) {
        let malformed_public_coefficients = {
            let mut ans = public_coefficients;
            let PublicKeyBytes(mut bytes) = ans.coefficients[0];
            bytes[0] = !bytes[0]; // The first byte is the elliptic curve sign byte.
            let malformed_pub_key_bytes = PublicKeyBytes(bytes);
            assert!(
                PublicKey::try_from(&malformed_pub_key_bytes).is_err(),
                "Bad test: 'Malformed' bytes can be parsed"
            );
            ans.coefficients[0] = malformed_pub_key_bytes;
            ans
        };
        let mut malformed_dealing = dealing;
        malformed_dealing.public_coefficients = malformed_public_coefficients;
        assert!(verify_dealing(threshold, receiver_keys, malformed_dealing).is_err());
    }
}

/// Values used in tests
#[derive(Debug)]
pub struct DealingFixture {
    seed: Randomness,
    dealer_secret_key: EphemeralSecretKey,
    dkg_id: IDkgId,
    threshold: NumberOfNodes,
    receiver_keys: Vec<Option<(EphemeralPublicKeyBytes, EphemeralPopBytes)>>,
}

prop_compose! {
    pub fn arbitrary_dealing_fixture() (
        seed: Randomness,
        dealer_secret_key_bytes: EphemeralSecretKeyBytes,
        dkg_id in arbitrary_types::dkg_id(),
        threshold in 1_u32..4,
        redundancy in 0_u32..4,
        receiver_secret_keys in proptest::collection::vec(any::<EphemeralSecretKeyBytes>(), 8..10),
    ) -> DealingFixture {
        let mut rng = ChaChaRng::from_seed(seed.get());
        let dealer_secret_key: EphemeralSecretKey = dealer_secret_key_bytes.try_into().expect("Failed to generate dealer secret key bytes");
        let all_receiver_keys: Vec<(EphemeralPublicKeyBytes, EphemeralPopBytes)> = receiver_secret_keys.iter().enumerate().map(|(index, secret_key_bytes)|{
            let sender = format!("Node Number {}", index);
            create_ephemeral_public_key(&mut rng, dkg_id, secret_key_bytes, &sender.as_bytes()).expect("Failed to generate test receiver public keys")
        }).collect();
        let receiver_keys = {
            let seed = Randomness::from(rng.gen::<[u8;32]>());
            let number_of_keys = NumberOfNodes::from(threshold + redundancy);
            select_n(seed, number_of_keys, &all_receiver_keys)
        };
        DealingFixture {seed: Randomness::from(rng.gen::<[u8;32]>()), dealer_secret_key, dkg_id, threshold: NumberOfNodes::from(threshold), receiver_keys}
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 2,
        max_shrink_iters: 0,
        .. ProptestConfig::default()
    })]

    #[test]
    fn honest_dealing_verifies(
        fixture in arbitrary_dealing_fixture()
    ) {
        let DealingFixture{ seed, dealer_secret_key, dkg_id, threshold, receiver_keys } = fixture;
        test_honest_dealing_verifies(seed, dealer_secret_key, dkg_id, threshold, &receiver_keys);
    }

    #[test]
    fn dealing_should_fail_with_malformed_public_key(
        fixture in arbitrary_dealing_fixture()
    ) {
        let DealingFixture{ seed, dealer_secret_key, dkg_id, threshold, receiver_keys } = fixture;
        test_dealing_should_fail_with_malformed_public_key(seed, dealer_secret_key, dkg_id, threshold, &receiver_keys);
    }

    #[test]
    fn malformed_dealing_fails_verification(
        fixture in arbitrary_dealing_fixture()
    ) {
        let DealingFixture{ seed, dealer_secret_key, dkg_id, threshold, receiver_keys } = fixture;
        let dealing = create_dealing(seed, EphemeralSecretKeyBytes::from(&dealer_secret_key), dkg_id, threshold, &receiver_keys).expect("CLibDealing failed");
        test_malformed_dealing_fails_verification(dealing, threshold, &receiver_keys);
    }

    #[test]
    fn different_threshold_fails(
        fixture in arbitrary_dealing_fixture(),
        receiver_threshold in 0_u32..40,
    ) {
        let receiver_threshold = NumberOfNodes::from(receiver_threshold);
        prop_assume!(fixture.threshold != receiver_threshold);
        let DealingFixture{ seed, dealer_secret_key, dkg_id, threshold, receiver_keys } = fixture;
        let dealing = create_dealing(seed, EphemeralSecretKeyBytes::from(&dealer_secret_key), dkg_id, threshold, &receiver_keys).expect("CLibDealing failed");
        assert!(verify_dealing(receiver_threshold, &receiver_keys, dealing).is_err(), "Verification should fail if the threshold differs");
    }

    #[test]
    fn different_number_of_potential_receivers_fails(
        fixture in arbitrary_dealing_fixture()
    ) {
        let DealingFixture{ seed, dealer_secret_key, dkg_id, threshold, receiver_keys } = fixture;
        let mut dealing = create_dealing(seed, EphemeralSecretKeyBytes::from(&dealer_secret_key), dkg_id, threshold, &receiver_keys).expect("CLibDealing failed");
        // One more receiver slot than expected:
        dealing.receiver_data.push(None);
        assert!(verify_dealing(threshold, &receiver_keys, dealing.clone()).is_err(), "Verification should fail if there are too many share slots");
        if threshold.get() > 0 {
            // One fewer:
            dealing.receiver_data.pop();
            dealing.receiver_data.pop();
            assert!(verify_dealing(threshold, &receiver_keys, dealing).is_err(), "Verification should fail if there are too few share slots");
        }
    }

    #[test]
    fn different_selection_of_potential_receivers_fails(
        seed: Randomness,
        dealer_secret_key_bytes: EphemeralSecretKeyBytes,
        dkg_id in arbitrary_types::dkg_id(),
        threshold in 0_u32..4,
        dealer_redundancy in 0_u32..4,
        verifier_redundancy in 0_u32..4,
        receiver_secret_keys in proptest::collection::vec(any::<EphemeralSecretKeyBytes>(), 8..10),
    ) {
        let mut rng = ChaChaRng::from_seed(seed.get());
        let dealer_secret_key: EphemeralSecretKey = dealer_secret_key_bytes.try_into().expect("Failed to generate dealer secret key bytes");
        let all_receiver_keys: Vec<(EphemeralPublicKeyBytes, EphemeralPopBytes)> = receiver_secret_keys.iter().enumerate().map(|(index, secret_key_bytes)|{
            let sender = format!("Node Number {}", index);
            create_ephemeral_public_key(&mut rng, dkg_id, secret_key_bytes, &sender.as_bytes()).expect("Failed to generate test receiver public keys")
        }).collect();
        let receiver_keys_used_by_dealer = {
            let seed = Randomness::from(rng.gen::<[u8;32]>());
            let number_of_keys = NumberOfNodes::from(threshold + dealer_redundancy);
            select_n(seed, number_of_keys, &all_receiver_keys)
        };
        let receiver_keys_used_by_verifier = {
            let seed = Randomness::from(rng.gen::<[u8;32]>());
            let number_of_keys = NumberOfNodes::from(threshold + verifier_redundancy);
            select_n(seed, number_of_keys, &all_receiver_keys)
        };
        prop_assume!(receiver_keys_used_by_dealer != receiver_keys_used_by_verifier);
        let dealing = create_dealing(Randomness::from(rng.gen::<[u8; 32]>()), EphemeralSecretKeyBytes::from(&dealer_secret_key), dkg_id, NumberOfNodes::from(threshold), &receiver_keys_used_by_dealer).expect("CLibDealing failed");
        assert!(verify_dealing(NumberOfNodes::from(threshold), &receiver_keys_used_by_verifier, dealing).is_err(), "Verification should fail if there are too many share slots");
    }
}
