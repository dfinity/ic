#![allow(clippy::unwrap_used)]
//! Tests for distributed key generation complaints and complaint verification

use super::*;
use crate::dkg::secp256k1::dealing::{create_dealing, verify_dealing};
use crate::dkg::secp256k1::ephemeral_key::tests::create_ephemeral_public_key;
use crate::dkg::secp256k1::types::{
    EphemeralPopBytes, EphemeralPublicKeyBytes, EphemeralSecretKeyBytes,
};
use crate::test_utils::select_n;
use ic_types::{NodeIndex, NumberOfNodes, Randomness};
use ic_types_test_utils::arbitrary as arbitrary_types;
use proptest::prelude::*;
use rand::seq::IteratorRandom;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use std::convert::{TryFrom, TryInto};

/// Indicates that the parameters provided to a test don't yield a valid test.
///
/// For example, if the claim is that the result of encryption by different keys
/// is different but the two keys passed in to test this are the same, the test
/// cannot be carried out in any meaningful way.
#[allow(unused)]
struct BadTest {
    message: String,
}
type ValidTest<T> = Result<T, BadTest>;

fn test_honest_dealing_gets_no_complaints(
    seed: Randomness,
    dealer_secret_key_bytes: EphemeralSecretKeyBytes,
    dkg_id: IDkgId,
    threshold: NumberOfNodes,
    redundancy: NumberOfNodes,
    receiver_secret_keys: Vec<EphemeralSecretKeyBytes>,
) -> ValidTest<()> {
    // Key setup:
    let mut rng = ChaChaRng::from_seed(seed.get());
    let dealer_secret_key: EphemeralSecretKey = dealer_secret_key_bytes
        .try_into()
        .expect("Failed to generate dealer secret key bytes");
    let all_receiver_keys: Vec<(EphemeralPublicKeyBytes, EphemeralPopBytes)> = receiver_secret_keys
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, secret_key_bytes)| {
            let sender = format!("Node Number {}", index);
            create_ephemeral_public_key(&mut rng, dkg_id, &secret_key_bytes, &sender.as_bytes())
                .expect("Failed to generate test receiver public keys")
        })
        .collect();
    let receiver_keys = {
        let seed = Randomness::from(rng.gen::<[u8; 32]>());
        let number_of_keys = threshold + redundancy;
        select_n(seed, number_of_keys, &all_receiver_keys)
    };
    let (receiver_index, receiver_secret_key_bytes): (NodeIndex, EphemeralSecretKeyBytes) = (0..)
        .zip(&receiver_secret_keys)
        .zip(&receiver_keys)
        .filter_map(|((index, key), option)| option.map(|_| (index, key)))
        .choose(&mut rng)
        .map(|(index, key)| (index, *key))
        .unwrap();
    let receiver_secret_key = EphemeralSecretKey::try_from(&receiver_secret_key_bytes)
        .expect("Test setup failed: Malformed receiver secret key");

    // Dealing setup:
    let mut dealer_rng = ChaChaRng::from_seed(rng.gen::<[u8; 32]>());
    let mut complainer_rng = ChaChaRng::from_seed(rng.gen::<[u8; 32]>());
    let dealing = create_dealing(
        Randomness::from(dealer_rng.gen::<[u8; 32]>()),
        EphemeralSecretKeyBytes::from(&dealer_secret_key),
        dkg_id,
        threshold,
        &receiver_keys,
    )
    .expect("Error in test setup: dealing failed");
    verify_dealing(threshold, &receiver_keys, dealing.clone())
        .expect("Error in test setup: Verification failed");

    // Test:
    let receiver_public_key = &EphemeralPublicKey::from(&receiver_secret_key);
    let dealer_public_key_bytes =
        &EphemeralPublicKeyBytes::from(EphemeralPublicKey::from(&dealer_secret_key));
    let complaint = complain_maybe(
        &mut complainer_rng,
        dkg_id,
        receiver_index,
        &receiver_secret_key,
        receiver_public_key,
        dealer_public_key_bytes,
        &dealing,
    );
    assert_eq!(
        Ok(None),
        complaint,
        "Expected honest dealing to have no complaint."
    );
    Ok(())
}

fn test_incorrect_share_gets_verified_complaint(
    seed: Randomness,
    dealer_secret_key_bytes: EphemeralSecretKeyBytes,
    dkg_id: IDkgId,
    threshold: NumberOfNodes,
    redundancy: NumberOfNodes,
    receiver_secret_keys: Vec<EphemeralSecretKeyBytes>,
) -> ValidTest<()> {
    // Key setup:
    let mut rng = ChaChaRng::from_seed(seed.get());
    let dealer_secret_key: EphemeralSecretKey = dealer_secret_key_bytes
        .try_into()
        .expect("Failed to generate dealer secret key bytes");
    let all_receiver_keys: Vec<(EphemeralPublicKeyBytes, EphemeralPopBytes)> = receiver_secret_keys
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, secret_key_bytes)| {
            let sender = format!("Node Number {}", index);
            create_ephemeral_public_key(&mut rng, dkg_id, &secret_key_bytes, &sender.as_bytes())
                .expect("Failed to generate test receiver public keys")
        })
        .collect();
    let receiver_keys = {
        let seed = Randomness::from(rng.gen::<[u8; 32]>());
        let number_of_keys = threshold + redundancy;
        select_n(seed, number_of_keys, &all_receiver_keys)
    };
    let (receiver_index, receiver_secret_key_bytes): (NodeIndex, EphemeralSecretKeyBytes) = (0..)
        .zip(&receiver_secret_keys)
        .zip(&receiver_keys)
        .filter_map(|((index, key), option)| option.map(|_| (index, key)))
        .choose(&mut rng)
        .map(|(index, key)| (index, *key))
        .unwrap();
    let receiver_secret_key = EphemeralSecretKey::try_from(&receiver_secret_key_bytes)
        .expect("Test setup failed: Malformed receiver secret key");

    // Dealing setup:
    let mut dealer_rng = ChaChaRng::from_seed(rng.gen::<[u8; 32]>());
    let mut complainer_rng = ChaChaRng::from_seed(rng.gen::<[u8; 32]>());
    let dealing = {
        let mut dealing1 = create_dealing(
            Randomness::from(dealer_rng.gen::<[u8; 32]>()),
            EphemeralSecretKeyBytes::from(&dealer_secret_key),
            dkg_id,
            threshold,
            &receiver_keys,
        )
        .expect("Error in test setup: dealing failed");
        let dealing2 = create_dealing(
            Randomness::from(dealer_rng.gen::<[u8; 32]>()),
            EphemeralSecretKeyBytes::from(&dealer_secret_key),
            dkg_id,
            threshold,
            &receiver_keys,
        )
        .expect("Error in test setup: dealing failed");
        let index = usize::try_from(receiver_index).expect("Failed to convert index to usize.");
        if dealing1.receiver_data[index] == dealing2.receiver_data[index] {
            if threshold == NumberOfNodes::from(0) {
                return Err(BadTest {
                    message: "The dealings are identical.  This is to be expected for threshold 0."
                        .to_string(),
                });
            } else {
                panic!("Two dealings yielded the same dealing; this suggests that dealings are not random.  This is probably not a problem with this test.  Please escalate.");
            }
        }
        dealing1.receiver_data[index] = dealing2.receiver_data[index];
        dealing1
    };
    verify_dealing(threshold, &receiver_keys, dealing.clone())
        .expect("Error in test setup: Verification failed");

    // Test:
    let receiver_public_key = EphemeralPublicKey::from(&receiver_secret_key);
    let receiver_public_key_bytes = &EphemeralPublicKeyBytes::from(&receiver_public_key);
    let dealer_public_key_bytes =
        &EphemeralPublicKeyBytes::from(EphemeralPublicKey::from(&dealer_secret_key));
    let complaint_bytes = complain_maybe(
        &mut complainer_rng,
        dkg_id,
        receiver_index,
        &receiver_secret_key,
        &receiver_public_key,
        dealer_public_key_bytes,
        &dealing,
    );

    let complaint_bytes = complaint_bytes.expect("Expected complaint generation to succeed");
    let complaint_bytes = complaint_bytes.expect("Expected point off curve to have complaint");

    let verification = verify_complaint(
        dkg_id,
        &dealing,
        receiver_index,
        &dealer_public_key_bytes,
        &receiver_public_key_bytes,
        &complaint_bytes,
    );
    verification.unwrap(); // CLibComplaint should be upheld; otherwise this
                           // will show how it
                           // failed.
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 2,
        max_shrink_iters: 0,
        .. ProptestConfig::default()
    })]

    #[test]
    fn honest_dealing_gets_no_complaints(
        seed: Randomness,
        dealer_secret_key_bytes: EphemeralSecretKeyBytes,
        dkg_id in arbitrary_types::dkg_id(),
        threshold in 0 as NodeIndex..4,
        redundancy in 0 as NodeIndex..4,
        receiver_secret_keys in proptest::collection::vec(any::<EphemeralSecretKeyBytes>(), 8..10),
    ) {
        prop_assume!(threshold + redundancy > 0);
        prop_assume!(test_honest_dealing_gets_no_complaints(seed, dealer_secret_key_bytes, dkg_id, NumberOfNodes::from(threshold), NumberOfNodes::from(redundancy), receiver_secret_keys).is_ok());
    }

    #[test]
    fn bad_share_gets_verified_complaint (
        seed: Randomness,
        dealer_secret_key_bytes: EphemeralSecretKeyBytes,
        dkg_id in arbitrary_types::dkg_id(),
        threshold in 1 as NodeIndex..4,
        redundancy in 0 as NodeIndex..4,
        receiver_secret_keys in proptest::collection::vec(any::<EphemeralSecretKeyBytes>(), 8..10),
    ) {
        prop_assume!(threshold + redundancy > 0);
        prop_assume!(test_incorrect_share_gets_verified_complaint(seed, dealer_secret_key_bytes, dkg_id, NumberOfNodes::from(threshold), NumberOfNodes::from(redundancy), receiver_secret_keys).is_ok());
    }
}
