//! Integration tests for the multisig lib public API

use ic_crypto_internal_multi_sig_bls12381 as multi_sig;
use ic_crypto_internal_multi_sig_bls12381::types::{
    CombinedSignatureBytes, IndividualSignatureBytes, PopBytes, PublicKeyBytes, SecretKeyBytes,
};
use ic_types::crypto::CryptoResult;
use proptest::prelude::*;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Proptest strategy for generating key pairs using the public API
fn key_pair_bytes() -> impl Strategy<Value = (SecretKeyBytes, PublicKeyBytes)> {
    any::<[u8; 32]>().prop_map(|seed| {
        let mut rng = ChaCha20Rng::from_seed(seed);
        multi_sig::keypair_from_rng(&mut rng)
    })
}

/// Proptest strategy for generating individual signatures using the public API
fn individual_signature_bytes() -> impl Strategy<Value = IndividualSignatureBytes> {
    (any::<[u8; 32]>(), any::<[u8; 8]>()).prop_map(|(seed, message)| {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let (secret_key, _public_key) = multi_sig::keypair_from_rng(&mut rng);
        multi_sig::sign(&message, &secret_key)
    })
}

/// Proptest strategy for generating PoPs using the public API
fn pop_bytes() -> impl Strategy<Value = PopBytes> {
    any::<[u8; 32]>().prop_map(|seed| {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let (secret_key, public_key) = multi_sig::keypair_from_rng(&mut rng);
        multi_sig::create_pop(&public_key, &secret_key).expect("Failed to create PoP")
    })
}

/// Proptest strategy for generating combined signatures using the public API
fn combined_signature_bytes() -> impl Strategy<Value = CombinedSignatureBytes> {
    individual_signature_bytes().prop_map(|signature| {
        multi_sig::combine(&[signature]).expect("Failed to combine signatures")
    })
}

fn test_happy_path(
    keys: &[(SecretKeyBytes, PublicKeyBytes)],
    message: &[u8],
) -> (
    Vec<IndividualSignatureBytes>,
    CombinedSignatureBytes,
    Vec<PublicKeyBytes>,
) {
    let pops: CryptoResult<Vec<PopBytes>> = keys
        .iter()
        .map(|(secret_key, public_key)| multi_sig::create_pop(public_key, secret_key))
        .collect();
    let signatures: Vec<IndividualSignatureBytes> = keys
        .iter()
        .map(|(secret_key, _)| multi_sig::sign(message, secret_key))
        .collect();
    let pops = pops.expect("PoP generation failed");
    let signature = multi_sig::combine(&signatures);
    let signature = signature.expect("Signature combination failed");
    let public_keys: Vec<PublicKeyBytes> = keys
        .iter()
        .map(|(_, public_key)| public_key)
        .copied()
        .collect();
    let pop_verification: CryptoResult<()> = public_keys
        .iter()
        .zip(pops)
        .try_for_each(|(public_key, pop)| multi_sig::verify_pop(&pop, public_key));
    let individual_verification: CryptoResult<()> = public_keys
        .iter()
        .zip(signatures.clone())
        .try_for_each(|(public_key, signature)| {
            multi_sig::verify_individual(message, &signature, public_key)
        });
    assert!(pop_verification.is_ok(), "PoP verification failed");
    assert!(
        individual_verification.is_ok(),
        "Individual signature verification failed"
    );
    assert!(
        multi_sig::verify_combined(message, &signature, &public_keys).is_ok(),
        "Signature verification failed"
    );
    (signatures, signature, public_keys)
}

// Slow tests
proptest! {
    #![proptest_config(ProptestConfig {
        cases: 5,
        .. ProptestConfig::default()
    })]

    #[test]
    fn multisig_verification_succeeds(
      keys in proptest::collection::vec(key_pair_bytes(), 1..10),
      message in proptest::collection::vec(any::<u8>(), 0..100),
    ) {
        test_happy_path(&keys, &message);
    }

    #[test]
    fn incorrect_individual_signature_fails(
      keys in key_pair_bytes(),
      message in proptest::collection::vec(any::<u8>(), 0..100),
      evil_signature in individual_signature_bytes()
    ) {
        let (secret_key, public_key) = keys;
        let signature = multi_sig::sign(&message, &secret_key);
        prop_assume!(evil_signature != signature);
        assert!(multi_sig::verify_individual(&message, &evil_signature, &public_key).is_err())
    }

    #[test]
    fn incorrect_pop_fails(
      keys in key_pair_bytes(),
      evil_pop in pop_bytes()
    ) {
        let (secret_key, public_key) = keys;
        let pop = multi_sig::create_pop(&public_key, &secret_key).expect("Failed to create PoP");
        prop_assume!(evil_pop != pop);
        assert!(multi_sig::verify_pop(&evil_pop, &public_key).is_err())
    }

    #[test]
    fn incorrect_combined_signature_fails(
      keys in proptest::collection::vec(key_pair_bytes(), 1..10),
      message in proptest::collection::vec(any::<u8>(), 0..100),
      evil_signature in combined_signature_bytes()
    ) {
        let (_signatures, signature, public_keys) = test_happy_path(&keys, &message);
        prop_assume!(evil_signature != signature);
        assert!(multi_sig::verify_combined(&message, &evil_signature, &public_keys).is_err())
    }
}
