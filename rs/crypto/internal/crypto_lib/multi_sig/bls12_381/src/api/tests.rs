//! Multisig lib API tests
use crate as multi_sig;
use crate::types::{
    arbitrary, CombinedSignatureBytes, IndividualSignatureBytes, PopBytes, PublicKeyBytes,
    SecretKeyBytes,
};
use ic_crypto_internal_test_vectors::unhex::{hex_to_32_bytes, hex_to_96_bytes};
use ic_types::crypto::CryptoResult;
use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

/// This test checks that the functionality is consistent; the values are
/// not "correct" but they must never change.
#[test]
fn bls12_key_generation_is_stable() {
    let mut csprng = ChaCha20Rng::seed_from_u64(42);
    let (secret_key, public_key) = multi_sig::keypair_from_rng(&mut csprng);

    assert_eq!(
        secret_key,
        SecretKeyBytes(hex_to_32_bytes(
            "54ee2937b4dfc1905ccaf277a60b5e53c7ea791f6b9bdadd7e84e7f458d4d0a4"
        ))
    );
    assert_eq!(
        public_key,
        PublicKeyBytes(hex_to_96_bytes("986b177ef16c61c633e13769c42b079791cfa9702decd36eeb347be21bd98e8d1c4d9f2a1f16f2e09b995ae7ff856a830d382d0081c6ae253a7d2abf97de945f70a42e677ca30b129bcd08c91f78f8573fe2463a86afacf870e9fe4960f5c55f"))

        );
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
        .map(|(secret_key, public_key)| multi_sig::create_pop(*public_key, *secret_key))
        .collect();
    let signatures: CryptoResult<Vec<IndividualSignatureBytes>> = keys
        .iter()
        .map(|(secret_key, _)| multi_sig::sign(message, *secret_key))
        .collect();
    let pops = pops.expect("PoP generation failed");
    let signatures = signatures.expect("Signature generation failed");
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
        .try_for_each(|(public_key, pop)| multi_sig::verify_pop(pop, *public_key));
    let individual_verification: CryptoResult<()> = public_keys
        .iter()
        .zip(signatures.clone())
        .try_for_each(|(public_key, signature)| {
            multi_sig::verify_individual(message, signature, *public_key)
        });
    assert!(pop_verification.is_ok(), "PoP verification failed");
    assert!(
        individual_verification.is_ok(),
        "Individual signature verification failed"
    );
    assert!(
        multi_sig::verify_combined(message, signature, &public_keys).is_ok(),
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
      keys in proptest::collection::vec(arbitrary::key_pair_bytes(), 1..10),
      message in proptest::collection::vec(any::<u8>(), 0..100),
    ) {
        test_happy_path(&keys, &message);
    }

    #[test]
    fn incorrect_individual_signature_fails(
      keys in arbitrary::key_pair_bytes(),
      message in proptest::collection::vec(any::<u8>(), 0..100),
      evil_signature in arbitrary::individual_signature_bytes()
    ) {
        let (secret_key, public_key) = keys;
        let signature = multi_sig::sign(&message, secret_key).expect("Failed to sign");
        prop_assume!(evil_signature != signature);
        assert!(multi_sig::verify_individual(&message, evil_signature, public_key).is_err())
    }

    #[test]
    fn incorrect_pop_fails(
      keys in arbitrary::key_pair_bytes(),
      evil_pop in arbitrary::pop_bytes()
    ) {
        let (secret_key, public_key) = keys;
        let pop = multi_sig::create_pop(public_key, secret_key).expect("Failed to create PoP");
        prop_assume!(evil_pop != pop);
        assert!(multi_sig::verify_pop(evil_pop, public_key).is_err())
    }

    #[test]
    fn incorrect_combined_signature_fails(
      keys in proptest::collection::vec(arbitrary::key_pair_bytes(), 1..10),
      message in proptest::collection::vec(any::<u8>(), 0..100),
      evil_signature in arbitrary::combined_signature_bytes()
    ) {
        let (_signatures, signature, public_keys) = test_happy_path(&keys, &message);
        prop_assume!(evil_signature != signature);
        assert!(multi_sig::verify_combined(&message, evil_signature, &public_keys).is_err())
    }
}
