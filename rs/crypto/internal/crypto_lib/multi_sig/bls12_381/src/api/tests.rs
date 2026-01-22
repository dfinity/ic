//! Multisig lib API tests
use crate as multi_sig;
use crate::types::{
    CombinedSignatureBytes, IndividualSignatureBytes, PopBytes, PublicKeyBytes, SecretKeyBytes,
    arbitrary,
};
use ic_crypto_internal_seed::Seed;
use ic_types::crypto::CryptoResult;
use proptest::prelude::*;

/// This test checks that the functionality is consistent; the values are
/// not "correct" but they must never change.
#[test]
fn bls12_key_generation_is_stable() {
    let seed = Seed::from_bytes(&[42u8]);
    let (secret_key, public_key) = multi_sig::keypair_from_seed(seed);

    assert_eq!(
        hex::encode(secret_key.0.expose_secret()),
        "73481d06d01187a77fe0752b5d8ddffda57f1bbda3bd455b25a661290beafa49"
    );
    assert_eq!(
        hex::encode(public_key.0),
        "a0006d9c7a98d3267552f132cf2ddc9ebd13ff5913dbb02d756275edb9bdedb474ac511e911f544d5a892ede57db614f035c72f5c11f95ca1417be429ad2a5d7c4e4cd3a03fffb106d4e8fcc847955f11913a46cc65a9a8e012f61df9aa8b9bd"
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
        let signature = multi_sig::sign(&message, &secret_key);
        prop_assume!(evil_signature != signature);
        assert!(multi_sig::verify_individual(&message, &evil_signature, &public_key).is_err())
    }

    #[test]
    fn incorrect_pop_fails(
      keys in arbitrary::key_pair_bytes(),
      evil_pop in arbitrary::pop_bytes()
    ) {
        let (secret_key, public_key) = keys;
        let pop = multi_sig::create_pop(&public_key, &secret_key).expect("Failed to create PoP");
        prop_assume!(evil_pop != pop);
        assert!(multi_sig::verify_pop(&evil_pop, &public_key).is_err())
    }

    #[test]
    fn incorrect_combined_signature_fails(
      keys in proptest::collection::vec(arbitrary::key_pair_bytes(), 1..10),
      message in proptest::collection::vec(any::<u8>(), 0..100),
      evil_signature in arbitrary::combined_signature_bytes()
    ) {
        let (_signatures, signature, public_keys) = test_happy_path(&keys, &message);
        prop_assume!(evil_signature != signature);
        assert!(multi_sig::verify_combined(&message, &evil_signature, &public_keys).is_err())
    }
}
