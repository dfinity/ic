#![allow(clippy::unwrap_used)]
use super::super::api as tsig;
use super::super::crypto;
use super::super::test_utils::select_n;
use super::super::types::{
    CombinedSignatureBytes, IndividualSignature, IndividualSignatureBytes, SecretKeyBytes,
};
use ic_crypto_internal_types::sign::threshold_sig::public_coefficients::bls12_381::PublicCoefficientsBytes;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
use ic_types::{NumberOfNodes, Randomness};
use proptest::prelude::*;

mod util {
    use super::super::super::api as tsig;
    use super::super::super::types::SecretKeyBytes;
    use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::PublicCoefficientsBytes;
    use ic_types::crypto::CryptoResult;
    use ic_types::{NumberOfNodes, Randomness};

    /// Shim for tests that use the old API that generated keys for all
    /// participants. The new API generates only select keys.
    ///
    /// TODO(DFN-1412): Test scenarios where only some keys are generated
    pub fn keygen(
        seed: Randomness,
        threshold: NumberOfNodes,
        group_size: NumberOfNodes,
    ) -> CryptoResult<(PublicCoefficientsBytes, Vec<SecretKeyBytes>)> {
        let selection = &vec![true; group_size.get() as usize];
        tsig::keygen(seed, threshold, selection).map(|(public_coefficients, selected_keys)| {
            let all_keys: Vec<SecretKeyBytes> = selected_keys
                .into_iter()
                .map(|key_maybe| key_maybe.unwrap())
                .collect();
            (public_coefficients, all_keys)
        })
    }
}

/// Individual signatures should be verifiable
fn test_individual_signature_verifies(
    seed: Randomness,
    group_size: NumberOfNodes,
    threshold: NumberOfNodes,
    message: &[u8],
) {
    let (public_coefficients, secret_keys) =
        util::keygen(seed, threshold, group_size).expect("Failed to deal");
    for (index, secret_key) in (0..).zip(secret_keys) {
        let signature = tsig::sign_message(message, &secret_key).expect("Failed to sign");
        let public_key = tsig::individual_public_key(&public_coefficients, index)
            .expect("failed to generate public key");
        assert!(tsig::verify_individual_signature(message, signature, public_key).is_ok());
    }
}

fn test_combined_signature_verifies(
    seed: Randomness,
    group_size: NumberOfNodes,
    threshold: NumberOfNodes,
    message: &[u8],
) {
    let (public_coefficients, secret_keys) =
        util::keygen(seed, threshold, group_size).expect("Failed to deal");
    let signatures: Vec<IndividualSignatureBytes> = secret_keys
        .iter()
        .map(|secret_key| tsig::sign_message(message, secret_key).expect("Failed to sign"))
        .collect();
    let signatures = select_n(seed, threshold, &signatures);
    let signature =
        tsig::combine_signatures(&signatures, threshold).expect("Failed to combine signatures");
    let public_key =
        tsig::combined_public_key(&public_coefficients).expect("Failed to get combined public key");
    assert_eq!(
        tsig::verify_combined_signature(message, signature, public_key),
        Ok(())
    );
}

/// Assertion:  Computing with the external interface is equivalent to working
/// with the core library.
fn test_threshold_sig_api_and_core_match(
    seed: Randomness,
    group_size: NumberOfNodes,
    threshold: NumberOfNodes,
    message: &[u8],
) {
    let (core_public_coefficients, core_secret_keys) =
        crypto::tests::util::keygen(seed, threshold, group_size).expect("Core failed to deal");
    let (tsig_public_coefficients, tsig_secret_keys) =
        util::keygen(seed, threshold, group_size).expect("Threshold sig failed to deal");
    assert_eq!(
        PublicCoefficientsBytes::from(&core_public_coefficients),
        tsig_public_coefficients
    );
    assert_eq!(
        core_secret_keys
            .iter()
            .map(SecretKeyBytes::from)
            .collect::<Vec<_>>(),
        tsig_secret_keys
    );

    let core_signatures: Vec<IndividualSignature> = core_secret_keys
        .iter()
        .map(|secret_key| crypto::sign_message(message, secret_key))
        .collect();
    let tsig_signatures: Vec<IndividualSignatureBytes> = tsig_secret_keys
        .iter()
        .map(|secret_key| {
            tsig::sign_message(message, secret_key).expect("Threshold sig failed to sign")
        })
        .collect();
    assert_eq!(
        core_signatures
            .iter()
            .map(IndividualSignatureBytes::from)
            .collect::<Vec<_>>(),
        tsig_signatures
    );

    let core_signature_selection = select_n(seed, threshold, &core_signatures);
    let tsig_signature_selection = select_n(seed, threshold, &tsig_signatures);
    assert_eq!(
        core_signature_selection
            .iter()
            .map(|option| option.map(|signature| IndividualSignatureBytes::from(&signature)))
            .collect::<Vec<_>>(),
        tsig_signature_selection
    );

    let core_signature = crypto::combine_signatures(&core_signature_selection, threshold)
        .expect("Core failed to combine signatures");
    let tsig_signature = tsig::combine_signatures(&tsig_signature_selection, threshold)
        .expect("Threshold sig failed to combine signatures");
    assert_eq!(
        CombinedSignatureBytes::from(&core_signature),
        tsig_signature
    );

    let core_public_key = crypto::combined_public_key(&core_public_coefficients);
    let tsig_public_key = tsig::combined_public_key(&tsig_public_coefficients)
        .expect("Threshold sig failed to get combined public key");
    assert_eq!(PublicKeyBytes::from(core_public_key), tsig_public_key);

    assert_eq!(
        crypto::verify_combined_sig(message, core_signature, core_public_key),
        Ok(())
    );
    assert_eq!(
        tsig::verify_combined_signature(message, tsig_signature, tsig_public_key),
        Ok(())
    );
}

#[test]
fn test_public_key_to_der() {
    // Test vectors generated from Haskell as follows:
    // ic-ref/impl $ cabal repl ic-ref
    // …
    // Ok, 35 modules loaded.
    // *Main> import IC.Types (prettyBlob)
    // *Main IC.Types> import qualified IC.Crypto.DER as DER
    // *Main IC.Types DER> import qualified IC.Crypto.BLS as BLS
    // *Main IC.Types DER BLS> :set -XOverloadedStrings
    // *Main IC.Types DER BLS> let pk1 = BLS.toPublicKey (BLS.createKey "testseed1")
    // *Main IC.Types DER BLS> putStrLn (prettyBlob pk1)
    // 0xa7623a93cdb56c4d23d99c14216afaab3dfd6d4f9eb3db23d038280b6d5cb2caaee2a19dd92c9df7001dede23bf036bc0f33982dfb41e8fa9b8e96b5dc3e83d55ca4dd146c7eb2e8b6859cb5a5db815db86810b8d12cee1588b5dbf34a4dc9a5
    // *Main IC.Types DER BLS> putStrLn (prettyBlob (DER.encode DER.BLS pk1))
    // 0x308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100a7623a93cdb56c4d23d99c14216afaab3dfd6d4f9eb3db23d038280b6d5cb2caaee2a19dd92c9df7001dede23bf036bc0f33982dfb41e8fa9b8e96b5dc3e83d55ca4dd146c7eb2e8b6859cb5a5db815db86810b8d12cee1588b5dbf34a4dc9a5
    // *Main IC.Types DER BLS> let pk2 = BLS.toPublicKey (BLS.createKey "testseed2")
    // *Main IC.Types DER BLS> putStrLn (prettyBlob pk2)
    // 0xb613303bda180e6b474bc15183870828c54999ee3a4797c9dd00cabe59ce78e307b212884878ec437ae9fd73f5c1f13d01f34edf1e746c192f7f6e9614bc950b705b5d2825d87499c9778db2b032955badb5b4eb103b46b0f4fa476b45b784ed
    // *Main IC.Types DER BLS> putStrLn (prettyBlob (DER.encode DER.BLS pk2))
    // 0x308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100b613303bda180e6b474bc15183870828c54999ee3a4797c9dd00cabe59ce78e307b212884878ec437ae9fd73f5c1f13d01f34edf1e746c192f7f6e9614bc950b705b5d2825d87499c9778db2b032955badb5b4eb103b46b0f4fa476b45b784edu
    struct BlsPublicKey<'a> {
        raw_hex: &'a str,
        der_hex: &'a str,
    }

    let test_vectors = [
        BlsPublicKey {
            raw_hex: "a7623a93cdb56c4d23d99c14216afaab3dfd6d4f9eb3db23d038280b6d5cb2caaee2a19dd92c9df7001dede23bf036bc0f33982dfb41e8fa9b8e96b5dc3e83d55ca4dd146c7eb2e8b6859cb5a5db815db86810b8d12cee1588b5dbf34a4dc9a5",
            der_hex: "308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100a7623a93cdb56c4d23d99c14216afaab3dfd6d4f9eb3db23d038280b6d5cb2caaee2a19dd92c9df7001dede23bf036bc0f33982dfb41e8fa9b8e96b5dc3e83d55ca4dd146c7eb2e8b6859cb5a5db815db86810b8d12cee1588b5dbf34a4dc9a5"
        },
        BlsPublicKey {
            raw_hex: "b613303bda180e6b474bc15183870828c54999ee3a4797c9dd00cabe59ce78e307b212884878ec437ae9fd73f5c1f13d01f34edf1e746c192f7f6e9614bc950b705b5d2825d87499c9778db2b032955badb5b4eb103b46b0f4fa476b45b784ed",
            der_hex: "308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100b613303bda180e6b474bc15183870828c54999ee3a4797c9dd00cabe59ce78e307b212884878ec437ae9fd73f5c1f13d01f34edf1e746c192f7f6e9614bc950b705b5d2825d87499c9778db2b032955badb5b4eb103b46b0f4fa476b45b784ed"
        }
    ];

    for public_key in test_vectors.iter() {
        let mut bytes = [0u8; PublicKeyBytes::SIZE];
        bytes.copy_from_slice(&hex::decode(public_key.raw_hex).unwrap());
        let public_key_raw = PublicKeyBytes(bytes);
        let der = hex::decode(public_key.der_hex).unwrap();

        assert_eq!(tsig::public_key_to_der(public_key_raw).unwrap(), der);
        assert_eq!(public_key_raw, tsig::public_key_from_der(&der[..]).unwrap());

        let mut buf = der.clone();
        for i in 0..der.len() {
            buf[i] = !buf[i];
            assert_ne!(tsig::public_key_from_der(&buf), Ok(public_key_raw));
            buf[i] = !buf[i];
        }
    }
}

proptest! {
        #![proptest_config(ProptestConfig {
            cases: 4,
            .. ProptestConfig::default()
        })]

        #[test]
        fn individual_signature_verifies(seed: [u8;32], threshold in 0_u32..20, redundancy in 0_u32..20, message: Vec<u8>) {
            test_individual_signature_verifies(Randomness::from(seed), NumberOfNodes::from(threshold + redundancy), NumberOfNodes::from(threshold), &message);
        }
        #[test]
        fn combined_signature_verifies(seed: [u8;32], threshold in 0_u32..20, redundancy in 0_u32..20, message: Vec<u8>) {
            test_combined_signature_verifies(Randomness::from(seed), NumberOfNodes::from(threshold + redundancy), NumberOfNodes::from(threshold), &message);
        }
        #[test]
        fn threshold_sig_api_and_core_match(seed: [u8;32], threshold in 0_u32..10, redundancy in 0_u32..10, message: Vec<u8>) {
            test_threshold_sig_api_and_core_match(Randomness::from(seed), NumberOfNodes::from(threshold + redundancy), NumberOfNodes::from(threshold), &message);
        }
}

#[test]
fn should_use_correct_key_size_in_der_utils() {
    assert_eq!(
        ic_crypto_internal_threshold_sig_bls12381_der::KEY_SIZE,
        PublicKeyBytes::SIZE
    );
}
