use crate::api::{CspSigner, CspThresholdSignError, ThresholdSignatureCspClient};
use crate::keygen::public_key_hash_as_key_id;
use crate::secret_key_store::test_utils::TempSecretKeyStore;
use crate::server::api::{
    BasicSignatureCspVault, CspBasicSignatureError, CspBasicSignatureKeygenError,
    CspMultiSignatureError, CspMultiSignatureKeygenError, CspVault, MultiSignatureCspVault,
};
use crate::types::{CspPublicCoefficients, CspPublicKey, CspSignature, ThresBls12_381_Signature};
use crate::Csp;
use ic_crypto_internal_basic_sig_ed25519 as ed25519;
use ic_crypto_internal_threshold_sig_bls12381::test_utils::select_n;
use ic_crypto_internal_threshold_sig_bls12381::types::public_coefficients::conversions::try_number_of_nodes_from_csp_pub_coeffs;
use ic_types::crypto::{AlgorithmId, KeyId};
use ic_types::{NodeIndex, NumberOfNodes, Randomness};
use rand::{thread_rng, Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use std::path::PathBuf;
use std::sync::Arc;
use strum::IntoEnumIterator;

// TODO(CRP-1290): add more structure, maybe rename to test_utils.rs

/// Creates a temporary file; it is the caller's responsibility to delete it
/// after use.
pub fn get_temp_file_path() -> PathBuf {
    // So, tempfile has no method for creating just the temporary file NAME,
    // instead, it suggests you create the file and then close it, to make sure
    // it gets deleted; but keep the path around.
    // (https://docs.rs/tempfile/3.2.0/tempfile/struct.TempPath.html#method.close)
    let tmp_file = tempfile::NamedTempFile::new().expect("Could not create temp file");
    let tmp_file = tmp_file.into_temp_path();
    let file_path = tmp_file.to_path_buf();
    tmp_file
        .close()
        .expect("Could not close temp file in order to make temp file name");
    file_path
}

fn multi_sig_verifier() -> impl CspSigner {
    let dummy_key_store = TempSecretKeyStore::new();
    let csprng = ChaChaRng::from_seed(thread_rng().gen::<[u8; 32]>());
    Csp::of(csprng, dummy_key_store)
}

pub fn should_generate_ed25519_key_pair(csp_vault: &dyn BasicSignatureCspVault) {
    let gen_key_result = csp_vault.gen_key_pair(AlgorithmId::Ed25519);
    assert!(gen_key_result.is_ok());
    let (key_id, pk) = gen_key_result.expect("Failed to unwrap key_id");
    match pk {
        CspPublicKey::Ed25519(_) => {}
        _ => panic!("Wrong CspPublicKey: {:?}", pk),
    }
    assert_eq!(key_id, public_key_hash_as_key_id(&pk));
}

pub fn should_fail_to_generate_basic_sig_key_for_wrong_algorithm_id(
    csp_vault: &dyn BasicSignatureCspVault,
) {
    for algorithm_id in AlgorithmId::iter() {
        if algorithm_id != AlgorithmId::Ed25519 {
            assert_eq!(
                csp_vault.gen_key_pair(algorithm_id).unwrap_err(),
                CspBasicSignatureKeygenError::UnsupportedAlgorithm {
                    algorithm: algorithm_id,
                }
            );
        }
    }
}

pub fn should_sign_and_verify_with_generated_ed25519_key_pair(
    csp_vault: &dyn BasicSignatureCspVault,
) {
    let (key_id, csp_pk) = csp_vault
        .gen_key_pair(AlgorithmId::Ed25519)
        .expect("failed to generate keys");
    let pk_bytes = match csp_pk {
        CspPublicKey::Ed25519(pk_bytes) => pk_bytes,
        _ => panic!("Wrong CspPublicKey: {:?}", csp_pk),
    };

    let mut rng = thread_rng();
    let msg_len: usize = rng.gen_range(0, 1024);
    let msg: Vec<u8> = (0..msg_len).map(|_| rng.gen::<u8>()).collect();

    let sign_result = csp_vault.sign(AlgorithmId::Ed25519, &msg, key_id);
    assert!(sign_result.is_ok());
    let signature = sign_result.expect("Failed to extract the signature");
    let signature_bytes = match signature {
        CspSignature::Ed25519(signature_bytes) => signature_bytes,
        _ => panic!("Wrong CspSignature: {:?}", signature),
    };
    assert!(ed25519::verify(&signature_bytes, &msg, &pk_bytes).is_ok());
}

pub fn should_not_basic_sign_with_unsupported_algorithm_id(csp_vault: &dyn BasicSignatureCspVault) {
    let (key_id, _) = csp_vault
        .gen_key_pair(AlgorithmId::Ed25519)
        .expect("failed to generate keys");

    let msg = "sample message";
    for algorithm_id in AlgorithmId::iter() {
        if algorithm_id != AlgorithmId::Ed25519 {
            let sign_result = csp_vault.sign(AlgorithmId::EcdsaP256, msg.as_ref(), key_id);
            assert!(sign_result.is_err());
            let err = sign_result.err().expect("Expected an error.");
            match err {
                CspBasicSignatureError::UnsupportedAlgorithm { .. } => {}
                _ => panic!("Expected UnsupportedAlgorithm, got {:?}", err),
            }
        }
    }
}

pub fn should_not_basic_sign_with_non_existent_key(csp_vault: &dyn BasicSignatureCspVault) {
    let mut rng = thread_rng();
    let (_, pk_bytes) = ed25519::keypair_from_rng(&mut rng);

    let key_id = public_key_hash_as_key_id(&CspPublicKey::Ed25519(pk_bytes));
    let msg = "some message";
    let sign_result = csp_vault.sign(AlgorithmId::Ed25519, msg.as_ref(), key_id);
    assert!(sign_result.is_err());
}

pub fn should_generate_multi_bls12_381_key_pair(csp_vault: &dyn MultiSignatureCspVault) {
    let gen_key_result = csp_vault.gen_key_pair_with_pop(AlgorithmId::MultiBls12_381);
    assert!(gen_key_result.is_ok());
    let (key_id, pk, _pop) = gen_key_result.expect("Failed to unwrap key_id");
    match pk {
        CspPublicKey::MultiBls12_381(_) => {}
        _ => panic!("Wrong CspPublicKey: {:?}", pk),
    }
    assert_eq!(key_id, public_key_hash_as_key_id(&pk));
}

pub fn should_fail_to_generate_multi_sig_key_for_wrong_algorithm_id(
    csp_vault: &dyn MultiSignatureCspVault,
) {
    for algorithm_id in AlgorithmId::iter() {
        if algorithm_id != AlgorithmId::MultiBls12_381 {
            assert_eq!(
                csp_vault.gen_key_pair_with_pop(algorithm_id).unwrap_err(),
                CspMultiSignatureKeygenError::UnsupportedAlgorithm {
                    algorithm: algorithm_id,
                }
            );
        }
    }
}

pub fn should_generate_verifiable_pop(csp_vault: &dyn MultiSignatureCspVault) {
    let (_key_id, public_key, pop) = csp_vault
        .gen_key_pair_with_pop(AlgorithmId::MultiBls12_381)
        .expect("Failed to generate key pair with PoP");

    let verifier = multi_sig_verifier();
    assert!(verifier
        .verify_pop(&pop, AlgorithmId::MultiBls12_381, public_key)
        .is_ok());
}

pub fn should_multi_sign_and_verify_with_generated_key(csp_vault: &dyn MultiSignatureCspVault) {
    let (key_id, csp_pub_key, csp_pop) = csp_vault
        .gen_key_pair_with_pop(AlgorithmId::MultiBls12_381)
        .expect("failed to generate keys");

    let mut rng = thread_rng();
    let msg_len: usize = rng.gen_range(0, 1024);
    let msg: Vec<u8> = (0..msg_len).map(|_| rng.gen::<u8>()).collect();

    let verifier = multi_sig_verifier();
    let sig = csp_vault
        .multi_sign(AlgorithmId::MultiBls12_381, &msg, key_id)
        .expect("failed to generate signature");

    assert!(verifier
        .verify(&sig, &msg, AlgorithmId::MultiBls12_381, csp_pub_key.clone())
        .is_ok());

    assert!(verifier
        .verify_pop(&csp_pop, AlgorithmId::MultiBls12_381, csp_pub_key)
        .is_ok());
}

pub fn should_not_multi_sign_with_unsupported_algorithm_id(csp_vault: &dyn MultiSignatureCspVault) {
    let (key_id, _csp_pub_key, _csp_pop) = csp_vault
        .gen_key_pair_with_pop(AlgorithmId::MultiBls12_381)
        .expect("failed to generate keys");

    let msg = [31; 41];

    for algorithm_id in AlgorithmId::iter() {
        if algorithm_id != AlgorithmId::MultiBls12_381 {
            assert_eq!(
                csp_vault
                    .multi_sign(algorithm_id, &msg, key_id)
                    .unwrap_err(),
                CspMultiSignatureError::UnsupportedAlgorithm {
                    algorithm: algorithm_id,
                }
            );
        }
    }
}

// NOTE: the trait below is just for "technical" reasons.  The argument
// `csp_vault` should have type `&(dyn MultiSignatureCspVault +
// BasicSignatureCspVault)`, but the compiler doesn't like it:
// error[E0225]:
//    only auto traits can be used as additional traits in a trait object
pub trait SignaturesTrait: BasicSignatureCspVault + MultiSignatureCspVault {}

pub fn should_not_multi_sign_if_secret_key_in_store_has_wrong_type(
    csp_vault: &dyn SignaturesTrait,
) {
    let (key_id, _wrong_csp_pub_key) = csp_vault
        .gen_key_pair(AlgorithmId::Ed25519)
        .expect("failed to generate keys");

    let msg = [31; 41];
    let result = csp_vault.multi_sign(AlgorithmId::MultiBls12_381, &msg, key_id);

    assert_eq!(
        result.unwrap_err(),
        CspMultiSignatureError::WrongSecretKeyType {
            algorithm: AlgorithmId::Ed25519
        }
    );
}

/// Test that a set of threshold signatures behaves correctly.
///
/// This assumes that a set of keys has been provided and verifies that:
/// * If the threshold signatures are used correctly, signatures verify.
/// * If incorrect values are provided at any stage, relevant methods fail.
/// Note: We assume that all signers have been dealt keys but disqualify
/// some as part of the test.
///
/// # Arguments
/// * `public_coefficients` is the public part of the threshold key.  This can
///   be used by third parties to verify individual and combined threshold
///   signatures.
/// * `signers` is the entities with the secret threshold keys.  For each signer
///   the array contains a reference to the signer's crypto service provider,
///   which contains the secret key, and the key identifier.
/// * `seed` is a source of randomness.
/// * `message` is a test message.
pub fn test_threshold_signatures(
    public_coefficients: &CspPublicCoefficients,
    signers: &[(Arc<dyn CspVault>, KeyId)],
    seed: Randomness,
    message: &[u8],
) {
    let mut rng = ChaChaRng::from_seed(seed.get());
    let threshold = try_number_of_nodes_from_csp_pub_coeffs(public_coefficients)
        .expect("Intolerable number of nodes");
    let incorrect_message = [&b"pound of flesh"[..], message].concat();

    // Signatures can be generated correctly:
    let signatures: Result<Vec<CspSignature>, CspThresholdSignError> = signers
        .iter()
        .map(|(csp_vault, key_id)| {
            csp_vault.threshold_sign(AlgorithmId::ThresBls12_381, message, *key_id)
        })
        .collect();
    let signatures = signatures.expect("Signing failed");
    {
        // But:
        // * Signatures cannot be generated with an incorrect AlgorithmId:
        for algorithm_id in AlgorithmId::iter() {
            if algorithm_id != AlgorithmId::ThresBls12_381 {
                if let Some((csp_vault, key_id)) = signers.get(0) {
                    assert!(
                        csp_vault
                            .threshold_sign(algorithm_id, message, *key_id)
                            .is_err(),
                        "Managed to threshold sign with algorithm ID {:?}",
                        algorithm_id
                    )
                }
            }
        }
        //
        // * Signatures cannot be generated with an incorrect key_id:
        if let Some((csp_vault, _key_id)) = signers.get(0) {
            let wrong_key_id = KeyId::from(rng.gen::<[u8; 32]>());
            let mut key_ids = signers.iter().map(|(_, key_id)| *key_id);

            assert!(
                !key_ids.any(|x| x == wrong_key_id),
                "Bad RNG: A randomly generated KeyId was in the list of keys"
            );
            assert!(
                csp_vault
                    .threshold_sign(AlgorithmId::ThresBls12_381, message, wrong_key_id)
                    .is_err(),
                "A randomly generated key_id managed to sign"
            );
        }
    }
    // Verify each individual signature:
    let verifier = {
        let dummy_key_store = TempSecretKeyStore::new();
        let csprng = ChaChaRng::from_seed(rng.gen::<[u8; 32]>());
        Csp::of(csprng, dummy_key_store)
    };
    for (index, signature) in signatures.iter().enumerate() {
        let public_key = match verifier.threshold_individual_public_key(
            AlgorithmId::ThresBls12_381,
            index as NodeIndex,
            (*public_coefficients).clone(),
        ) {
            Ok(public_key) => public_key,
            Err(error) => panic!("Could not calculate individual public key: {:?}", error),
        };

        // Correct values validate:
        assert_eq!(
            verifier.threshold_verify_individual_signature(
                AlgorithmId::ThresBls12_381,
                message,
                signature.clone(),
                public_key
            ),
            Ok(()),
            "Individual signature failed verification for signatory number {}/{}",
            index,
            signers.len()
        );

        // Mismatched public key fails to validate:
        if threshold > NumberOfNodes::from(1)
        // Otherwise all the secret keys are the same
        {
            // Here we mix up signatures and keys so that we are validating valid signatures
            // with valid public keys but the two are not matched.  We expect to see that if
            // the signature or (equivalently) the public key is wrong, validation fails.
            let wrong_index = (index + 1) % signers.len();
            let wrong_public_key = verifier
                .threshold_individual_public_key(
                    AlgorithmId::ThresBls12_381,
                    wrong_index as NodeIndex,
                    public_coefficients.clone(),
                )
                .expect("Should be able to compute the wrong public key.");
            assert!(
                verifier.threshold_verify_individual_signature(AlgorithmId::ThresBls12_381, message, signature.clone(), wrong_public_key).is_err(),
                "Individual signature verification accepted incorrect signatory {} instead of {}/{}",
                wrong_index,
                index,
                signers.len()
            );
        }
        // Incorrect message fails to validate:
        if threshold > NumberOfNodes::from(0)
        // threshold > 0 otherwise all signatures are the same
        {
            assert!(
                verifier.threshold_verify_individual_signature(AlgorithmId::ThresBls12_381, &incorrect_message, signature.clone(), public_key).is_err(),
                "Individual signature verification accepted incorrect message '{:?}' instead of '{:?}'",
                &incorrect_message,
                message
            );
        }
    }

    // Combine a random subset of signatures:
    let signature_selection = select_n(seed, threshold, &signatures);
    let signature = verifier
        .threshold_combine_signatures(
            AlgorithmId::ThresBls12_381,
            &signature_selection,
            public_coefficients.clone(),
        )
        .expect("Failed to combine signatures");

    // Correct values validate:
    assert_eq!(
        verifier.threshold_verify_combined_signature(
            AlgorithmId::ThresBls12_381,
            message,
            signature.clone(),
            public_coefficients.clone()
        ),
        Ok(())
    );

    // Incorrect values are rejected:
    if threshold > NumberOfNodes::from(0) {
        // threshold > 0, otherwise all signatures are the same.
        // Incorrect message:
        assert!(verifier
            .threshold_verify_combined_signature(
                AlgorithmId::ThresBls12_381,
                &incorrect_message,
                signature.clone(),
                public_coefficients.clone()
            )
            .is_err());
        // Incorrect signature:
        let incorrect_signature = {
            if let CspSignature::ThresBls12_381(ThresBls12_381_Signature::Combined(
                mut signature_bytes,
            )) = signature
            {
                signature_bytes.0[0] = !signature_bytes.0[0];
                CspSignature::ThresBls12_381(ThresBls12_381_Signature::Combined(signature_bytes))
            } else {
                unreachable!()
            }
        };
        assert!(verifier
            .threshold_verify_combined_signature(
                AlgorithmId::ThresBls12_381,
                message,
                incorrect_signature,
                public_coefficients.clone()
            )
            .is_err());
    }
    if threshold > NumberOfNodes::from(1) {
        // Otherwise all secret keys are the same.
        let some_individual_signature = signatures[0].clone();
        assert!(
            verifier.threshold_verify_combined_signature(
                AlgorithmId::ThresBls12_381,
                message,
                some_individual_signature.clone(),
                public_coefficients.clone()
            )
                .is_err(),
            "Combined signature verification passed with an individual signature: Used signature: {:?} Correct signature: {:?}",
            some_individual_signature,
            signature
        );
    }
}

/// Verify that the threshold signatures with basic key generation behave
/// correctly:
/// * Incorrect keygen arguments return an error:
///   * If the threshold is higher than the number of signers, keygen fails.
/// * Correct keygen arguments yield keys that behave correctly with regards to
///   signing and verification.
pub fn test_threshold_scheme_with_basic_keygen(
    seed: Randomness,
    csp_vault: Arc<dyn CspVault>,
    message: &[u8],
) {
    let mut rng = ChaChaRng::from_seed(seed.get());
    let threshold = NumberOfNodes::from(rng.gen_range(0, 10));
    let number_of_signers = NumberOfNodes::from(rng.gen_range(0, 10));
    println!(
        "--- threshold: {}, number_of_signers: {}",
        threshold, number_of_signers
    );
    match csp_vault.threshold_keygen_for_test(
        AlgorithmId::ThresBls12_381,
        threshold,
        &vec![true; number_of_signers.get() as usize],
    ) {
        Ok((public_coefficients, key_ids)) => {
            assert!(
                number_of_signers >= threshold,
                "Generated keys even though the threshold is too high"
            );

            let signers: Vec<_> = key_ids
                .iter()
                .map(|key_id_maybe| (csp_vault.clone(), key_id_maybe.expect("Missing key")))
                .collect();

            test_threshold_signatures(
                &public_coefficients,
                &signers,
                Randomness::from(rng.gen::<[u8; 32]>()),
                message,
            );
        }
        Err(_) => assert!(number_of_signers < threshold, "Failed to generate keys"),
    }
}

/// Key should be present only after key generation.
///
/// Note:  Theoretically the invariant is: The key should be present only in the
/// CSP that generated it, and only after generation and before deletion, if
/// deletion is supported for that key type.  Thus ideally there should be a
/// test that generates many sequences of events and verifies that this
/// invariant holds, regardless of the sequence of events, the number or type of
/// keys in the CSP and so on.  Making such a test is hard, so this is just one
/// sequence of events.
pub fn sks_should_contain_keys_only_after_generation(
    csp_vault1: &dyn CspVault,
    csp_vault2: &dyn CspVault,
) {
    let (key_id1, _public_key) = csp_vault1
        .gen_key_pair(AlgorithmId::Ed25519)
        .expect("Test setup failed: Failed to generate keys");
    assert!(
        csp_vault1.sks_contains(&key_id1),
        "Key should be present after generation."
    );
    assert!(
        !csp_vault2.sks_contains(&key_id1),
        "Key should be absent if not generated in the CSP."
    );

    let (key_id2, _public_key) = csp_vault2
        .gen_key_pair(AlgorithmId::Ed25519)
        .expect("Test setup failed: Failed to generate keys");
    assert!(
        key_id1 != key_id2,
        "Test failure: Key IDs from different CSPs were the same.  Check random number generation."
    );
    assert!(
        csp_vault2.sks_contains(&key_id2),
        "Key should be present in the CSP that generated it."
    );
    assert!(
        !csp_vault2.sks_contains(&key_id1),
        "The second CSP should not contain thekeys of the first."
    );
    assert!(
        !csp_vault1.sks_contains(&key_id2),
        "Key first CSP should not contain the keys of the second."
    );
}
