//! Tests of Basic Signature operations in the CSP server.
use crate::api::CspSigner;
use crate::imported_test_utils::ed25519::csp_testvec;
use crate::secret_key_store::test_utils::TempSecretKeyStore;
use crate::secret_key_store::SecretKeyStore;
use crate::server::api::{
    BasicSignatureCspServer, CspBasicSignatureError, CspBasicSignatureKeygenError,
};
use crate::server::local_csp_server::LocalCspServer;
use crate::Csp;
use ic_crypto_internal_test_vectors::ed25519::Ed25519TestVector::RFC8032_ED25519_SHA_ABC;
use ic_types::crypto::{AlgorithmId, KeyId};
use ic_types::NumberOfNodes;
use rand::{thread_rng, Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use strum::IntoEnumIterator;

#[test]
fn should_generate_key_ok() {
    let csp_server = {
        let key_store = TempSecretKeyStore::new();
        let csprng = ChaChaRng::from_seed(thread_rng().gen::<[u8; 32]>());
        LocalCspServer::new_for_test(csprng, key_store)
    };

    assert!(csp_server.gen_key_pair(AlgorithmId::Ed25519).is_ok());
}

#[test]
fn should_fail_to_generate_key_for_wrong_algorithm_id() {
    let csp_server = {
        let key_store = TempSecretKeyStore::new();
        let csprng = ChaChaRng::from_seed(thread_rng().gen::<[u8; 32]>());
        LocalCspServer::new_for_test(csprng, key_store)
    };

    for algorithm_id in AlgorithmId::iter() {
        if algorithm_id != AlgorithmId::Ed25519 {
            assert_eq!(
                csp_server.gen_key_pair(algorithm_id).unwrap_err(),
                CspBasicSignatureKeygenError::UnsupportedAlgorithm {
                    algorithm: algorithm_id,
                }
            );
        }
    }
}

#[test]
fn should_correctly_sign_compared_to_testvec() {
    // Here we only test with a single test vector: an extensive test with the
    // entire test vector suite is done at the crypto lib level.

    let mut rng = thread_rng();

    let key_id = rng.gen::<[u8; 32]>();

    let (sk, _pk, msg, sig) = csp_testvec(RFC8032_ED25519_SHA_ABC);

    let csp_server = {
        let mut key_store = TempSecretKeyStore::new();

        key_store
            .insert(KeyId::from(key_id), sk, None)
            .expect("failed to insert key into SKS");

        let csprng = ChaChaRng::from_seed(rng.gen::<[u8; 32]>());
        LocalCspServer::new_for_test(csprng, key_store)
    };

    assert_eq!(
        csp_server
            .sign(AlgorithmId::Ed25519, &msg, KeyId::from(key_id))
            .expect("failed to create signature"),
        sig
    );
}

#[test]
fn should_sign_ok_with_generated_key() {
    let mut rng = thread_rng();

    let csp_server = {
        let key_store = TempSecretKeyStore::new();
        let csprng = ChaChaRng::from_seed(rng.gen::<[u8; 32]>());
        LocalCspServer::new_for_test(csprng, key_store)
    };

    let (key_id, _csp_pub_key) = csp_server
        .gen_key_pair(AlgorithmId::Ed25519)
        .expect("failed to generate keys");

    let msg_len: usize = rng.gen_range(0, 1024);
    let msg: Vec<u8> = (0..msg_len).map(|_| rng.gen::<u8>()).collect();

    assert!(csp_server.sign(AlgorithmId::Ed25519, &msg, key_id).is_ok());
}

#[test]
fn should_sign_verifiably_with_generated_key() {
    let mut rng = thread_rng();

    let csp_server = {
        let key_store = TempSecretKeyStore::new();
        let csprng = ChaChaRng::from_seed(rng.gen::<[u8; 32]>());
        LocalCspServer::new_for_test(csprng, key_store)
    };

    let (key_id, csp_pub_key) = csp_server
        .gen_key_pair(AlgorithmId::Ed25519)
        .expect("failed to generate keys");

    let msg_len: usize = rng.gen_range(0, 1024);
    let msg: Vec<u8> = (0..msg_len).map(|_| rng.gen::<u8>()).collect();

    let sig = csp_server
        .sign(AlgorithmId::Ed25519, &msg, key_id)
        .expect("failed to generate signature");

    let verifier = {
        let dummy_key_store = TempSecretKeyStore::new();
        let csprng = ChaChaRng::from_seed(rng.gen::<[u8; 32]>());
        Csp::of(csprng, dummy_key_store)
    };

    assert!(verifier
        .verify(&sig, &msg, AlgorithmId::Ed25519, csp_pub_key)
        .is_ok());
}

#[test]
fn should_fail_to_sign_with_unsupported_algorithm_id() {
    let csp_server = {
        let key_store = TempSecretKeyStore::new();
        let csprng = ChaChaRng::from_seed(thread_rng().gen::<[u8; 32]>());
        LocalCspServer::new_for_test(csprng, key_store)
    };

    let (key_id, _csp_pub_key) = csp_server
        .gen_key_pair(AlgorithmId::Ed25519)
        .expect("failed to generate keys");

    let msg = [31; 41];

    for algorithm_id in AlgorithmId::iter() {
        if algorithm_id != AlgorithmId::Ed25519 {
            assert_eq!(
                csp_server.sign(algorithm_id, &msg, key_id).unwrap_err(),
                CspBasicSignatureError::UnsupportedAlgorithm {
                    algorithm: algorithm_id,
                }
            );
        }
    }
}

#[test]
fn should_fail_to_sign_if_secret_key_in_store_has_wrong_type() {
    use crate::server::api::ThresholdSignatureCspServer;

    let mut rng = thread_rng();

    let csp_server = {
        let key_store = TempSecretKeyStore::new();
        let csprng = ChaChaRng::from_seed(rng.gen::<[u8; 32]>());
        LocalCspServer::new_for_test(csprng, key_store)
    };

    let threshold = NumberOfNodes::from(1);
    let (_pub_coeffs, key_ids) = csp_server
        .threshold_keygen_for_test(AlgorithmId::ThresBls12_381, threshold, &[true])
        .expect("failed to generate threshold sig keys");
    let key_id = key_ids[0].expect("threshold sig key not generated");

    let msg_len: usize = rng.gen_range(0, 1024);
    let msg: Vec<u8> = (0..msg_len).map(|_| rng.gen::<u8>()).collect();

    let result = csp_server.sign(AlgorithmId::Ed25519, &msg, key_id);

    assert_eq!(
        result.unwrap_err(),
        CspBasicSignatureError::WrongSecretKeyType {
            algorithm: AlgorithmId::ThresBls12_381
        }
    );
}
