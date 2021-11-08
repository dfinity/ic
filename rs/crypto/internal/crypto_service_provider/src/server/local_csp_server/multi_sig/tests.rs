//! Tests of Multi-Signature operations in the CSP server.
use crate::api::CspSigner;
use crate::secret_key_store::test_utils::TempSecretKeyStore;
use crate::server::api::{
    BasicSignatureCspServer, CspMultiSignatureError, CspMultiSignatureKeygenError,
    MultiSignatureCspServer,
};
use crate::server::local_csp_server::LocalCspServer;
use crate::Csp;
use ic_types::crypto::AlgorithmId;
use rand::{thread_rng, Rng, SeedableRng};
use rand_chacha::{ChaCha20Rng, ChaChaRng};
use strum::IntoEnumIterator;

#[test]
fn should_generate_key_ok() {
    let csp_server = csp_server_with_empty_key_store();

    assert!(csp_server
        .gen_key_pair_with_pop(AlgorithmId::MultiBls12_381)
        .is_ok());
}

#[test]
fn should_fail_to_generate_key_for_wrong_algorithm_id() {
    let csp_server = csp_server_with_empty_key_store();

    for algorithm_id in AlgorithmId::iter() {
        if algorithm_id != AlgorithmId::MultiBls12_381 {
            assert_eq!(
                csp_server.gen_key_pair_with_pop(algorithm_id).unwrap_err(),
                CspMultiSignatureKeygenError::UnsupportedAlgorithm {
                    algorithm: algorithm_id,
                }
            );
        }
    }
}

#[test]
fn should_generate_verifiable_pop() {
    let csp_server = csp_server_with_empty_key_store();
    let verifier = verifier();

    let (_key_id, public_key, pop) = csp_server
        .gen_key_pair_with_pop(AlgorithmId::MultiBls12_381)
        .expect("Failed to generate key pair with PoP");

    assert!(verifier
        .verify_pop(&pop, AlgorithmId::MultiBls12_381, public_key)
        .is_ok());
}

#[test]
fn should_sign_ok_with_generated_key() {
    let mut rng = thread_rng();
    let csp_server = csp_server_with_empty_key_store();

    let (key_id, _csp_pub_key, _csp_pop) = csp_server
        .gen_key_pair_with_pop(AlgorithmId::MultiBls12_381)
        .expect("failed to generate keys");

    let msg_len: usize = rng.gen_range(0, 1024);
    let msg: Vec<u8> = (0..msg_len).map(|_| rng.gen::<u8>()).collect();

    assert!(csp_server
        .multi_sign(AlgorithmId::MultiBls12_381, &msg, key_id)
        .is_ok());
}

#[test]
fn should_sign_verifiably_with_generated_key() {
    let mut rng = thread_rng();
    let csp_server = csp_server_with_empty_key_store();
    let verifier = verifier();

    let (key_id, csp_pub_key, csp_pop) = csp_server
        .gen_key_pair_with_pop(AlgorithmId::MultiBls12_381)
        .expect("failed to generate keys");

    let msg_len: usize = rng.gen_range(0, 1024);
    let msg: Vec<u8> = (0..msg_len).map(|_| rng.gen::<u8>()).collect();

    let sig = csp_server
        .multi_sign(AlgorithmId::MultiBls12_381, &msg, key_id)
        .expect("failed to generate signature");

    assert!(verifier
        .verify(&sig, &msg, AlgorithmId::MultiBls12_381, csp_pub_key.clone())
        .is_ok());

    assert!(verifier
        .verify_pop(&csp_pop, AlgorithmId::MultiBls12_381, csp_pub_key)
        .is_ok());
}

#[test]
fn should_fail_to_sign_with_unsupported_algorithm_id() {
    let csp_server = csp_server_with_empty_key_store();

    let (key_id, _csp_pub_key, _csp_pop) = csp_server
        .gen_key_pair_with_pop(AlgorithmId::MultiBls12_381)
        .expect("failed to generate keys");

    let msg = [31; 41];

    for algorithm_id in AlgorithmId::iter() {
        if algorithm_id != AlgorithmId::MultiBls12_381 {
            assert_eq!(
                csp_server
                    .multi_sign(algorithm_id, &msg, key_id)
                    .unwrap_err(),
                CspMultiSignatureError::UnsupportedAlgorithm {
                    algorithm: algorithm_id,
                }
            );
        }
    }
}

#[test]
fn should_fail_to_sign_if_secret_key_in_store_has_wrong_type() {
    let mut rng = thread_rng();
    let csp_server = csp_server_with_empty_key_store();

    let (key_id, _wrong_csp_pub_key) = csp_server
        .gen_key_pair(AlgorithmId::Ed25519)
        .expect("failed to generate keys");

    let msg_len: usize = rng.gen_range(0, 1024);
    let msg: Vec<u8> = (0..msg_len).map(|_| rng.gen::<u8>()).collect();

    let result = csp_server.multi_sign(AlgorithmId::MultiBls12_381, &msg, key_id);

    assert_eq!(
        result.unwrap_err(),
        CspMultiSignatureError::WrongSecretKeyType {
            algorithm: AlgorithmId::Ed25519
        }
    );
}

fn csp_server_with_empty_key_store() -> LocalCspServer<ChaCha20Rng, TempSecretKeyStore> {
    let key_store = TempSecretKeyStore::new();
    let csprng = ChaChaRng::from_seed(thread_rng().gen::<[u8; 32]>());
    LocalCspServer::new_for_test(csprng, key_store)
}

fn verifier() -> Csp<ChaCha20Rng, TempSecretKeyStore> {
    let dummy_key_store = TempSecretKeyStore::new();
    let csprng = ChaChaRng::from_seed(thread_rng().gen::<[u8; 32]>());
    Csp::of(csprng, dummy_key_store)
}
