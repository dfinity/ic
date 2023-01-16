//! Tests of Basic Signature operations in the CSP vault.
use crate::imported_test_utils::ed25519::csp_testvec;
use crate::key_id::KeyId;
use crate::public_key_store::mock_pubkey_store::MockPublicKeyStore;
use crate::public_key_store::PublicKeySetOnceError;
use crate::secret_key_store::temp_secret_key_store::TempSecretKeyStore;
use crate::secret_key_store::test_utils::MockSecretKeyStore;
use crate::secret_key_store::SecretKeyStore;
use crate::vault::api::{BasicSignatureCspVault, CspBasicSignatureError};
use crate::vault::local_csp_vault::LocalCspVault;
use crate::vault::test_utils;
use ic_crypto_internal_test_vectors::ed25519::Ed25519TestVector::RFC8032_ED25519_SHA_ABC;
use ic_types::crypto::AlgorithmId;
use ic_types::NumberOfNodes;
use mockall::Sequence;
use rand::{thread_rng, Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use std::io;

#[test]
fn should_generate_node_signing_key_pair_and_store_keys() {
    test_utils::basic_sig::should_generate_node_signing_key_pair_and_store_keys(
        LocalCspVault::builder().build_into_arc(),
    );
}

#[test]
fn should_store_node_signing_secret_key_before_public_key() {
    let mut seq = Sequence::new();
    let mut sks = MockSecretKeyStore::new();
    sks.expect_insert()
        .times(1)
        .returning(|_key, _key_id, _scope| Ok(()))
        .in_sequence(&mut seq);
    let mut pks = MockPublicKeyStore::new();
    pks.expect_set_once_node_signing_pubkey()
        .times(1)
        .returning(|_key| Ok(()))
        .in_sequence(&mut seq);
    let vault = LocalCspVault::builder()
        .with_node_secret_key_store(sks)
        .with_public_key_store(pks)
        .build_into_arc();

    assert!(vault.gen_node_signing_key_pair().is_ok());
}

#[test]
fn should_fail_with_internal_error_if_node_signing_key_already_set() {
    let mut pks_returning_already_set_error = MockPublicKeyStore::new();
    pks_returning_already_set_error
        .expect_set_once_node_signing_pubkey()
        .returning(|_key| Err(PublicKeySetOnceError::AlreadySet));
    let vault = LocalCspVault::builder()
        .with_public_key_store(pks_returning_already_set_error)
        .build_into_arc();
    test_utils::basic_sig::should_fail_with_internal_error_if_node_signing_key_already_set(vault);
}

#[test]
fn should_fail_with_internal_error_if_node_signing_key_generated_more_than_once() {
    let vault = LocalCspVault::builder().build_into_arc();
    test_utils::basic_sig::should_fail_with_internal_error_if_node_signing_key_generated_more_than_once(vault);
}

#[test]
fn should_fail_with_transient_internal_error_if_node_signing_key_persistence_fails() {
    let mut pks_returning_io_error = MockPublicKeyStore::new();
    let io_error = io::Error::new(io::ErrorKind::Other, "oh no!");
    pks_returning_io_error
        .expect_set_once_node_signing_pubkey()
        .return_once(|_key| Err(PublicKeySetOnceError::Io(io_error)));
    let vault = LocalCspVault::builder()
        .with_public_key_store(pks_returning_io_error)
        .build_into_arc();
    test_utils::basic_sig::should_fail_with_transient_internal_error_if_node_signing_key_persistence_fails(
        vault,
    );
}

#[test]
fn should_correctly_sign_compared_to_testvec() {
    // Here we only test with a single test vector: an extensive test with the
    // entire test vector suite is done at the crypto lib level.

    let mut rng = thread_rng();

    let key_id = rng.gen::<[u8; 32]>();

    let (sk, _pk, msg, sig) = csp_testvec(RFC8032_ED25519_SHA_ABC);

    let csp_vault = {
        let mut key_store = TempSecretKeyStore::new();

        key_store
            .insert(KeyId::from(key_id), sk, None)
            .expect("failed to insert key into SKS");

        let csprng = ChaChaRng::from_seed(rng.gen::<[u8; 32]>());
        LocalCspVault::builder()
            .with_rng(csprng)
            .with_node_secret_key_store(key_store)
            .build()
    };

    assert_eq!(
        csp_vault
            .sign(AlgorithmId::Ed25519, &msg, KeyId::from(key_id))
            .expect("failed to create signature"),
        sig
    );
}

#[test]
fn should_sign_verifiably_with_generated_node_signing_key() {
    test_utils::basic_sig::should_sign_verifiably_with_generated_node_signing_key(
        LocalCspVault::builder().build_into_arc(),
    );
}

#[test]
fn should_fail_to_sign_with_unsupported_algorithm_id() {
    test_utils::basic_sig::should_not_basic_sign_with_unsupported_algorithm_id(
        LocalCspVault::builder().build_into_arc(),
    );
}

#[test]
fn should_fail_to_sign_with_non_existent_key() {
    test_utils::basic_sig::should_not_basic_sign_with_non_existent_key(
        LocalCspVault::builder().build_into_arc(),
    );
}

#[test]
fn should_fail_to_sign_if_secret_key_in_store_has_wrong_type() {
    use crate::vault::api::ThresholdSignatureCspVault;

    let csp_vault = LocalCspVault::builder().build();

    let threshold = NumberOfNodes::from(1);
    let (_pub_coeffs, key_ids) = csp_vault
        .threshold_keygen_for_test(
            AlgorithmId::ThresBls12_381,
            threshold,
            NumberOfNodes::from(1),
        )
        .expect("failed to generate threshold sig keys");
    let key_id = key_ids[0];

    let mut rng = thread_rng();
    let msg_len: usize = rng.gen_range(0..1024);
    let msg: Vec<u8> = (0..msg_len).map(|_| rng.gen::<u8>()).collect();

    let result = csp_vault.sign(AlgorithmId::Ed25519, &msg, key_id);

    assert_eq!(
        result.expect_err("Unexpected success."),
        CspBasicSignatureError::WrongSecretKeyType {
            algorithm: AlgorithmId::Ed25519,
            secret_key_variant: "ThresBls12_381".to_string()
        }
    );
}

//slow tests
mod basic_sig_large_message {
    use super::*;

    #[test]
    fn should_sign_a_large_hundred_megabytes_message() {
        test_utils::basic_sig::should_sign_a_large_hundred_megabytes_message(
            LocalCspVault::builder().build_into_arc(),
        );
    }
}
