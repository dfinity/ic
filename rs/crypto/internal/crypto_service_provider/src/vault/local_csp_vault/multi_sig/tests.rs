//! Tests of Multi-Signature operations in the CSP vault.
use std::sync::Arc;

use mockall::Sequence;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::public_key_store::mock_pubkey_store::MockPublicKeyStore;
use crate::public_key_store::{PublicKeySetOnceError, PublicKeyStore};
use crate::secret_key_store::test_utils::{MockSecretKeyStore, TempSecretKeyStore};
use crate::secret_key_store::SecretKeyStore;
use crate::vault::api::CspVault;
use crate::vault::test_utils;
use crate::vault::test_utils::local_csp_vault::new_local_csp_vault;
use crate::LocalCspVault;

#[test]
fn should_generate_committee_signing_key_pair_and_store_pubkey() {
    test_utils::multi_sig::should_generate_committee_signing_key_pair_and_store_pubkey(
        new_local_csp_vault(),
    );
}

#[test]
fn should_store_committee_signing_secret_key_before_public_key() {
    let mut seq = Sequence::new();
    let mut sks = MockSecretKeyStore::new();
    sks.expect_insert()
        .times(1)
        .returning(|_key, _key_id, _scope| Ok(()))
        .in_sequence(&mut seq);
    let mut pks = MockPublicKeyStore::new();
    pks.expect_set_once_committee_signing_pubkey()
        .times(1)
        .returning(|_key| Ok(()))
        .in_sequence(&mut seq);
    let vault = vault_with_node_secret_key_store_and_public_key_store(sks, pks);

    let _ = vault.gen_committee_signing_key_pair();
}

#[test]
fn should_fail_with_internal_error_if_committee_signing_key_already_set() {
    let mut pks_returning_already_set_error = MockPublicKeyStore::new();
    pks_returning_already_set_error
        .expect_set_once_committee_signing_pubkey()
        .returning(|_key| Err(PublicKeySetOnceError::AlreadySet));
    let vault = vault_with_public_key_store(pks_returning_already_set_error);
    test_utils::multi_sig::should_fail_with_internal_error_if_committee_signing_key_already_set(
        vault,
    );
}

#[test]
fn should_fail_with_internal_error_if_committee_signing_key_generated_more_than_once() {
    let vault = new_local_csp_vault();
    test_utils::multi_sig::should_fail_with_internal_error_if_committee_signing_key_generated_more_than_once(vault);
}

#[test]
fn should_fail_with_transient_internal_error_if_committee_signing_key_persistence_fails() {
    let mut pks_returning_io_error = MockPublicKeyStore::new();
    let io_error = std::io::Error::new(std::io::ErrorKind::Other, "oh no!");
    pks_returning_io_error
        .expect_set_once_committee_signing_pubkey()
        .return_once(|_key| Err(PublicKeySetOnceError::Io(io_error)));
    let vault = vault_with_public_key_store(pks_returning_io_error);
    test_utils::multi_sig::should_fail_with_transient_internal_error_if_committee_signing_key_persistence_fails(
        vault,
    );
}

#[test]
fn should_generate_verifiable_pop() {
    test_utils::multi_sig::should_generate_verifiable_pop(new_local_csp_vault());
}

#[test]
fn should_multi_sign_and_verify_with_generated_key() {
    test_utils::multi_sig::should_multi_sign_and_verify_with_generated_key(new_local_csp_vault());
}

#[test]
fn should_fail_to_multi_sign_with_unsupported_algorithm_id() {
    test_utils::multi_sig::should_not_multi_sign_with_unsupported_algorithm_id(
        new_local_csp_vault(),
    );
}

#[test]
fn should_fail_to_multi_sign_if_secret_key_in_store_has_wrong_type() {
    test_utils::multi_sig::should_not_multi_sign_if_secret_key_in_store_has_wrong_type(
        new_local_csp_vault(),
    );
}

fn vault_with_public_key_store<P: PublicKeyStore + 'static>(
    public_key_store: P,
) -> Arc<dyn CspVault> {
    let dummy_rng = ChaCha20Rng::seed_from_u64(42);
    let temp_sks = TempSecretKeyStore::new();
    let vault = LocalCspVault::new_for_test(dummy_rng, temp_sks, public_key_store);
    Arc::new(vault)
}

fn vault_with_node_secret_key_store_and_public_key_store<
    S: SecretKeyStore + 'static,
    P: PublicKeyStore + 'static,
>(
    node_secret_key_store: S,
    public_key_store: P,
) -> Arc<dyn CspVault> {
    let dummy_rng = ChaCha20Rng::seed_from_u64(42);
    let vault = LocalCspVault::new_for_test(dummy_rng, node_secret_key_store, public_key_store);
    Arc::new(vault)
}
