//! Tests of the whole NiDKG protocol
use crate::public_key_store::mock_pubkey_store::MockPublicKeyStore;
use crate::public_key_store::{PublicKeySetOnceError, PublicKeyStore};
use crate::secret_key_store::test_utils::{MockSecretKeyStore, TempSecretKeyStore};
use crate::secret_key_store::SecretKeyStore;
use crate::vault::api::CspVault;
use crate::vault::local_csp_vault::LocalCspVault;
use crate::vault::test_utils;
use crate::vault::test_utils::local_csp_vault::new_local_csp_vault;
use crate::vault::test_utils::ni_dkg::fixtures::MockNetwork;
use ic_types_test_utils::ids::NODE_42;
use mockall::Sequence;
use proptest::prelude::*;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::io;
use std::sync::Arc;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 4,
        max_shrink_iters: 0,
        .. ProptestConfig::default()
    })]

    #[test]
    fn ni_dkg_should_work_with_all_players_acting_correctly(seed: [u8;32], network_size in MockNetwork::MIN_SIZE..MockNetwork::DEFAULT_MAX_SIZE, num_reshares in 0..4) {
      test_utils::ni_dkg::test_ni_dkg_should_work_with_all_players_acting_correctly(seed, network_size, num_reshares, new_local_csp_vault);
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 4,
        max_shrink_iters: 0,
        .. ProptestConfig::default()
    })]

    #[test]
    fn create_dealing_should_detect_errors(seed: [u8;32], network_size in MockNetwork::MIN_SIZE..=MockNetwork::DEFAULT_MAX_SIZE, num_reshares in 0..4) {
      test_utils::ni_dkg::test_create_dealing_should_detect_errors(seed, network_size, num_reshares, new_local_csp_vault);
    }
}

#[test]
fn test_retention() {
    test_utils::ni_dkg::test_retention(new_local_csp_vault);
}

#[test]
fn should_generate_dealing_encryption_key_pair_and_store_keys() {
    test_utils::ni_dkg::should_generate_dealing_encryption_key_pair_and_store_keys(
        new_local_csp_vault(),
    );
}

#[test]
fn should_store_dkg_dealing_encryption_secret_key_before_public_key() {
    let mut seq = Sequence::new();
    let mut sks = MockSecretKeyStore::new();
    sks.expect_insert()
        .times(1)
        .returning(|_key, _key_id, _scope| Ok(()))
        .in_sequence(&mut seq);
    let mut pks = MockPublicKeyStore::new();
    pks.expect_set_once_ni_dkg_dealing_encryption_pubkey()
        .times(1)
        .returning(|_key| Ok(()))
        .in_sequence(&mut seq);
    let vault = vault_with_node_secret_key_store_and_public_key_store(sks, pks);

    assert!(vault.gen_dealing_encryption_key_pair(NODE_42).is_ok());
}

#[test]
fn should_fail_with_internal_error_if_dkg_dealing_encryption_key_already_set() {
    let mut pks_returning_already_set_error = MockPublicKeyStore::new();
    pks_returning_already_set_error
        .expect_set_once_ni_dkg_dealing_encryption_pubkey()
        .returning(|_key| Err(PublicKeySetOnceError::AlreadySet));
    let vault = vault_with_public_key_store(pks_returning_already_set_error);
    test_utils::ni_dkg::should_fail_with_internal_error_if_ni_dkg_dealing_encryption_key_already_set(vault);
}

#[test]
fn should_fail_with_internal_error_if_dkg_dealing_encryption_key_generated_more_than_once() {
    let vault = new_local_csp_vault();
    test_utils::ni_dkg::should_fail_with_internal_error_if_dkg_dealing_encryption_key_generated_more_than_once(vault);
}

#[test]
fn should_fail_with_transient_internal_error_if_dkg_dealing_encryption_key_persistence_fails() {
    let mut pks_returning_io_error = MockPublicKeyStore::new();
    let io_error = io::Error::new(io::ErrorKind::Other, "oh no!");
    pks_returning_io_error
        .expect_set_once_ni_dkg_dealing_encryption_pubkey()
        .return_once(|_key| Err(PublicKeySetOnceError::Io(io_error)));
    let vault = vault_with_public_key_store(pks_returning_io_error);
    test_utils::ni_dkg::should_fail_with_transient_internal_error_if_dkg_dealing_encryption_key_persistence_fails(
        vault,
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
