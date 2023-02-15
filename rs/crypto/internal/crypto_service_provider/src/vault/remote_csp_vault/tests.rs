#![allow(clippy::unwrap_used)]
// TODO(CRP-1240): remove the clippy-exception above.
// TODO(CRP-1255): add tests with multiple clients.
// TODO(CRP-1259): add tests with timeouts.

use crate::public_key_store::mock_pubkey_store::MockPublicKeyStore;
use crate::secret_key_store::mock_secret_key_store::MockSecretKeyStore;
use crate::vault::api::BasicSignatureCspVault;
use crate::vault::api::CspVault;
use crate::vault::remote_csp_vault::TarpcCspVaultServerImpl;
use crate::vault::test_utils;
use crate::vault::test_utils::sks::secret_key_store_containing_key_with_invalid_encoding;
use crate::vault::test_utils::sks::secret_key_store_containing_key_with_invalid_length;
use crate::vault::test_utils::sks::secret_key_store_with_duplicated_key_id_error_on_insert;
use crate::LocalCspVault;
use crate::RemoteCspVault;
use assert_matches::assert_matches;
use ic_crypto_internal_csp_test_utils::remote_csp_vault::setup_listener;
use ic_crypto_internal_csp_test_utils::remote_csp_vault::start_new_remote_csp_vault_server_for_test;
use rand::Rng;
use std::sync::Arc;
use std::time::Duration;

fn new_remote_csp_vault(rt_handle: &tokio::runtime::Handle) -> Arc<dyn CspVault> {
    let socket_path = start_new_remote_csp_vault_server_for_test(rt_handle);
    let remote_csp_vault = RemoteCspVault::new_for_test(&socket_path, rt_handle.clone(), None)
        .expect("Could not create RemoteCspVault");
    Arc::new(remote_csp_vault)
}

fn new_remote_csp_vault_with_local_csp_vault<C: CspVault + 'static>(
    rt_handle: &tokio::runtime::Handle,
    local_csp_vault: Arc<C>,
) -> Arc<dyn CspVault> {
    let (socket_path, sks_dir, listener) = setup_listener(rt_handle);
    let server = TarpcCspVaultServerImpl::new_for_test(local_csp_vault, listener);

    rt_handle.spawn(async move {
        let _move_temp_dir_here_to_ensure_it_is_not_cleaned_up = sks_dir;
        server.run().await;
    });
    let remote_csp_vault = RemoteCspVault::new_for_test(&socket_path, rt_handle.clone(), None)
        .expect("Could not create RemoteCspVault");
    Arc::new(remote_csp_vault)
}

// Starts a fresh CSP Vault server instance for testing, and creates a CSP Vault client
// that is connected to the server.  Returns the resulting `CspVault`-object, which will
// use the specified `timeout` when making RPC calls to the server.
fn new_csp_vault_for_test_with_timeout(
    timeout: Duration,
    rt_handle: &tokio::runtime::Handle,
) -> Arc<dyn CspVault> {
    let socket_path = start_new_remote_csp_vault_server_for_test(rt_handle);
    Arc::new(
        RemoteCspVault::new_for_test(&socket_path, rt_handle.clone(), Some(timeout))
            .expect("Could not create RemoteCspVault"),
    )
}

fn new_tokio_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().expect("failed to create runtime")
}

mod timeout {
    use super::*;
    use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors::CspDkgCreateFsKeyError;
    use ic_types::NodeId;
    use ic_types::PrincipalId;

    #[test]
    fn should_fail_with_deadline_exceeded() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault =
            new_csp_vault_for_test_with_timeout(Duration::from_millis(1), tokio_rt.handle());
        let node_id = NodeId::from(PrincipalId::new_node_test_id(1u64));
        let gen_key_result = csp_vault.gen_dealing_encryption_key_pair(node_id);

        assert_matches!(gen_key_result,
            Err(CspDkgCreateFsKeyError::TransientInternalError ( internal_error ))
            if internal_error.contains("the request exceeded its deadline")
        );
    }
}

mod multi_sig {
    use super::*;
    use crate::{
        public_key_store::{mock_pubkey_store::MockPublicKeyStore, PublicKeySetOnceError},
        secret_key_store::mock_secret_key_store::MockSecretKeyStore,
    };
    use mockall::Sequence;
    use std::io;

    #[test]
    fn should_generate_node_signing_key_pair_and_store_keys() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::multi_sig::should_generate_committee_signing_key_pair_and_store_keys(csp_vault);
    }

    #[test]
    fn should_generate_verifiable_pop() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::multi_sig::should_generate_verifiable_pop(csp_vault);
    }

    #[test]
    fn should_multi_sign_and_verify_with_generated_key() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::multi_sig::should_multi_sign_and_verify_with_generated_key(csp_vault);
    }

    #[test]
    fn should_fail_to_multi_sign_with_unsupported_algorithm_id() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::multi_sig::should_not_multi_sign_with_unsupported_algorithm_id(csp_vault);
    }

    #[test]
    fn should_fail_to_multi_sign_if_secret_key_in_store_has_wrong_type() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::multi_sig::should_not_multi_sign_if_secret_key_in_store_has_wrong_type(
            csp_vault,
        );
    }

    #[test]
    fn should_store_node_signing_secret_key_before_public_key() {
        let local_vault = {
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
            LocalCspVault::builder()
                .with_node_secret_key_store(sks)
                .with_public_key_store(pks)
                .build_into_arc()
        };
        let tokio_rt = new_tokio_runtime();
        let remote_vault =
            new_remote_csp_vault_with_local_csp_vault(tokio_rt.handle(), local_vault);

        let _ = remote_vault.gen_committee_signing_key_pair();
    }

    #[test]
    fn should_fail_with_internal_error_if_node_signing_key_already_set() {
        let local_vault = {
            let mut pks_returning_already_set_error = MockPublicKeyStore::new();
            pks_returning_already_set_error
                .expect_set_once_committee_signing_pubkey()
                .returning(|_key| Err(PublicKeySetOnceError::AlreadySet));
            LocalCspVault::builder()
                .with_public_key_store(pks_returning_already_set_error)
                .build_into_arc()
        };
        let tokio_rt = new_tokio_runtime();
        let remote_vault =
            new_remote_csp_vault_with_local_csp_vault(tokio_rt.handle(), local_vault);

        test_utils::multi_sig::should_fail_with_internal_error_if_committee_signing_key_already_set(
            remote_vault,
        );
    }

    #[test]
    fn should_fail_with_internal_error_if_node_signing_key_generated_more_than_once() {
        let tokio_rt = new_tokio_runtime();
        let vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::multi_sig::should_fail_with_internal_error_if_committee_signing_key_generated_more_than_once(vault);
    }

    #[test]
    fn should_fail_with_transient_internal_error_if_node_signing_key_persistence_fails() {
        let local_vault = {
            let mut pks_returning_io_error = MockPublicKeyStore::new();
            let io_error = io::Error::new(io::ErrorKind::Other, "oh no!");
            pks_returning_io_error
                .expect_set_once_committee_signing_pubkey()
                .return_once(|_key| Err(PublicKeySetOnceError::Io(io_error)));
            LocalCspVault::builder()
                .with_public_key_store(pks_returning_io_error)
                .build_into_arc()
        };
        let tokio_rt = new_tokio_runtime();
        let remote_vault =
            new_remote_csp_vault_with_local_csp_vault(tokio_rt.handle(), local_vault);

        test_utils::multi_sig::should_fail_with_transient_internal_error_if_committee_signing_key_persistence_fails(
            remote_vault,
        );
    }
}

mod threshold_sig {
    use super::*;
    use ic_crypto_internal_seed::Seed;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaChaRng;

    fn test_threshold_sigs(seed: [u8; 32]) {
        let tokio_rt = new_tokio_runtime();
        let mut rng = ChaChaRng::from_seed(seed);
        let message = rng.gen::<[u8; 32]>();
        test_utils::threshold_sig::test_threshold_scheme_with_basic_keygen(
            Seed::from_rng(&mut rng),
            new_remote_csp_vault(tokio_rt.handle()),
            &message,
        );
    }

    // TODO(CRP-1286): make a proptest instead of the manual repetition.
    #[test]
    fn test_threshold_scheme_with_basic_keygen_1() {
        test_threshold_sigs([5; 32]);
    }

    #[test]
    fn test_threshold_scheme_with_basic_keygen_2() {
        test_threshold_sigs([7; 32]);
    }

    #[test]
    fn test_threshold_scheme_with_basic_keygen_3() {
        test_threshold_sigs([9; 32]);
    }
}

mod secret_key_store {
    use super::*;

    #[test]
    fn key_should_be_present_only_after_generation() {
        let tokio_rt = new_tokio_runtime();
        let (vault_1, vault_2) = new_csp_vaults_for_test(tokio_rt.handle());

        test_utils::sks::sks_should_contain_keys_only_after_generation(vault_1, vault_2);
    }

    #[test]
    fn tls_key_should_be_present_only_after_generation() {
        let tokio_rt = new_tokio_runtime();
        let (vault_1, vault_2) = new_csp_vaults_for_test(tokio_rt.handle());

        test_utils::sks::sks_should_contain_tls_keys_only_after_generation(vault_1, vault_2);
    }

    fn new_csp_vaults_for_test(
        rt_handle: &tokio::runtime::Handle,
    ) -> (Arc<dyn CspVault>, Arc<dyn CspVault>) {
        let csp_vault_1 = new_remote_csp_vault(rt_handle);
        let csp_vault_2 = new_remote_csp_vault(rt_handle);
        (csp_vault_1, csp_vault_2)
    }
}

mod ni_dkg {
    use super::*;
    use crate::public_key_store::mock_pubkey_store::MockPublicKeyStore;
    use crate::public_key_store::PublicKeySetOnceError;
    use crate::secret_key_store::mock_secret_key_store::MockSecretKeyStore;
    use crate::vault::local_csp_vault::LocalCspVault;
    use crate::vault::test_utils;
    use crate::vault::test_utils::ni_dkg::fixtures::MockNetwork;
    use ic_types_test_utils::ids::NODE_42;
    use mockall::Sequence;
    use std::io;

    #[test]
    fn test_retention() {
        let tokio_rt = new_tokio_runtime();
        test_utils::ni_dkg::test_retention(|| new_remote_csp_vault(tokio_rt.handle()));
    }

    // TODO(CRP-1286): make a proptest instead of the manual repetition.
    #[test]
    fn ni_dkg_should_work_with_all_players_acting_correctly_1() {
        let tokio_rt = new_tokio_runtime();
        test_utils::ni_dkg::test_ni_dkg_should_work_with_all_players_acting_correctly(
            [1; 32],
            MockNetwork::MIN_SIZE,
            0,
            || new_remote_csp_vault(tokio_rt.handle()),
        );
    }
    #[test]
    fn ni_dkg_should_work_with_all_players_acting_correctly_2() {
        let tokio_rt = new_tokio_runtime();
        test_utils::ni_dkg::test_ni_dkg_should_work_with_all_players_acting_correctly(
            [2; 32],
            MockNetwork::MIN_SIZE + 1,
            1,
            || new_remote_csp_vault(tokio_rt.handle()),
        );
    }

    #[test]
    fn ni_dkg_should_work_with_all_players_acting_correctly_3() {
        let tokio_rt = new_tokio_runtime();
        test_utils::ni_dkg::test_ni_dkg_should_work_with_all_players_acting_correctly(
            [3; 32],
            MockNetwork::MIN_SIZE + 1,
            2,
            || new_remote_csp_vault(tokio_rt.handle()),
        );
    }

    // TODO(CRP-1286): make a proptest instead of the manual repetition.
    #[test]
    fn create_dealing_should_detect_errors_1() {
        let tokio_rt = new_tokio_runtime();
        test_utils::ni_dkg::test_create_dealing_should_detect_errors(
            [11; 32],
            MockNetwork::MIN_SIZE,
            0,
            || new_remote_csp_vault(tokio_rt.handle()),
        );
    }
    #[test]
    fn create_dealing_should_detect_errors_2() {
        let tokio_rt = new_tokio_runtime();
        test_utils::ni_dkg::test_create_dealing_should_detect_errors(
            [22; 32],
            MockNetwork::MIN_SIZE + 2,
            0,
            || new_remote_csp_vault(tokio_rt.handle()),
        );
    }
    #[test]
    fn create_dealing_should_detect_errors_3() {
        let tokio_rt = new_tokio_runtime();
        test_utils::ni_dkg::test_create_dealing_should_detect_errors(
            [33; 32],
            MockNetwork::DEFAULT_MAX_SIZE - 1,
            0,
            || new_remote_csp_vault(tokio_rt.handle()),
        );
    }

    #[test]
    fn should_generate_dealing_encryption_key_pair_and_store_keys() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::ni_dkg::should_generate_dealing_encryption_key_pair_and_store_keys(csp_vault);
    }

    #[test]
    fn should_store_dealing_encryption_secret_key_before_public_key() {
        let local_vault = {
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
            LocalCspVault::builder()
                .with_node_secret_key_store(sks)
                .with_public_key_store(pks)
                .build_into_arc()
        };
        let tokio_rt = new_tokio_runtime();
        let remote_vault =
            new_remote_csp_vault_with_local_csp_vault(tokio_rt.handle(), local_vault);

        assert!(remote_vault
            .gen_dealing_encryption_key_pair(NODE_42)
            .is_ok());
    }

    #[test]
    fn should_fail_with_internal_error_if_dealing_encryption_key_already_set() {
        let local_vault = {
            let mut pks_returning_already_set_error = MockPublicKeyStore::new();
            pks_returning_already_set_error
                .expect_set_once_ni_dkg_dealing_encryption_pubkey()
                .returning(|_key| Err(PublicKeySetOnceError::AlreadySet));
            LocalCspVault::builder()
                .with_public_key_store(pks_returning_already_set_error)
                .build_into_arc()
        };
        let tokio_rt = new_tokio_runtime();
        let remote_vault =
            new_remote_csp_vault_with_local_csp_vault(tokio_rt.handle(), local_vault);

        test_utils::ni_dkg::should_fail_with_internal_error_if_ni_dkg_dealing_encryption_key_already_set(
            remote_vault,
        );
    }

    #[test]
    fn should_fail_with_internal_error_if_dealing_encryption_key_generated_more_than_once() {
        let tokio_rt = new_tokio_runtime();
        let vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::ni_dkg::should_fail_with_internal_error_if_dkg_dealing_encryption_key_generated_more_than_once(
            vault);
    }

    #[test]
    fn should_fail_with_transient_internal_error_if_dealing_encryption_key_persistence_fails() {
        let local_vault = {
            let mut pks_returning_io_error = MockPublicKeyStore::new();
            let io_error = io::Error::new(io::ErrorKind::Other, "oh no!");
            pks_returning_io_error
                .expect_set_once_ni_dkg_dealing_encryption_pubkey()
                .return_once(|_key| Err(PublicKeySetOnceError::Io(io_error)));
            LocalCspVault::builder()
                .with_public_key_store(pks_returning_io_error)
                .build_into_arc()
        };
        let tokio_rt = new_tokio_runtime();
        let remote_vault =
            new_remote_csp_vault_with_local_csp_vault(tokio_rt.handle(), local_vault);

        test_utils::ni_dkg::should_fail_with_transient_internal_error_if_dkg_dealing_encryption_key_persistence_fails(
            remote_vault,
        );
    }
}

mod idkg {
    use super::*;
    use crate::public_key_store::PublicKeyAddError;
    use mockall::Sequence;

    #[test]
    fn should_generate_and_store_dealing_encryption_key_pair_multiple_times() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::idkg::should_generate_and_store_dealing_encryption_key_pair_multiple_times(
            csp_vault,
        );
    }

    #[test]
    fn should_store_idkg_secret_key_before_public_key() {
        let local_vault = {
            let mut seq = Sequence::new();
            let mut sks = MockSecretKeyStore::new();
            sks.expect_insert()
                .times(1)
                .returning(|_key, _key_id, _scope| Ok(()))
                .in_sequence(&mut seq);
            let mut pks = MockPublicKeyStore::new();
            pks.expect_add_idkg_dealing_encryption_pubkey()
                .times(1)
                .return_once(|_key| Ok(()))
                .in_sequence(&mut seq);
            LocalCspVault::builder()
                .with_node_secret_key_store(sks)
                .with_public_key_store(pks)
                .build_into_arc()
        };

        let tokio_rt = new_tokio_runtime();
        let remote_vault =
            new_remote_csp_vault_with_local_csp_vault(tokio_rt.handle(), local_vault);

        assert!(remote_vault.idkg_gen_dealing_encryption_key_pair().is_ok())
    }

    #[test]
    fn should_fail_with_transient_internal_error_if_storing_idkg_public_key_fails() {
        let local_vault = {
            let io_error = std::io::Error::new(std::io::ErrorKind::Other, "oh no!");
            let mut pks_returning_io_error = MockPublicKeyStore::new();
            pks_returning_io_error
                .expect_add_idkg_dealing_encryption_pubkey()
                .return_once(|_| Err(PublicKeyAddError::Io(io_error)));
            LocalCspVault::builder()
                .with_public_key_store(pks_returning_io_error)
                .build_into_arc()
        };
        let tokio_rt = new_tokio_runtime();
        let remote_vault =
            new_remote_csp_vault_with_local_csp_vault(tokio_rt.handle(), local_vault);

        test_utils::idkg::should_fail_with_transient_internal_error_if_storing_idkg_public_key_fails(remote_vault);
    }
}

mod tls_keygen {
    use std::io;

    use super::*;
    use crate::public_key_store::PublicKeySetOnceError;
    use crate::KeyId;
    use ic_types_test_utils::ids::node_test_id;
    use mockall::Sequence;

    /// Date in the past
    const NOT_AFTER: &str = "20211004235959Z";

    #[test]
    fn should_generate_tls_key_pair_and_store_certificate() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::tls::should_generate_tls_key_pair_and_store_certificate(csp_vault);
    }

    #[test]
    fn should_fail_if_secret_key_insertion_yields_duplicate_error() {
        let tokio_rt = new_tokio_runtime();
        let duplicated_key_id = KeyId::from([42; 32]);
        let secret_key_store =
            secret_key_store_with_duplicated_key_id_error_on_insert(duplicated_key_id);
        let local_csp_vault = LocalCspVault::builder()
            .with_node_secret_key_store(secret_key_store)
            .build_into_arc();
        let remote_csp_vault =
            new_remote_csp_vault_with_local_csp_vault(tokio_rt.handle(), local_csp_vault);

        test_utils::tls::should_fail_if_secret_key_insertion_yields_duplicate_error(
            remote_csp_vault,
            &duplicated_key_id,
        );
    }

    #[test]
    fn should_return_der_encoded_self_signed_certificate() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::tls::should_return_der_encoded_self_signed_certificate(csp_vault);
    }

    #[test]
    fn should_set_cert_subject_cn_as_node_id() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::tls::should_set_cert_subject_cn_as_node_id(csp_vault);
    }

    #[test]
    fn should_use_stable_node_id_string_representation_as_subject_cn() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::tls::should_use_stable_node_id_string_representation_as_subject_cn(csp_vault);
    }

    #[test]
    fn should_set_cert_issuer_cn_as_node_id() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::tls::should_set_cert_issuer_cn_as_node_id(csp_vault);
    }

    #[test]
    fn should_not_set_cert_subject_alt_name() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::tls::should_not_set_cert_subject_alt_name(csp_vault);
    }

    #[test]
    fn should_set_random_cert_serial_number() {
        let local_csp_vault = LocalCspVault::builder()
            .with_rng(test_utils::tls::csprng_seeded_with(
                test_utils::tls::FIXED_SEED,
            ))
            .build_into_arc();
        let tokio_rt = new_tokio_runtime();
        let remote_csp_vault =
            new_remote_csp_vault_with_local_csp_vault(tokio_rt.handle(), local_csp_vault);

        test_utils::tls::should_set_random_cert_serial_number(remote_csp_vault);
    }

    #[test]
    fn should_set_different_serial_numbers_for_multiple_certs() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault_factory = || new_remote_csp_vault(tokio_rt.handle());
        test_utils::tls::should_set_different_serial_numbers_for_multiple_certs(&csp_vault_factory);
    }

    #[test]
    fn should_set_cert_not_after_correctly() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::tls::should_set_cert_not_after_correctly(csp_vault);
    }

    #[test]
    fn should_fail_on_invalid_not_after_date() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        let result = csp_vault.gen_tls_key_pair(
            node_test_id(test_utils::tls::NODE_1),
            "invalid_not_after_date",
        );
        assert!(result.is_err());
    }

    #[test]
    fn should_fail_if_not_after_date_is_in_the_past() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        let date_in_the_past = "20211004235959Z";

        let result =
            csp_vault.gen_tls_key_pair(node_test_id(test_utils::tls::NODE_1), date_in_the_past);
        assert!(result.is_err());
    }

    #[test]
    fn should_store_tls_secret_key_before_certificate() {
        let local_vault = {
            let mut seq = Sequence::new();
            let mut sks = MockSecretKeyStore::new();
            sks.expect_insert()
                .times(1)
                .returning(|_key, _key_id, _scope| Ok(()))
                .in_sequence(&mut seq);
            let mut pks = MockPublicKeyStore::new();
            pks.expect_set_once_tls_certificate()
                .times(1)
                .returning(|_key| Ok(()))
                .in_sequence(&mut seq);
            LocalCspVault::builder()
                .with_node_secret_key_store(sks)
                .with_public_key_store(pks)
                .build_into_arc()
        };
        let tokio_rt = new_tokio_runtime();
        let remote_vault =
            new_remote_csp_vault_with_local_csp_vault(tokio_rt.handle(), local_vault);

        let _ = remote_vault.gen_tls_key_pair(node_test_id(test_utils::tls::NODE_1), NOT_AFTER);
    }

    #[test]
    fn should_fail_with_internal_error_if_node_signing_key_already_set() {
        let local_vault = {
            let mut pks_returning_already_set_error = MockPublicKeyStore::new();
            pks_returning_already_set_error
                .expect_set_once_tls_certificate()
                .returning(|_key| Err(PublicKeySetOnceError::AlreadySet));
            LocalCspVault::builder()
                .with_public_key_store(pks_returning_already_set_error)
                .build_into_arc()
        };
        let tokio_rt = new_tokio_runtime();
        let remote_vault =
            new_remote_csp_vault_with_local_csp_vault(tokio_rt.handle(), local_vault);

        test_utils::tls::should_fail_with_internal_error_if_tls_certificate_already_set(
            remote_vault,
        );
    }

    #[test]
    fn should_fail_with_internal_error_if_node_signing_key_generated_more_than_once() {
        let tokio_rt = new_tokio_runtime();
        let vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::tls::should_fail_with_internal_error_if_tls_certificate_generated_more_than_once(vault);
    }

    #[test]
    fn should_fail_with_transient_internal_error_if_node_signing_key_persistence_fails() {
        let local_vault = {
            let mut pks_returning_io_error = MockPublicKeyStore::new();
            let io_error = io::Error::new(io::ErrorKind::Other, "oh no!");
            pks_returning_io_error
                .expect_set_once_tls_certificate()
                .return_once(|_key| Err(PublicKeySetOnceError::Io(io_error)));
            LocalCspVault::builder()
                .with_public_key_store(pks_returning_io_error)
                .build_into_arc()
        };
        let tokio_rt = new_tokio_runtime();
        let remote_vault =
            new_remote_csp_vault_with_local_csp_vault(tokio_rt.handle(), local_vault);

        test_utils::tls::should_fail_with_transient_internal_error_if_tls_keygen_persistance_fails(
            remote_vault,
        );
    }
}

mod tls_sign {
    use super::*;
    use crate::KeyId;

    #[test]
    fn should_sign_with_valid_key() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::tls::should_sign_with_valid_key(csp_vault);
    }

    #[test]
    fn should_sign_verifiably() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::tls::should_sign_verifiably(csp_vault);
    }

    #[test]
    fn should_fail_to_sign_if_secret_key_not_found() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::tls::should_fail_to_sign_if_secret_key_not_found(csp_vault);
    }

    #[test]
    fn should_fail_to_sign_if_secret_key_in_store_has_wrong_type() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::tls::should_fail_to_sign_if_secret_key_in_store_has_wrong_type(csp_vault);
    }

    #[test]
    fn should_fail_to_sign_if_secret_key_in_store_has_invalid_encoding() {
        let key_id = KeyId::from([42; 32]);
        let key_store = secret_key_store_containing_key_with_invalid_encoding(key_id);
        let local_csp_vault = LocalCspVault::builder()
            .with_node_secret_key_store(key_store)
            .build_into_arc();
        let tokio_rt = new_tokio_runtime();
        let remote_csp_vault =
            new_remote_csp_vault_with_local_csp_vault(tokio_rt.handle(), local_csp_vault);

        test_utils::tls::should_fail_to_sign_if_secret_key_in_store_has_invalid_encoding(
            key_id,
            remote_csp_vault,
        );
    }

    #[test]
    fn should_fail_to_sign_if_secret_key_in_store_has_invalid_length() {
        let key_id = KeyId::from([43; 32]);
        let key_store = secret_key_store_containing_key_with_invalid_length(key_id);
        let local_csp_vault = LocalCspVault::builder()
            .with_node_secret_key_store(key_store)
            .build_into_arc();
        let tokio_rt = new_tokio_runtime();
        let remote_csp_vault =
            new_remote_csp_vault_with_local_csp_vault(tokio_rt.handle(), local_csp_vault);

        test_utils::tls::should_fail_to_sign_if_secret_key_in_store_has_invalid_length(
            key_id,
            remote_csp_vault,
        );
    }
}

mod public_key_store {
    use super::*;

    #[test]
    fn should_retrieve_current_public_keys() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::public_key_store::should_retrieve_current_public_keys(csp_vault);
    }

    #[test]
    fn should_retrieve_last_idkg_public_key() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::public_key_store::should_retrieve_last_idkg_public_key(csp_vault);
    }

    #[test]
    fn should_correctly_return_idkg_key_count_for_no_keys() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::public_key_store::should_correctly_return_idkg_dealing_encryption_pubkeys_count_for_no_keys(csp_vault);
    }

    #[test]
    fn should_correctly_return_idkg_key_count_for_single_key() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::public_key_store::should_correctly_return_idkg_dealing_encryption_pubkeys_count_for_single_key(
            csp_vault,
        );
    }

    #[test]
    fn should_correctly_return_idkg_key_count_for_two_keys() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::public_key_store::should_correctly_return_idkg_dealing_encryption_pubkeys_count_for_two_keys(
            csp_vault,
        );
    }

    #[test]
    fn should_correctly_return_idkg_key_count_when_all_other_keys_exist_except_idkg_key() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::public_key_store::should_correctly_return_idkg_dealing_encryption_pubkeys_count_when_all_other_keys_exist_except_idkg_key(
            csp_vault,
        );
    }

    mod current_node_public_keys_with_timestamps {
        use super::*;
        use crate::vault::test_utils::public_key_store::genesis_time_source;
        use ic_types::time::GENESIS;

        #[test]
        fn should_be_consistent_with_current_node_public_keys() {
            let tokio_rt = new_tokio_runtime();
            let csp_vault = new_remote_csp_vault(tokio_rt.handle());
            test_utils::public_key_store::should_be_consistent_with_current_node_public_keys(
                csp_vault,
            );
        }

        #[test]
        fn should_retrieve_timestamp_of_generated_idkg_public_key() {
            let local_vault = LocalCspVault::builder()
                .with_time_source(genesis_time_source())
                .build_into_arc();
            let tokio_rt = new_tokio_runtime();
            let csp_vault =
                new_remote_csp_vault_with_local_csp_vault(tokio_rt.handle(), local_vault);

            test_utils::public_key_store::should_retrieve_timestamp_of_generated_idkg_public_key(
                csp_vault, GENESIS,
            );
        }

        #[test]
        fn should_not_retrieve_timestamps_of_other_generated_keys_because_they_are_not_set_yet() {
            let tokio_rt = new_tokio_runtime();
            let csp_vault = new_remote_csp_vault(tokio_rt.handle());
            test_utils::public_key_store::should_not_retrieve_timestamps_of_other_generated_keys_because_they_are_not_set_yet(
                csp_vault,
            );
        }
    }
}

mod public_seed {
    use super::*;
    use ic_crypto_internal_seed::Seed;
    use rand::thread_rng;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn remote_csp_vault_should_generate_correct_public_seeds() {
        let tokio_rt = new_tokio_runtime();
        let mut csprng = ChaCha20Rng::from_seed(thread_rng().gen::<[u8; 32]>());
        let vault = LocalCspVault::builder()
            .with_rng(csprng.clone())
            .build_into_arc();
        let expected_seeds: Vec<_> = (0..10)
            .map(|_| {
                let intermediate_seed: [u8; 32] = csprng.gen();
                Seed::from_bytes(&intermediate_seed)
            })
            .collect();
        let csp_vault = new_remote_csp_vault_with_local_csp_vault(tokio_rt.handle(), vault);
        test_utils::public_seed::should_generate_particular_seeds(csp_vault, expected_seeds);
    }
}

mod logging {
    use super::*;
    use crate::CryptoMetrics;
    use ic_logger::ReplicaLogger;
    use ic_test_utilities_in_memory_logger::assertions::LogEntriesAssert;
    use ic_test_utilities_in_memory_logger::InMemoryReplicaLogger;
    use slog::Level;

    #[test]
    fn should_log_payload_size_transmitted_over_rpc_socket() {
        let in_memory_logger = InMemoryReplicaLogger::new();
        let tokio_rt = new_tokio_runtime();
        let socket_path = start_new_remote_csp_vault_server_for_test(tokio_rt.handle());
        let csp_vault = RemoteCspVault::new(
            &socket_path,
            tokio_rt.handle().clone(),
            ReplicaLogger::from(&in_memory_logger),
            Arc::new(CryptoMetrics::none()),
        )
        .expect("failed instantiating remote CSP vault client");

        csp_vault
            .gen_node_signing_key_pair()
            .expect("failed to generate keys");

        let logs = in_memory_logger.drain_logs();

        LogEntriesAssert::assert_that(logs)
            .has_len(3)
            .has_only_one_message_containing(&Level::Debug, "Instantiated remote CSP vault client")
            .has_only_one_message_containing(
                &Level::Debug,
                "CSP vault client sent 37 bytes (request to 'gen_node_signing_key_pair')",
            )
            .has_only_one_message_containing(
                &Level::Debug,
                "CSP vault client received 38 bytes (response of 'gen_node_signing_key_pair')",
            );
    }
}

mod pks_and_sks {
    use super::*;

    #[test]
    fn should_return_success_for_pks_and_sks_contains_if_all_keys_match_with_one_idkg_key() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::pks_and_sks::should_return_success_for_pks_and_sks_contains_if_all_keys_match_with_one_idkg_key(csp_vault);
    }

    #[test]
    fn should_return_success_for_pks_and_sks_contains_if_all_keys_match_with_multiple_idkg_keys() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::pks_and_sks::should_return_success_for_pks_and_sks_contains_if_all_keys_match_with_multiple_idkg_keys(csp_vault);
    }

    #[test]
    fn should_return_success_for_pks_and_sks_contains_if_all_keys_match_with_multiple_idkg_keys_and_external_key_not_first_in_vector(
    ) {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::pks_and_sks::should_return_success_for_pks_and_sks_contains_if_all_keys_match_with_multiple_idkg_keys_and_external_key_not_first_in_vector(csp_vault);
    }

    #[test]
    fn should_return_success_for_pks_and_sks_contains_if_all_keys_match_where_idkg_keys_have_different_timestamps(
    ) {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::pks_and_sks::should_return_success_for_pks_and_sks_contains_if_all_keys_match_where_idkg_keys_have_different_timestamps(csp_vault);
    }

    #[test]
    fn should_return_error_for_pks_and_sks_contains_if_no_keys_match() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        let shadow_csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::pks_and_sks::should_return_error_for_pks_and_sks_contains_if_no_keys_match(
            csp_vault,
            shadow_csp_vault,
        );
    }

    #[test]
    fn should_return_error_for_pks_and_sks_contains_if_node_signing_key_does_not_match() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        let shadow_csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::pks_and_sks::should_return_error_for_pks_and_sks_contains_if_node_signing_key_does_not_match(csp_vault, shadow_csp_vault);
    }

    #[test]
    fn should_return_error_for_pks_and_sks_contains_if_committee_signing_key_does_not_match() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        let shadow_csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::pks_and_sks::should_return_error_for_pks_and_sks_contains_if_committee_signing_key_does_not_match(csp_vault, shadow_csp_vault);
    }

    #[test]
    fn should_return_error_for_pks_and_sks_contains_if_dkg_dealing_encryption_key_does_not_match() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        let shadow_csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::pks_and_sks::should_return_error_for_pks_and_sks_contains_if_dkg_dealing_encryption_key_does_not_match(csp_vault, shadow_csp_vault);
    }

    #[test]
    fn should_return_error_for_pks_and_sks_contains_if_tls_certificate_does_not_match() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        let shadow_csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::pks_and_sks::should_return_error_for_pks_and_sks_contains_if_tls_certificate_does_not_match(csp_vault, shadow_csp_vault);
    }

    #[test]
    fn should_return_error_for_pks_and_sks_contains_if_idkg_dealing_encryption_key_does_not_match()
    {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        let shadow_csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::pks_and_sks::should_return_error_for_pks_and_sks_contains_if_idkg_dealing_encryption_key_does_not_match(csp_vault, shadow_csp_vault);
    }

    #[test]
    fn should_return_error_for_pks_and_sks_contains_if_external_node_signing_key_is_malformed() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::pks_and_sks::should_return_error_for_pks_and_sks_contains_if_external_node_signing_key_is_malformed(csp_vault);
    }

    #[test]
    fn should_return_error_for_pks_and_sks_contains_if_external_committee_signing_key_is_malformed()
    {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::pks_and_sks::should_return_error_for_pks_and_sks_contains_if_external_committee_signing_key_is_malformed(csp_vault);
    }

    #[test]
    fn should_return_error_for_pks_and_sks_contains_if_external_dkg_dealing_encryption_key_is_malformed(
    ) {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::pks_and_sks::should_return_error_for_pks_and_sks_contains_if_external_dkg_dealing_encryption_key_is_malformed(csp_vault);
    }

    #[test]
    fn should_return_error_for_pks_and_sks_contains_if_external_tls_certificate_is_malformed() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::pks_and_sks::should_return_error_for_pks_and_sks_contains_if_external_tls_certificate_is_malformed(csp_vault);
    }

    #[test]
    fn should_return_error_for_pks_and_sks_contains_if_external_idkg_dealing_encryption_key_is_malformed(
    ) {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::pks_and_sks::should_return_error_for_pks_and_sks_contains_if_external_idkg_dealing_encryption_key_is_malformed(csp_vault);
    }
}
