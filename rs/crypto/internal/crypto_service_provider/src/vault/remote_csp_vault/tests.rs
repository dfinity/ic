#![allow(clippy::unwrap_used)]
// TODO(CRP-1240): remove the clippy-exception above.
// TODO(CRP-1255): add tests with multiple clients.
// TODO(CRP-1259): add tests with timeouts.

use crate::secret_key_store::test_utils::TempSecretKeyStore;
use crate::vault::api::CspVault;
use crate::vault::remote_csp_vault::TarpcCspVaultServerImpl;
use crate::vault::test_utils;
use crate::vault::test_utils::sks::secret_key_store_containing_key_with_invalid_encoding;
use crate::vault::test_utils::sks::secret_key_store_containing_key_with_invalid_length;
use crate::vault::test_utils::sks::secret_key_store_with_error_on_insert;
use crate::LocalCspVault;
use crate::RemoteCspVault;
use crate::SecretKeyStore;
use ic_crypto_internal_csp_test_utils::remote_csp_vault::setup_listener;
use ic_crypto_internal_csp_test_utils::remote_csp_vault::start_new_remote_csp_vault_server_for_test;
use rand::{CryptoRng, Rng};
use std::sync::Arc;
use std::time::Duration;

fn new_remote_csp_vault(rt_handle: &tokio::runtime::Handle) -> Arc<dyn CspVault> {
    let socket_path = start_new_remote_csp_vault_server_for_test(rt_handle);
    let remote_csp_vault = RemoteCspVault::new(&socket_path, rt_handle.clone())
        .expect("Could not create RemoteCspVault");
    Arc::new(remote_csp_vault)
}

fn new_remote_csp_vault_with_local_csp_vault<
    R: Rng + CryptoRng + Send + Sync + 'static,
    S: SecretKeyStore + 'static,
    C: SecretKeyStore + 'static,
>(
    rt_handle: &tokio::runtime::Handle,
    local_csp_vault: Arc<LocalCspVault<R, S, C>>,
) -> Arc<dyn CspVault> {
    let (socket_path, sks_dir, listener) = setup_listener(rt_handle);
    let server = TarpcCspVaultServerImpl::new_for_test(local_csp_vault, listener);

    rt_handle.spawn(async move {
        let _move_temp_dir_here_to_ensure_it_is_not_cleaned_up = sks_dir;
        server.run().await;
    });
    let remote_csp_vault =
        RemoteCspVault::new_for_test(&socket_path, rt_handle.clone(), Duration::from_secs(10))
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
        RemoteCspVault::new_for_test(&socket_path, rt_handle.clone(), timeout)
            .expect("Could not create RemoteCspVault"),
    )
}

fn new_tokio_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().expect("failed to create runtime")
}

mod timeout {
    use super::*;
    use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors::CspDkgCreateFsKeyError;
    use ic_types::crypto::AlgorithmId;
    use ic_types::NodeId;
    use ic_types::PrincipalId;

    #[test]
    fn should_fail_with_deadline_exceeded() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault =
            new_csp_vault_for_test_with_timeout(Duration::from_millis(1), tokio_rt.handle());
        let node_id = NodeId::from(PrincipalId::new_node_test_id(1u64));
        let gen_key_result =
            csp_vault.gen_forward_secure_key_pair(node_id, AlgorithmId::NiDkg_Groth20_Bls12_381);

        assert!(matches!(gen_key_result,
            Err(CspDkgCreateFsKeyError::InternalError ( internal_error ))
            if internal_error.internal_error.contains("the request exceeded its deadline")
        ));
    }
}

mod basic_sig {
    use super::*;

    #[test]
    fn should_generate_ed25519_key_pair() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::basic_sig::should_generate_ed25519_key_pair(csp_vault);
    }

    #[test]
    fn should_fail_to_generate_key_for_wrong_algorithm_id() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::basic_sig::should_fail_to_generate_basic_sig_key_for_wrong_algorithm_id(
            csp_vault,
        );
    }

    #[test]
    fn should_sign_verifiably_with_generated_key() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::basic_sig::should_sign_and_verify_with_generated_ed25519_key_pair(csp_vault);
    }

    #[test]
    fn should_not_sign_with_unsupported_algorithm_id() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::basic_sig::should_not_basic_sign_with_unsupported_algorithm_id(csp_vault);
    }

    #[test]
    fn should_not_sign_with_non_existent_key() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::basic_sig::should_not_basic_sign_with_non_existent_key(csp_vault);
    }
}

mod multi_sig {
    use super::*;

    #[test]
    fn should_generate_key_ok() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::multi_sig::should_generate_multi_bls12_381_key_pair(csp_vault);
    }

    #[test]
    fn should_fail_to_generate_key_for_wrong_algorithm_id() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::multi_sig::should_fail_to_generate_multi_sig_key_for_wrong_algorithm_id(
            csp_vault,
        );
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
    use crate::vault::test_utils;
    use crate::vault::test_utils::ni_dkg::fixtures::MockNetwork;

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
}

mod tls_keygen {
    use super::*;
    use crate::vault::test_utils::local_csp_vault::new_local_csp_vault_with_secret_key_store;
    use crate::KeyId;
    use ic_types_test_utils::ids::node_test_id;

    #[test]
    fn should_insert_secret_key_into_key_store() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::tls::should_insert_secret_key_into_key_store(csp_vault);
    }

    #[test]
    fn should_fail_if_secret_key_insertion_yields_duplicate_error() {
        let tokio_rt = new_tokio_runtime();
        let duplicated_key_id = KeyId::from([42; 32]);
        let local_csp_vault = new_local_csp_vault_with_secret_key_store(
            secret_key_store_with_error_on_insert(duplicated_key_id),
        );
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
        let local_csp_vault = {
            let key_store = TempSecretKeyStore::new();
            LocalCspVault::new_for_test(
                test_utils::tls::csprng_seeded_with(test_utils::tls::FIXED_SEED),
                key_store,
            )
        };
        let tokio_rt = new_tokio_runtime();
        let remote_csp_vault =
            new_remote_csp_vault_with_local_csp_vault(tokio_rt.handle(), Arc::new(local_csp_vault));

        test_utils::tls::should_set_random_cert_serial_number(remote_csp_vault);
    }

    #[test]
    fn should_set_different_serial_numbers_for_multiple_certs() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_remote_csp_vault(tokio_rt.handle());
        test_utils::tls::should_set_different_serial_numbers_for_multiple_certs(csp_vault);
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
}

mod tls_sign {
    use super::*;
    use crate::vault::test_utils::local_csp_vault::new_local_csp_vault_with_secret_key_store;
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
        let local_csp_vault = new_local_csp_vault_with_secret_key_store(key_store);
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
        let local_csp_vault = new_local_csp_vault_with_secret_key_store(key_store);
        let tokio_rt = new_tokio_runtime();
        let remote_csp_vault =
            new_remote_csp_vault_with_local_csp_vault(tokio_rt.handle(), local_csp_vault);

        test_utils::tls::should_fail_to_sign_if_secret_key_in_store_has_invalid_length(
            key_id,
            remote_csp_vault,
        );
    }
}
