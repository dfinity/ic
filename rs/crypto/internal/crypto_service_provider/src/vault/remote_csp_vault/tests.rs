#![allow(clippy::unwrap_used)]
// TODO(CRP-1240): remove the clippy-exception above.
// TODO(CRP-1255): add tests with multiple clients.
// TODO(CRP-1259): add tests with timeouts.

use crate::vault::api::CspVault;
use crate::vault::test_utils;
use crate::RemoteCspVault;
use ic_crypto_internal_csp_test_utils::remote_csp_vault::start_new_remote_csp_vault_server_for_test;
use std::sync::Arc;
use std::time::Duration;

// Starts a fresh CSP Vault server instance for testing, and creates a CSP Vault client
// that is connected to the server.  Returns the resulting `CspVault`-object.
fn new_csp_vault_for_test() -> Arc<dyn CspVault> {
    let socket_path = start_new_remote_csp_vault_server_for_test();
    Arc::new(RemoteCspVault::new(&socket_path).expect("Could not create RemoteCspVault"))
}

// Starts a fresh CSP Vault server instance for testing, and creates a CSP Vault client
// that is connected to the server.  Returns the resulting `CspVault`-object, which will
// use the specified `timeout` when making RPC calls to the server.
fn new_csp_vault_for_test_with_timeout(timeout: Duration) -> Arc<dyn CspVault> {
    let socket_path = start_new_remote_csp_vault_server_for_test();
    Arc::new(
        RemoteCspVault::new_for_test(&socket_path, timeout)
            .expect("Could not create RemoteCspVault"),
    )
}
mod thread_blocking {
    use super::super::tarpc_csp_vault_client::thread_universal_block_on;

    async fn async_function() -> String {
        if tokio::runtime::Handle::try_current().is_ok() {
            "tokio".to_string()
        } else {
            "std".to_string()
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_block_on_tokio_thread() {
        assert_eq!(thread_universal_block_on(async_function()), "tokio");
    }

    #[test]
    fn should_block_on_std_thread() {
        let join_handle = std::thread::spawn(move || async_function());
        assert_eq!(
            thread_universal_block_on(join_handle.join().expect("could not join thread")),
            "std"
        );
    }
}

mod timeout {
    use super::*;
    use crate::vault::api::CspBasicSignatureKeygenError;
    use ic_types::crypto::AlgorithmId;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_fail_with_deadline_exceeded() {
        let csp_vault = new_csp_vault_for_test_with_timeout(Duration::from_millis(1));
        let gen_key_result = csp_vault.gen_key_pair(AlgorithmId::Ed25519);
        assert!(
            matches!(
                gen_key_result.clone(),
                Err(CspBasicSignatureKeygenError::InternalError { internal_error })
                if internal_error.contains("the request exceeded its deadline")
            ),
            "Unexpected gen_key_result: {:?}",
            gen_key_result
        );
    }
}

mod basic_sig {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_generate_ed25519_key_pair() {
        test_utils::basic_sig::should_generate_ed25519_key_pair(new_csp_vault_for_test());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_fail_to_generate_key_for_wrong_algorithm_id() {
        test_utils::basic_sig::should_fail_to_generate_basic_sig_key_for_wrong_algorithm_id(
            new_csp_vault_for_test(),
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_sign_verifiably_with_generated_key() {
        test_utils::basic_sig::should_sign_and_verify_with_generated_ed25519_key_pair(
            new_csp_vault_for_test(),
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_not_sign_with_unsupported_algorithm_id() {
        test_utils::basic_sig::should_not_basic_sign_with_unsupported_algorithm_id(
            new_csp_vault_for_test(),
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_not_sign_with_non_existent_key() {
        test_utils::basic_sig::should_not_basic_sign_with_non_existent_key(new_csp_vault_for_test());
    }
}

mod multi_sig {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_generate_key_ok() {
        test_utils::multi_sig::should_generate_multi_bls12_381_key_pair(new_csp_vault_for_test());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_fail_to_generate_key_for_wrong_algorithm_id() {
        test_utils::multi_sig::should_fail_to_generate_multi_sig_key_for_wrong_algorithm_id(
            new_csp_vault_for_test(),
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_generate_verifiable_pop() {
        test_utils::multi_sig::should_generate_verifiable_pop(new_csp_vault_for_test());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_multi_sign_and_verify_with_generated_key() {
        test_utils::multi_sig::should_multi_sign_and_verify_with_generated_key(
            new_csp_vault_for_test(),
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_fail_to_multi_sign_with_unsupported_algorithm_id() {
        test_utils::multi_sig::should_not_multi_sign_with_unsupported_algorithm_id(
            new_csp_vault_for_test(),
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_fail_to_multi_sign_if_secret_key_in_store_has_wrong_type() {
        test_utils::multi_sig::should_not_multi_sign_if_secret_key_in_store_has_wrong_type(
            new_csp_vault_for_test(),
        );
    }
}

mod threshold_sig {
    use super::*;
    use ic_types::Randomness;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaChaRng;

    fn test_threshold_sigs(seed: [u8; 32]) {
        let mut rng = ChaChaRng::from_seed(seed);
        let message = rng.gen::<[u8; 32]>();
        test_utils::threshold_sig::test_threshold_scheme_with_basic_keygen(
            Randomness::from(rng.gen::<[u8; 32]>()),
            new_csp_vault_for_test(),
            &message,
        );
    }

    // TODO(CRP-1286): make a proptest instead of the manual repetition.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_threshold_scheme_with_basic_keygen_1() {
        test_threshold_sigs([5; 32]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_threshold_scheme_with_basic_keygen_2() {
        test_threshold_sigs([7; 32]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_threshold_scheme_with_basic_keygen_3() {
        test_threshold_sigs([9; 32]);
    }
}

mod secret_key_store {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn key_should_be_present_only_after_generation() {
        test_utils::sks::sks_should_contain_keys_only_after_generation(
            new_csp_vault_for_test(),
            new_csp_vault_for_test(),
        );
    }
}

mod ni_dkg {
    use super::*;
    use crate::vault::test_utils;
    use crate::vault::test_utils::ni_dkg::fixtures::MockNetwork;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_retention() {
        test_utils::ni_dkg::test_retention(new_csp_vault_for_test);
    }

    // TODO(CRP-1286): make a proptest instead of the manual repetition.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ni_dkg_should_work_with_all_players_acting_correctly_1() {
        test_utils::ni_dkg::test_ni_dkg_should_work_with_all_players_acting_correctly(
            [1; 32],
            MockNetwork::MIN_SIZE,
            0,
            new_csp_vault_for_test,
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ni_dkg_should_work_with_all_players_acting_correctly_2() {
        test_utils::ni_dkg::test_ni_dkg_should_work_with_all_players_acting_correctly(
            [2; 32],
            MockNetwork::MIN_SIZE + 1,
            1,
            new_csp_vault_for_test,
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ni_dkg_should_work_with_all_players_acting_correctly_3() {
        test_utils::ni_dkg::test_ni_dkg_should_work_with_all_players_acting_correctly(
            [3; 32],
            MockNetwork::MIN_SIZE + 1,
            2,
            new_csp_vault_for_test,
        );
    }

    // TODO(CRP-1286): make a proptest instead of the manual repetition.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_dealing_should_detect_errors_1() {
        test_utils::ni_dkg::test_create_dealing_should_detect_errors(
            [11; 32],
            MockNetwork::MIN_SIZE,
            0,
            new_csp_vault_for_test,
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_dealing_should_detect_errors_2() {
        test_utils::ni_dkg::test_create_dealing_should_detect_errors(
            [22; 32],
            MockNetwork::MIN_SIZE + 2,
            0,
            new_csp_vault_for_test,
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_dealing_should_detect_errors_3() {
        test_utils::ni_dkg::test_create_dealing_should_detect_errors(
            [33; 32],
            MockNetwork::DEFAULT_MAX_SIZE - 1,
            0,
            new_csp_vault_for_test,
        );
    }
}

// TODO(CRP-1302): Add TLS tests with custom SKS setup.
mod tls_keygen {
    use super::*;
    use ic_types_test_utils::ids::node_test_id;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_insert_secret_key_into_key_store() {
        test_utils::tls::should_insert_secret_key_into_key_store(new_csp_vault_for_test());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_return_der_encoded_self_signed_certificate() {
        test_utils::tls::should_return_der_encoded_self_signed_certificate(new_csp_vault_for_test());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_set_cert_subject_cn_as_node_id() {
        test_utils::tls::should_set_cert_subject_cn_as_node_id(new_csp_vault_for_test());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_use_stable_node_id_string_representation_as_subject_cn() {
        test_utils::tls::should_use_stable_node_id_string_representation_as_subject_cn(
            new_csp_vault_for_test(),
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_set_cert_issuer_cn_as_node_id() {
        test_utils::tls::should_set_cert_issuer_cn_as_node_id(new_csp_vault_for_test());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_not_set_cert_subject_alt_name() {
        test_utils::tls::should_not_set_cert_subject_alt_name(new_csp_vault_for_test());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_set_different_serial_numbers_for_multiple_certs() {
        test_utils::tls::should_set_different_serial_numbers_for_multiple_certs(
            new_csp_vault_for_test(),
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_set_cert_not_after_correctly() {
        test_utils::tls::should_set_cert_not_after_correctly(new_csp_vault_for_test());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_fail_on_invalid_not_after_date() {
        let csp_vault = new_csp_vault_for_test();
        let result = csp_vault.gen_tls_key_pair(
            node_test_id(test_utils::tls::NODE_1),
            "invalid_not_after_date",
        );
        assert!(result.is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_fail_if_not_after_date_is_in_the_past() {
        let csp_vault = new_csp_vault_for_test();
        let date_in_the_past = "20211004235959Z";

        let result =
            csp_vault.gen_tls_key_pair(node_test_id(test_utils::tls::NODE_1), date_in_the_past);
        assert!(result.is_err());
    }
}

mod tls_sign {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_sign_with_valid_key() {
        test_utils::tls::should_sign_with_valid_key(new_csp_vault_for_test());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_sign_verifiably() {
        test_utils::tls::should_sign_verifiably(new_csp_vault_for_test());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_fail_to_sign_if_secret_key_not_found() {
        test_utils::tls::should_fail_to_sign_if_secret_key_not_found(new_csp_vault_for_test());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_fail_to_sign_if_secret_key_in_store_has_wrong_type() {
        test_utils::tls::should_fail_to_sign_if_secret_key_in_store_has_wrong_type(
            new_csp_vault_for_test(),
        );
    }
}
