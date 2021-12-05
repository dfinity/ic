#![allow(clippy::unwrap_used)]
// TODO(CRP-1240): remove the clippy-exception above.
// TODO(CRP-1255): add tests with multiple clients.
// TODO(CRP-1259): add tests with timeouts.

use crate::vault::api::CspVault;
use crate::vault::remote_csp_vault::tarpc_csp_vault_client::RemoteCspVault;
use crate::vault::remote_csp_vault::tarpc_csp_vault_server;
use crate::vault::test_utils;
use ic_crypto_internal_csp_test_utils::files::mk_temp_dir_with_permissions;
use std::path::PathBuf;
use std::sync::Arc;

fn start_new_csp_vault_server() -> PathBuf {
    let socket_path = test_utils::get_temp_file_path();
    let return_socket_path = socket_path.clone();
    let _ = std::fs::remove_file(&socket_path); // ignore if file doesn't exist
    let sks_dir = mk_temp_dir_with_permissions(0o700);
    let server = tarpc_csp_vault_server::TarpcCspVaultServerImpl::new(sks_dir.path(), &socket_path);
    tokio::spawn(async move {
        let _move_temp_dir_here_to_ensure_it_is_not_cleaned_up = sks_dir;
        server.run().await;
    });
    return_socket_path
}

fn new_csp_vault() -> Arc<dyn CspVault> {
    let socket_path = start_new_csp_vault_server();
    Arc::new(RemoteCspVault::new(&socket_path).expect("Could not create RemoteCspVault"))
}

mod basic_sig {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_generate_ed25519_key_pair() {
        test_utils::should_generate_ed25519_key_pair(new_csp_vault());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_fail_to_generate_key_for_wrong_algorithm_id() {
        test_utils::should_fail_to_generate_basic_sig_key_for_wrong_algorithm_id(new_csp_vault());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_sign_verifiably_with_generated_key() {
        test_utils::should_sign_and_verify_with_generated_ed25519_key_pair(new_csp_vault());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_not_sign_with_unsupported_algorithm_id() {
        test_utils::should_not_basic_sign_with_unsupported_algorithm_id(new_csp_vault());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_not_sign_with_non_existent_key() {
        test_utils::should_not_basic_sign_with_non_existent_key(new_csp_vault());
    }
}

mod multi_sign {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_generate_key_ok() {
        test_utils::should_generate_multi_bls12_381_key_pair(new_csp_vault());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_fail_to_generate_key_for_wrong_algorithm_id() {
        test_utils::should_fail_to_generate_multi_sig_key_for_wrong_algorithm_id(new_csp_vault());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_generate_verifiable_pop() {
        test_utils::should_generate_verifiable_pop(new_csp_vault());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_multi_sign_and_verify_with_generated_key() {
        test_utils::should_multi_sign_and_verify_with_generated_key(new_csp_vault());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_fail_to_multi_sign_with_unsupported_algorithm_id() {
        test_utils::should_not_multi_sign_with_unsupported_algorithm_id(new_csp_vault());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_fail_to_multi_sign_if_secret_key_in_store_has_wrong_type() {
        test_utils::should_not_multi_sign_if_secret_key_in_store_has_wrong_type(new_csp_vault());
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
        test_utils::test_threshold_scheme_with_basic_keygen(
            Randomness::from(rng.gen::<[u8; 32]>()),
            new_csp_vault(),
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
        test_utils::sks_should_contain_keys_only_after_generation(new_csp_vault(), new_csp_vault());
    }
}

mod ni_dkg {
    use super::*;
    use crate::vault::test_utils;
    use crate::vault::test_utils::ni_dkg::fixtures::MockNetwork;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_retention() {
        test_utils::ni_dkg::test_retention(new_csp_vault);
    }

    // TODO(CRP-1286): make a proptest instead of the manual repetition.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ni_dkg_should_work_with_all_players_acting_correctly_1() {
        test_utils::ni_dkg::test_ni_dkg_should_work_with_all_players_acting_correctly(
            [1; 32],
            MockNetwork::MIN_SIZE,
            0,
            new_csp_vault,
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ni_dkg_should_work_with_all_players_acting_correctly_2() {
        test_utils::ni_dkg::test_ni_dkg_should_work_with_all_players_acting_correctly(
            [2; 32],
            MockNetwork::MIN_SIZE + 1,
            1,
            new_csp_vault,
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ni_dkg_should_work_with_all_players_acting_correctly_3() {
        test_utils::ni_dkg::test_ni_dkg_should_work_with_all_players_acting_correctly(
            [3; 32],
            MockNetwork::MIN_SIZE + 1,
            2,
            new_csp_vault,
        );
    }

    // TODO(CRP-1286): make a proptest instead of the manual repetition.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_dealing_should_detect_errors_1() {
        test_utils::ni_dkg::test_create_dealing_should_detect_errors(
            [11; 32],
            MockNetwork::MIN_SIZE,
            0,
            new_csp_vault,
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_dealing_should_detect_errors_2() {
        test_utils::ni_dkg::test_create_dealing_should_detect_errors(
            [22; 32],
            MockNetwork::MIN_SIZE + 2,
            0,
            new_csp_vault,
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_dealing_should_detect_errors_3() {
        test_utils::ni_dkg::test_create_dealing_should_detect_errors(
            [33; 32],
            MockNetwork::DEFAULT_MAX_SIZE - 1,
            0,
            new_csp_vault,
        );
    }
}

// TODO(CRP-1302): Add TLS tests with custom SKS setup.
mod tls_keygen {
    use super::*;
    use ic_types_test_utils::ids::node_test_id;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_insert_secret_key_into_key_store() {
        test_utils::tls::should_insert_secret_key_into_key_store(new_csp_vault());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_return_der_encoded_self_signed_certificate() {
        test_utils::tls::should_return_der_encoded_self_signed_certificate(new_csp_vault());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_set_cert_subject_cn_as_node_id() {
        test_utils::tls::should_set_cert_subject_cn_as_node_id(new_csp_vault());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_use_stable_node_id_string_representation_as_subject_cn() {
        test_utils::tls::should_use_stable_node_id_string_representation_as_subject_cn(
            new_csp_vault(),
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_set_cert_issuer_cn_as_node_id() {
        test_utils::tls::should_set_cert_issuer_cn_as_node_id(new_csp_vault());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_not_set_cert_subject_alt_name() {
        test_utils::tls::should_not_set_cert_subject_alt_name(new_csp_vault());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_set_different_serial_numbers_for_multiple_certs() {
        test_utils::tls::should_set_different_serial_numbers_for_multiple_certs(new_csp_vault());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_set_cert_not_after_correctly() {
        test_utils::tls::should_set_cert_not_after_correctly(new_csp_vault());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_fail_on_invalid_not_after_date() {
        let csp_vault = new_csp_vault();
        let result = csp_vault.gen_tls_key_pair(
            node_test_id(test_utils::tls::NODE_1),
            "invalid_not_after_date",
        );
        assert!(result.is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_fail_if_not_after_date_is_in_the_past() {
        let csp_vault = new_csp_vault();
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
        test_utils::tls::should_sign_with_valid_key(new_csp_vault());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_sign_verifiably() {
        test_utils::tls::should_sign_verifiably(new_csp_vault());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_fail_to_sign_if_secret_key_not_found() {
        test_utils::tls::should_fail_to_sign_if_secret_key_not_found(new_csp_vault());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_fail_to_sign_if_secret_key_in_store_has_wrong_type() {
        test_utils::tls::should_fail_to_sign_if_secret_key_in_store_has_wrong_type(new_csp_vault());
    }
}
