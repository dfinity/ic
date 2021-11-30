#![allow(clippy::unwrap_used)]
// TODO(CRP-1240): remove the clippy-exception above.
// TODO(CRP-1255): add tests with multiple clients.
// TODO(CRP-1259): add tests with timeouts.

use crate::vault::remote_csp_vault::tarpc_csp_vault_client::RemoteCspVault;
use crate::vault::remote_csp_vault::tarpc_csp_vault_server;
use crate::vault::test_util;
use ic_crypto_internal_csp_test_utils::files::mk_temp_dir_with_permissions;
use std::path::PathBuf;

fn start_new_csp_server() -> PathBuf {
    let socket_path = test_util::get_temp_file_path();
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

mod basic_signature_tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_generate_ed25519_key_pair() {
        let socket_path = start_new_csp_server();
        let csp_vault = RemoteCspVault::new(&socket_path).expect("Could not create RemoteCspVault");
        test_util::should_generate_ed25519_key_pair(&csp_vault);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_fail_to_generate_key_for_wrong_algorithm_id() {
        let socket_path = start_new_csp_server();
        let csp_vault = RemoteCspVault::new(&socket_path).expect("Could not create RemoteCspVault");
        test_util::should_fail_to_generate_basic_sig_key_for_wrong_algorithm_id(&csp_vault);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_sign_verifiably_with_generated_key() {
        let socket_path = start_new_csp_server();
        let csp_vault = RemoteCspVault::new(&socket_path).expect("Could not create RemoteCspVault");
        test_util::should_sign_and_verify_with_generated_ed25519_key_pair(&csp_vault);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_not_sign_with_unsupported_algorithm_id() {
        let socket_path = start_new_csp_server();
        let csp_vault = RemoteCspVault::new(&socket_path).expect("Could not create RemoteCspVault");
        test_util::should_not_basic_sign_with_unsupported_algorithm_id(&csp_vault);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_not_sign_with_non_existent_key() {
        let socket_path = start_new_csp_server();
        let csp_vault = RemoteCspVault::new(&socket_path).expect("Could not create RemoteCspVault");
        test_util::should_not_basic_sign_with_non_existent_key(&csp_vault);
    }
}

mod multi_signature_tests {
    use super::*;
    use crate::vault::test_util::SignaturesTrait;

    impl SignaturesTrait for RemoteCspVault {}

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_generate_key_ok() {
        let socket_path = start_new_csp_server();
        let csp_vault = RemoteCspVault::new(&socket_path).expect("Could not create RemoteCspVault");
        test_util::should_generate_multi_bls12_381_key_pair(&csp_vault);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_fail_to_generate_key_for_wrong_algorithm_id() {
        let socket_path = start_new_csp_server();
        let csp_vault = RemoteCspVault::new(&socket_path).expect("Could not create RemoteCspVault");
        test_util::should_fail_to_generate_multi_sig_key_for_wrong_algorithm_id(&csp_vault);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_generate_verifiable_pop() {
        let socket_path = start_new_csp_server();
        let csp_vault = RemoteCspVault::new(&socket_path).expect("Could not create RemoteCspVault");
        test_util::should_generate_verifiable_pop(&csp_vault);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_multi_sign_and_verify_with_generated_key() {
        let socket_path = start_new_csp_server();
        let csp_vault = RemoteCspVault::new(&socket_path).expect("Could not create RemoteCspVault");
        test_util::should_multi_sign_and_verify_with_generated_key(&csp_vault);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_fail_to_multi_sign_with_unsupported_algorithm_id() {
        let socket_path = start_new_csp_server();
        let csp_vault = RemoteCspVault::new(&socket_path).expect("Could not create RemoteCspVault");
        test_util::should_not_multi_sign_with_unsupported_algorithm_id(&csp_vault);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_fail_to_multi_sign_if_secret_key_in_store_has_wrong_type() {
        let socket_path = start_new_csp_server();
        let csp_vault = RemoteCspVault::new(&socket_path).expect("Could not create RemoteCspVault");
        test_util::should_not_multi_sign_if_secret_key_in_store_has_wrong_type(&csp_vault);
    }
}

mod threshold_sig_tests {
    use super::*;
    use crate::vault::api::CspVault;
    use ic_types::Randomness;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaChaRng;
    use std::sync::Arc;

    fn test_threshold_sigs(seed: [u8; 32]) {
        let mut rng = ChaChaRng::from_seed(seed);
        let message = rng.gen::<[u8; 32]>();
        let csp_vault: Arc<dyn CspVault> = {
            let socket_path = start_new_csp_server();
            let remote_csp_server =
                RemoteCspVault::new(&socket_path).expect("Could not create RemoteCspVault");
            Arc::new(remote_csp_server)
        };
        test_util::test_threshold_scheme_with_basic_keygen(
            Randomness::from(rng.gen::<[u8; 32]>()),
            csp_vault,
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

mod secret_key_store_tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn key_should_be_present_only_after_generation() {
        let csp_vault1 = {
            let socket_path = start_new_csp_server();
            RemoteCspVault::new(&socket_path).expect("Could not create RemoteCspVault")
        };
        let csp_vault2 = {
            let socket_path = start_new_csp_server();
            RemoteCspVault::new(&socket_path).expect("Could not create RemoteCspVault")
        };
        test_util::sks_should_contain_keys_only_after_generation(&csp_vault1, &csp_vault2);
    }
}
