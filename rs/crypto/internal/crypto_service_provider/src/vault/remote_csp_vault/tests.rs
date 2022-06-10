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
fn new_csp_vault_for_test(rt_handle: &tokio::runtime::Handle) -> Arc<dyn CspVault> {
    let socket_path = start_new_remote_csp_vault_server_for_test(rt_handle);
    let remote_csp_vault = RemoteCspVault::new(&socket_path, rt_handle.clone())
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
    use crate::vault::api::CspBasicSignatureKeygenError;
    use ic_types::crypto::AlgorithmId;

    #[test]
    fn should_fail_with_deadline_exceeded() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault =
            new_csp_vault_for_test_with_timeout(Duration::from_millis(1), tokio_rt.handle());
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

    #[test]
    fn should_generate_ed25519_key_pair() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_csp_vault_for_test(tokio_rt.handle());
        test_utils::basic_sig::should_generate_ed25519_key_pair(csp_vault);
    }

    #[test]
    fn should_fail_to_generate_key_for_wrong_algorithm_id() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_csp_vault_for_test(tokio_rt.handle());
        test_utils::basic_sig::should_fail_to_generate_basic_sig_key_for_wrong_algorithm_id(
            csp_vault,
        );
    }

    #[test]
    fn should_sign_verifiably_with_generated_key() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_csp_vault_for_test(tokio_rt.handle());
        test_utils::basic_sig::should_sign_and_verify_with_generated_ed25519_key_pair(csp_vault);
    }

    #[test]
    fn should_not_sign_with_unsupported_algorithm_id() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_csp_vault_for_test(tokio_rt.handle());
        test_utils::basic_sig::should_not_basic_sign_with_unsupported_algorithm_id(csp_vault);
    }

    #[test]
    fn should_not_sign_with_non_existent_key() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_csp_vault_for_test(tokio_rt.handle());
        test_utils::basic_sig::should_not_basic_sign_with_non_existent_key(csp_vault);
    }
}

mod multi_sig {
    use super::*;

    #[test]
    fn should_generate_key_ok() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_csp_vault_for_test(tokio_rt.handle());
        test_utils::multi_sig::should_generate_multi_bls12_381_key_pair(csp_vault);
    }

    #[test]
    fn should_fail_to_generate_key_for_wrong_algorithm_id() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_csp_vault_for_test(tokio_rt.handle());
        test_utils::multi_sig::should_fail_to_generate_multi_sig_key_for_wrong_algorithm_id(
            csp_vault,
        );
    }

    #[test]
    fn should_generate_verifiable_pop() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_csp_vault_for_test(tokio_rt.handle());
        test_utils::multi_sig::should_generate_verifiable_pop(csp_vault);
    }

    #[test]
    fn should_multi_sign_and_verify_with_generated_key() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_csp_vault_for_test(tokio_rt.handle());
        test_utils::multi_sig::should_multi_sign_and_verify_with_generated_key(csp_vault);
    }

    #[test]
    fn should_fail_to_multi_sign_with_unsupported_algorithm_id() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_csp_vault_for_test(tokio_rt.handle());
        test_utils::multi_sig::should_not_multi_sign_with_unsupported_algorithm_id(csp_vault);
    }

    #[test]
    fn should_fail_to_multi_sign_if_secret_key_in_store_has_wrong_type() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_csp_vault_for_test(tokio_rt.handle());
        test_utils::multi_sig::should_not_multi_sign_if_secret_key_in_store_has_wrong_type(
            csp_vault,
        );
    }
}

mod threshold_sig {
    use super::*;
    use ic_types::Randomness;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaChaRng;

    fn test_threshold_sigs(seed: [u8; 32]) {
        let tokio_rt = new_tokio_runtime();
        let mut rng = ChaChaRng::from_seed(seed);
        let message = rng.gen::<[u8; 32]>();
        test_utils::threshold_sig::test_threshold_scheme_with_basic_keygen(
            Randomness::from(rng.gen::<[u8; 32]>()),
            new_csp_vault_for_test(tokio_rt.handle()),
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
        let csp_vault_1 = new_csp_vault_for_test(tokio_rt.handle());
        let csp_vault_2 = new_csp_vault_for_test(tokio_rt.handle());

        test_utils::sks::sks_should_contain_keys_only_after_generation(csp_vault_1, csp_vault_2);
    }
}

mod ni_dkg {
    use super::*;
    use crate::vault::test_utils;
    use crate::vault::test_utils::ni_dkg::fixtures::MockNetwork;

    #[test]
    fn test_retention() {
        let tokio_rt = new_tokio_runtime();
        test_utils::ni_dkg::test_retention(|| new_csp_vault_for_test(tokio_rt.handle()));
    }

    // TODO(CRP-1286): make a proptest instead of the manual repetition.
    #[test]
    fn ni_dkg_should_work_with_all_players_acting_correctly_1() {
        let tokio_rt = new_tokio_runtime();
        test_utils::ni_dkg::test_ni_dkg_should_work_with_all_players_acting_correctly(
            [1; 32],
            MockNetwork::MIN_SIZE,
            0,
            || new_csp_vault_for_test(tokio_rt.handle()),
        );
    }
    #[test]
    fn ni_dkg_should_work_with_all_players_acting_correctly_2() {
        let tokio_rt = new_tokio_runtime();
        test_utils::ni_dkg::test_ni_dkg_should_work_with_all_players_acting_correctly(
            [2; 32],
            MockNetwork::MIN_SIZE + 1,
            1,
            || new_csp_vault_for_test(tokio_rt.handle()),
        );
    }

    #[test]
    fn ni_dkg_should_work_with_all_players_acting_correctly_3() {
        let tokio_rt = new_tokio_runtime();
        test_utils::ni_dkg::test_ni_dkg_should_work_with_all_players_acting_correctly(
            [3; 32],
            MockNetwork::MIN_SIZE + 1,
            2,
            || new_csp_vault_for_test(tokio_rt.handle()),
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
            || new_csp_vault_for_test(tokio_rt.handle()),
        );
    }
    #[test]
    fn create_dealing_should_detect_errors_2() {
        let tokio_rt = new_tokio_runtime();
        test_utils::ni_dkg::test_create_dealing_should_detect_errors(
            [22; 32],
            MockNetwork::MIN_SIZE + 2,
            0,
            || new_csp_vault_for_test(tokio_rt.handle()),
        );
    }
    #[test]
    fn create_dealing_should_detect_errors_3() {
        let tokio_rt = new_tokio_runtime();
        test_utils::ni_dkg::test_create_dealing_should_detect_errors(
            [33; 32],
            MockNetwork::DEFAULT_MAX_SIZE - 1,
            0,
            || new_csp_vault_for_test(tokio_rt.handle()),
        );
    }
}

// TODO(CRP-1302): Add TLS tests with custom SKS setup.
mod tls_keygen {
    use super::*;
    use ic_types_test_utils::ids::node_test_id;

    #[test]
    fn should_insert_secret_key_into_key_store() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_csp_vault_for_test(tokio_rt.handle());
        test_utils::tls::should_insert_secret_key_into_key_store(csp_vault);
    }

    #[test]
    fn should_return_der_encoded_self_signed_certificate() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_csp_vault_for_test(tokio_rt.handle());
        test_utils::tls::should_return_der_encoded_self_signed_certificate(csp_vault);
    }

    #[test]
    fn should_set_cert_subject_cn_as_node_id() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_csp_vault_for_test(tokio_rt.handle());
        test_utils::tls::should_set_cert_subject_cn_as_node_id(csp_vault);
    }

    #[test]
    fn should_use_stable_node_id_string_representation_as_subject_cn() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_csp_vault_for_test(tokio_rt.handle());
        test_utils::tls::should_use_stable_node_id_string_representation_as_subject_cn(csp_vault);
    }

    #[test]
    fn should_set_cert_issuer_cn_as_node_id() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_csp_vault_for_test(tokio_rt.handle());
        test_utils::tls::should_set_cert_issuer_cn_as_node_id(csp_vault);
    }

    #[test]
    fn should_not_set_cert_subject_alt_name() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_csp_vault_for_test(tokio_rt.handle());
        test_utils::tls::should_not_set_cert_subject_alt_name(csp_vault);
    }

    #[test]
    fn should_set_different_serial_numbers_for_multiple_certs() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_csp_vault_for_test(tokio_rt.handle());
        test_utils::tls::should_set_different_serial_numbers_for_multiple_certs(csp_vault);
    }

    #[test]
    fn should_set_cert_not_after_correctly() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_csp_vault_for_test(tokio_rt.handle());
        test_utils::tls::should_set_cert_not_after_correctly(csp_vault);
    }

    #[test]
    fn should_fail_on_invalid_not_after_date() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_csp_vault_for_test(tokio_rt.handle());
        let result = csp_vault.gen_tls_key_pair(
            node_test_id(test_utils::tls::NODE_1),
            "invalid_not_after_date",
        );
        assert!(result.is_err());
    }

    #[test]
    fn should_fail_if_not_after_date_is_in_the_past() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_csp_vault_for_test(tokio_rt.handle());
        let date_in_the_past = "20211004235959Z";

        let result =
            csp_vault.gen_tls_key_pair(node_test_id(test_utils::tls::NODE_1), date_in_the_past);
        assert!(result.is_err());
    }
}

mod tls_sign {
    use super::*;

    #[test]
    fn should_sign_with_valid_key() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_csp_vault_for_test(tokio_rt.handle());
        test_utils::tls::should_sign_with_valid_key(csp_vault);
    }

    #[test]
    fn should_sign_verifiably() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_csp_vault_for_test(tokio_rt.handle());
        test_utils::tls::should_sign_verifiably(csp_vault);
    }

    #[test]
    fn should_fail_to_sign_if_secret_key_not_found() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_csp_vault_for_test(tokio_rt.handle());
        test_utils::tls::should_fail_to_sign_if_secret_key_not_found(csp_vault);
    }

    #[test]
    fn should_fail_to_sign_if_secret_key_in_store_has_wrong_type() {
        let tokio_rt = new_tokio_runtime();
        let csp_vault = new_csp_vault_for_test(tokio_rt.handle());
        test_utils::tls::should_fail_to_sign_if_secret_key_in_store_has_wrong_type(csp_vault);
    }
}
