use ic_crypto_internal_basic_sig_ed25519 as ed25519;
use ic_crypto_internal_csp::key_id::KeyId;
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_crypto_temp_crypto_vault::RemoteVaultEnvironment;
use ic_crypto_test_utils_local_csp_vault::MockLocalCspVault;
use ic_logger::replica_logger::no_op_logger;
use ic_types::crypto::AlgorithmId;
use proptest::collection::vec;
use proptest::prelude::any;
use proptest::prelude::ProptestConfig;
use proptest::result::maybe_err;
use proptest::{prop_assert_eq, proptest};
use std::sync::Arc;

mod basic_signature_csp_vault {
    use super::*;
    use assert_matches::assert_matches;
    use ic_config::crypto::CryptoConfig;
    use ic_crypto_internal_csp::public_key_store::proto_pubkey_store::ProtoPublicKeyStore;
    use ic_crypto_internal_csp::secret_key_store::proto_store::ProtoSecretKeyStore;
    use ic_crypto_internal_csp::types::{CspPublicKey, CspSignature};
    use ic_crypto_internal_csp::LocalCspVault;
    use ic_crypto_internal_csp_proptest_utils::arb_algorithm_id;
    use ic_crypto_internal_csp_proptest_utils::arb_csp_basic_signature_error;
    use ic_crypto_internal_csp_proptest_utils::arb_csp_basic_signature_keygen_error;
    use ic_crypto_internal_csp_proptest_utils::arb_csp_public_key;
    use ic_crypto_internal_csp_proptest_utils::arb_csp_signature;
    use ic_crypto_internal_csp_proptest_utils::arb_key_id;

    proptest! {
        #![proptest_config(proptest_config_for_delegation())]
        #[test]
        fn should_delegate_for_sign(
            algorithm_id in arb_algorithm_id(),
            key_id in arb_key_id(),
            message in vec(any::<u8>(), 0..1024),
            expected_result in maybe_err(arb_csp_signature(), arb_csp_basic_signature_error())) {
            let expected_message = message.clone();
            let mut local_vault = MockLocalCspVault::new();
            local_vault
                .expect_sign()
                .times(1)
                .withf(move |algorithm_id_, message_, key_id_| {
                    *algorithm_id_ == algorithm_id && message_ == expected_message && *key_id_ == key_id
                })
                .return_const(expected_result.clone());
            let env = RemoteVaultEnvironment::start_server_with_local_csp_vault(Arc::new(local_vault));
            let remote_vault = env.new_vault_client();

            let result = remote_vault.sign(algorithm_id, &message, key_id);

            prop_assert_eq!(result, expected_result);
        }
    }

    proptest! {
        #![proptest_config(proptest_config_for_delegation())]
        #[test]
        fn should_delegate_for_gen_node_signing_key_pair(
            expected_result in maybe_err(arb_csp_public_key(), arb_csp_basic_signature_keygen_error())) {
            let mut local_vault = MockLocalCspVault::new();
            local_vault
                .expect_gen_node_signing_key_pair()
                .times(1)
                .return_const(expected_result.clone());
            let env = RemoteVaultEnvironment::start_server_with_local_csp_vault(Arc::new(local_vault));
            let remote_vault = env.new_vault_client();

            let result = remote_vault.gen_node_signing_key_pair();

            prop_assert_eq!(result, expected_result);
        }
    }

    #[test]
    fn should_sign_a_large_hundred_megabytes_message() {
        const HUNDRED_MEGA_BYTES: usize = 100 * 1024 * 1024;
        let message = vec![0_u8; HUNDRED_MEGA_BYTES];

        let (config, _temp_dir) = CryptoConfig::new_in_temp_dir();
        let secret_key_store =
            ProtoSecretKeyStore::open(&config.crypto_root, "sks_data.pb", Some(no_op_logger()));
        let canister_key_store = ProtoSecretKeyStore::open(
            &config.crypto_root,
            "canister_sks_data.pb",
            Some(no_op_logger()),
        );
        let public_key_store =
            ProtoPublicKeyStore::open(&config.crypto_root, "public_keys.pb", no_op_logger());
        let local_vault = LocalCspVault::new(
            secret_key_store,
            canister_key_store,
            public_key_store,
            Arc::new(CryptoMetrics::none()),
            no_op_logger(),
        );
        let env = RemoteVaultEnvironment::start_server_with_local_csp_vault(Arc::new(local_vault));
        let remote_vault = env.new_vault_client();

        let node_signing_public_key = remote_vault
            .gen_node_signing_key_pair()
            .expect("failed to generate keys");

        let signature = remote_vault
            .sign(
                AlgorithmId::Ed25519,
                &message,
                KeyId::try_from(&node_signing_public_key).unwrap(),
            )
            .expect("could not sign large message");

        match (node_signing_public_key, signature) {
            (CspPublicKey::Ed25519(public_key_bytes), CspSignature::Ed25519(signature_bytes)) => {
                let verification = ed25519::verify(&signature_bytes, &message, &public_key_bytes);
                assert_matches!(verification, Ok(()))
            }
            _ => panic!("unexpected type for node signing public key or signature"),
        }
    }
}

mod multi_signature_csp_vault {
    use super::*;
    use ic_crypto_internal_csp_proptest_utils::arb_algorithm_id;
    use ic_crypto_internal_csp_proptest_utils::arb_csp_multi_signature_error;
    use ic_crypto_internal_csp_proptest_utils::arb_csp_multi_signature_keygen_error;
    use ic_crypto_internal_csp_proptest_utils::arb_csp_pop;
    use ic_crypto_internal_csp_proptest_utils::arb_csp_public_key;
    use ic_crypto_internal_csp_proptest_utils::arb_csp_signature;
    use ic_crypto_internal_csp_proptest_utils::arb_key_id;

    proptest! {
        #![proptest_config(proptest_config_for_delegation())]
        #[test]
        fn should_delegate_for_multi_sign(
            algorithm_id in arb_algorithm_id(),
            key_id in arb_key_id(),
            message in vec(any::<u8>(), 0..1024),
            expected_result in maybe_err(arb_csp_signature(), arb_csp_multi_signature_error())) {
            let expected_message = message.clone();
            let mut local_vault = MockLocalCspVault::new();
            local_vault
                .expect_multi_sign()
                .times(1)
                .withf(move |algorithm_id_, message_, key_id_| {
                    *algorithm_id_ == algorithm_id && message_ == expected_message && *key_id_ == key_id
                })
                .return_const(expected_result.clone());
            let env = RemoteVaultEnvironment::start_server_with_local_csp_vault(Arc::new(local_vault));
            let remote_vault = env.new_vault_client();

            let result = remote_vault.multi_sign(algorithm_id, &message, key_id);

            prop_assert_eq!(result, expected_result);
        }
    }

    proptest! {
        #![proptest_config(proptest_config_for_delegation())]
        #[test]
        fn should_delegate_for_gen_committee_signing_key_pair(
            expected_result in maybe_err((arb_csp_public_key(), arb_csp_pop()), arb_csp_multi_signature_keygen_error())) {
            let mut local_vault = MockLocalCspVault::new();
            local_vault
                .expect_gen_committee_signing_key_pair()
                .times(1)
                .return_const(expected_result.clone());
            let env = RemoteVaultEnvironment::start_server_with_local_csp_vault(Arc::new(local_vault));
            let remote_vault = env.new_vault_client();

            let result = remote_vault.gen_committee_signing_key_pair();

            prop_assert_eq!(result, expected_result);
        }
    }
}

fn proptest_config_for_delegation() -> ProptestConfig {
    ProptestConfig {
        //default uses FileFailurePersistence::SourceParallel which expects a main.rs or a lib.rs,
        //which does not work for a Rust integration test and results in a warning being printed.
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}
