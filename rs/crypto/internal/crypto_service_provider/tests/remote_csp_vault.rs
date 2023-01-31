use ic_crypto_internal_csp::key_id::KeyId;
use ic_crypto_internal_csp::vault::api::CspVault;
use ic_crypto_internal_csp::vault::remote_csp_vault::{RemoteCspVault, TarpcCspVaultServerImpl};
use ic_crypto_internal_csp_test_utils::remote_csp_vault::setup_listener;
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_logger::replica_logger::no_op_logger;
use ic_types::crypto::AlgorithmId;
use proptest::array::uniform32;
use proptest::collection::vec;
use proptest::prelude::ProptestConfig;
use proptest::prelude::{any, BoxedStrategy};
use proptest::result::maybe_err;
use proptest::strategy::Strategy;
use proptest::test_runner::FileFailurePersistence;
use proptest::{prop_assert_eq, prop_compose, prop_oneof, proptest};
use std::sync::Arc;

const MAX_ALGORITHM_ID_INDEX: i32 = 16;

mod basic_signature_csp_vault {
    use super::*;
    use crate::basic_signature_csp_vault::proptest_csp_basic_signature_error::arb_csp_basic_signature_error;
    use crate::basic_signature_csp_vault::proptest_csp_signature::arb_csp_signature;
    use ic_crypto_test_utils_local_csp_vault::MockLocalCspVault;

    proptest! {
        #![proptest_config(ProptestConfig {
            //default uses FileFailurePersistence::SourceParallel which expects a main.rs or a lib.rs,
            //which does not work for a Rust integration test and results in a warning being printed.
            failure_persistence: Some(Box::new(FileFailurePersistence::WithSource("proptest-regressions"))),
            .. ProptestConfig::default()
        })]
        #[test]
        fn should_delegate_for_sign(
            algorithm_id in arb_algorithm_id(),
            key_id in arb_key_id(),
            message in vec(any::<u8>(), 0..100),
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
            let tokio_rt = new_tokio_runtime();
            let remote_vault =
                new_remote_csp_vault_with_local_csp_vault(tokio_rt.handle(), Arc::new(local_vault));

            let result = remote_vault.sign(algorithm_id, &message, key_id);

            prop_assert_eq!(result, expected_result);
        }
    }

    mod proptest_csp_basic_signature_error {
        use super::*;
        use ic_crypto_internal_csp::vault::api::CspBasicSignatureError;

        prop_compose! {
            fn arb_secret_key_not_found_error()(algorithm in arb_algorithm_id(), key_id in arb_key_id()) -> CspBasicSignatureError {
                CspBasicSignatureError::SecretKeyNotFound { algorithm, key_id }
            }
        }

        prop_compose! {
            fn arb_unsupported_algorithm_error()(algorithm in arb_algorithm_id()) -> CspBasicSignatureError {
                CspBasicSignatureError::UnsupportedAlgorithm { algorithm }
            }
        }

        prop_compose! {
            fn arb_wrong_secret_key_type_error()(algorithm in arb_algorithm_id(), secret_key_variant in ".*") -> CspBasicSignatureError {
                CspBasicSignatureError::WrongSecretKeyType { algorithm, secret_key_variant }
            }
        }

        prop_compose! {
            fn arb_malformed_secret_key_error()(algorithm in arb_algorithm_id()) -> CspBasicSignatureError {
                CspBasicSignatureError::MalformedSecretKey { algorithm }
            }
        }

        prop_compose! {
            fn arb_internal_error()(internal_error in ".*") -> CspBasicSignatureError {
                CspBasicSignatureError::InternalError { internal_error }
            }
        }

        pub fn arb_csp_basic_signature_error() -> BoxedStrategy<CspBasicSignatureError> {
            prop_oneof![
                arb_secret_key_not_found_error(),
                arb_unsupported_algorithm_error(),
                arb_wrong_secret_key_type_error(),
                arb_malformed_secret_key_error(),
                arb_internal_error()
            ]
            .boxed()
        }
    }

    mod proptest_csp_signature {
        use super::*;
        use ic_crypto_internal_basic_sig_ecdsa_secp256k1::types as ecdsa_secp256k1_types;
        use ic_crypto_internal_basic_sig_ecdsa_secp256r1::types as ecdsa_secp256r1_types;
        use ic_crypto_internal_basic_sig_ed25519::types as ed25519_types;
        use ic_crypto_internal_csp::types::CspSignature;

        prop_compose! {
            fn arb_ecdsa_p256_signature()(bytes in arb_64_bytes()) -> CspSignature {
                CspSignature::EcdsaP256(ecdsa_secp256r1_types::SignatureBytes(bytes))
            }
        }

        prop_compose! {
            fn arb_ecdsa_secp_256k1_signature()(bytes in arb_64_bytes()) -> CspSignature {
                CspSignature::EcdsaSecp256k1(ecdsa_secp256k1_types::SignatureBytes(bytes))
            }
        }

        prop_compose! {
            fn arb_ed25519_signature()(bytes in arb_64_bytes()) -> CspSignature {
                CspSignature::Ed25519(ed25519_types::SignatureBytes(bytes))
            }
        }

        prop_compose! {
            fn arb_rsa_sha256_signature()(bytes in vec(any::<u8>(), 0..100)) -> CspSignature {
                CspSignature::RsaSha256(bytes)
            }
        }

        pub fn arb_csp_signature() -> BoxedStrategy<CspSignature> {
            prop_oneof![
                arb_ecdsa_p256_signature(),
                arb_ecdsa_secp_256k1_signature(),
                arb_ed25519_signature(),
                arb_rsa_sha256_signature()
            ]
            .boxed()
        }
    }
}

#[test]
fn should_be_maximal_algorithm_index_id() {
    assert_eq!(
        AlgorithmId::MegaSecp256k1,
        AlgorithmId::from(MAX_ALGORITHM_ID_INDEX)
    );
    assert_eq!(
        AlgorithmId::Placeholder,
        AlgorithmId::from(MAX_ALGORITHM_ID_INDEX + 1)
    );
}

prop_compose! {
    fn arb_key_id()(id in uniform32(any::<u8>())) -> KeyId {
        KeyId::from(id)
    }
}

prop_compose! {
    fn arb_algorithm_id()(id in 0..MAX_ALGORITHM_ID_INDEX) -> AlgorithmId {
        AlgorithmId::from(id)
    }
}

prop_compose! {
    fn arb_64_bytes()(left in uniform32(any::<u8>()), right in uniform32(any::<u8>())) -> [u8; 64] {
        [left, right].concat().try_into().unwrap()
    }
}

fn new_tokio_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().expect("failed to create runtime")
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
    let remote_csp_vault = RemoteCspVault::new(
        &socket_path,
        rt_handle.clone(),
        no_op_logger(),
        Arc::new(CryptoMetrics::none()),
    )
    .expect("Could not create RemoteCspVault");
    Arc::new(remote_csp_vault)
}
