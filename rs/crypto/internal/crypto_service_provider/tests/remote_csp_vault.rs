use ic_crypto_internal_basic_sig_ed25519 as ed25519;
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
use proptest::{prop_assert_eq, prop_compose, prop_oneof, proptest};
use std::sync::Arc;

const MAX_ALGORITHM_ID_INDEX: i32 = 16;

mod basic_signature_csp_vault {
    use super::*;
    use crate::basic_signature_csp_vault::proptest_csp_basic_signature_error::arb_csp_basic_signature_error;
    use crate::basic_signature_csp_vault::proptest_csp_basic_signature_keygen_error::arb_csp_basic_signature_keygen_error;
    use crate::basic_signature_csp_vault::proptest_csp_public_key::arb_csp_public_key;
    use crate::basic_signature_csp_vault::proptest_csp_signature::arb_csp_signature;
    use assert_matches::assert_matches;
    use ic_config::crypto::CryptoConfig;
    use ic_crypto_internal_csp::public_key_store::proto_pubkey_store::ProtoPublicKeyStore;
    use ic_crypto_internal_csp::secret_key_store::proto_store::ProtoSecretKeyStore;
    use ic_crypto_internal_csp::types::{CspPublicKey, CspSignature};
    use ic_crypto_internal_csp::LocalCspVault;
    use ic_crypto_test_utils_local_csp_vault::MockLocalCspVault;

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
            let tokio_rt = new_tokio_runtime();
            let remote_vault =
                new_remote_csp_vault_with_local_csp_vault(tokio_rt.handle(), Arc::new(local_vault));

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
            let tokio_rt = new_tokio_runtime();
            let remote_vault =
                new_remote_csp_vault_with_local_csp_vault(tokio_rt.handle(), Arc::new(local_vault));

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
        let tokio_rt = new_tokio_runtime();
        let remote_vault =
            new_remote_csp_vault_with_local_csp_vault(tokio_rt.handle(), Arc::new(local_vault));

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

    mod proptest_csp_public_key {
        use super::*;
        use ic_crypto_internal_basic_sig_ecdsa_secp256k1::types as ecdsa_secp256k1_types;
        use ic_crypto_internal_basic_sig_ecdsa_secp256r1::types as ecdsa_secp256r1_types;
        use ic_crypto_internal_basic_sig_ed25519::types as ed25519_types;
        use ic_crypto_internal_basic_sig_rsa_pkcs1::RsaPublicKey;
        use ic_crypto_internal_csp::types::CspPublicKey;
        use ic_crypto_internal_multi_sig_bls12381::types as multi_types;

        prop_compose! {
            fn arb_ecdsa_p256_public_key()(bytes in vec(any::<u8>(), 0..100)) -> CspPublicKey {
                CspPublicKey::EcdsaP256(ecdsa_secp256r1_types::PublicKeyBytes(bytes))
            }
        }
        prop_compose! {
            fn arb_ecdsa_scep_256k1_public_key()(bytes in vec(any::<u8>(), 0..100)) -> CspPublicKey {
                CspPublicKey::EcdsaSecp256k1(ecdsa_secp256k1_types::PublicKeyBytes(bytes))
            }
        }
        prop_compose! {
            fn arb_ed25519_public_key()(bytes in uniform32(any::<u8>())) -> CspPublicKey {
                CspPublicKey::Ed25519(ed25519_types::PublicKeyBytes(bytes))
            }
        }
        prop_compose! {
            fn arb_multi_bls12_381_public_key()(bytes in arb_96_bytes()) -> CspPublicKey {
                CspPublicKey::MultiBls12_381(multi_types::PublicKeyBytes(bytes))
            }
        }
        prop_compose! {
            //minimal size of RSA public key is 2048 bits, corresponding to 512 hexadecimal characters
            //the first character must be such that its binary representation does not have any leading zeroes,
            //to ensure that the key will contain 2048 bits.
            //the last character must correspond to an odd number to ensure the modulus being odd
            fn arb_rsa_sha_256_public_key()(modulus_in_hex in "[8-9a-f]{1}[0-9a-f]{510}[13579bdf]{1}") -> CspPublicKey {
                let n = hex::decode(modulus_in_hex).expect("invalid hexadecimal");
                let e = [1,0,1];
                let rsa_public_key = RsaPublicKey::from_components(&e, &n).expect("invalid RSA public key");
                CspPublicKey::RsaSha256(rsa_public_key)
            }
        }

        pub fn arb_csp_public_key() -> BoxedStrategy<CspPublicKey> {
            prop_oneof![
                arb_ecdsa_p256_public_key(),
                arb_ecdsa_scep_256k1_public_key(),
                arb_multi_bls12_381_public_key(),
                arb_rsa_sha_256_public_key()
            ]
            .boxed()
        }
    }

    mod proptest_csp_basic_signature_keygen_error {
        use super::*;
        use ic_crypto_internal_csp::vault::api::CspBasicSignatureKeygenError;

        prop_compose! {
            fn arb_internal_error()(internal_error in ".*") -> CspBasicSignatureKeygenError {
                CspBasicSignatureKeygenError::InternalError { internal_error }
            }
        }
        prop_compose! {
            fn arb_duplicated_key_id_error()(key_id in arb_key_id()) -> CspBasicSignatureKeygenError {
                CspBasicSignatureKeygenError::DuplicateKeyId {key_id}
            }
        }
        prop_compose! {
            fn arb_transient_internal_error()(internal_error in ".*") -> CspBasicSignatureKeygenError {
                CspBasicSignatureKeygenError::TransientInternalError { internal_error }
            }
        }

        pub fn arb_csp_basic_signature_keygen_error() -> BoxedStrategy<CspBasicSignatureKeygenError>
        {
            prop_oneof![
                arb_internal_error(),
                arb_duplicated_key_id_error(),
                arb_transient_internal_error()
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

prop_compose! {
    fn arb_96_bytes()(left in uniform32(any::<u8>()), middle in uniform32(any::<u8>()), right in uniform32(any::<u8>())) -> [u8; 96] {
        [left, middle, right].concat().try_into().unwrap()
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

fn proptest_config_for_delegation() -> ProptestConfig {
    ProptestConfig {
        //default uses FileFailurePersistence::SourceParallel which expects a main.rs or a lib.rs,
        //which does not work for a Rust integration test and results in a warning being printed.
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}
