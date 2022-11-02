mod csp_tests {
    use crate::api::CspSigner;
    use crate::api::CspTlsHandshakeSignerProvider;
    use crate::api::{CspKeyGenerator, CspSecretKeyStoreChecker};
    use crate::secret_key_store::volatile_store::VolatileSecretKeyStore;
    use crate::vault::test_utils::tls::ed25519_csp_pubkey_from_tls_pubkey_cert;
    use crate::CryptoRng;
    use crate::Csp;
    use crate::CspPublicKey;
    use crate::KeyId;
    use crate::Rng;
    use ic_crypto_tls_interfaces::TlsPublicKeyCert;
    use ic_types::crypto::AlgorithmId;
    use ic_types_test_utils::ids::node_test_id;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    mod public_key_data {
        use super::*;
        use crate::{NodePublicKeyData, PublicKeyData};
        use ic_crypto_internal_basic_sig_ed25519::types::PublicKeyBytes;
        use ic_crypto_internal_types::curves::bls12_381;
        use ic_protobuf::crypto::v1::NodePublicKeys;
        use ic_protobuf::registry::crypto::v1::AlgorithmId;
        use ic_protobuf::registry::crypto::v1::PublicKey;

        const INVALID_PUBLIC_KEY: PublicKey = PublicKey {
            version: 0,
            algorithm: 0,
            key_value: vec![],
            proof_data: None,
            timestamp: None,
        };

        #[test]
        fn should_be_ok_when_empty() {
            let data = PublicKeyData::try_from(NodePublicKeys {
                version: 0,
                node_signing_pk: None,
                committee_signing_pk: None,
                tls_certificate: None,
                dkg_dealing_encryption_pk: None,
                idkg_dealing_encryption_pk: None,
                idkg_dealing_encryption_pks: vec![],
            });
            assert!(data.is_ok());
        }

        #[test]
        fn should_be_ok_when_valid_node_signing_key() {
            let data = PublicKeyData::try_from(NodePublicKeys {
                version: 0,
                node_signing_pk: Some(valid_node_signing_key()),
                committee_signing_pk: None,
                tls_certificate: None,
                dkg_dealing_encryption_pk: None,
                idkg_dealing_encryption_pk: None,
                idkg_dealing_encryption_pks: vec![],
            });

            assert!(data.is_ok());
        }

        #[test]
        fn should_be_ok_with_valid_dkg_dealing_encryption_pk() {
            let data = PublicKeyData::try_from(NodePublicKeys {
                version: 0,
                node_signing_pk: None,
                committee_signing_pk: None,
                tls_certificate: None,
                dkg_dealing_encryption_pk: Some(valid_dkg_dealing_encryption_pk()),
                idkg_dealing_encryption_pk: None,
                idkg_dealing_encryption_pks: vec![],
            });

            assert!(data.is_ok());
        }

        #[test]
        fn should_be_ok_with_node_signing_pk_and_dkg_dealing_encryption_pk() {
            let data = PublicKeyData::try_from(NodePublicKeys {
                version: 0,
                node_signing_pk: Some(valid_node_signing_key()),
                committee_signing_pk: None,
                tls_certificate: None,
                dkg_dealing_encryption_pk: Some(valid_dkg_dealing_encryption_pk()),
                idkg_dealing_encryption_pk: None,
                idkg_dealing_encryption_pks: vec![],
            });

            assert!(data.is_ok());
        }

        #[test]
        fn should_err_when_invalid_dkg_dealing_encryption_key() {
            let data = PublicKeyData::try_from(NodePublicKeys {
                version: 0,
                node_signing_pk: None,
                committee_signing_pk: None,
                tls_certificate: None,
                dkg_dealing_encryption_pk: Some(INVALID_PUBLIC_KEY),
                idkg_dealing_encryption_pk: None,
                idkg_dealing_encryption_pks: vec![],
            });

            assert!(data.is_err())
        }

        #[test]
        fn should_err_when_invalid_node_signing_key() {
            let data = PublicKeyData::try_from(NodePublicKeys {
                version: 0,
                node_signing_pk: Some(INVALID_PUBLIC_KEY),
                committee_signing_pk: None,
                tls_certificate: None,
                dkg_dealing_encryption_pk: None,
                idkg_dealing_encryption_pk: None,
                idkg_dealing_encryption_pks: vec![],
            });

            assert!(data.is_err())
        }

        #[test]
        fn should_not_panic_when_no_public_keys() {
            let csp = csp_with_public_keys(NodePublicKeys {
                version: 0,
                node_signing_pk: None,
                committee_signing_pk: None,
                tls_certificate: None,
                dkg_dealing_encryption_pk: None,
                idkg_dealing_encryption_pk: None,
                idkg_dealing_encryption_pks: vec![],
            });

            let _current_public_keys = csp.current_node_public_keys();
        }

        fn csp_with_public_keys(public_keys: NodePublicKeys) -> Csp {
            let mut csp = Csp::of(csprng(), VolatileSecretKeyStore::new());
            csp.public_key_data =
                PublicKeyData::try_from(public_keys).expect("invalid public key data");
            csp
        }

        fn valid_node_signing_key() -> PublicKey {
            PublicKey {
                version: 0,
                algorithm: AlgorithmId::Ed25519 as i32,
                key_value: [0; PublicKeyBytes::SIZE].to_vec(),
                proof_data: None,
                timestamp: None,
            }
        }

        fn valid_dkg_dealing_encryption_pk() -> PublicKey {
            PublicKey {
                version: 0,
                algorithm: AlgorithmId::Groth20Bls12381 as i32,
                key_value: [0u8; bls12_381::G1::SIZE].to_vec(),
                proof_data: None,
                timestamp: None,
            }
        }
    }

    mod migration_to_rotated_idkg_dealing_enc_pubkey {
        use super::super::super::public_key_store;
        use crate::{read_node_public_keys, Csp};
        use ic_config::crypto::CryptoConfig;
        use ic_crypto_internal_logmon::metrics::CryptoMetrics;
        use ic_crypto_node_key_generation::get_node_keys_or_generate_if_missing;
        use ic_protobuf::crypto::v1::NodePublicKeys;
        use ic_protobuf::registry::crypto::v1::PublicKey;
        use std::path::Path;
        use std::sync::Arc;
        use tempfile::TempDir;

        #[test]
        fn should_migrate_if_idkg_vec_empty_and_legacy_key_exists() {
            let (mut node_public_keys, config, crypto_root) = generate_node_keys_in_temp_dir();
            node_public_keys.idkg_dealing_encryption_pks = vec![];
            write_to_public_key_store_file(crypto_root.path(), &node_public_keys);

            let csp = csp_from_config(&config);
            assert_eq!(
                only_element_in_vec(
                    &csp.public_key_data
                        .node_public_keys
                        .idkg_dealing_encryption_pks
                ),
                only_element_in_option(
                    &csp.public_key_data
                        .node_public_keys
                        .idkg_dealing_encryption_pk
                )
            );

            let node_public_keys =
                read_node_public_keys(crypto_root.path()).expect("failed to read public keys");
            assert_eq!(
                only_element_in_vec(&node_public_keys.idkg_dealing_encryption_pks),
                only_element_in_option(&node_public_keys.idkg_dealing_encryption_pk)
            );
        }

        #[test]
        fn should_not_migrate_if_idkg_vec_not_empty() {
            let (mut node_public_keys, config, crypto_root) = generate_node_keys_in_temp_dir();
            let original_idkg_keys_vec = node_public_keys.idkg_dealing_encryption_pks.clone();
            let legacy_idkg_key = PublicKey {
                version: 0,
                algorithm: 0,
                key_value: vec![42, 43, 44, 45, 46, 47],
                proof_data: None,
                timestamp: None,
            };
            assert_ne!(
                &legacy_idkg_key,
                only_element_in_vec(&original_idkg_keys_vec)
            );
            node_public_keys.idkg_dealing_encryption_pk = Some(legacy_idkg_key);
            write_to_public_key_store_file(crypto_root.path(), &node_public_keys);

            let csp = csp_from_config(&config);
            assert_eq!(
                csp.public_key_data
                    .node_public_keys
                    .idkg_dealing_encryption_pks,
                original_idkg_keys_vec
            );

            let node_public_keys = read_from_public_key_store_file(crypto_root.path());
            assert_eq!(
                node_public_keys.idkg_dealing_encryption_pks,
                original_idkg_keys_vec
            );
        }

        #[test]
        fn should_not_migrate_if_idkg_vec_empty_but_no_legacy_key() {
            let (mut node_public_keys, config, crypto_root) = generate_node_keys_in_temp_dir();
            node_public_keys.idkg_dealing_encryption_pk = None;
            node_public_keys.idkg_dealing_encryption_pks = vec![];
            write_to_public_key_store_file(crypto_root.path(), &node_public_keys);

            let csp = csp_from_config(&config);
            assert!(csp
                .public_key_data
                .node_public_keys
                .idkg_dealing_encryption_pks
                .is_empty());

            assert!(read_from_public_key_store_file(crypto_root.path())
                .idkg_dealing_encryption_pks
                .is_empty());
        }

        #[test]
        fn should_not_generate_idkg_legacy_key_if_vec_non_empty() {
            let (mut generated_node_public_keys, config, crypto_root) =
                generate_node_keys_in_temp_dir();
            generated_node_public_keys.idkg_dealing_encryption_pk = None;
            write_to_public_key_store_file(crypto_root.path(), &generated_node_public_keys);

            get_node_keys_or_generate_if_missing(&config, None);
            let read_node_public_keys = read_from_public_key_store_file(crypto_root.path());

            assert!(read_node_public_keys.idkg_dealing_encryption_pk.is_none());
            assert_eq!(
                read_node_public_keys.idkg_dealing_encryption_pks,
                generated_node_public_keys.idkg_dealing_encryption_pks
            );
        }

        fn generate_node_keys_in_temp_dir() -> (NodePublicKeys, CryptoConfig, TempDir) {
            let (config, temp_dir) = CryptoConfig::new_in_temp_dir();
            let (_current_node_public_keys, _node_id) =
                get_node_keys_or_generate_if_missing(&config, None);
            let node_public_keys_from_disk = read_from_public_key_store_file(temp_dir.path());
            assert!(node_public_keys_from_disk.node_signing_pk.is_some());
            assert!(node_public_keys_from_disk.committee_signing_pk.is_some());
            assert!(node_public_keys_from_disk.tls_certificate.is_some());
            assert!(node_public_keys_from_disk
                .dkg_dealing_encryption_pk
                .is_some());
            assert!(node_public_keys_from_disk
                .idkg_dealing_encryption_pk
                .is_some());
            assert_eq!(
                node_public_keys_from_disk.idkg_dealing_encryption_pks.len(),
                1,
            );
            (node_public_keys_from_disk, config, temp_dir)
        }

        fn csp_from_config(config: &CryptoConfig) -> Csp {
            Csp::new(config, None, None, Arc::new(CryptoMetrics::none()))
        }

        fn read_from_public_key_store_file(crypto_root: &Path) -> NodePublicKeys {
            read_node_public_keys(crypto_root).expect("failed to read public keys")
        }

        fn write_to_public_key_store_file(crypto_root: &Path, node_public_keys: &NodePublicKeys) {
            public_key_store::store_node_public_keys(crypto_root, node_public_keys)
                .unwrap_or_else(|err| panic!("Failed to store public key material: {err:?}"));
        }

        fn only_element_in_vec<T>(slice: &[T]) -> &T {
            assert_eq!(slice.len(), 1);
            slice.first().expect("missing element")
        }

        fn only_element_in_option<T>(option: &Option<T>) -> &T {
            option.as_ref().expect("missing element")
        }
    }

    #[test]
    fn should_contain_newly_generated_secret_key_from_store() {
        let (csp, public_key) = csp_with_key_pair();
        let key_id = KeyId::from(&public_key);

        let is_contained_in_sks_store = csp
            .sks_contains(&key_id)
            .expect("error looking for secret key");

        assert!(is_contained_in_sks_store);
    }

    #[test]
    fn should_sign_and_verify_with_newly_generated_secret_key_from_store() {
        let (csp, public_key) = csp_with_key_pair();
        let key_id = KeyId::from(&public_key);
        let message = "Hello world!".as_bytes();

        let signature = csp
            .sign(AlgorithmId::Ed25519, message, key_id)
            .expect("error signing message");

        let verification = csp.verify(&signature, message, AlgorithmId::Ed25519, public_key);

        assert!(verification.is_ok());
    }

    #[test]
    fn should_contain_newly_generated_tls_secret_key_from_store() {
        let (csp, cert) = csp_with_tls_key_pair();

        let is_contained_in_sks_store = csp
            .sks_contains_tls_key(&cert)
            .expect("error looking for TLS secret key");

        assert!(is_contained_in_sks_store);
    }

    #[test]
    fn should_sign_and_verify_with_newly_generated_tls_secret_key_from_store() {
        let (csp, cert) = csp_with_tls_key_pair();
        let key_id = KeyId::from(&cert);
        let message = "Hello world!".as_bytes();

        let signature = csp
            .handshake_signer()
            .tls_sign(message, &key_id)
            .expect("error signing message with TLS private key");

        let public_key = ed25519_csp_pubkey_from_tls_pubkey_cert(&cert);
        let verification = csp.verify(&signature, message, AlgorithmId::Ed25519, public_key);

        assert!(verification.is_ok());
    }

    fn csp_with_key_pair() -> (Csp, CspPublicKey) {
        let csp = Csp::of(csprng(), VolatileSecretKeyStore::new());
        let public_key = csp
            .gen_key_pair(AlgorithmId::Ed25519)
            .expect("error generating public/private key pair");
        (csp, public_key)
    }

    fn csp_with_tls_key_pair() -> (Csp, TlsPublicKeyCert) {
        const NODE_1: u64 = 4241;
        const NOT_AFTER: &str = "25670102030405Z";
        let csp = Csp::of(csprng(), VolatileSecretKeyStore::new());
        let cert = csp
            .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER)
            .expect("error generating TLS key pair");
        (csp, cert)
    }

    fn csprng() -> impl CryptoRng + Rng {
        ChaCha20Rng::seed_from_u64(42)
    }
}
