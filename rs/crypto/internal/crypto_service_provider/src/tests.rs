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
            });

            assert!(data.is_err())
        }

        #[test]
        fn should_retrieve_current_node_public_keys() {
            let csp = csp_with_public_keys(NodePublicKeys {
                version: 0,
                node_signing_pk: Some(valid_node_signing_key()),
                committee_signing_pk: None,
                tls_certificate: None,
                dkg_dealing_encryption_pk: Some(valid_dkg_dealing_encryption_pk()),
                idkg_dealing_encryption_pk: None,
            });

            let current_public_keys = csp.current_node_public_keys();

            assert_eq!(
                current_public_keys.node_signing_public_key,
                Some(valid_node_signing_key())
            );
            assert!(current_public_keys.committee_signing_public_key.is_none());
            assert!(current_public_keys.tls_certificate.is_none());
            assert_eq!(
                current_public_keys.dkg_dealing_encryption_public_key,
                Some(valid_dkg_dealing_encryption_pk())
            );
            assert!(current_public_keys
                .idkg_dealing_encryption_public_key
                .is_none());
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
            });

            let current_public_keys = csp.current_node_public_keys();

            assert!(current_public_keys.node_signing_public_key.is_none());
            assert!(current_public_keys.committee_signing_public_key.is_none());
            assert!(current_public_keys.tls_certificate.is_none());
            assert!(current_public_keys
                .dkg_dealing_encryption_public_key
                .is_none());
            assert!(current_public_keys
                .idkg_dealing_encryption_public_key
                .is_none());
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
