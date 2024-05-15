#![allow(clippy::unwrap_used)]
mod csp_tests {
    use crate::api::CspSigner;
    use crate::api::CspTlsHandshakeSignerProvider;
    use crate::vault::test_utils::ed25519_csp_pubkey_from_tls_pubkey_cert;
    use crate::Csp;
    use crate::CspPublicKey;
    use crate::KeyId;
    use ic_crypto_tls_interfaces::TlsPublicKeyCert;
    use ic_types::crypto::AlgorithmId;
    use ic_types_test_utils::ids::node_test_id;

    mod csp_public_key_store {
        use super::*;
        use crate::CspPublicKeyStore;
        use ic_types::crypto::CurrentNodePublicKeys;

        #[test]
        fn should_return_empty_when_no_public_keys() {
            let csp = Csp::builder_for_test().build();

            let current_node_public_keys = csp
                .current_node_public_keys()
                .expect("Failed to retrieve node public keys");

            assert_eq!(
                current_node_public_keys,
                CurrentNodePublicKeys {
                    node_signing_public_key: None,
                    committee_signing_public_key: None,
                    tls_certificate: None,
                    dkg_dealing_encryption_public_key: None,
                    idkg_dealing_encryption_public_key: None
                }
            );
        }

        #[test]
        fn should_return_zero_key_count_when_no_public_keys() {
            let csp = Csp::builder_for_test().build();

            let key_count = csp
                .idkg_dealing_encryption_pubkeys_count()
                .expect("Failed to retrieve iDKG dealing encryption public keys count");

            assert_eq!(key_count, 0);
        }
    }

    #[test]
    fn should_sign_and_verify_with_newly_generated_secret_key_from_store() {
        let (csp, public_key) = csp_with_node_signing_key_pair();
        let key_id = KeyId::try_from(&public_key).unwrap();
        let message = "Hello world!".as_bytes();

        let signature = csp
            .sign(AlgorithmId::Ed25519, message.to_vec(), key_id)
            .expect("error signing message");

        let verification = csp.verify(&signature, message, AlgorithmId::Ed25519, public_key);

        assert!(verification.is_ok());
    }

    #[test]
    fn should_sign_and_verify_with_newly_generated_tls_secret_key_from_store() {
        let (csp, cert) = csp_with_tls_key_pair();
        let key_id = KeyId::try_from(&cert).unwrap();
        let message = "Hello world!".as_bytes();

        let signature = csp
            .handshake_signer()
            .tls_sign(message.to_vec(), key_id)
            .expect("error signing message with TLS private key");

        let public_key = ed25519_csp_pubkey_from_tls_pubkey_cert(&cert);
        let verification = csp.verify(&signature, message, AlgorithmId::Ed25519, public_key);

        assert!(verification.is_ok());
    }

    fn csp_with_node_signing_key_pair() -> (Csp, CspPublicKey) {
        let csp = Csp::builder_for_test().build();
        let public_key = csp
            .csp_vault
            .gen_node_signing_key_pair()
            .expect("error generating public/private key pair");
        (csp, public_key)
    }

    fn csp_with_tls_key_pair() -> (Csp, TlsPublicKeyCert) {
        const NODE_1: u64 = 4241;
        let csp = Csp::builder_for_test().build();
        let cert = csp
            .csp_vault
            .gen_tls_key_pair(node_test_id(NODE_1))
            .expect("error generating TLS key pair");
        (csp, cert)
    }
}
