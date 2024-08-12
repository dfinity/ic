#![allow(clippy::unwrap_used)]
mod csp_tests {
    use crate::api::CspSigner;
    use crate::Csp;
    use crate::CspPublicKey;
    use crate::KeyId;
    use ic_types::crypto::AlgorithmId;

    mod csp_public_key_store {
        use super::*;
        use ic_types::crypto::CurrentNodePublicKeys;

        #[test]
        fn should_return_empty_when_no_public_keys() {
            let csp = Csp::builder_for_test().build();

            let current_node_public_keys = csp
                .csp_vault
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
                .csp_vault
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

    fn csp_with_node_signing_key_pair() -> (Csp, CspPublicKey) {
        let csp = Csp::builder_for_test().build();
        let public_key = csp
            .csp_vault
            .gen_node_signing_key_pair()
            .expect("error generating public/private key pair");
        (csp, public_key)
    }
}
