use ic_crypto::{ecdsa_p256_signature_from_der_bytes, rsa_signature_from_bytes};
use ic_interfaces::crypto::{IngressSigVerifier, Signable};
use ic_types::crypto::BasicSig;
use ic_types::{
    crypto::{AlgorithmId, BasicSigOf, UserPublicKey},
    messages::{WebAuthnEnvelope, WebAuthnSignature},
};
use std::convert::TryFrom;

/// Verifies that a `WebAuthnSignature` signs a `Signable`.
pub(crate) fn validate_webauthn_sig(
    verifier: &dyn IngressSigVerifier,
    webauthn_sig: &WebAuthnSignature,
    signable: &impl Signable,
    public_key: &UserPublicKey,
) -> Result<(), String> {
    let basic_sig = basic_sig_from_webauthn_sig(&webauthn_sig, public_key.algorithm_id)?;

    let envelope = match WebAuthnEnvelope::try_from(webauthn_sig) {
        Ok(envelope) => envelope,
        Err(err) => {
            return Err(format!("WebAuthn envelope creation failed: {}", err));
        }
    };

    // Verify the signature signs the `WebAuthnEnvelope` provided.
    verifier
        .verify_basic_sig_by_public_key(&BasicSigOf::from(basic_sig.clone()), &envelope, public_key)
        .map_err(|e| {
            format!(
                "Verifying signature failed. signature: {:?}; envelope: {:?}; public_key: {}. Error: {}",
                basic_sig, envelope.clone(), public_key, e
            )
        })?;

    // The challenge in the webauthn envelope must match signed bytes.
    let signed_bytes = signable.as_signed_bytes();
    if envelope.challenge() != signed_bytes {
        Err(format!(
            "Challenge in webauthn is {:?} while it is expected to be {:?}",
            envelope.challenge(),
            signed_bytes,
        ))
    } else {
        Ok(())
    }
}

fn basic_sig_from_webauthn_sig(
    webauthn_sig: &&WebAuthnSignature,
    algorithm_id: AlgorithmId,
) -> Result<BasicSig, String> {
    match algorithm_id {
        AlgorithmId::EcdsaP256 => {
            // ECDSA signatures are DER wrapped, see https://www.w3.org/TR/webauthn-2/#sctn-signature-attestation-types
            ecdsa_p256_signature_from_der_bytes(&webauthn_sig.signature().0)
                .map_err(|e| format!("Failed to parse EcdsaP256 signature: {}", e))
        }
        AlgorithmId::RsaSha256 => {
            // RSA signatures are not DER wrapped, see https://www.w3.org/TR/webauthn-2/#sctn-signature-attestation-types
            Ok(rsa_signature_from_bytes(&webauthn_sig.signature()))
        }
        _ => return Err(format!(
            "Only ECDSA on curve P-256 and RSA PKCS #1 v1.5 are supported for WebAuthn, given: {:?}",
            algorithm_id
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webauthn::tests::ecdsa::{
        ECDSA_P256_PK_COSE_DER_WRAPPED_HEX, ECDSA_WEBAUTHN_SIG_HELLO_HEX,
    };
    use ic_crypto::user_public_key_from_bytes;
    use ic_interfaces::crypto::SignableMock;
    use ic_test_utilities::crypto::temp_crypto_component_with_fake_registry;
    use ic_test_utilities::types::ids::{message_test_id, node_test_id};
    use ic_types::{
        messages::{Blob, Delegation},
        time::UNIX_EPOCH,
    };

    mod ecdsa {
        use super::*;

        /// An ECDSA P256 public key in COSE format, DER wrapped. The key was
        /// obtained analogous to the RSA keys in the rsa mod, but in an
        /// interaction with a YubiKey authenticator.
        pub const ECDSA_P256_PK_COSE_DER_WRAPPED_HEX: &str = "305e300c060a2b0601040183b8430101034e00a5010203262001215820b487d183dc4806058eb31a29bedefd7bcca987b77a381a3684871d8449c183942258202a122cc711a80453678c3032de4b6fff2c86342e82d1e7adb617c4165c43ce5e";

        /// An ECDSA P256 signature with the secret key corresponding to the
        /// above public key of the bytes b"hello". The signature was
        /// obtained analogous to the RSA keys in the rsa mod, but in an
        /// interaction with a YubiKey authenticator.
        pub const ECDSA_WEBAUTHN_SIG_HELLO_HEX: &str = "d9d9f7a37261757468656e74696361746f725f646174615825bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b5010000000170636c69656e745f646174615f6a736f6e58517b2274797065223a2022776562617574686e2e676574222c20226368616c6c656e6765223a202261475673624738222c20226f726967696e223a202268747470733a2f2f6578616d706c652e6f7267227d697369676e617475726558463044022063627c69661048fb111b13dec2f3675010493c1c276c6a144f44e1fabab01d300220517d3cbd70658933dab63fd23cf05f7274aea6afad206be04d4ec5e268b471d2";

        #[test]
        fn should_verify_valid_ecdsa_signature_on_bytes() {
            let verifier = temp_crypto_component_with_fake_registry(node_test_id(0));
            // The signature parsed here verifies the bytes b"hello".
            let (pk, sig) = load_pk_and_sig(
                ECDSA_P256_PK_COSE_DER_WRAPPED_HEX.as_ref(),
                ECDSA_WEBAUTHN_SIG_HELLO_HEX.as_bytes(),
            );
            assert_eq!(pk.algorithm_id, AlgorithmId::EcdsaP256);
            let hello_message = SignableMock {
                domain: vec![],
                signed_bytes_without_domain: b"hello".to_vec(),
            };

            assert_eq!(
                validate_webauthn_sig(&verifier, &sig, &hello_message, &pk),
                Ok(())
            );
        }

        #[test]
        fn should_return_error_on_valid_signature_but_wrong_message() {
            let verifier = temp_crypto_component_with_fake_registry(node_test_id(0));
            // The signature parsed here verifies the bytes b"hello".
            let (pk, sig) = load_pk_and_sig(
                ECDSA_P256_PK_COSE_DER_WRAPPED_HEX.as_ref(),
                ECDSA_WEBAUTHN_SIG_HELLO_HEX.as_bytes(),
            );
            let wrong_message = SignableMock {
                domain: vec![0],
                signed_bytes_without_domain: vec![1, 2, 3],
            };

            let result = validate_webauthn_sig(&verifier, &sig, &wrong_message, &pk);

            assert_eq!(result, Err("Challenge in webauthn is [104, 101, 108, 108, 111] while it is expected to be [0, 1, 2, 3]".to_string()));
        }

        #[test]
        fn should_return_error_on_malformed_ecdsa_signature() {
            let verifier = temp_crypto_component_with_fake_registry(node_test_id(0));
            let (pk, sig) = load_pk_and_sig(
                ECDSA_P256_PK_COSE_DER_WRAPPED_HEX.as_ref(),
                ECDSA_WEBAUTHN_SIG_HELLO_HEX.as_bytes(),
            );
            // Replace the correct signature with a malformed one.
            let sig = WebAuthnSignature::new(
                sig.authenticator_data(),
                sig.client_data_json(),
                Blob(vec![]), /* malformed signature */
            );

            let result = validate_webauthn_sig(&verifier, &sig, &SignableMock::new(vec![]), &pk);

            assert!(result
                .err()
                .unwrap()
                .contains("Failed to parse EcdsaP256 signature"));
        }

        #[test]
        fn should_return_error_on_incorrect_public_key() {
            const WRONG_ECDSA_P256_PK_COSE_DER_WRAPPED_HEX: &str = "305E300C060A2B0601040183B8430101034E00A50102032620012158207FFD83632072FD1BFEAF3FBAA43146E0EF95C3F55E3994A41BBF2B5174D771DA22582032497EED0A7F6F000928765B8318162CFD80A94E525A6A368C2363063D04E6ED";
            let verifier = temp_crypto_component_with_fake_registry(node_test_id(0));
            // The signature signs the delegation prepended by its domain separator.
            let (wrong_pk, sig) = load_pk_and_sig(
                WRONG_ECDSA_P256_PK_COSE_DER_WRAPPED_HEX.as_ref(),
                ECDSA_WEBAUTHN_SIG_HELLO_HEX.as_bytes(),
            );
            let result =
                validate_webauthn_sig(&verifier, &sig, &SignableMock::new(vec![]), &wrong_pk);

            assert!(result
                .err()
                .unwrap()
                .contains("Verifying signature failed."));
        }
    }

    mod rsa {
        use super::*;

        /// An RSA PKCS #1 v1.5 public key in COSE format, DER wrapped. The key
        /// was obtained as follows in an interaction with a Windows
        /// Hello authenticator:
        /// * navigator.credentials.create() returns a public key in COSE.
        /// * This public key was then DER encoded according to the interface spec here: https://docs.dfinity.systems/spec/public/#webauthn
        /// * Finally, the key was hex encoded.
        pub const RSA_PK_COSE_DER_WRAPPED_HEX: &str = "30820123300c060a2b0601040183b84301010382011100a401030339010020590100c6b690341eef02719f6d1dfce2db1f77ac9bd632ba70efcee92bae2073c09927ee3670a6696eec0cee96189ddb448d04ec4e4674e940af9f905e893b4ce25821ada8b45c6cd11f2ee0cda668c7c2a2a8a56d5e1f23f5ca0bb6e193c1d34ead16d84cc4b72e26763711fcf49fac3b508715dc9f494ec1379ed5a95c53b9b1edcc027d7013248bbe6d1e1445912a5a21b27168db7f60aa73253e981c33f54f61c67dbce3d9c10d5f0e6af1c112a65c8ce64a1d01ae1e31a53e3d4525addcece402f1e62208d42ebde528830f93bebc898901947ec0fb218a96a53968d07e09b8a067e5a4c825632e24e450c4c9ef8138dcc91f9f9168a603c13bd4f2f8a0d3ee6b2143010001";

        /// An RSA signature with the secret key corresponding to the above
        /// public key of the bytes b"hello"
        /// * navigator.credentials.get() takes a challenge set to b"hello"
        /// * The returned signature was then hex encoded.
        pub const RSA_WEBAUTHN_SIG_HELLO_HEX: &str = "d9d9f7a3697369676e617475726559010001dac0ad9ee89c9b9d3f772bb8dd79bc16839a026bf4378629789bede8e5e284bce9c59e2c5b2fd5d8daff964d4eec1a43eb6f083595f1ce42c9f78445dba95146e3338680ca72f7720371d88d56ab6578a67f9791954787d54e4c5687bb0d3379a268dbaa9dc8dd550187953c349e10e454c0950cfeaf37c5f01ff09a5b581fb81de8bfe9be21a8baa5f96653fce6eaf485d8726e1f620454c145fa542756e7b606f1ab9439a081bb01fec8be7679c72e2ce110655a36a01bde34be7be9e6270334d9b3f242ff12852992eeb515b13989245d049500629a5ac38c40f09dd218e8e1a790d3034418b7c3b59a6ac73e91b5bf4cf7c62d8e6de2dbaf00117045c070636c69656e745f646174615f6a736f6e786a7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2261475673624738222c226f726967696e223a2268747470733a2f2f6333656634366165616437622e6e67726f6b2e696f222c2263726f73734f726967696e223a66616c73657d7261757468656e74696361746f725f6461746158252f8ceaf48dec5b53d9ddacaaf8b66392ded1691211f24e687badad8049b59ef60500000001";

        #[test]
        fn should_verify_valid_rsa_signature_on_bytes() {
            let verifier = temp_crypto_component_with_fake_registry(node_test_id(0));
            // The signature parsed here verifies the bytes b"hello".
            let (pk, sig) = load_pk_and_sig(
                RSA_PK_COSE_DER_WRAPPED_HEX.as_ref(),
                RSA_WEBAUTHN_SIG_HELLO_HEX.as_bytes(),
            );
            assert_eq!(pk.algorithm_id, AlgorithmId::RsaSha256);
            let hello_message = SignableMock {
                domain: vec![],
                signed_bytes_without_domain: b"hello".to_vec(),
            };

            assert_eq!(
                validate_webauthn_sig(&verifier, &sig, &hello_message, &pk),
                Ok(())
            );
        }

        #[test]
        fn should_return_error_on_valid_signature_but_wrong_message() {
            let verifier = temp_crypto_component_with_fake_registry(node_test_id(0));
            // The signature parsed here verifies the bytes b"hello".
            let (pk, sig) = load_pk_and_sig(
                RSA_PK_COSE_DER_WRAPPED_HEX.as_ref(),
                RSA_WEBAUTHN_SIG_HELLO_HEX.as_bytes(),
            );
            let wrong_message = SignableMock {
                domain: vec![0],
                signed_bytes_without_domain: vec![1, 2, 3],
            };

            let result = validate_webauthn_sig(&verifier, &sig, &wrong_message, &pk);

            assert_eq!(result, Err("Challenge in webauthn is [104, 101, 108, 108, 111] while it is expected to be [0, 1, 2, 3]".to_string()));
        }

        #[test]
        fn should_return_error_on_malformed_rsa_signature() {
            let verifier = temp_crypto_component_with_fake_registry(node_test_id(0));
            let (pk, sig) = load_pk_and_sig(
                RSA_PK_COSE_DER_WRAPPED_HEX.as_ref(),
                RSA_WEBAUTHN_SIG_HELLO_HEX.as_bytes(),
            );
            println!("{}", pk);
            // Replace the correct signature with a malformed one.
            let sig = WebAuthnSignature::new(
                sig.authenticator_data(),
                sig.client_data_json(),
                Blob(vec![0, 1, 2]), /* malformed signature */
            );

            let result = validate_webauthn_sig(&verifier, &sig, &SignableMock::new(vec![]), &pk);

            assert!(result.err().unwrap().contains("Verifying signature failed"));
        }

        #[test]
        fn should_return_error_on_incorrect_public_key() {
            const WRONG_RSA_PK_COSE_DER_WRAPPED_HEX: &str = "30820123300c060a2b0601040183b84301010382011100a401030339010020590100c0d78fff40992040ab05d549607fec811e8402770e0b99bd338d30b22b961282c75087e68481736322ba174f06c15297e283fc6fa6f5ea9e87fc6330183d1552364eb17dc2538a8029de64e4ef7f6099fe7d9db8ffb5f9d820d6092d9f8421ef6123163b993ff6fff83878165d0a609960ca16e1c427af6f7e74382afd8ec8c3ce231f96d48ea26c2013f3de07f9904f8f6a89f4a76bc2daa03e6a744559cc638380ef2f4bff030a44a8266eba1850492d90e55030bc04b34cadd74b7234e4116ee42f00915d4fb77ca37592ab86fb4d9a436ebbbefffbb9a9ce2fcb0528b3fca7fa73267750f6aa35ece632f9fbca73f2a37e4fb10e81f108dabd59d74478832143010001";
            let verifier = temp_crypto_component_with_fake_registry(node_test_id(0));
            // The signature signs the delegation prepended by its domain separator.
            let (wrong_pk, sig) = load_pk_and_sig(
                WRONG_RSA_PK_COSE_DER_WRAPPED_HEX.as_ref(),
                RSA_WEBAUTHN_SIG_HELLO_HEX.as_bytes(),
            );

            let result =
                validate_webauthn_sig(&verifier, &sig, &SignableMock::new(vec![]), &wrong_pk);

            assert!(result
                .err()
                .unwrap()
                .contains("Verifying signature failed."));
        }
    }

    #[test]
    fn should_return_error_if_algorithm_id_is_not_supported() {
        let verifier = temp_crypto_component_with_fake_registry(node_test_id(0));
        let delegation = Delegation::new(vec![1, 2, 3], UNIX_EPOCH);
        let (mut pk, sig) = load_pk_and_sig(
            ECDSA_P256_PK_COSE_DER_WRAPPED_HEX.as_ref(),
            ECDSA_WEBAUTHN_SIG_HELLO_HEX.as_ref(),
        );
        let unsupported_algorithm_id = AlgorithmId::Ed25519;
        pk.algorithm_id = unsupported_algorithm_id;

        let result = validate_webauthn_sig(&verifier, &sig, &delegation, &pk);

        assert!(
            result.err().unwrap().contains("Only ECDSA on curve P-256 and RSA PKCS #1 v1.5 are supported for WebAuthn, given: Ed25519")
        );
    }

    #[test]
    fn should_verify_delegation() {
        let verifier = temp_crypto_component_with_fake_registry(node_test_id(0));
        let delegation = Delegation::new(vec![1, 2, 3], UNIX_EPOCH);

        let (pk, sig) = load_pk_and_sig(
            ECDSA_P256_PK_COSE_DER_WRAPPED_HEX.as_ref(),
            "d9d9f7a37261757468656e74696361746f725f646174615825bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b5010000000170636c69656e745f646174615f6a736f6e58997b2274797065223a2022776562617574686e2e676574222c20226368616c6c656e6765223a2022476d6c6a4c584a6c6358566c63335174595856306143316b5a57786c5a32463061573975624d7952313366786f7246576730775069346566504e774b562d7a76486467504868716649536d77677141222c20226f726967696e223a202268747470733a2f2f6578616d706c652e6f7267227d697369676e617475726558483046022100d4b7541f3b1b61dd9c6f818f20f54f8b938fe222d88cca6700fabd82a522f13b022100c636b52dfd679b1f86eeb5fcaff360e70b57caa9fe186e1e77c42228eca49037".as_ref(),
        );

        assert!(validate_webauthn_sig(&verifier, &sig, &delegation, &pk).is_ok());
    }

    #[test]
    fn should_verify_message_id() {
        let verifier = temp_crypto_component_with_fake_registry(node_test_id(0));
        let message_id = message_test_id(13);

        // The signature signs the message ID prepended by its domain separator.
        let (pk, sig) = load_pk_and_sig(
            ECDSA_P256_PK_COSE_DER_WRAPPED_HEX.as_ref(),
            "d9d9f7a37261757468656e74696361746f725f646174615825bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b5010000000170636c69656e745f646174615f6a736f6e58847b2274797065223a2022776562617574686e2e676574222c20226368616c6c656e6765223a2022436d6c6a4c584a6c6358566c6333514e414141414141414141414141414141414141414141414141414141414141414141414141414141414141222c20226f726967696e223a202268747470733a2f2f6578616d706c652e6f7267227d697369676e617475726558473045022100e4029fcf1cec44e0e2a33b2b2b981411376d89f90bec9ee7d4e20ca33ce8f088022070e95aa9dd3f0cf0d6f97f306d52211288482d565012202b349b2a2d80852635".as_ref(),
        );

        assert!(validate_webauthn_sig(&verifier, &sig, &message_id, &pk).is_ok());
    }

    fn load_pk_and_sig(pk_bytes: &[u8], sig_bytes: &[u8]) -> (UserPublicKey, WebAuthnSignature) {
        let pk = {
            let pk_cose = hex::decode(pk_bytes).unwrap();
            let (pk, _) = user_public_key_from_bytes(&pk_cose).unwrap();
            pk
        };
        let sig = {
            let sig = hex::decode(sig_bytes).unwrap();
            WebAuthnSignature::try_from(sig.as_slice()).unwrap()
        };
        (pk, sig)
    }
}
