use ic_crypto::ecdsa_p256_signature_from_der_bytes;
use ic_interfaces::crypto::{IngressSigVerifier, Signable};
use ic_types::{
    crypto::{BasicSigOf, UserPublicKey},
    messages::{WebAuthnEnvelope, WebAuthnSignature},
};
use std::convert::TryFrom;

/// Verifies that a `WebAuthnSignature` signs a `Signable`.
pub(crate) fn validate_webauthn_sig(
    verifier: &dyn IngressSigVerifier,
    signature: &WebAuthnSignature,
    signable: &impl Signable,
    public_key: &UserPublicKey,
) -> Result<(), String> {
    let envelope = match WebAuthnEnvelope::try_from(signature) {
        Ok(envelope) => envelope,
        Err(err) => {
            return Err(format!("WebAuthn envelope creation failed: {}", err));
        }
    };

    let signature = BasicSigOf::from(
        ecdsa_p256_signature_from_der_bytes(&signature.signature().0)
            .map_err(|e| format!("Failed parsing signature: {}", e))?,
    );

    // Verify the signature signs the `WebAuthnEnvelope` provided.
    verifier
        .verify_basic_sig_by_public_key(&signature, &envelope, public_key)
        .map_err(|e| format!("Verifying signature for failed: {}", e))?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use ic_crypto::user_public_key_from_bytes;
    use ic_interfaces::crypto::SignableMock;
    use ic_test_utilities::crypto::temp_crypto_component_with_fake_registry;
    use ic_test_utilities::types::ids::{message_test_id, node_test_id};
    use ic_types::{
        messages::{Blob, Delegation},
        time::UNIX_EPOCH,
    };

    const ECDSA_P256_PK_COSE_DER_WRAPPED_HEX: &str = "305e300c060a2b0601040183b8430101034e00a5010203262001215820b487d183dc4806058eb31a29bedefd7bcca987b77a381a3684871d8449c183942258202a122cc711a80453678c3032de4b6fff2c86342e82d1e7adb617c4165c43ce5e";

    const WEBAUTHN_SIG_HELLO: &str = "d9d9f7a37261757468656e74696361746f725f646174615825bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b5010000000170636c69656e745f646174615f6a736f6e58517b2274797065223a2022776562617574686e2e676574222c20226368616c6c656e6765223a202261475673624738222c20226f726967696e223a202268747470733a2f2f6578616d706c652e6f7267227d697369676e617475726558463044022063627c69661048fb111b13dec2f3675010493c1c276c6a144f44e1fabab01d300220517d3cbd70658933dab63fd23cf05f7274aea6afad206be04d4ec5e268b471d2";

    #[test]
    fn verify_signature_on_bytes() {
        let verifier = temp_crypto_component_with_fake_registry(node_test_id(0));

        // The signature parsed here verifies the bytes b"hello".
        let (pk, sig) = load_pk_and_sig(
            ECDSA_P256_PK_COSE_DER_WRAPPED_HEX.as_ref(),
            WEBAUTHN_SIG_HELLO.as_bytes(),
        );

        let signable = SignableMock {
            domain: vec![],
            signed_bytes_without_domain: b"hello".to_vec(),
        };

        assert_eq!(
            validate_webauthn_sig(&verifier, &sig, &signable, &pk),
            Ok(())
        );

        // Try again with an incorrect `Signable`. Should fail.
        let wrong_signable = SignableMock {
            domain: vec![],
            signed_bytes_without_domain: vec![],
        };
        assert!(validate_webauthn_sig(&verifier, &sig, &wrong_signable, &pk).is_err());
    }

    #[test]
    fn malformed_signature_fails() {
        let verifier = temp_crypto_component_with_fake_registry(node_test_id(0));

        let (pk, sig) = load_pk_and_sig(
            ECDSA_P256_PK_COSE_DER_WRAPPED_HEX.as_ref(),
            WEBAUTHN_SIG_HELLO.as_bytes(),
        );

        // Replace the correct signature with a malformed one.
        let sig = WebAuthnSignature::new(
            sig.authenticator_data(),
            sig.client_data_json(),
            Blob(vec![]), /* malformed signature */
        );

        assert!(validate_webauthn_sig(&verifier, &sig, &SignableMock::new(vec![]), &pk).is_err());
    }

    #[test]
    fn incorrect_public_key_fails() {
        let verifier = temp_crypto_component_with_fake_registry(node_test_id(0));

        // The signature signs the delegation prepended by its domain separator.
        let (pk, sig) = load_pk_and_sig(
            "305E300C060A2B0601040183B8430101034E00A50102032620012158207FFD83632072FD1BFEAF3FBAA43146E0EF95C3F55E3994A41BBF2B5174D771DA22582032497EED0A7F6F000928765B8318162CFD80A94E525A6A368C2363063D04E6ED".as_ref(), // Incorrect public key.
            WEBAUTHN_SIG_HELLO.as_bytes(),
        );

        assert!(validate_webauthn_sig(&verifier, &sig, &SignableMock::new(vec![]), &pk).is_err());
    }

    #[test]
    fn verifying_delegation_succeeds() {
        let verifier = temp_crypto_component_with_fake_registry(node_test_id(0));
        let delegation = Delegation::new(vec![1, 2, 3], UNIX_EPOCH);

        let (pk, sig) = load_pk_and_sig(
            ECDSA_P256_PK_COSE_DER_WRAPPED_HEX.as_ref(),
            "d9d9f7a37261757468656e74696361746f725f646174615825bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b5010000000170636c69656e745f646174615f6a736f6e58997b2274797065223a2022776562617574686e2e676574222c20226368616c6c656e6765223a2022476d6c6a4c584a6c6358566c63335174595856306143316b5a57786c5a32463061573975624d7952313366786f7246576730775069346566504e774b562d7a76486467504868716649536d77677141222c20226f726967696e223a202268747470733a2f2f6578616d706c652e6f7267227d697369676e617475726558483046022100d4b7541f3b1b61dd9c6f818f20f54f8b938fe222d88cca6700fabd82a522f13b022100c636b52dfd679b1f86eeb5fcaff360e70b57caa9fe186e1e77c42228eca49037".as_ref(),
        );

        assert!(validate_webauthn_sig(&verifier, &sig, &delegation, &pk).is_ok());
    }

    #[test]
    fn verifying_message_id_succeeds() {
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
