use assert_matches::assert_matches;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_types::crypto::Signable;
use ic_types::messages::{
    Delegation, HttpCallContent, HttpRequest, SignedDelegation, SignedIngressContent,
};
use ic_types::time::GENESIS;
use ic_types::Time;
use ic_validator_ingress_message::IngressMessageVerifier;
use ic_validator_ingress_message::TimeProvider;
use ic_validator_ingress_message::{HttpRequestVerifier, RequestValidationError};
use rand::{CryptoRng, Rng};

#[test]
fn should_reject_request_when_expired_with_default_verifier() {
    let verifier = IngressMessageVerifier::default();
    let request = anonymous_http_request_with_ingress_expiry(GENESIS.as_nanos_since_unix_epoch());

    let result = verifier.validate_request(&request);

    assert_matches!(result, Err(RequestValidationError::InvalidIngressExpiry(_)))
}

#[test]
fn should_validate_anonymous_request() {
    let current_time = GENESIS;
    let verifier = IngressMessageVerifier::builder()
        .with_time_provider(TimeProvider::Constant(current_time))
        .build();
    let request =
        anonymous_http_request_with_ingress_expiry(current_time.as_nanos_since_unix_epoch());

    let result = verifier.validate_request(&request);

    assert_matches!(result, Ok(()))
}

#[test]
fn should_validate_signed_request_without_delegation() {
    let mut rng = reproducible_rng();
    let current_time = GENESIS;
    let verifier = IngressMessageVerifier::builder()
        .with_time_provider(TimeProvider::Constant(current_time))
        .build();
    let request =
        signed_http_request_with_ed25519(&mut rng, current_time.as_nanos_since_unix_epoch());

    let result = verifier.validate_request(&request);

    assert_matches!(result, Ok(()))
}

#[test]
fn should_validate_signed_request_with_delegation() {
    let mut rng = reproducible_rng();
    let current_time = GENESIS;
    let verifier = IngressMessageVerifier::builder()
        .with_time_provider(TimeProvider::Constant(current_time))
        .build();
    let request = signed_http_request_with_delegation(
        &mut rng,
        current_time.as_nanos_since_unix_epoch(),
        current_time.as_nanos_since_unix_epoch(),
    );

    let result = verifier.validate_request(&request);

    assert_matches!(result, Ok(()))
}

fn anonymous_http_request_with_ingress_expiry(
    ingress_expiry: u64,
) -> HttpRequest<SignedIngressContent> {
    use ic_types::messages::Blob;
    use ic_types::messages::HttpCanisterUpdate;
    use ic_types::messages::HttpRequestEnvelope;
    HttpRequest::try_from(HttpRequestEnvelope::<HttpCallContent> {
        content: HttpCallContent::Call {
            update: HttpCanisterUpdate {
                canister_id: Blob(vec![42; 8]),
                method_name: "some_method".to_string(),
                arg: Blob(b"".to_vec()),
                sender: Blob(vec![0x04]),
                nonce: None,
                ingress_expiry,
            },
        },
        sender_pubkey: None,
        sender_sig: None,
        sender_delegation: None,
    })
    .expect("invalid http envelope")
}

fn signed_http_request_with_ed25519<R: Rng + CryptoRng>(
    rng: &mut R,
    ingress_expiry: u64,
) -> HttpRequest<SignedIngressContent> {
    use ic_canister_client_sender::{Ed25519KeyPair, Sender};
    use ic_types::messages::Blob;
    use ic_types::messages::HttpCanisterUpdate;
    use ic_types::messages::HttpRequestEnvelope;
    use ic_types::UserId;

    let keypair = Ed25519KeyPair::generate(rng);
    let sender = Sender::from_keypair(&keypair);
    let update = HttpCanisterUpdate {
        canister_id: Blob(vec![51]),
        method_name: "foo".to_string(),
        arg: Blob(vec![12, 13, 99]),
        nonce: None,
        sender: Blob(UserId::from(sender.get_principal_id()).get().into_vec()),
        ingress_expiry,
    };
    let message_id = update.id();
    let content = HttpCallContent::Call { update };
    let sender_pubkey = sender.sender_pubkey_der().map(Blob);
    let sender_sig = sender
        .sign_message_id(&message_id)
        .expect("Failed signing message with ED25519")
        .map(Blob);

    let envelope = HttpRequestEnvelope::<HttpCallContent> {
        content,
        sender_pubkey,
        sender_sig,
        sender_delegation: None,
    };
    HttpRequest::try_from(envelope).expect("invalid http request")
}

fn signed_http_request_with_delegation<R: Rng + CryptoRng>(
    rng: &mut R,
    ingress_expiry: u64,
    delegation_expiry: u64,
) -> HttpRequest<SignedIngressContent> {
    use ic_canister_client_sender::{ed25519_public_key_to_der, Ed25519KeyPair, Sender};
    use ic_types::messages::Blob;
    use ic_types::messages::HttpCanisterUpdate;
    use ic_types::messages::HttpRequestEnvelope;
    use ic_types::UserId;

    let sender_keypair = Ed25519KeyPair::generate(rng);
    let intermediate_keypair = Ed25519KeyPair::generate(rng);
    let signer_keypair = Ed25519KeyPair::generate(rng);
    let sender_delegate_to_intermediate = {
        let delegation = Delegation::new(
            ed25519_public_key_to_der(intermediate_keypair.public_key.to_vec()),
            Time::from_nanos_since_unix_epoch(delegation_expiry),
        );
        let signature = sender_keypair.sign(&delegation.as_signed_bytes()).to_vec();
        SignedDelegation::new(delegation, signature)
    };
    let intermediate_delegate_to_signer = {
        let delegation = Delegation::new(
            ed25519_public_key_to_der(signer_keypair.public_key.to_vec()),
            Time::from_nanos_since_unix_epoch(delegation_expiry),
        );
        let signature = intermediate_keypair
            .sign(&delegation.as_signed_bytes())
            .to_vec();
        SignedDelegation::new(delegation, signature)
    };

    let sender = Sender::from_keypair(&sender_keypair);
    let signer = Sender::from_keypair(&signer_keypair);
    let update = HttpCanisterUpdate {
        canister_id: Blob(vec![51]),
        method_name: "foo".to_string(),
        arg: Blob(vec![12, 13, 99]),
        nonce: None,
        sender: Blob(UserId::from(sender.get_principal_id()).get().into_vec()),
        ingress_expiry,
    };
    let message_id = update.id();
    let content = HttpCallContent::Call { update };
    let sender_pubkey = sender.sender_pubkey_der().map(Blob);
    let sender_sig = signer
        .sign_message_id(&message_id)
        .expect("Failed signing message with ED25519")
        .map(Blob);

    let envelope = HttpRequestEnvelope::<HttpCallContent> {
        content,
        sender_pubkey,
        sender_sig,
        sender_delegation: Some(vec![
            sender_delegate_to_intermediate,
            intermediate_delegate_to_signer,
        ]),
    };
    HttpRequest::try_from(envelope).expect("invalid http request")
}
