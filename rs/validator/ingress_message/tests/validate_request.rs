use assert_matches::assert_matches;
use ic_certification_test_utils::{generate_root_of_trust, CertificateBuilder};
use ic_crypto_internal_threshold_sig_bls12381::types::SecretKeyBytes;
use ic_crypto_test_utils_canister_sigs::{encode_sig, CanisterState};
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use ic_types::crypto::{CanisterSig, Signable};
use ic_types::messages::{
    Delegation, HttpCallContent, HttpRequest, SignedDelegation, SignedIngressContent,
};
use ic_types::time::GENESIS;
use ic_types::{CanisterId, PrincipalId, Time};
use ic_validator_ingress_message::IngressMessageVerifier;
use ic_validator_ingress_message::TimeProvider;
use ic_validator_ingress_message::{HttpRequestVerifier, RequestValidationError};
use rand::{CryptoRng, Rng};

const CANISTER_SIGNATURE_SEED: [u8; 1] = [42];
const CANISTER_ID_SIGNER: CanisterId = CanisterId::from_u64(1185);

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

    assert_eq!(result, Ok(()))
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

    assert_eq!(result, Ok(()))
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

    assert_eq!(result, Ok(()))
}

#[test]
fn should_validate_signed_request_from_canister() {
    let mut rng = reproducible_rng();
    let current_time = GENESIS;
    let (root_public_key, root_secret_key) = generate_root_of_trust(&mut rng);
    let verifier = IngressMessageVerifier::builder()
        .with_time_provider(TimeProvider::Constant(current_time))
        .with_root_of_trust(root_public_key)
        .build();
    let request = signed_http_request_by_canister(
        &mut rng,
        current_time.as_nanos_since_unix_epoch(),
        root_public_key,
        root_secret_key,
    );

    let result = verifier.validate_request(&request);

    assert_eq!(result, Ok(()))
}

#[test]
fn should_validate_signed_request_with_delegation_from_canister() {
    let mut rng = reproducible_rng();
    let current_time = GENESIS;
    let (root_public_key, root_secret_key) = generate_root_of_trust(&mut rng);
    let verifier = IngressMessageVerifier::builder()
        .with_time_provider(TimeProvider::Constant(current_time))
        .with_root_of_trust(root_public_key)
        .build();
    let request = signed_http_request_with_delegation_by_canister(
        &mut rng,
        current_time.as_nanos_since_unix_epoch(),
        current_time.as_nanos_since_unix_epoch(),
        root_public_key,
        root_secret_key,
    );

    let result = verifier.validate_request(&request);

    assert_eq!(result, Ok(()))
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

fn signed_http_request_by_canister<R: Rng + CryptoRng>(
    rng: &mut R,
    ingress_expiry: u64,
    root_public_key: ThresholdSigPublicKey,
    root_secret_key: SecretKeyBytes,
) -> HttpRequest<SignedIngressContent> {
    use ic_types::messages::Blob;
    use ic_types::messages::HttpCanisterUpdate;
    use ic_types::messages::HttpRequestEnvelope;

    let derived_public_key =
        derive_canister_public_key_der_format(CANISTER_ID_SIGNER, &CANISTER_SIGNATURE_SEED);

    let update = HttpCanisterUpdate {
        canister_id: Blob(vec![51]),
        method_name: "foo".to_string(),
        arg: Blob(vec![12, 13, 99]),
        nonce: None,
        sender: Blob(
            PrincipalId::new_self_authenticating(&derived_public_key)
                .as_slice()
                .to_vec(),
        ),
        ingress_expiry,
    };
    let message_id = update.id();
    let content = HttpCallContent::Call { update };
    let sender_sig = canister_signature_for_message(
        message_id.as_signed_bytes(),
        CANISTER_ID_SIGNER,
        &CANISTER_SIGNATURE_SEED,
        root_public_key,
        root_secret_key,
        rng,
    );

    let envelope = HttpRequestEnvelope::<HttpCallContent> {
        content,
        sender_pubkey: Some(Blob(derived_public_key)),
        sender_sig: Some(Blob(sender_sig.0)),
        sender_delegation: None,
    };
    HttpRequest::try_from(envelope).expect("invalid http request")
}

fn signed_http_request_with_delegation_by_canister<R: Rng + CryptoRng>(
    rng: &mut R,
    ingress_expiry: u64,
    delegation_expiry: u64,
    root_public_key: ThresholdSigPublicKey,
    root_secret_key: SecretKeyBytes,
) -> HttpRequest<SignedIngressContent> {
    use ic_canister_client_sender::{ed25519_public_key_to_der, Ed25519KeyPair, Sender};
    use ic_types::messages::Blob;
    use ic_types::messages::HttpCanisterUpdate;
    use ic_types::messages::HttpRequestEnvelope;

    let derived_public_key =
        derive_canister_public_key_der_format(CANISTER_ID_SIGNER, &CANISTER_SIGNATURE_SEED);
    let session_keypair = Ed25519KeyPair::generate(rng);
    let canister_delegate_to_session = {
        let delegation = Delegation::new(
            ed25519_public_key_to_der(session_keypair.public_key.to_vec()),
            Time::from_nanos_since_unix_epoch(delegation_expiry),
        );
        let canister_signature = canister_signature_for_message(
            delegation.as_signed_bytes(),
            CANISTER_ID_SIGNER,
            &CANISTER_SIGNATURE_SEED,
            root_public_key,
            root_secret_key,
            rng,
        );
        SignedDelegation::new(delegation, canister_signature.0)
    };
    let update = HttpCanisterUpdate {
        canister_id: Blob(vec![51]),
        method_name: "foo".to_string(),
        arg: Blob(vec![12, 13, 99]),
        nonce: None,
        sender: Blob(
            PrincipalId::new_self_authenticating(&derived_public_key)
                .as_slice()
                .to_vec(),
        ),
        ingress_expiry,
    };
    let message_id = update.id();
    let content = HttpCallContent::Call { update };

    let signer = Sender::from_keypair(&session_keypair);
    let sender_sig = signer
        .sign_message_id(&message_id)
        .expect("Failed signing message with ED25519")
        .map(Blob);

    let envelope = HttpRequestEnvelope::<HttpCallContent> {
        content,
        sender_pubkey: Some(Blob(derived_public_key)),
        sender_sig,
        sender_delegation: Some(vec![canister_delegate_to_session]),
    };
    HttpRequest::try_from(envelope).expect("invalid http request")
}

fn derive_canister_public_key_der_format(signing_canister_id: CanisterId, seed: &[u8]) -> Vec<u8> {
    use ic_crypto_internal_basic_sig_der_utils::subject_public_key_info_der;
    use ic_crypto_test_utils::canister_signatures::canister_sig_pub_key_to_bytes;
    use simple_asn1::oid;

    let pubkey_bytes = canister_sig_pub_key_to_bytes(signing_canister_id, seed);
    subject_public_key_info_der(oid!(1, 3, 6, 1, 4, 1, 56387, 1, 2), &pubkey_bytes)
        .expect("error encoding to DER")
}

fn canister_signature_for_message<R: Rng + CryptoRng>(
    message: Vec<u8>,
    canister_id: CanisterId,
    seed: &[u8],
    root_public_key: ThresholdSigPublicKey,
    root_secret_key: SecretKeyBytes,
    rng: &mut R,
) -> CanisterSig {
    use ic_certification_test_utils::CertificateData;
    use ic_crypto_iccsa::types::Signature;
    use ic_types::messages::Blob;

    let canister_state = canister_state_with_message(message, seed);
    let certificate_data = CertificateData::CanisterData {
        canister_id,
        certified_data: canister_state.root_digest,
    };
    let (_cert, _root_pk, cbor_cert) = CertificateBuilder::new_with_rng(certificate_data, rng)
        .with_root_of_trust(root_public_key, root_secret_key)
        .build();
    let sig_with_canister_witness = Signature {
        certificate: Blob(cbor_cert),
        tree: canister_state.witness,
    };
    CanisterSig(encode_sig(sig_with_canister_witness))
}

fn canister_state_with_message(message: Vec<u8>, seed: &[u8]) -> CanisterState {
    use ic_crypto_test_utils_canister_sigs::{new_canister_state_tree, witness_from_tree};

    let canister_state_tree = new_canister_state_tree(seed, &message[..]);
    let mixed_tree = witness_from_tree(canister_state_tree);
    let hash_tree_digest = mixed_tree.digest();

    CanisterState {
        seed: seed.to_vec(),
        msg: message,
        witness: mixed_tree,
        root_digest: hash_tree_digest,
    }
}
