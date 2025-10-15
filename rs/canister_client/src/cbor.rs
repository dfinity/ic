use ic_canister_client_sender::Sender;
use ic_crypto_tree_hash::Path;
use ic_read_state_response_parser::RequestStatus;
use ic_types::{
    CanisterId, Time,
    messages::{
        Blob, HttpCallContent, HttpCanisterUpdate, HttpQueryContent, HttpReadState,
        HttpReadStateContent, HttpRequestEnvelope, HttpUserQuery, MessageId, SignedRequestBytes,
    },
    time::expiry_time_from_now,
};
use serde_cbor::value::Value as CBOR;
use std::convert::TryFrom;
use std::error::Error;

/// Given a CBOR response from a `query`, extract the response.
pub fn parse_query_response(message: &CBOR) -> Result<RequestStatus, String> {
    let content = match message {
        CBOR::Map(content) => Ok(content),
        cbor => Err(format!(
            "Expected a Map in the reply root but found {cbor:?}"
        )),
    }?;

    let status_key = &CBOR::Text("status".to_string());
    let status = match &content.get(status_key) {
        Some(CBOR::Text(t)) => Ok(t.to_string()),
        Some(cbor) => Err(format!(
            "Expected Text at key '{status_key:?}', but found '{cbor:?}'"
        )),
        None => Err(format!(
            "Key '{:?}' not found in '{:?}'",
            status_key, &content
        )),
    }?;

    let reply_key = CBOR::Text("reply".to_string());
    let reply = match &content.get(&reply_key) {
        Some(CBOR::Map(btree)) => Ok(Some(btree)),
        Some(cbor) => Err(format!(
            "Expected Map at key '{reply_key:?}' but found '{cbor:?}'"
        )),
        None => Ok(None),
    }?;

    let reply = match reply {
        None => Ok(None),
        Some(r) => {
            let arg_key = CBOR::Text("arg".to_string());
            match r.get(&arg_key) {
                Some(CBOR::Bytes(bytes)) => Ok(Some(bytes.to_vec())),
                Some(cbor) => Err(format!(
                    "Expected the value of key '{arg_key:?}' to be bytes, but found '{cbor:?}'"
                )),
                None => Ok(None),
            }
        }
    }?;

    // Attempt to extract reject message from reply
    let mut reject_message = None;
    if let Some(CBOR::Text(b)) = &content.get(&CBOR::Text("reject_message".to_string())) {
        reject_message = Some(b.to_string());
    }

    Ok(RequestStatus {
        status,
        reply,
        reject_message,
    })
}

/// Prepares an update request.
pub fn prepare_update<S: ToString>(
    sender: &Sender,
    canister_id: &CanisterId,
    method: S,
    arguments: Vec<u8>,
    nonce: Vec<u8>,
    ingress_expiry: Time,
    sender_field: Blob,
) -> Result<(SignedRequestBytes, MessageId), Box<dyn Error>> {
    let content = HttpCallContent::Call {
        update: HttpCanisterUpdate {
            canister_id: to_blob(canister_id),
            method_name: method.to_string(),
            arg: Blob(arguments),
            nonce: Some(Blob(nonce)),
            sender: sender_field,
            ingress_expiry: ingress_expiry.as_nanos_since_unix_epoch(),
        },
    };

    let (submit_request, request_id) = sign_submit(content, sender)?;
    let signed_request_bytes = SignedRequestBytes::try_from(submit_request)?;
    Ok((signed_request_bytes, request_id))
}

/// Prepares and serializes a CBOR query request.
pub fn prepare_query(
    sender: &Sender,
    canister_id: &CanisterId,
    method: &str,
    arguments: Vec<u8>,
    sender_field: Blob,
) -> Result<SignedRequestBytes, Box<dyn Error>> {
    let content = HttpQueryContent::Query {
        query: HttpUserQuery {
            canister_id: to_blob(canister_id),
            method_name: method.to_string(),
            arg: Blob(arguments),
            sender: sender_field,
            nonce: None,
            ingress_expiry: expiry_time_from_now().as_nanos_since_unix_epoch(),
        },
    };

    let request = sign_query(content, sender)?;
    Ok(SignedRequestBytes::try_from(request)?)
}

/// Prepares and serializes a CBOR read_state request, with the given paths
pub fn prepare_read_state(
    sender: &Sender,
    paths: &[Path],
    sender_field: Blob,
) -> Result<SignedRequestBytes, Box<dyn Error>> {
    let content = HttpReadStateContent::ReadState {
        read_state: HttpReadState {
            sender: sender_field,
            paths: paths.to_vec(),
            nonce: None,
            ingress_expiry: expiry_time_from_now().as_nanos_since_unix_epoch(),
        },
    };

    let request = sign_read_state(content, sender)?;
    Ok(SignedRequestBytes::try_from(request)?)
}

fn to_blob(canister_id: &CanisterId) -> Blob {
    Blob(canister_id.get().into_vec())
}

/// Wraps the content into an envelope that contains the message signature.
///
/// Prerequisite: `content` contains a `sender` field that is compatible with
/// the `keypair` argument.
fn sign_submit(
    content: HttpCallContent,
    sender: &Sender,
) -> Result<(HttpRequestEnvelope<HttpCallContent>, MessageId), Box<dyn Error>> {
    // Open question: should this also set the `sender` field of the `content`? The
    // two are linked, but it's a bit weird for a function that presents itself
    // as 'wrapping a content into an envelope' to mess up with the content.

    let message_id = match &content {
        HttpCallContent::Call { update } => update.id(),
    };

    let pub_key_der = sender.sender_pubkey_der().map(Blob);
    let sender_sig = sender.sign_message_id(&message_id)?.map(Blob);

    let envelope = HttpRequestEnvelope::<HttpCallContent> {
        content,
        sender_pubkey: pub_key_der,
        sender_sig,
        sender_delegation: None,
    };
    Ok((envelope, message_id))
}

/// Wraps the content into an envelope that contains the message signature.
///
/// Prerequisite: if `content` contains a `sender` field (this is the case for
/// queries, but not for request_status), then this 'sender' must be compatible
/// with the `keypair` argument.
fn sign_read_state(
    content: HttpReadStateContent,
    sender: &Sender,
) -> Result<HttpRequestEnvelope<HttpReadStateContent>, Box<dyn Error>> {
    let message_id = content.id();
    let pub_key_der = sender.sender_pubkey_der().map(Blob);
    let sender_sig = sender.sign_message_id(&message_id)?.map(Blob);

    Ok(HttpRequestEnvelope::<HttpReadStateContent> {
        content,
        sender_pubkey: pub_key_der,
        sender_sig,
        sender_delegation: None,
    })
}

/// Wraps the content into an envelope that contains the message signature.
///
/// Prerequisite: if `content` contains a `sender` field (this is the case for
/// queries, but not for request_status), then this 'sender' must be compatible
/// with the `keypair` argument.
fn sign_query(
    content: HttpQueryContent,
    sender: &Sender,
) -> Result<HttpRequestEnvelope<HttpQueryContent>, Box<dyn Error>> {
    let message_id = content.id();
    let pub_key_der = sender.sender_pubkey_der().map(Blob);
    let sender_sig = sender.sign_message_id(&message_id)?.map(Blob);

    Ok(HttpRequestEnvelope::<HttpQueryContent> {
        content,
        sender_pubkey: pub_key_der,
        sender_sig,
        sender_delegation: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_canister_client_sender::{Ed25519KeyPair, ed25519_public_key_to_der};
    use ic_crypto_temp_crypto::temp_crypto_component_with_fake_registry;
    use ic_crypto_test_utils_root_of_trust::MockRootOfTrustProvider;
    use ic_test_utilities_types::ids::node_test_id;
    use ic_types::messages::{HttpCanisterUpdate, HttpRequest, HttpUserQuery, Query};
    use ic_types::time::current_time;
    use ic_types::{PrincipalId, UserId};
    use ic_validator::HttpRequestVerifier;
    use ic_validator::HttpRequestVerifierImpl;
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;
    use std::convert::TryFrom;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio_test::assert_ok;

    // The node id of the node that validates message signatures
    const VALIDATOR_NODE_ID: u64 = 42;

    /// Create an HttpRequest with a non-anonymous user and then verify
    /// that `validate_message` manages to authenticate it.
    #[test]
    fn sign_and_verify_submit_content_with_ed25519() {
        let test_start_time = current_time();
        let expiry_time = test_start_time + Duration::from_secs(4 * 60);
        // Set up an arbitrary legal input
        let keypair = {
            let mut rng = ChaChaRng::seed_from_u64(789_u64);
            Ed25519KeyPair::generate(&mut rng)
        };
        let content = HttpCallContent::Call {
            update: HttpCanisterUpdate {
                canister_id: Blob(vec![51]),
                method_name: "foo".to_string(),
                arg: Blob(vec![12, 13, 99]),

                nonce: None,
                sender: Blob(
                    UserId::from(PrincipalId::new_self_authenticating(
                        &ed25519_public_key_to_der(keypair.public_key.to_vec()),
                    ))
                    .get()
                    .into_vec(),
                ),
                ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
            },
        };
        let sender = Sender::from_keypair(&keypair);
        let (submit, id) = sign_submit(content.clone(), &sender).unwrap();

        // The wrapped content is content, without modification
        assert_eq!(submit.content, content);

        // The message id matches one that can be reconstructed from the output
        let request = HttpRequest::try_from(submit).unwrap();
        assert_eq!(id, request.id());

        // The envelope can be successfully authenticated
        assert!(
            request_validator()
                .validate_request(&request, test_start_time, &MockRootOfTrustProvider::new())
                .unwrap()
                .contains(&request.content().canister_id())
        );
    }

    /// Create an HttpRequest with a non-anonymous user and then verify
    /// that `validate_message` manages to authenticate it.
    #[test]
    fn sign_and_verify_submit_content_with_ecdsa_secp256k1() {
        let test_start_time = current_time();
        let expiry_time = test_start_time + Duration::from_secs(4 * 60);
        // Set up an arbitrary legal input
        // Set up an arbitrary legal input
        let (sk, pk) = {
            let mut rng = ChaChaRng::seed_from_u64(89_u64);
            let sk = ic_secp256k1::PrivateKey::generate_using_rng(&mut rng);
            let pk = sk.public_key();
            (sk, pk)
        };
        let sender_id = UserId::from(PrincipalId::new_self_authenticating(&pk.serialize_der()));
        let content = HttpCallContent::Call {
            update: HttpCanisterUpdate {
                canister_id: Blob(vec![51]),
                method_name: "foo".to_string(),
                arg: Blob(vec![12, 13, 99]),
                nonce: None,
                sender: Blob(sender_id.get().into_vec()),
                ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
            },
        };
        let sender =
            Sender::from_secp256k1_keys(&sk.serialize_sec1(), &pk.serialize_sec1(false)).unwrap();
        let (submit, id) = sign_submit(content.clone(), &sender).unwrap();

        // The wrapped content is content, without modification
        assert_eq!(submit.content, content);

        // The message id matches one that can be reconstructed from the output
        let request = HttpRequest::try_from(submit).unwrap();
        assert_eq!(id, request.id());

        // The envelope can be successfully authenticated
        assert!(
            request_validator()
                .validate_request(&request, test_start_time, &MockRootOfTrustProvider::new())
                .unwrap()
                .contains(&request.content().canister_id())
        );
    }

    /// Create an HttpRequest with an explicit anonymous user and then
    /// verify that `validate_message` manages to authenticate it.
    #[test]
    fn sign_and_verify_submit_content_explicit_anonymous() {
        let test_start_time = current_time();
        let expiry_time = test_start_time + Duration::from_secs(4 * 60);

        // Set up an arbitrary legal input
        let content = HttpCallContent::Call {
            update: HttpCanisterUpdate {
                canister_id: Blob(vec![51]),
                method_name: "foo".to_string(),
                arg: Blob(vec![12, 13, 99]),

                nonce: None,
                sender: Blob(UserId::from(PrincipalId::new_anonymous()).get().into_vec()),
                ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
            },
        };
        let (submit, id) = sign_submit(content.clone(), &Sender::Anonymous).unwrap();

        // The wrapped content is content, without modification
        assert_eq!(submit.content, content);

        // The message id matches one that can be reconstructed from the output
        let request = HttpRequest::try_from(submit).unwrap();
        assert_eq!(id, request.id());

        // The envelope can be successfully authenticated
        assert!(
            request_validator()
                .validate_request(&request, test_start_time, &MockRootOfTrustProvider::new())
                .unwrap()
                .contains(&request.content().canister_id())
        );
    }

    #[test]
    fn sign_and_verify_request_status_content_valid_query_with_ed25519() {
        let test_start_time = current_time();
        let expiry_time = test_start_time + Duration::from_secs(4 * 60);

        // Set up an arbitrary legal input
        let keypair = {
            let mut rng = ChaChaRng::seed_from_u64(89_u64);
            Ed25519KeyPair::generate(&mut rng)
        };
        let sender = UserId::from(PrincipalId::new_self_authenticating(
            &ed25519_public_key_to_der(keypair.public_key.to_vec()),
        ));
        let content = HttpQueryContent::Query {
            query: HttpUserQuery {
                canister_id: Blob(vec![67, 3]),
                method_name: "foo".to_string(),
                arg: Blob(vec![23, 19, 4]),
                sender: Blob(sender.get().into_vec()),
                nonce: None,
                ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
            },
        };
        // Workaround because HttpQueryContent is not cloneable
        let content_copy = serde_cbor::value::from_value::<HttpQueryContent>(
            serde_cbor::value::to_value(&content).unwrap(),
        )
        .unwrap();

        let read = sign_query(content, &Sender::from_keypair(&keypair)).unwrap();

        // The wrapped content is content, without modification
        assert_eq!(read.content, content_copy);

        // The signature matches
        let read_request = HttpRequest::<Query>::try_from(read).unwrap();
        assert_ok!(request_validator().validate_request(
            &read_request,
            test_start_time,
            &MockRootOfTrustProvider::new()
        ));
    }

    #[test]
    fn sign_and_verify_request_status_content_valid_query_with_ecdsa_secp256k1() {
        let test_start_time = current_time();
        let expiry_time = test_start_time + Duration::from_secs(4 * 60);

        // Set up an arbitrary legal input
        let (sk, pk) = {
            let mut rng = ChaChaRng::seed_from_u64(89_u64);
            let sk = ic_secp256k1::PrivateKey::generate_using_rng(&mut rng);
            let pk = sk.public_key();
            (sk, pk)
        };

        let sender_id = UserId::from(PrincipalId::new_self_authenticating(&pk.serialize_der()));
        let content = HttpQueryContent::Query {
            query: HttpUserQuery {
                canister_id: Blob(vec![67, 3]),
                method_name: "foo".to_string(),
                arg: Blob(vec![23, 19, 4]),
                sender: Blob(sender_id.get().into_vec()),
                nonce: None,
                ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
            },
        };
        // Workaround because HttpQueryContent is not cloneable
        let content_copy = serde_cbor::value::from_value::<HttpQueryContent>(
            serde_cbor::value::to_value(&content).unwrap(),
        )
        .unwrap();

        let sender =
            Sender::from_secp256k1_keys(&sk.serialize_sec1(), &pk.serialize_sec1(false)).unwrap();
        let read = sign_query(content, &sender).unwrap();

        // The wrapped content is content, without modification
        assert_eq!(read.content, content_copy);

        // The signature matches
        let read_request = HttpRequest::<Query>::try_from(read).unwrap();
        assert_ok!(request_validator().validate_request(
            &read_request,
            test_start_time,
            &MockRootOfTrustProvider::new()
        ));
    }

    fn request_validator() -> HttpRequestVerifierImpl {
        HttpRequestVerifierImpl::new(Arc::new(temp_crypto_component_with_fake_registry(
            node_test_id(VALIDATOR_NODE_ID),
        )))
    }
}
