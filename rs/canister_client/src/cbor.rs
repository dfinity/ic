use crate::agent::Agent;
use ic_canister_client_sender::Sender;
use ic_crypto_tree_hash::{LabeledTree, LookupStatus, Path};
use ic_types::{
    messages::{
        Blob, Certificate, HttpCallContent, HttpCanisterUpdate, HttpQueryContent, HttpReadState,
        HttpReadStateContent, HttpReadStateResponse, HttpRequestEnvelope, HttpUserQuery, MessageId,
        SignedRequestBytes,
    },
    time::current_time_and_expiry_time,
    CanisterId, Time,
};
use serde::Deserialize;
use serde_cbor::value::Value as CBOR;
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::error::Error;

// An auxiliary structure that mirrors the request statuses
// encoded in a certificate, starting from the root of the tree.
#[derive(Debug, Deserialize)]
struct RequestStatuses {
    request_status: Option<BTreeMap<MessageId, RequestStatus>>,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct RequestStatus {
    pub status: String,
    pub reply: Option<Vec<u8>>,
    pub reject_message: Option<String>,
}

impl RequestStatus {
    fn unknown() -> Self {
        RequestStatus {
            status: "unknown".to_string(),
            reply: None,
            reject_message: None,
        }
    }
}

/// Given a CBOR response from a `read_state` and a `request_id` extracts
/// the `RequestStatus` if available.
pub fn parse_read_state_response(
    request_id: &MessageId,
    message: CBOR,
) -> Result<RequestStatus, String> {
    let response = serde_cbor::value::from_value::<HttpReadStateResponse>(message)
        .map_err(|source| format!("decoding to HttpReadStateResponse failed: {}", source))?;

    let certificate: Certificate = serde_cbor::from_slice(response.certificate.as_slice())
        .map_err(|source| format!("decoding Certificate failed: {}", source))?;

    match certificate
        .tree
        .lookup(&[&b"request_status"[..], request_id.as_ref()])
    {
        LookupStatus::Found(_) => (),
        // TODO(MR-249): return an error in the Unknown case once the replica
        // implements absence proofs.
        LookupStatus::Absent | LookupStatus::Unknown => return Ok(RequestStatus::unknown()),
    }

    // Parse the tree.
    let tree = LabeledTree::try_from(certificate.tree)
        .map_err(|e| format!("parsing tree in certificate failed: {:?}", e))?;

    let request_statuses =
        RequestStatuses::deserialize(tree_deserializer::LabeledTreeDeserializer::new(&tree))
            .map_err(|err| format!("deserializing request statuses failed: {:?}", err))?;

    Ok(match request_statuses.request_status {
        Some(mut request_status_map) => request_status_map
            .remove(request_id)
            .unwrap_or_else(RequestStatus::unknown),
        None => RequestStatus::unknown(),
    })
}

/// Given a CBOR response from a `query`, extract the response.
pub(crate) fn parse_query_response(message: &CBOR) -> Result<RequestStatus, String> {
    let content = match message {
        CBOR::Map(content) => Ok(content),
        cbor => Err(format!(
            "Expected a Map in the reply root but found {:?}",
            cbor
        )),
    }?;

    let status_key = &CBOR::Text("status".to_string());
    let status = match &content.get(status_key) {
        Some(CBOR::Text(t)) => Ok(t.to_string()),
        Some(cbor) => Err(format!(
            "Expected Text at key '{:?}', but found '{:?}'",
            status_key, cbor
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
            "Expected Map at key '{:?}' but found '{:?}'",
            reply_key, cbor
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
                    "Expected the value of key '{:?}' to be bytes, but found '{:?}'",
                    arg_key, cbor
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

impl Agent {
    /// Prepares an update request.
    pub fn prepare_update_raw<S: ToString>(
        &self,
        canister_id: &CanisterId,
        method: S,
        arguments: Vec<u8>,
        nonce: Vec<u8>,
        ingress_expiry: Time,
    ) -> Result<(HttpRequestEnvelope<HttpCallContent>, MessageId), Box<dyn Error>> {
        let content = HttpCallContent::Call {
            update: HttpCanisterUpdate {
                canister_id: to_blob(canister_id),
                method_name: method.to_string(),
                arg: Blob(arguments),
                nonce: Some(Blob(nonce)),
                sender: self.sender_field.clone(),
                ingress_expiry: ingress_expiry.as_nanos_since_unix_epoch(),
            },
        };

        sign_submit(content, &self.sender)
    }

    /// Prepares and serailizes a CBOR update request.
    pub fn prepare_update<S: ToString>(
        &self,
        canister_id: &CanisterId,
        method: S,
        arguments: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Result<(Vec<u8>, MessageId), Box<dyn Error>> {
        let (submit_request, request_id) = self.prepare_update_raw(
            canister_id,
            method,
            arguments,
            nonce,
            current_time_and_expiry_time().1,
        )?;
        let http_body = SignedRequestBytes::try_from(submit_request)?;
        Ok((http_body.into(), request_id))
    }

    /// Prepares and serializes a CBOR query request.
    pub fn prepare_query(
        &self,
        canister_id: &CanisterId,
        method: &str,
        arguments: Vec<u8>,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let content = HttpQueryContent::Query {
            query: HttpUserQuery {
                canister_id: to_blob(canister_id),
                method_name: method.to_string(),
                arg: Blob(arguments),
                sender: self.sender_field.clone(),
                nonce: None,
                ingress_expiry: current_time_and_expiry_time().1.as_nanos_since_unix_epoch(),
            },
        };

        let request = sign_query(content, &self.sender)?;
        Ok(SignedRequestBytes::try_from(request)?.into())
    }

    /// Prepares and serializes a CBOR read_state request, with the given paths
    pub fn prepare_read_state(&self, paths: &[Path]) -> Result<Vec<u8>, Box<dyn Error>> {
        let content = HttpReadStateContent::ReadState {
            read_state: HttpReadState {
                sender: self.sender_field.clone(),
                paths: paths.to_vec(),
                nonce: None,
                ingress_expiry: current_time_and_expiry_time().1.as_nanos_since_unix_epoch(),
            },
        };

        let request = sign_read_state(content, &self.sender)?;
        Ok(SignedRequestBytes::try_from(request)?.into())
    }
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

pub(crate) fn bytes_to_cbor(bytes: Vec<u8>) -> Result<CBOR, String> {
    let cbor = serde_cbor::from_slice(&bytes).map_err(|e| {
        format!(
            "Agent::bytes_to_cbor: Failed to parse result from IC, got: {:?} - error {:?}",
            String::from_utf8(
                bytes
                    .iter()
                    .copied()
                    .flat_map(std::ascii::escape_default)
                    .collect()
            )
            .expect("ASCII is legal utf8"),
            e
        )
    })?;
    Ok(cbor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_canister_client_sender::{ed25519_public_key_to_der, Ed25519KeyPair};
    use ic_crypto_tree_hash::{Digest, Label, MixedHashTree};
    use ic_test_utilities::crypto::temp_crypto_component_with_fake_registry;
    use ic_test_utilities::types::ids::node_test_id;
    use ic_types::malicious_flags::MaliciousFlags;
    use ic_types::messages::{
        HttpCanisterUpdate, HttpReadStateResponse, HttpRequest, HttpUserQuery, UserQuery,
    };
    use ic_types::time::current_time;
    use ic_types::{PrincipalId, RegistryVersion, UserId};
    use ic_validator::get_authorized_canisters;
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;
    use serde::Serialize;
    use std::convert::TryFrom;
    use std::time::Duration;
    use tokio_test::assert_ok;

    // The node id of the node that validates message signatures
    const VALIDATOR_NODE_ID: u64 = 42;
    fn mock_registry_version() -> RegistryVersion {
        RegistryVersion::from(0)
    }

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
        let validator = temp_crypto_component_with_fake_registry(node_test_id(VALIDATOR_NODE_ID));
        assert!(get_authorized_canisters(
            &request,
            &validator,
            test_start_time,
            mock_registry_version(),
            &MaliciousFlags::default(),
        )
        .unwrap()
        .contains(&request.content().canister_id()));
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
            let sk = libsecp256k1::SecretKey::random(&mut rng);
            let pk = libsecp256k1::PublicKey::from_secret_key(&sk);
            (sk.serialize(), pk.serialize())
        };
        let sender_id = UserId::from(PrincipalId::new_self_authenticating(
            &ecdsa_secp256k1::api::public_key_to_der(
                &ecdsa_secp256k1::types::PublicKeyBytes::from(pk.to_vec()),
            )
            .expect("DER encoding failed"),
        ));
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
        let sender = Sender::from_secp256k1_keys(&sk, &pk);
        let (submit, id) = sign_submit(content.clone(), &sender).unwrap();

        // The wrapped content is content, without modification
        assert_eq!(submit.content, content);

        // The message id matches one that can be reconstructed from the output
        let request = HttpRequest::try_from(submit).unwrap();
        assert_eq!(id, request.id());

        // The envelope can be successfully authenticated
        let validator = temp_crypto_component_with_fake_registry(node_test_id(VALIDATOR_NODE_ID));
        assert!(get_authorized_canisters(
            &request,
            &validator,
            test_start_time,
            mock_registry_version(),
            &MaliciousFlags::default(),
        )
        .unwrap()
        .contains(&request.content().canister_id()));
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
        let validator = temp_crypto_component_with_fake_registry(node_test_id(VALIDATOR_NODE_ID));
        assert!(get_authorized_canisters(
            &request,
            &validator,
            test_start_time,
            mock_registry_version(),
            &MaliciousFlags::default(),
        )
        .unwrap()
        .contains(&request.content().canister_id()));
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
        let read_request = HttpRequest::<UserQuery>::try_from(read).unwrap();
        let validator = temp_crypto_component_with_fake_registry(node_test_id(VALIDATOR_NODE_ID));
        assert_ok!(get_authorized_canisters(
            &read_request,
            &validator,
            test_start_time,
            mock_registry_version(),
            &MaliciousFlags::default(),
        ));
    }

    #[test]
    fn sign_and_verify_request_status_content_valid_query_with_ecdsa_secp256k1() {
        let test_start_time = current_time();
        let expiry_time = test_start_time + Duration::from_secs(4 * 60);

        // Set up an arbitrary legal input
        let (sk, pk) = {
            let mut rng = ChaChaRng::seed_from_u64(89_u64);
            let sk = libsecp256k1::SecretKey::random(&mut rng);
            let pk = libsecp256k1::PublicKey::from_secret_key(&sk);
            (sk.serialize(), pk.serialize())
        };

        let sender_id = UserId::from(PrincipalId::new_self_authenticating(
            &ecdsa_secp256k1::api::public_key_to_der(
                &ecdsa_secp256k1::types::PublicKeyBytes::from(pk.to_vec()),
            )
            .expect("DER encoding failed"),
        ));
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

        let sender = Sender::from_secp256k1_keys(&sk, &pk);
        let read = sign_query(content, &sender).unwrap();

        // The wrapped content is content, without modification
        assert_eq!(read.content, content_copy);

        // The signature matches
        let read_request = HttpRequest::<UserQuery>::try_from(read).unwrap();
        let validator = temp_crypto_component_with_fake_registry(node_test_id(VALIDATOR_NODE_ID));
        assert_ok!(get_authorized_canisters(
            &read_request,
            &validator,
            test_start_time,
            mock_registry_version(),
            &MaliciousFlags::default(),
        ));
    }

    fn to_self_describing_cbor<T: Serialize>(e: &T) -> serde_cbor::Result<Vec<u8>> {
        let mut serialized_bytes = Vec::new();
        let mut serializer = serde_cbor::Serializer::new(&mut serialized_bytes);
        serializer.self_describe()?;
        e.serialize(&mut serializer)?;
        Ok(serialized_bytes)
    }

    #[test]
    fn test_parse_read_state_response_unknown() {
        let certificate = Certificate {
            tree: MixedHashTree::Labeled("time".into(), Box::new(MixedHashTree::Leaf(vec![1]))),
            signature: Blob(vec![]),
            delegation: None,
        };

        let certificate_cbor: Vec<u8> = to_self_describing_cbor(&certificate).unwrap();

        let response = HttpReadStateResponse {
            certificate: Blob(certificate_cbor),
        };

        let response_cbor: Vec<u8> = to_self_describing_cbor(&response).unwrap();

        let response: CBOR = serde_cbor::from_slice(response_cbor.as_slice()).unwrap();

        let request_id: MessageId = MessageId::from([0; 32]);
        assert_eq!(
            parse_read_state_response(&request_id, response),
            Ok(RequestStatus::unknown())
        );
    }

    #[test]
    fn test_parse_read_state_response_replied() {
        let tree = MixedHashTree::Fork(Box::new((
            MixedHashTree::Labeled(
                "request_status".into(),
                Box::new(MixedHashTree::Labeled(
                    vec![
                        184, 255, 145, 192, 128, 156, 132, 76, 67, 213, 87, 237, 189, 136, 206,
                        184, 254, 192, 233, 210, 142, 173, 27, 123, 112, 187, 82, 222, 130, 129,
                        245, 41,
                    ]
                    .into(),
                    Box::new(MixedHashTree::Fork(Box::new((
                        MixedHashTree::Labeled(
                            "reply".into(),
                            Box::new(MixedHashTree::Leaf(vec![68, 73, 68, 76, 0, 0])),
                        ),
                        MixedHashTree::Labeled(
                            "status".into(),
                            Box::new(MixedHashTree::Leaf(b"replied".to_vec())),
                        ),
                    )))),
                )),
            ),
            MixedHashTree::Labeled("time".into(), Box::new(MixedHashTree::Leaf(vec![1]))),
        )));

        let certificate = Certificate {
            tree,
            signature: Blob(vec![]),
            delegation: None,
        };

        let certificate_cbor: Vec<u8> = to_self_describing_cbor(&certificate).unwrap();

        let response = HttpReadStateResponse {
            certificate: Blob(certificate_cbor),
        };

        let response_cbor: Vec<u8> = to_self_describing_cbor(&response).unwrap();

        let response: CBOR = serde_cbor::from_slice(response_cbor.as_slice()).unwrap();

        // Request ID that exists.
        let request_id: MessageId = MessageId::from([
            184, 255, 145, 192, 128, 156, 132, 76, 67, 213, 87, 237, 189, 136, 206, 184, 254, 192,
            233, 210, 142, 173, 27, 123, 112, 187, 82, 222, 130, 129, 245, 41,
        ]);

        assert_eq!(
            parse_read_state_response(&request_id, response.clone()),
            Ok(RequestStatus {
                status: "replied".to_string(),
                reply: Some(vec![68, 73, 68, 76, 0, 0]),
                reject_message: None
            }),
        );

        // Request ID that doesn't exist.
        let request_id: MessageId = MessageId::from([0; 32]);
        assert_eq!(
            parse_read_state_response(&request_id, response),
            Ok(RequestStatus::unknown())
        );
    }

    #[test]
    fn test_parse_read_state_response_pruned() {
        fn mklabeled(l: impl Into<Label>, t: MixedHashTree) -> MixedHashTree {
            MixedHashTree::Labeled(l.into(), Box::new(t))
        }

        fn mkfork(l: MixedHashTree, r: MixedHashTree) -> MixedHashTree {
            MixedHashTree::Fork(Box::new((l, r)))
        }

        let tree = mkfork(
            mklabeled(
                "request_status",
                mkfork(
                    mklabeled(
                        vec![
                            184, 255, 145, 192, 128, 156, 132, 76, 67, 213, 87, 237, 189, 136, 206,
                            184, 254, 192, 233, 210, 142, 173, 27, 123, 112, 187, 82, 222, 130,
                            129, 245, 40,
                        ],
                        MixedHashTree::Pruned(Digest([0; 32])),
                    ),
                    mklabeled(
                        vec![
                            184, 255, 145, 192, 128, 156, 132, 76, 67, 213, 87, 237, 189, 136, 206,
                            184, 254, 192, 233, 210, 142, 173, 27, 123, 112, 187, 82, 222, 130,
                            129, 245, 42,
                        ],
                        MixedHashTree::Pruned(Digest([0; 32])),
                    ),
                ),
            ),
            mklabeled("time", MixedHashTree::Leaf(vec![1])),
        );

        let certificate = Certificate {
            tree,
            signature: Blob(vec![]),
            delegation: None,
        };

        let certificate_cbor: Vec<u8> = to_self_describing_cbor(&certificate).unwrap();

        let response = HttpReadStateResponse {
            certificate: Blob(certificate_cbor),
        };

        let response_cbor: Vec<u8> = to_self_describing_cbor(&response).unwrap();

        let response: CBOR = serde_cbor::from_slice(response_cbor.as_slice()).unwrap();

        // Request ID that is between two pruned labels.
        let request_id: MessageId = MessageId::from([
            184, 255, 145, 192, 128, 156, 132, 76, 67, 213, 87, 237, 189, 136, 206, 184, 254, 192,
            233, 210, 142, 173, 27, 123, 112, 187, 82, 222, 130, 129, 245, 41,
        ]);

        assert_eq!(
            parse_read_state_response(&request_id, response),
            Ok(RequestStatus::unknown())
        );
    }
}
