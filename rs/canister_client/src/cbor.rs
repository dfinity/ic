use crate::{
    agent::{sign_read, Agent},
    sign_submit,
};
use ic_crypto_tree_hash::{LabeledTree, Path};
use ic_types::Time;
use ic_types::{
    messages::{
        Blob, Certificate, HttpCanisterUpdate, HttpReadContent, HttpReadState,
        HttpReadStateResponse, HttpRequestEnvelope, HttpSubmitContent, HttpUserQuery, MessageId,
        SignedRequestBytes,
    },
    time::current_time_and_expiry_time,
    CanisterId,
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

#[derive(Debug)]
struct CanisterCallResponse {
    status: String,
    arg: Option<Vec<u8>>,
    reject_message: Option<String>,
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
pub(crate) fn parse_canister_query_response(message: &CBOR) -> Result<RequestStatus, String> {
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
    ) -> Result<(HttpRequestEnvelope<HttpSubmitContent>, MessageId), Box<dyn Error>> {
        let content = HttpSubmitContent::Call {
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
        let content = HttpReadContent::Query {
            query: HttpUserQuery {
                canister_id: to_blob(canister_id),
                method_name: method.to_string(),
                arg: Blob(arguments),
                sender: self.sender_field.clone(),
                nonce: None,
                ingress_expiry: current_time_and_expiry_time().1.as_nanos_since_unix_epoch(),
            },
        };

        let request = sign_read(content, &self.sender)?;
        Ok(SignedRequestBytes::try_from(request)?.into())
    }

    /// Prepares and serializes a CBOR read_state request, with the given paths
    pub fn prepare_read_state(&self, paths: &[Path]) -> Result<Vec<u8>, Box<dyn Error>> {
        let content = HttpReadContent::ReadState {
            read_state: HttpReadState {
                sender: self.sender_field.clone(),
                paths: paths.to_vec(),
                nonce: None,
                ingress_expiry: current_time_and_expiry_time().1.as_nanos_since_unix_epoch(),
            },
        };

        let request = sign_read(content, &self.sender)?;
        Ok(SignedRequestBytes::try_from(request)?.into())
    }
}

fn to_blob(canister_id: &CanisterId) -> Blob {
    Blob(canister_id.get().into_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_crypto_tree_hash::MixedHashTree;
    use ic_types::messages::HttpReadStateResponse;
    use serde::Serialize;

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
}
