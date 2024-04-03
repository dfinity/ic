use crate::{state_reader_executor::StateReaderExecutor, HttpError};
use axum::{body::Body, response::IntoResponse};
use http::{
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
    HeaderValue, Method,
};
use http_body_util::{BodyExt, Empty};
use hyper::{header, Response, StatusCode};
use ic_crypto_tree_hash::{sparse_labeled_tree_from_paths, Label, Path, TooLongPathError};
use ic_error_types::UserError;
use ic_interfaces_registry::RegistryClient;
use ic_logger::{info, warn, ReplicaLogger};
use ic_registry_client_helpers::crypto::CryptoRegistry;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    crypto::threshold_sig::ThresholdSigPublicKey, messages::MessageId, RegistryVersion, SubnetId,
};
use ic_validator::RequestValidationError;
use serde::Serialize;
use serde_cbor::value::Value as CBOR;
use std::collections::BTreeMap;
use std::sync::Arc;
use tower::{load_shed::error::Overloaded, timeout::error::Elapsed, BoxError};
use tower_http::cors::{CorsLayer, Vary};

pub const CONTENT_TYPE_CBOR: &str = "application/cbor";
pub const CONTENT_TYPE_PROTOBUF: &str = "application/x-protobuf";
pub const CONTENT_TYPE_SVG: &str = "image/svg+xml";
pub const CONTENT_TYPE_TEXT: &str = "text/plain";

pub(crate) fn get_root_threshold_public_key(
    log: &ReplicaLogger,
    registry_client: &dyn RegistryClient,
    version: RegistryVersion,
    nns_subnet_id: &SubnetId,
) -> Option<ThresholdSigPublicKey> {
    match registry_client.get_threshold_signing_public_key_for_subnet(*nns_subnet_id, version) {
        Ok(Some(key)) => Some(key),
        Err(err) => {
            warn!(log, "Failed to get key for subnet {}", err);
            None
        }
        Ok(None) => {
            warn!(log, "Received no public key for subnet {}", nns_subnet_id);
            None
        }
    }
}

pub(crate) fn make_plaintext_response(status: StatusCode, message: String) -> Response<Body> {
    let mut resp = Response::new(Body::new(message.map_err(BoxError::from)));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static(CONTENT_TYPE_TEXT),
    );
    resp
}

pub(crate) async fn map_box_error_to_response(err: BoxError) -> Response<Body> {
    if err.is::<Overloaded>() {
        make_plaintext_response(
            StatusCode::TOO_MANY_REQUESTS,
            "The service is overloaded.".to_string(),
        )
    } else if err.is::<Elapsed>() {
        make_plaintext_response(
            StatusCode::GATEWAY_TIMEOUT,
            "Request took longer than the deadline.".to_string(),
        )
    } else {
        make_plaintext_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Unexpected error: {}", err),
        )
    }
}

// TODO: NET-1667
pub fn cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([AUTHORIZATION, ACCEPT, CONTENT_TYPE])
        .allow_origin(tower_http::cors::Any)
        // No Vary header
        .vary(Vary::list(vec![]))
}

/// Convert an object into CBOR binary.
pub(crate) fn into_cbor<R: Serialize>(r: &R) -> Vec<u8> {
    let mut ser = serde_cbor::Serializer::new(Vec::new());
    ser.self_describe().expect("Could not write magic tag.");
    r.serialize(&mut ser).expect("Serialization failed.");
    ser.into_inner()
}

/// `IntoResponse` implementation for Cbor. Similar to axum implementation for JSON.
/// https://docs.rs/axum/latest/axum/struct.Json.html#impl-IntoResponse-for-Json%3CT%3E
pub struct Cbor<T>(pub T);

impl<T> IntoResponse for Cbor<T>
where
    T: Serialize,
{
    fn into_response(self) -> axum::response::Response {
        // Use a small initial capacity of 128 bytes like serde_json::to_vec
        // https://docs.rs/serde_json/1.0.82/src/serde_json/ser.rs.html#2189
        let buf = Vec::with_capacity(128);
        let mut ser = serde_cbor::Serializer::new(buf);
        ser.self_describe().expect("Could not write magic tag.");
        match &self.0.serialize(&mut ser) {
            Ok(()) => (
                [(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static(CONTENT_TYPE_CBOR),
                )],
                ser.into_inner(),
            )
                .into_response(),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static(CONTENT_TYPE_TEXT),
                )],
                err.to_string(),
            )
                .into_response(),
        }
    }
}

/// Converts a user error into an HTTP response.
///
/// We need this conversion because we validate user requests twice:
///
///   1. Ingress filter checks user messages before including them in blocks
///      so that we don't have to reach a consensus on payloads that we will
///      throw away in the execution.
///      We cannot put UserErrors produced at this stage in the state tree;
///      We have to return them in the  HTTP body.
///
///   2. Once messages reach execution, we include UserErrors into the state tree.
///      Users can fetch the details via the read_state endpoint.
///
/// make_response conversion applies the first case.
pub struct CborUserError(pub UserError);

impl IntoResponse for CborUserError {
    fn into_response(self) -> axum::response::Response {
        let reject_response: CBOR = CBOR::Map(BTreeMap::from([
            (
                CBOR::Text("error_code".to_string()),
                CBOR::Text(self.0.code().to_string()),
            ),
            (
                CBOR::Text("reject_message".to_string()),
                CBOR::Text(self.0.description().to_string()),
            ),
            (
                CBOR::Text("reject_code".to_string()),
                CBOR::Integer(self.0.reject_code() as i128),
            ),
        ]));
        Cbor(reject_response).into_response()
    }
}

/// Empty response.
pub(crate) fn empty_response() -> Response<Body> {
    let mut response = Response::new(Body::new(Empty::new().map_err(BoxError::from)));
    *response.status_mut() = StatusCode::NO_CONTENT;
    response
}

pub(crate) fn validation_error_to_http_error(
    message_id: MessageId,
    err: RequestValidationError,
    log: &ReplicaLogger,
) -> HttpError {
    match err {
        RequestValidationError::InvalidIngressExpiry(message)
        | RequestValidationError::InvalidDelegationExpiry(message) => HttpError {
            status: StatusCode::BAD_REQUEST,
            message,
        },
        _ => {
            let message = format!(
                "Failed to authenticate request {} due to: {}",
                message_id, err
            );
            info!(log, "Unexpected http request validation error: {}", message);

            HttpError {
                status: StatusCode::FORBIDDEN,
                message,
            }
        }
    }
}

pub(crate) async fn get_latest_certified_state(
    state_reader_executor: &StateReaderExecutor,
) -> Option<Arc<ReplicatedState>> {
    let paths = &mut [Path::from(Label::from("time"))];
    let labeled_tree = match sparse_labeled_tree_from_paths(paths) {
        Ok(labeled_tree) => labeled_tree,
        // This error is not recoverable and should never happen, because the
        // path is valid and required to start the HTTP endpoint.
        Err(TooLongPathError {}) => panic!("bug: failed to convert path to LabeledTree"),
    };
    state_reader_executor
        .read_certified_state(labeled_tree)
        .await
        .ok()?
        .map(|r| r.0)
}

// A few test helpers, improving readability in the tests
#[cfg(test)]
pub(crate) mod test {

    use super::*;
    use hyper::header;
    use ic_types::messages::{Blob, CertificateDelegation};
    use maplit::btreemap;
    use pretty_assertions::assert_eq;
    use serde::Serialize;
    use serde_cbor::Value;

    #[test]
    fn test_cbor_response() {
        let response = Cbor(b"").into_response();
        assert_eq!(response.headers().len(), 1);
        assert_eq!(
            response
                .headers()
                .get_all(header::CONTENT_TYPE)
                .iter()
                .count(),
            1
        );
    }

    /// Makes sure that the serialized CBOR version of `obj` is the same as
    /// `Value`. Used when testing _outgoing_ messages from the HTTP
    /// Handler's point of view
    pub(crate) fn assert_cbor_ser_equal<T>(obj: &T, val: Value)
    where
        for<'de> T: Serialize,
    {
        assert_eq!(serde_cbor::value::to_value(obj).unwrap(), val)
    }

    pub(crate) fn text(text: &'static str) -> Value {
        Value::Text(text.to_string())
    }

    pub(crate) fn int(i: i128) -> Value {
        Value::Integer(i)
    }

    pub(crate) fn bytes(bs: &[u8]) -> Value {
        Value::Bytes(bs.to_vec())
    }

    pub(crate) fn array(values: Vec<Value>) -> Value {
        Value::Array(values)
    }

    #[test]
    fn encoding_delegation() {
        let delegation = CertificateDelegation {
            subnet_id: Blob(vec![1, 2, 3]),
            certificate: Blob(vec![4, 5, 6]),
        };
        assert_cbor_ser_equal(
            &delegation,
            Value::Map(btreemap! {
                text("subnet_id") => bytes(&[1, 2, 3]),
                text("certificate") => bytes(&[4, 5, 6]),
            }),
        );
    }
}
