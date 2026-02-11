use crate::HttpError;
use axum::{body::Body, extract::FromRequest, response::IntoResponse};
use bytes::Bytes;
use http::{
    HeaderMap, HeaderValue, Method,
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
};
use http_body_util::BodyExt;
use hyper::{Response, StatusCode, header};
use ic_crypto_interfaces_sig_verification::IngressSigVerifier;
use ic_crypto_tree_hash::{Label, Path, TooLongPathError, sparse_labeled_tree_from_paths};
use ic_error_types::UserError;
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::StateReader;
use ic_logger::{ReplicaLogger, info, warn};
use ic_registry_client_helpers::crypto::{
    CryptoRegistry, root_of_trust::RegistryRootOfTrustProvider,
};
use ic_replicated_state::ReplicatedState;
use ic_types::{
    RegistryVersion, SubnetId, Time,
    crypto::threshold_sig::ThresholdSigPublicKey,
    malicious_flags::MaliciousFlags,
    messages::{HttpRequest, HttpRequestContent},
};
use ic_utils::str::StrEllipsize;
use ic_validator::{
    CanisterIdSet, HttpRequestVerifier, HttpRequestVerifierImpl, RequestValidationError,
};
use serde::{Deserialize, Serialize};
use serde_cbor::value::Value as CBOR;
use std::sync::Arc;
use std::{collections::BTreeMap, time::Duration};
use tokio::time::timeout;
use tower::{BoxError, load_shed::error::Overloaded, timeout::error::Elapsed};
use tower_http::cors::{CorsLayer, Vary};

pub const CONTENT_TYPE_CBOR: &str = "application/cbor";
pub const CONTENT_TYPE_PROTOBUF: &str = "application/x-protobuf";
pub const CONTENT_TYPE_SVG: &str = "image/svg+xml";
pub const CONTENT_TYPE_TEXT: &str = "text/plain; charset=utf-8";
/// If the request body is not received/parsed within
/// `max_request_receive_seconds`, then the request will be rejected and
/// [`408 Request Timeout`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/408) will be returned to the user.
const MAX_REQUEST_RECEIVE_TIMEOUT: Duration = Duration::from_secs(300);

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

pub fn make_plaintext_response(status: StatusCode, message: String) -> Response<Body> {
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
            format!("Unexpected error: {err}"),
        )
    }
}

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

fn cbor_content_type(headers: &HeaderMap) -> bool {
    let Some(content_type) = headers.get(header::CONTENT_TYPE) else {
        return false;
    };

    let Ok(content_type) = content_type.to_str() else {
        return false;
    };

    content_type.to_lowercase() == CONTENT_TYPE_CBOR
}

impl<T, S> FromRequest<S> for Cbor<T>
where
    T: for<'a> Deserialize<'a>,
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);
    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        if cbor_content_type(req.headers()) {
            let bytes = Bytes::from_request(req, state)
                .await
                .map_err(|e| (e.status(), e.body_text()))?;
            match serde_cbor::from_slice(&bytes) {
                Ok(value) => Ok(Cbor(value)),
                Err(err) => Err((
                    StatusCode::BAD_REQUEST,
                    format!("Failed to deserialize cbor request: {err}"),
                )),
            }
        } else {
            Err((
                StatusCode::BAD_REQUEST,
                format!("Unexpected content-type, expected {CONTENT_TYPE_CBOR}."),
            ))
        }
    }
}

pub(crate) struct WithTimeout<E>(pub E);

impl<S, E> FromRequest<S> for WithTimeout<E>
where
    S: Send + Sync,
    E: FromRequest<S>,
{
    type Rejection = axum::response::Response;
    async fn from_request(req: axum::extract::Request, s: &S) -> Result<Self, Self::Rejection> {
        match timeout(MAX_REQUEST_RECEIVE_TIMEOUT, E::from_request(req, s)).await {
            Ok(Ok(bytes)) => Ok(WithTimeout(bytes)),
            Ok(Err(err)) => Err(err.into_response()),
            Err(_) => Err((
                StatusCode::REQUEST_TIMEOUT,
                format!(
                    "receiving request took longer than {}s",
                    MAX_REQUEST_RECEIVE_TIMEOUT.as_secs()
                ),
            )
                .into_response()),
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

pub(crate) fn validation_error_to_http_error<C: std::fmt::Debug + HttpRequestContent>(
    request: &HttpRequest<C>,
    err: RequestValidationError,
    log: &ReplicaLogger,
) -> HttpError {
    let message_id = request.id();
    match err {
        RequestValidationError::InvalidRequestExpiry(_)
        | RequestValidationError::InvalidSignature(_) => {
            let request_ellipsized = format!("{request:?}").ellipsize(1024, 90);
            info!(
                log,
                "msg_id: {}, err: {}, request: {}", message_id, err, request_ellipsized,
            )
        }
        _ => info!(log, "msg_id: {}, err: {}", message_id, err),
    }

    HttpError {
        status: StatusCode::BAD_REQUEST,
        message: format!("{err}"),
    }
}

pub(crate) fn certified_state_unavailable_error() -> HttpError {
    let status = StatusCode::SERVICE_UNAVAILABLE;
    let message = "Certified state unavailable. Please try again.".to_string();
    HttpError { status, message }
}

pub(crate) async fn get_latest_certified_state(
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
) -> Option<Arc<ReplicatedState>> {
    tokio::task::spawn_blocking(move || {
        let paths = &mut [Path::from(Label::from("time"))];
        let labeled_tree = match sparse_labeled_tree_from_paths(paths) {
            Ok(labeled_tree) => labeled_tree,
            // This error is not recoverable and should never happen, because the
            // path is valid and required to start the HTTP endpoint.
            Err(TooLongPathError {}) => panic!("bug: failed to convert path to LabeledTree"),
        };
        let state = state_reader.read_certified_state(&labeled_tree);
        state.map(|r| r.0)
    })
    .await
    .ok()?
}

pub(crate) fn build_validator<T: HttpRequestContent>(
    ingress_verifier: Arc<dyn IngressSigVerifier>,
    malicious_flags: Option<MaliciousFlags>,
) -> Arc<dyn HttpRequestVerifier<T, RegistryRootOfTrustProvider>>
where
    HttpRequestVerifierImpl: HttpRequestVerifier<T, RegistryRootOfTrustProvider>,
{
    if malicious_flags.is_some_and(|f| f.maliciously_disable_ingress_validation) {
        pub struct DisabledHttpRequestVerifier;

        impl<C: HttpRequestContent, R> HttpRequestVerifier<C, R> for DisabledHttpRequestVerifier {
            fn validate_request(
                &self,
                _request: &HttpRequest<C>,
                _current_time: Time,
                _root_of_trust_provider: &R,
            ) -> Result<CanisterIdSet, RequestValidationError> {
                Ok(CanisterIdSet::all())
            }
        }

        Arc::new(DisabledHttpRequestVerifier) as Arc<_>
    } else {
        Arc::new(HttpRequestVerifierImpl::new(ingress_verifier)) as Arc<_>
    }
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
