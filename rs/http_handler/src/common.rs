use hyper::{Body, HeaderMap, Response, StatusCode};
use ic_crypto_tree_hash::Path;
use ic_crypto_tree_hash::{sparse_labeled_tree_from_paths, Label};
use ic_error_types::UserError;
use ic_interfaces_state_manager::StateReader;
use ic_logger::{info, ReplicaLogger};
use ic_replicated_state::ReplicatedState;
use ic_types::messages::MessageId;
use ic_validator::RequestValidationError;
use serde::Serialize;
use std::sync::Arc;
use tower::{load_shed::error::Overloaded, BoxError};

pub const CONTENT_TYPE_HTML: &str = "text/html";
pub const CONTENT_TYPE_CBOR: &str = "application/cbor";
pub const CONTENT_TYPE_PROTOBUF: &str = "application/x-protobuf";

pub(crate) fn make_plaintext_response(status: StatusCode, message: String) -> Response<Body> {
    let mut resp = Response::new(Body::from(message));
    *resp.status_mut() = status;
    *resp.headers_mut() = get_cors_headers();
    resp
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
pub(crate) fn make_response(user_error: UserError) -> Response<Body> {
    use ic_error_types::ErrorCode as C;

    let status = match user_error.code() {
        C::SubnetOversubscribed => StatusCode::SERVICE_UNAVAILABLE,
        C::MaxNumberOfCanistersReached => StatusCode::SERVICE_UNAVAILABLE,
        C::CanisterOutputQueueFull => StatusCode::SERVICE_UNAVAILABLE,
        C::IngressMessageTimeout => StatusCode::GATEWAY_TIMEOUT,
        C::CanisterNotFound => StatusCode::NOT_FOUND,
        C::CanisterMethodNotFound => StatusCode::NOT_FOUND,
        C::CanisterAlreadyInstalled => StatusCode::PRECONDITION_FAILED,
        C::CanisterWasmModuleNotFound => StatusCode::SERVICE_UNAVAILABLE,
        C::CanisterEmpty => StatusCode::SERVICE_UNAVAILABLE,
        C::InsufficientTransferFunds => StatusCode::SERVICE_UNAVAILABLE,
        C::InsufficientMemoryAllocation => StatusCode::SERVICE_UNAVAILABLE,
        C::InsufficientCyclesForCreateCanister => StatusCode::SERVICE_UNAVAILABLE,
        C::SubnetNotFound => StatusCode::NOT_FOUND,
        C::CanisterOutOfCycles => StatusCode::SERVICE_UNAVAILABLE,
        C::CanisterTrapped => StatusCode::INTERNAL_SERVER_ERROR,
        C::CanisterCalledTrap => StatusCode::INTERNAL_SERVER_ERROR,
        C::CanisterContractViolation => StatusCode::BAD_REQUEST,
        C::CanisterInvalidWasm => StatusCode::BAD_REQUEST,
        C::CanisterDidNotReply => StatusCode::INTERNAL_SERVER_ERROR,
        C::CanisterOutOfMemory => StatusCode::SERVICE_UNAVAILABLE,
        C::CanisterStopped => StatusCode::SERVICE_UNAVAILABLE,
        C::CanisterStopping => StatusCode::SERVICE_UNAVAILABLE,
        C::CanisterNotStopped => StatusCode::PRECONDITION_FAILED,
        C::CanisterStoppingCancelled => StatusCode::PRECONDITION_FAILED,
        C::CanisterInvalidController => StatusCode::FORBIDDEN,
        C::CanisterFunctionNotFound => StatusCode::NOT_FOUND,
        C::CanisterNonEmpty => StatusCode::PRECONDITION_FAILED,
        C::CertifiedStateUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        C::CanisterRejectedMessage => StatusCode::FORBIDDEN,
        C::InterCanisterQueryLoopDetected => StatusCode::INTERNAL_SERVER_ERROR,
        C::UnknownManagementMessage => StatusCode::BAD_REQUEST,
        C::InvalidManagementPayload => StatusCode::BAD_REQUEST,
        C::InsufficientCyclesInCall => StatusCode::SERVICE_UNAVAILABLE,
        C::CanisterWasmEngineError => StatusCode::INTERNAL_SERVER_ERROR,
        C::CanisterInstructionLimitExceeded => StatusCode::INTERNAL_SERVER_ERROR,
        C::CanisterInstallCodeRateLimited => StatusCode::TOO_MANY_REQUESTS,
    };
    make_plaintext_response(status, user_error.description().to_string())
}

pub(crate) fn map_box_error_to_response(err: BoxError) -> Response<Body> {
    if let Some(user_error) = err.downcast_ref::<UserError>() {
        return make_response(user_error.clone());
    }
    if err.is::<Overloaded>() {
        return make_plaintext_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "The service is overloaded.".to_string(),
        );
    }
    make_plaintext_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Unexpected error: {}", err),
    )
}

/// Add CORS headers to provided Response. In particular we allow
/// wildcard origin, POST and GET and allow Accept, Authorization and
/// Content Type headers.
pub(crate) fn get_cors_headers() -> HeaderMap {
    use hyper::header;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        header::HeaderValue::from_static("POST, GET"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        header::HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        header::HeaderValue::from_static("Accept, Authorization, Content-Type"),
    );
    headers
}

/// Convert an object into CBOR binary.
pub(crate) fn into_cbor<R: Serialize>(r: &R) -> Vec<u8> {
    let mut ser = serde_cbor::Serializer::new(Vec::new());
    ser.self_describe().expect("Could not write magic tag.");
    r.serialize(&mut ser).expect("Serialization failed.");
    ser.into_inner()
}

/// Write the "self describing" CBOR tag and serialize the response
pub(crate) fn cbor_response<R: Serialize>(r: &R) -> Response<Body> {
    use hyper::header;
    let mut response = Response::new(Body::from(into_cbor(r)));
    *response.status_mut() = StatusCode::OK;
    *response.headers_mut() = get_cors_headers();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static(CONTENT_TYPE_CBOR),
    );
    response
}

/// Empty response.
pub(crate) fn empty_response() -> Response<Body> {
    let mut response = Response::new(Body::from(""));
    *response.status_mut() = StatusCode::NO_CONTENT;
    response
}

pub(crate) fn make_response_on_validation_error(
    message_id: MessageId,
    err: RequestValidationError,
    log: &ReplicaLogger,
) -> Response<Body> {
    match err {
        RequestValidationError::InvalidIngressExpiry(msg)
        | RequestValidationError::InvalidDelegationExpiry(msg) => {
            make_plaintext_response(StatusCode::BAD_REQUEST, msg)
        }
        _ => {
            let message = format!(
                "Failed to authenticate request {} due to: {}",
                message_id, err
            );
            info!(log, "{}", message);
            make_plaintext_response(StatusCode::FORBIDDEN, message)
        }
    }
}

pub(crate) fn get_latest_certified_state(
    state_reader: &dyn StateReader<State = ReplicatedState>,
) -> Option<Arc<ReplicatedState>> {
    let paths = &mut [Path::from(Label::from("time"))];
    let labeled_tree = sparse_labeled_tree_from_paths(paths);
    state_reader
        .read_certified_state(&labeled_tree)
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

    fn check_cors_headers(hm: &HeaderMap) {
        let acl_headers = hm.get_all(header::ACCESS_CONTROL_ALLOW_HEADERS).iter();
        assert!(acl_headers.eq(["Accept, Authorization, Content-Type"].iter()));
        let acl_methods = hm.get_all(header::ACCESS_CONTROL_ALLOW_METHODS).iter();
        assert!(acl_methods.eq(["POST, GET"].iter()));
        let acl_origin = hm.get_all(header::ACCESS_CONTROL_ALLOW_ORIGIN).iter();
        assert!(acl_origin.eq(["*"].iter()));
    }

    #[test]
    fn test_add_headers() {
        let hm = get_cors_headers();
        assert_eq!(hm.len(), 3);
        check_cors_headers(&hm);
    }

    #[test]
    fn test_cbor_response() {
        let response = cbor_response(b"");
        assert_eq!(response.headers().len(), 4);
        assert_eq!(
            response
                .headers()
                .get_all(header::CONTENT_TYPE)
                .iter()
                .count(),
            1
        );
        check_cors_headers(response.headers());
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
