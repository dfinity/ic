use anyhow::anyhow;
use axum::{
    BoxError,
    http::StatusCode,
    response::{IntoResponse, Response},
};

use ic_bn_lib::http::headers::X_IC_ERROR_CAUSE;
use strum::{Display, IntoStaticStr};
use tower_governor::GovernorError;

#[derive(Clone, Debug, Display)]
#[strum(serialize_all = "snake_case")]
pub enum RateLimitCause {
    Normal,
    Bouncer,
    Generic,
}

/// Categorized possible causes for request processing failures
#[derive(Clone, Debug, Display)]
#[strum(serialize_all = "snake_case")]
pub enum ErrorCause {
    BodyTimedOut,
    UnableToReadBody(String),
    PayloadTooLarge(usize),
    UnableToParseCBOR(String),
    UnableToParseHTTPArg(String),
    LoadShed,
    Forbidden,
    MalformedRequest(String),
    NoRoutingTable,
    SubnetNotFound,
    CanisterNotFound,
    NoHealthyNodes,
    ReplicaErrorDNS(String),
    ReplicaErrorConnect,
    ReplicaTimeout,
    ReplicaTLSErrorOther(String),
    ReplicaTLSErrorCert(String),
    ReplicaErrorOther(String),
    #[strum(serialize = "rate_limited_{0}")]
    RateLimited(RateLimitCause),
    #[strum(serialize = "internal_server_error")]
    Other(String),
}

impl ErrorCause {
    pub fn details(&self) -> Option<String> {
        match self {
            Self::Other(x) => Some(x.clone()),
            Self::PayloadTooLarge(x) => Some(format!("maximum body size is {x} bytes")),
            Self::UnableToReadBody(x) => Some(x.clone()),
            Self::UnableToParseCBOR(x) => Some(x.clone()),
            Self::UnableToParseHTTPArg(x) => Some(x.clone()),
            Self::LoadShed => Some("Overloaded".into()),
            Self::MalformedRequest(x) => Some(x.clone()),
            Self::ReplicaErrorDNS(x) => Some(x.clone()),
            Self::ReplicaTLSErrorOther(x) => Some(x.clone()),
            Self::ReplicaTLSErrorCert(x) => Some(x.clone()),
            Self::ReplicaErrorOther(x) => Some(x.clone()),
            _ => None,
        }
    }

    pub fn retriable(&self) -> bool {
        !matches!(self, Self::PayloadTooLarge(_))
    }

    pub fn to_client_facing_error(&self) -> ErrorClientFacing {
        match self {
            Self::Other(_) => ErrorClientFacing::Other,
            Self::BodyTimedOut => ErrorClientFacing::BodyTimedOut,
            Self::UnableToReadBody(_) => ErrorClientFacing::Other,
            Self::PayloadTooLarge(x) => ErrorClientFacing::PayloadTooLarge(*x),
            Self::UnableToParseCBOR(x) => ErrorClientFacing::UnableToParseCBOR(x.clone()),
            Self::UnableToParseHTTPArg(x) => ErrorClientFacing::UnableToParseHTTPArg(x.clone()),
            Self::LoadShed => ErrorClientFacing::LoadShed,
            Self::MalformedRequest(x) => ErrorClientFacing::MalformedRequest(x.clone()),
            Self::NoRoutingTable => ErrorClientFacing::ServiceUnavailable,
            Self::SubnetNotFound => ErrorClientFacing::SubnetNotFound,
            Self::CanisterNotFound => ErrorClientFacing::CanisterNotFound,
            Self::NoHealthyNodes => ErrorClientFacing::NoHealthyNodes,
            Self::ReplicaErrorDNS(_) => ErrorClientFacing::ReplicaError,
            Self::ReplicaErrorConnect => ErrorClientFacing::ReplicaError,
            Self::ReplicaTimeout => ErrorClientFacing::ReplicaError,
            Self::ReplicaTLSErrorOther(_) => ErrorClientFacing::ReplicaError,
            Self::ReplicaTLSErrorCert(_) => ErrorClientFacing::ReplicaError,
            Self::ReplicaErrorOther(_) => ErrorClientFacing::ReplicaError,
            Self::Forbidden => ErrorClientFacing::Forbidden,
            Self::RateLimited(_) => ErrorClientFacing::RateLimited,
        }
    }
}

// Creates the response from ErrorCause and injects itself into extensions to be visible by middleware
impl IntoResponse for ErrorCause {
    fn into_response(self) -> Response {
        let client_facing_error = self.to_client_facing_error();
        let mut resp = client_facing_error.into_response();
        resp.extensions_mut().insert(self);
        resp
    }
}

#[derive(Clone, Debug, Display, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum ErrorClientFacing {
    BodyTimedOut,
    CanisterNotFound,
    LoadShed,
    MalformedRequest(String),
    NoHealthyNodes,
    #[strum(serialize = "internal_server_error")]
    Other,
    PayloadTooLarge(usize),
    Forbidden,
    RateLimited,
    ReplicaError,
    ServiceUnavailable,
    SubnetNotFound,
    UnableToParseCBOR(String),
    UnableToParseHTTPArg(String),
}

impl ErrorClientFacing {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::BodyTimedOut => StatusCode::REQUEST_TIMEOUT,
            Self::CanisterNotFound => StatusCode::BAD_REQUEST,
            Self::LoadShed => StatusCode::TOO_MANY_REQUESTS,
            Self::MalformedRequest(_) => StatusCode::BAD_REQUEST,
            Self::NoHealthyNodes => StatusCode::SERVICE_UNAVAILABLE,
            Self::Other => StatusCode::INTERNAL_SERVER_ERROR,
            Self::PayloadTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::ReplicaError => StatusCode::SERVICE_UNAVAILABLE,
            Self::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::SubnetNotFound => StatusCode::BAD_REQUEST,
            Self::UnableToParseCBOR(_) => StatusCode::BAD_REQUEST,
            Self::UnableToParseHTTPArg(_) => StatusCode::BAD_REQUEST,
        }
    }

    pub fn details(&self) -> String {
        match self {
            Self::BodyTimedOut => "Reading the request body timed out due to data arriving too slowly.".to_string(),
            Self::CanisterNotFound => "The specified canister does not exist.".to_string(),
            Self::LoadShed => "Temporarily unable to handle the request due to high load. Please try again later.".to_string(),
            Self::MalformedRequest(x) => x.clone(),
            Self::NoHealthyNodes => "There are currently no healthy replica nodes available to handle the request. This may be due to an ongoing upgrade of the replica software in the subnet. Please try again later.".to_string(),
            Self::Other => "Internal Server Error".to_string(),
            Self::PayloadTooLarge(x) => format!("Payload is too large: maximum body size is {x} bytes."),
            Self::Forbidden => "Request is forbidden according to currently active policy, it might work later.".to_string(),
            Self::RateLimited => "Rate limit exceeded. Please slow down requests and try again later.".to_string(),
            Self::ReplicaError => "An unexpected error occurred while communicating with the upstream replica node. Please try again later.".to_string(),
            Self::ServiceUnavailable => "The API boundary node is temporarily unable to process the request. Please try again later.".to_string(),
            Self::SubnetNotFound => "The specified subnet cannot be found.".to_string(),
            Self::UnableToParseCBOR(x) => format!("Failed to parse the CBOR request body: {x}"),
            Self::UnableToParseHTTPArg(x) => format!("Unable to decode the arguments of the request to the http_request method: {x}"),
        }
    }
}

// Creates the response from ErrorClientFacing and injects itself into extensions to be visible by middleware
impl IntoResponse for ErrorClientFacing {
    fn into_response(self) -> Response {
        let error_cause = self.to_string();

        let headers = [(X_IC_ERROR_CAUSE, error_cause.clone())];
        let body = format!("error: {}\ndetails: {}", error_cause, self.details());

        (self.status_code(), headers, body).into_response()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("status {0}: {1}")]
    _Custom(StatusCode, String),

    #[error("proxy error: {0}")]
    ProxyError(ErrorCause),

    #[error(transparent)]
    Unspecified(#[from] anyhow::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            ApiError::_Custom(c, b) => (c, b).into_response(),
            ApiError::ProxyError(c) => c.into_response(),
            ApiError::Unspecified(err) => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
            }
        }
    }
}

impl From<ErrorCause> for ApiError {
    fn from(c: ErrorCause) -> Self {
        ApiError::ProxyError(c)
    }
}

impl From<BoxError> for ApiError {
    fn from(item: BoxError) -> Self {
        if !item.is::<GovernorError>() {
            return ApiError::Unspecified(anyhow!(item.to_string()));
        }

        // it's a GovernorError
        let error = item.downcast_ref::<GovernorError>().unwrap().to_owned();
        match error {
            GovernorError::TooManyRequests { .. } => {
                ApiError::from(ErrorCause::RateLimited(RateLimitCause::Normal))
            }
            GovernorError::UnableToExtractKey => ApiError::from(ErrorCause::Other(
                "unable to extract rate-limiting key".into(),
            )),
            GovernorError::Other { msg, .. } => ApiError::from(ErrorCause::Other(format!(
                "governor_error: {}",
                msg.unwrap_or_default()
            ))),
        }
    }
}
