#![allow(clippy::declare_interior_mutable_const)]

use std::time::Duration;

use http::{
    header::{
        HeaderName, ACCEPT_RANGES, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE,
        COOKIE, DNT, IF_MODIFIED_SINCE, IF_NONE_MATCH, RANGE, USER_AGENT,
    },
    Method,
};
use ic_bn_lib::http::headers::{X_IC_CANISTER_ID, X_REQUESTED_WITH, X_REQUEST_ID};
use tower_http::cors::{Any, CorsLayer};

// Methods allowed
pub const ALLOW_METHODS: [Method; 6] = [
    Method::HEAD,
    Method::GET,
    Method::POST,
    Method::PUT,
    Method::DELETE,
    Method::PATCH,
];

// Base headers
const EXPOSE_HEADERS: [HeaderName; 5] = [
    ACCEPT_RANGES,
    CONTENT_LENGTH,
    CONTENT_RANGE,
    X_REQUEST_ID,
    X_IC_CANISTER_ID,
];

pub const ALLOW_HEADERS: [HeaderName; 10] = [
    USER_AGENT,
    DNT,
    IF_NONE_MATCH,
    IF_MODIFIED_SINCE,
    CACHE_CONTROL,
    CONTENT_TYPE,
    RANGE,
    COOKIE,
    X_REQUESTED_WITH,
    X_IC_CANISTER_ID,
];

/// Some default CORS layer
pub fn layer() -> CorsLayer {
    CorsLayer::new()
        .expose_headers(EXPOSE_HEADERS)
        .allow_headers(ALLOW_HEADERS)
        .allow_methods(ALLOW_METHODS)
        .allow_origin(Any)
        .max_age(Duration::from_secs(7200))
}
