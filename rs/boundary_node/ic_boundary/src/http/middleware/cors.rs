#![allow(clippy::declare_interior_mutable_const)]

use std::time::Duration;

use http::{
    Method,
    header::{
        ACCEPT_RANGES, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, COOKIE, DNT,
        HeaderName, IF_MODIFIED_SINCE, IF_NONE_MATCH, RANGE, USER_AGENT,
    },
};
use ic_bn_lib::http::headers::X_REQUESTED_WITH;
use tower_http::cors::{Any, CorsLayer};

// Methods allowed
const ALLOW_METHODS: [Method; 3] = [Method::HEAD, Method::GET, Method::POST];

// Base headers
const EXPOSE_HEADERS: [HeaderName; 3] = [ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE];

const ALLOW_HEADERS: [HeaderName; 9] = [
    USER_AGENT,
    DNT,
    IF_NONE_MATCH,
    IF_MODIFIED_SINCE,
    CACHE_CONTROL,
    CONTENT_TYPE,
    RANGE,
    COOKIE,
    X_REQUESTED_WITH,
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
