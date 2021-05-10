pub mod types;

use candid::CandidType;
use serde::Deserialize;

/// This is currently unstable and may stop working on the IC with little or no
/// warning.
/// This represents a HTTP request and accompanying metadata
#[derive(CandidType, Deserialize)]
pub struct RequestWrapper {
    pub secure: bool,
    // This has more ownership than I'd otherwise like, but serde will give you
    // absolutely hellish error messages if you try and serialize things with the wrong ownership
    pub remote_address: String,
    pub request: Request,
}

pub const HTTP_CANISTER_ID: u8 = 0x05;

#[derive(CandidType, Deserialize)]
pub struct Request {
    pub http_version: (u8, u8),
    pub method: Method,
    pub path: String,
    pub headers: Vec<Header>,
    pub body: Vec<u8>,
}

#[derive(CandidType, Deserialize)]
pub struct Header {
    pub field: String,
    pub value: String,
}

#[derive(CandidType, Deserialize)]
pub struct Response {
    pub body: Vec<u8>,
    pub status_code: u16,
    pub headers: Vec<Header>,
}

/// Some builder functions for creating responses.
/// Terseness has been prioritized over guarantees about not marshaling data
impl Response {
    pub fn from_status_code(status_code: u16) -> Self {
        Response {
            status_code,
            body: Vec::new(),
            headers: Vec::new(),
        }
    }

    /// Sets and overwrites the body of the response
    /// ```no_run
    /// # use dfn_http::*;
    /// Response
    ///     ::from_status_code(404)
    ///     .set_body("Page not found");
    /// ```
    pub fn set_body(mut self, body: &str) -> Self {
        self.body = body.bytes().collect();
        self
    }

    /// Sets and overwrites the values of all the existing headers in the
    /// response ```no_run
    /// # use dfn_http::*;
    /// Response
    ///    ::from_status_code(200)
    ///    .set_header(&[("Content-Type", "text/html"),
    /// ("Access-Control-Allow-Origin", "*")]); ```
    pub fn set_headers(mut self, headers: &[(&str, &str)]) -> Self {
        self.headers = headers
            .iter()
            .map(|(field, value)| Header {
                field: (*field).to_string(),
                value: (*value).to_string(),
            })
            .collect();
        self
    }

    /// Appends a header to the back of the list of headers
    /// ```no_run
    /// # use dfn_http::*;
    /// Response
    ///    ::from_status_code(200)
    ///    .push_header("Content-Type", "text/html");
    /// ```
    pub fn push_header(mut self, field: &str, value: &str) -> Self {
        self.headers.push(Header {
            field: field.to_string(),
            value: value.to_string(),
        });
        self
    }
}

#[derive(CandidType, Deserialize)]
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Delete,
    Connect,
    Options,
    Trace,
    Patch,
    NonStandard(String),
}

#[allow(clippy::needless_doctest_main)]
/// This is currently unstable and may stop working on the IC with little or no
/// warning
///
/// This allows you to use a canister as an HTTP server
///
/// # Example
///
/// ```no_run
/// # use dfn_http::*;
/// #[export_name = "canister_query http_query"]
/// pub fn main() {
///     http(handler)
/// }
///
/// fn handler(http: RequestWrapper) -> Response {
/// // Take the request and return a response
/// # Response::from_status_code(404)
/// }
/// ```
/// Requests send to query.<canister_id>.<ic_domain> will reach the handler
pub fn http<F>(handler: F)
where
    F: FnOnce(RequestWrapper) -> Response,
{
    let caller = dfn_core::api::caller().into_vec();

    // Generate CanisterHttp id which is a bunch of 0s then a 5
    let mut http_caller: Vec<u8> = vec![0; caller.len()];
    let end = http_caller
        .last_mut()
        .expect("The caller id had a length of zero");
    *end = HTTP_CANISTER_ID;

    if http_caller == caller {
        http_unchecked(handler)
    } else {
        panic!(
            "Expected caller {:?} but found caller {:?}",
            http_caller, caller
        )
    }
}

/// This is largely the same as "http" but the caller ID isn't checked
/// This allows other canisters to call this endpoint with arbitrary
/// data. This could lead to security issues if you're using
/// connection metadata to identify users.
/// If you're not sure what function to use, use "http"
pub fn http_unchecked<F>(handler: F)
where
    F: FnOnce(RequestWrapper) -> Response,
{
    dfn_core::over(dfn_candid::candid_one, handler)
}
