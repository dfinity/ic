//! From [HTTP Fields]
//!
//! Fields related to HTTP activity. Use the url field set to store the url of
//! the request.
//!
//! [HTTP Fields]: https://www.elastic.co/guide/en/ecs/current/ecs-http.html

use std::collections::HashMap;

use hyper::http;
use serde::Serialize;
use slog_derive::SerdeValue;

use crate::{value::ExtraValues, Long, SetTo, Value};

#[derive(Clone, Debug, Default, Serialize, SerdeValue)]
pub struct Http {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<Request>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<Response>,

    /// HTTP version.
    ///
    /// example: `1.1`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, SerdeValue)]
pub struct Request {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<RequestBody>,

    /// Total size in bytes of the request (body and headers)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<Long>,

    /// HTTP request method (maintain original case)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    /// Referrer for this HTTP request
    #[serde(skip_serializing_if = "Option::is_none")]
    pub referrer: Option<String>,
    #[serde(skip_serializing_if = "HashMap::is_empty", flatten)]
    pub extra_values: ExtraValues,
}

impl SetTo<(&'static str, Value)> for Option<Request> {
    // TODO: misnamed, this adds to, rather than sets
    fn set(&mut self, item: (&'static str, Value)) {
        let (key, value) = item;
        let request = self.get_or_insert(Request::default());
        request.extra_values.insert(key, value);
    }
}

#[derive(Clone, Debug, Default, Serialize, SerdeValue)]
pub struct RequestBody {
    /// Size in bytes of the request body
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<Long>,
    // TODO: content
}

impl SetTo<Request> for Option<Http> {
    fn set(&mut self, request: Request) {
        let http = self.get_or_insert(Http::default());
        http.request = Some(request);
    }
}

impl SetTo<&hyper::Request<hyper::Body>> for Option<Http> {
    fn set(&mut self, hyper_request: &hyper::Request<hyper::Body>) {
        let http = self.get_or_insert(Http::default());

        let request = http.request.get_or_insert(Request::default());

        request.method = Some(hyper_request.method().to_string());
        request.referrer = hyper_request
            .headers()
            .get(hyper::header::REFERER)
            .map(|header| header.to_str().unwrap_or("").to_string());

        http.version = Some(match hyper_request.version() {
            http::version::Version::HTTP_09 => "0.9".to_string(),
            http::version::Version::HTTP_10 => "1.0".to_string(),
            http::version::Version::HTTP_11 => "1.1".to_string(),
            http::version::Version::HTTP_2 => "2.0".to_string(),
            http::version::Version::HTTP_3 => "3.0".to_string(),
            _ => panic!("Unknown version"),
        });
    }
}

#[derive(Clone, Debug, Default, Serialize, SerdeValue)]
pub struct Response {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<ResponseBody>,

    /// Total size in bytes of the response (body and headers)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<Long>,

    /// HTTP request method (maintain original case)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<Long>,
    #[serde(skip_serializing_if = "HashMap::is_empty", flatten)]
    pub extra_values: ExtraValues,
}

impl SetTo<(&'static str, Value)> for Option<Response> {
    // TODO: misnamed, this adds to, rather than sets
    fn set(&mut self, item: (&'static str, Value)) {
        let (key, value) = item;
        let request = self.get_or_insert(Response::default());
        request.extra_values.insert(key, value);
    }
}

#[derive(Clone, Debug, Default, Serialize, SerdeValue)]
pub struct ResponseBody {
    /// Size in bytes of the response body
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<Long>,
    // TODO: content
}

impl SetTo<&hyper::Response<hyper::Body>> for Option<Http> {
    fn set(&mut self, hyper_response: &hyper::Response<hyper::Body>) {
        let http = self.get_or_insert(Http::default());

        let response = http.response.get_or_insert(Response::default());
        response.status_code = Some(hyper_response.status().as_u16() as Long);
    }
}
