//! This crate provides types for representing HTTP requests and responses. These types are
//! designed to simplify working with HTTP communication in canister development on the Internet
//! Computer.
//!
//! It includes:
//! - `HttpRequest`: A struct for encapsulating HTTP requests.
//! - `HttpResponse`: A struct for encapsulating HTTP responses.
//! - `HttpResponseBuilder`: A builder for constructing `HttpResponse` objects.

use candid::{CandidType, Deserialize};
use serde_bytes::ByteBuf;

/// Represents an HTTP request.
///
/// This struct is used to encapsulate the details of an HTTP request, including
/// the HTTP method, URL, headers, and body.
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct HttpRequest {
    /// The HTTP method (e.g., "GET", "POST").
    pub method: String,
    /// The URL of the request.
    pub url: String,
    /// A list of headers, where each header is represented as a key-value pair.
    pub headers: Vec<(String, String)>,
    /// The body of the request, represented as a byte buffer.
    pub body: ByteBuf,
}

impl HttpRequest {
    /// Extracts the path from the URL.
    ///
    /// If the URL contains a query string, the path is the portion before the `?`.
    /// If no query string is present, the entire URL is returned.
    ///
    /// # Examples
    ///
    /// ```
    /// use ic_http_types::{HttpRequest};
    /// use serde_bytes::ByteBuf;
    ///
    /// let request = HttpRequest {
    ///     method: "GET".to_string(),
    ///     url: "/path/to/resource?query=1".to_string(),
    ///     headers: vec![],
    ///     body: ByteBuf::default(),
    /// };
    /// assert_eq!(request.path(), "/path/to/resource");
    /// ```
    pub fn path(&self) -> &str {
        match self.url.find('?') {
            None => &self.url[..],
            Some(index) => &self.url[..index],
        }
    }

    /// Searches for the first appearance of a parameter in the request URL.
    ///
    /// Returns `None` if the given parameter does not appear in the query string.
    ///
    /// # Parameters
    /// - `param`: The name of the query parameter to search for.
    ///
    /// # Examples
    ///
    /// ```
    /// use ic_http_types::{HttpRequest};
    /// use serde_bytes::ByteBuf;
    ///
    /// let request = HttpRequest {
    ///     method: "GET".to_string(),
    ///     url: "/path?key=value".to_string(),
    ///     headers: vec![],
    ///     body: ByteBuf::default(),
    /// };
    /// assert_eq!(request.raw_query_param("key"), Some("value"));
    /// ```
    pub fn raw_query_param(&self, param: &str) -> Option<&str> {
        const QUERY_SEPARATOR: &str = "?";
        let query_string = self.url.split(QUERY_SEPARATOR).nth(1)?;
        if query_string.is_empty() {
            return None;
        }
        const PARAMETER_SEPARATOR: &str = "&";
        for chunk in query_string.split(PARAMETER_SEPARATOR) {
            const KEY_VALUE_SEPARATOR: &str = "=";
            let mut split = chunk.splitn(2, KEY_VALUE_SEPARATOR);
            let name = split.next()?;
            if name == param {
                return Some(split.next().unwrap_or_default());
            }
        }
        None
    }
}

/// Represents an HTTP response.
///
/// This struct is used to encapsulate the details of an HTTP response, including
/// the status code, headers, and body.
///
/// # Examples
///
/// ```
/// use ic_http_types::{HttpResponse};
/// use serde_bytes::ByteBuf;
///
/// let response = HttpResponse {
///     status_code: 200,
///     headers: vec![("Content-Type".to_string(), "application/json".to_string())],
///     body: ByteBuf::from("response body"),
/// };
///
/// assert_eq!(response.status_code, 200);
/// assert_eq!(response.headers.len(), 1);
/// assert_eq!(response.body, ByteBuf::from("response body"));
/// ```
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct HttpResponse {
    /// The HTTP status code (e.g., 200 for OK, 404 for Not Found).
    pub status_code: u16,
    /// A list of headers, where each header is represented as a key-value pair.
    pub headers: Vec<(String, String)>,
    /// The body of the response, represented as a byte buffer.
    pub body: ByteBuf,
}

/// A builder for constructing `HttpResponse` objects.
///
/// This struct provides a convenient way to create HTTP responses with
/// customizable status codes, headers, and bodies.
///
///
/// # Examples
///
/// ```
/// use ic_http_types::{HttpResponseBuilder};
/// use serde_bytes::ByteBuf;
///
/// let response = HttpResponseBuilder::ok()
///     .header("Content-Type", "application/json")
///     .body("response body")
///     .build();
///
/// assert_eq!(response.status_code, 200);
/// assert_eq!(response.headers, vec![("Content-Type".to_string(), "application/json".to_string())]);
/// assert_eq!(response.body, ByteBuf::from("response body"));
/// ```
///
/// ```
/// use ic_http_types::{HttpResponseBuilder};
/// use serde_bytes::ByteBuf;
///
/// let response = HttpResponseBuilder::server_error("internal error")
///     .header("Retry-After", "120")
///     .build();
///
/// assert_eq!(response.status_code, 500);
/// assert_eq!(response.headers, vec![("Retry-After".to_string(), "120".to_string())]);
/// assert_eq!(response.body, ByteBuf::from("internal error"));
/// ```
pub struct HttpResponseBuilder(HttpResponse);

impl HttpResponseBuilder {
    /// Creates a new `HttpResponse` with a 200 OK status.
    pub fn ok() -> Self {
        Self(HttpResponse {
            status_code: 200,
            headers: vec![],
            body: ByteBuf::default(),
        })
    }

    /// Creates a new `HttpResponse` with a 400 Bad Request status.
    pub fn bad_request() -> Self {
        Self(HttpResponse {
            status_code: 400,
            headers: vec![],
            body: ByteBuf::from("bad request"),
        })
    }

    /// Creates a new `HttpResponse` with a 404 Not Found status.
    pub fn not_found() -> Self {
        Self(HttpResponse {
            status_code: 404,
            headers: vec![],
            body: ByteBuf::from("not found"),
        })
    }

    /// Creates a new `HttpResponse` with a 500 Internal Server Error status.
    ///
    /// # Parameters
    /// - `reason`: A string describing the reason for the server error.
    pub fn server_error(reason: impl ToString) -> Self {
        Self(HttpResponse {
            status_code: 500,
            headers: vec![],
            body: ByteBuf::from(reason.to_string()),
        })
    }

    /// Adds a header to the `HttpResponse`.
    ///
    /// # Parameters
    /// - `name`: The name of the header.
    /// - `value`: The value of the header.
    pub fn header(mut self, name: impl ToString, value: impl ToString) -> Self {
        self.0.headers.push((name.to_string(), value.to_string()));
        self
    }

    /// Sets the body of the `HttpResponse`.
    ///
    /// # Parameters
    /// - `bytes`: The body content as a byte array.
    pub fn body(mut self, bytes: impl Into<Vec<u8>>) -> Self {
        self.0.body = ByteBuf::from(bytes.into());
        self
    }

    /// Sets the body of the `HttpResponse` and adds a `Content-Length` header.
    ///
    /// # Parameters
    /// - `bytes`: The body content as a byte array.
    pub fn with_body_and_content_length(self, bytes: impl Into<Vec<u8>>) -> Self {
        let bytes = bytes.into();
        self.header("Content-Length", bytes.len()).body(bytes)
    }

    /// Finalizes the builder and returns the constructed `HttpResponse`.
    pub fn build(self) -> HttpResponse {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_returns_full_url_when_no_query_string() {
        let http_request = HttpRequest {
            method: "GET".to_string(),
            url: "/path/to/resource".to_string(),
            headers: vec![],
            body: Default::default(),
        };
        assert_eq!(http_request.path(), "/path/to/resource");
    }

    #[test]
    fn path_returns_path_without_query_string() {
        let http_request = HttpRequest {
            method: "GET".to_string(),
            url: "/path/to/resource?query=1".to_string(),
            headers: vec![],
            body: Default::default(),
        };
        assert_eq!(http_request.path(), "/path/to/resource");
    }

    #[test]
    fn path_handles_empty_url() {
        let http_request = HttpRequest {
            method: "GET".to_string(),
            url: "".to_string(),
            headers: vec![],
            body: Default::default(),
        };
        assert_eq!(http_request.path(), "");
    }

    #[test]
    fn raw_query_param_returns_none_for_empty_query_string() {
        let http_request = HttpRequest {
            method: "GET".to_string(),
            url: "/endpoint?".to_string(),
            headers: vec![],
            body: Default::default(),
        };
        assert_eq!(http_request.raw_query_param("key"), None);
    }

    #[test]
    fn raw_query_param_returns_none_for_missing_key() {
        let http_request = HttpRequest {
            method: "GET".to_string(),
            url: "/endpoint?other=value".to_string(),
            headers: vec![],
            body: Default::default(),
        };
        assert_eq!(http_request.raw_query_param("key"), None);
    }

    #[test]
    fn raw_query_param_returns_empty_value_for_key_without_value() {
        let http_request = HttpRequest {
            method: "GET".to_string(),
            url: "/endpoint?key=".to_string(),
            headers: vec![],
            body: Default::default(),
        };
        assert_eq!(http_request.raw_query_param("key"), Some(""));
    }

    #[test]
    fn raw_query_param_handles_multiple_keys_with_same_name() {
        let http_request = HttpRequest {
            method: "GET".to_string(),
            url: "/endpoint?key=value1&key=value2".to_string(),
            headers: vec![],
            body: Default::default(),
        };
        assert_eq!(http_request.raw_query_param("key"), Some("value1"));
    }

    #[test]
    fn raw_query_param_handles_url_without_query_separator() {
        let http_request = HttpRequest {
            method: "GET".to_string(),
            url: "/endpoint".to_string(),
            headers: vec![],
            body: Default::default(),
        };
        assert_eq!(http_request.raw_query_param("key"), None);
    }

    #[test]
    fn raw_query_param_returns_none_for_partial_match() {
        let http_request = HttpRequest {
            method: "GET".to_string(),
            url: "/endpoint?key1=value1".to_string(),
            headers: vec![],
            body: Default::default(),
        };
        assert_eq!(http_request.raw_query_param("key"), None);
    }

    #[test]
    fn ok_response_has_status_200() {
        let response = HttpResponseBuilder::ok().build();
        assert_eq!(response.status_code, 200);
        assert!(response.body.is_empty());
    }

    #[test]
    fn bad_request_response_has_status_400_and_default_body() {
        let response = HttpResponseBuilder::bad_request().build();
        assert_eq!(response.status_code, 400);
        assert_eq!(response.body, ByteBuf::from("bad request"));
    }

    #[test]
    fn not_found_response_has_status_404_and_default_body() {
        let response = HttpResponseBuilder::not_found().build();
        assert_eq!(response.status_code, 404);
        assert_eq!(response.body, ByteBuf::from("not found"));
    }

    #[test]
    fn server_error_response_has_status_500_and_custom_body() {
        let response = HttpResponseBuilder::server_error("internal error").build();
        assert_eq!(response.status_code, 500);
        assert_eq!(response.body, ByteBuf::from("internal error"));
    }

    #[test]
    fn response_builder_adds_headers_correctly() {
        let response = HttpResponseBuilder::ok()
            .header("Content-Type", "application/json")
            .header("Cache-Control", "no-cache")
            .build();
        assert_eq!(
            response.headers,
            vec![
                ("Content-Type".to_string(), "application/json".to_string()),
                ("Cache-Control".to_string(), "no-cache".to_string())
            ]
        );
    }

    #[test]
    fn response_builder_sets_body_correctly() {
        let response = HttpResponseBuilder::ok().body("response body").build();
        assert_eq!(response.body, ByteBuf::from("response body"));
    }

    #[test]
    fn response_builder_sets_body_and_content_length() {
        let response = HttpResponseBuilder::ok()
            .with_body_and_content_length("response body")
            .build();
        assert_eq!(response.body, ByteBuf::from("response body"));
        assert_eq!(
            response.headers,
            vec![("Content-Length".to_string(), "13".to_string())]
        );
    }
}
