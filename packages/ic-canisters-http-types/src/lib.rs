//! This crate provides types for representing HTTP requests and responses.
//!
//! It includes:
//! - `HttpRequest`: A struct for encapsulating HTTP requests.
//! - `HttpResponse`: A struct for encapsulating HTTP responses.
//! - `HttpResponseBuilder`: A builder for constructing `HttpResponse` objects.
//!
//! These types are designed to simplify working with HTTP communication in the Internet Computer.

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
    fn test_raw_query_param() {
        fn request_with_url(url: String) -> HttpRequest {
            HttpRequest {
                method: "".to_string(),
                url,
                headers: vec![],
                body: Default::default(),
            }
        }
        let http_request = request_with_url("/endpoint?time=1000".to_string());
        assert_eq!(http_request.raw_query_param("time"), Some("1000"));
        let http_request = request_with_url("/endpoint".to_string());
        assert_eq!(http_request.raw_query_param("time"), None);
        let http_request =
            request_with_url("/endpoint?time=1000&time=1001&other=abcde&time=1002".to_string());
        assert_eq!(http_request.raw_query_param("time"), Some("1000"));
    }
}
