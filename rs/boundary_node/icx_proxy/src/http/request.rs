use crate::error::ErrorFactory;
use crate::http::body::read_streaming_body;
use crate::http::headers::REQUIRE_CERTIFICATION_HEADER_NAME;
use crate::proxy::REQUEST_BODY_SIZE_LIMIT;
use axum::body::Body;
use hyper::http::request::Parts;
use hyper::Uri;
use ic_http_certification::HttpRequest as Request;
use tracing::trace;

pub struct HttpRequest {
    pub uri: Uri,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl From<(&Parts, Vec<u8>)> for HttpRequest {
    fn from((request, request_body): (&Parts, Vec<u8>)) -> Self {
        let headers = request
            .headers
            .iter()
            .filter_map(|(name, value)| Some((name.as_str().into(), value.to_str().ok()?.into())))
            .inspect(|(name, value)| {
                trace!("<< {name}: {value}");
            })
            .collect::<Vec<(String, String)>>();

        HttpRequest {
            uri: request.uri.clone(),
            method: String::from(request.method.as_str()),
            body: request_body,
            headers,
        }
    }
}

impl From<&HttpRequest> for Request {
    fn from(http_request: &HttpRequest) -> Self {
        Request {
            url: http_request.uri.to_string(),
            method: http_request.method.clone(),
            headers: http_request.headers.clone(),
            body: http_request.body.clone(),
        }
    }
}

impl HttpRequest {
    /// If the header `x-icx-require-certification` is set then certification is required.
    pub fn is_certification_required(&self) -> bool {
        for (header_name, _) in self.headers.iter() {
            if header_name.eq_ignore_ascii_case(REQUIRE_CERTIFICATION_HEADER_NAME) {
                return true;
            }
        }

        false
    }

    /// Reads the body stream enforcing the request body size limit.
    pub async fn read_body(body: Body) -> Result<Vec<u8>, ErrorFactory> {
        read_streaming_body(body, REQUEST_BODY_SIZE_LIMIT).await
    }
}

#[cfg(test)]
mod tests {
    use crate::http::headers::REQUIRE_CERTIFICATION_HEADER_NAME;
    use crate::http::request::HttpRequest;
    use hyper::Uri;

    #[test]
    fn required_certification() {
        let request = HttpRequest {
            uri: Uri::from_static("http://localhost"),
            headers: [(
                REQUIRE_CERTIFICATION_HEADER_NAME.to_string(),
                "true".to_string(),
            )]
            .to_vec(),
            method: "GET".to_string(),
            body: Vec::new(),
        };

        assert!(request.is_certification_required());
    }

    #[test]
    fn not_required_certification() {
        let request = HttpRequest {
            uri: Uri::from_static("http://localhost"),
            headers: Vec::new(),
            method: "GET".to_string(),
            body: Vec::new(),
        };

        assert!(!request.is_certification_required());
    }
}
