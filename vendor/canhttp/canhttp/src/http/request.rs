use crate::convert::Convert;
use crate::{
    IsReplicatedRequestExtension, MaxResponseBytesRequestExtension,
    TransformContextRequestExtension,
};
use ic_cdk::management_canister::{
    HttpHeader as IcHttpHeader, HttpMethod as IcHttpMethod, HttpRequestArgs as IcHttpRequest,
    TransformContext,
};
use thiserror::Error;

/// HTTP request with a body made of bytes.
pub type HttpRequest = http::Request<Vec<u8>>;

#[derive(Clone, Debug, PartialEq, Eq)]
struct MaxResponseBytesExtension(pub u64);

impl<T> MaxResponseBytesRequestExtension for http::Request<T> {
    fn set_max_response_bytes(&mut self, value: u64) {
        let extensions = self.extensions_mut();
        extensions.insert(MaxResponseBytesExtension(value));
    }

    fn get_max_response_bytes(&self) -> Option<u64> {
        self.extensions()
            .get::<MaxResponseBytesExtension>()
            .map(|e| e.0)
    }
}

impl MaxResponseBytesRequestExtension for http::request::Builder {
    fn set_max_response_bytes(&mut self, value: u64) {
        if let Some(extensions) = self.extensions_mut() {
            extensions.insert(MaxResponseBytesExtension(value));
        }
    }

    fn get_max_response_bytes(&self) -> Option<u64> {
        self.extensions_ref()
            .and_then(|extensions| extensions.get::<MaxResponseBytesExtension>().map(|e| e.0))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TransformContextExtension(pub TransformContext);

impl<T> TransformContextRequestExtension for http::Request<T> {
    fn set_transform_context(&mut self, value: TransformContext) {
        let extensions = self.extensions_mut();
        extensions.insert(TransformContextExtension(value));
    }

    fn get_transform_context(&self) -> Option<&TransformContext> {
        self.extensions()
            .get::<TransformContextExtension>()
            .map(|e| &e.0)
    }
}

impl TransformContextRequestExtension for http::request::Builder {
    fn set_transform_context(&mut self, value: TransformContext) {
        if let Some(extensions) = self.extensions_mut() {
            extensions.insert(TransformContextExtension(value));
        }
    }

    fn get_transform_context(&self) -> Option<&TransformContext> {
        self.extensions_ref()
            .and_then(|extensions| extensions.get::<TransformContextExtension>().map(|e| &e.0))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct IsReplicatedExtension(pub bool);

impl<T> IsReplicatedRequestExtension for http::Request<T> {
    fn set_is_replicated(&mut self, value: bool) {
        let extensions = self.extensions_mut();
        extensions.insert(IsReplicatedExtension(value));
    }

    fn get_is_replicated(&self) -> Option<bool> {
        self.extensions()
            .get::<IsReplicatedExtension>()
            .map(|e| e.0)
    }
}

impl IsReplicatedRequestExtension for http::request::Builder {
    fn set_is_replicated(&mut self, value: bool) {
        if let Some(extensions) = self.extensions_mut() {
            extensions.insert(IsReplicatedExtension(value));
        }
    }

    fn get_is_replicated(&self) -> Option<bool> {
        self.extensions_ref()
            .and_then(|extensions| extensions.get::<IsReplicatedExtension>().map(|e| e.0))
    }
}

/// Error return when converting requests with [`HttpRequestConverter`].
#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum HttpRequestConversionError {
    /// HTTP method is not supported
    #[error("HTTP method `{0}` is not supported")]
    UnsupportedHttpMethod(String),
    /// Header name is invalid.
    #[error("HTTP header `{name}` has an invalid value: {reason}")]
    InvalidHttpHeaderValue {
        /// Header name
        name: String,
        /// Reason for header value being invalid.
        reason: String,
    },
}

/// Convert requests of type [`HttpRequest`] into [`IcHttpRequest`].
#[derive(Clone, Debug)]
pub struct HttpRequestConverter;

impl Convert<HttpRequest> for HttpRequestConverter {
    type Output = IcHttpRequest;
    type Error = HttpRequestConversionError;

    fn try_convert(&mut self, request: HttpRequest) -> Result<Self::Output, Self::Error> {
        let url = request.uri().to_string();
        let max_response_bytes = request.get_max_response_bytes();
        let method = match request.method().as_str() {
            "GET" => IcHttpMethod::GET,
            "POST" => IcHttpMethod::POST,
            "HEAD" => IcHttpMethod::HEAD,
            unsupported => {
                return Err(HttpRequestConversionError::UnsupportedHttpMethod(
                    unsupported.to_string(),
                ))
            }
        };
        let headers = request
            .headers()
            .iter()
            .map(|(header_name, header_value)| match header_value.to_str() {
                Ok(value) => Ok(IcHttpHeader {
                    name: header_name.to_string(),
                    value: value.to_string(),
                }),
                Err(e) => Err(HttpRequestConversionError::InvalidHttpHeaderValue {
                    name: header_name.to_string(),
                    reason: e.to_string(),
                }),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let transform = request.get_transform_context().cloned();
        let is_replicated = request.get_is_replicated();
        let body = Some(request.into_body());
        Ok(IcHttpRequest {
            url,
            max_response_bytes,
            method,
            headers,
            body,
            transform,
            is_replicated,
        })
    }
}
