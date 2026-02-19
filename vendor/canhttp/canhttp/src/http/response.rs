use crate::convert::{Convert, Filter};
use ic_cdk::management_canister::HttpRequestResult as IcHttpResponse;
use thiserror::Error;

/// HTTP response with a body made of bytes.
pub type HttpResponse = http::Response<Vec<u8>>;

/// Error returned when converting respones with [`HttpResponseConverter`].
#[derive(Error, Clone, Debug, Eq, PartialEq)]
#[allow(clippy::enum_variant_names)] //current variants reflect invalid data and so start with the prefix Invalid.
pub enum HttpResponseConversionError {
    /// Status code is invalid
    #[error("Status code is invalid")]
    InvalidStatusCode,
    /// Header name is invalid.
    #[error("HTTP header `{name}` is invalid: {reason}")]
    InvalidHttpHeaderName {
        /// Header name
        name: String,
        /// Reason for being invalid.
        reason: String,
    },
    /// Header value is invalid.
    #[error("HTTP header `{name}` has an invalid value: {reason}")]
    InvalidHttpHeaderValue {
        /// Header name
        name: String,
        /// Reason for header value being invalid.
        reason: String,
    },
}

/// Convert responses of type [`IcHttpResponse`] into [HttpResponse].
#[derive(Debug, Clone)]
pub struct HttpResponseConverter;

impl Convert<IcHttpResponse> for HttpResponseConverter {
    type Output = HttpResponse;
    type Error = HttpResponseConversionError;

    fn try_convert(&mut self, response: IcHttpResponse) -> Result<Self::Output, Self::Error> {
        use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
        use ic_cdk::management_canister::HttpHeader as IcHttpHeader;
        use num_traits::ToPrimitive;

        let status = response
            .status
            .0
            .to_u16()
            .and_then(|s| StatusCode::try_from(s).ok())
            .ok_or(HttpResponseConversionError::InvalidStatusCode)?;

        let mut builder = http::Response::builder().status(status);
        if let Some(headers) = builder.headers_mut() {
            let mut response_headers = HeaderMap::with_capacity(response.headers.len());
            for IcHttpHeader { name, value } in response.headers {
                response_headers.insert(
                    HeaderName::try_from(&name).map_err(|e| {
                        HttpResponseConversionError::InvalidHttpHeaderName {
                            name: name.clone(),
                            reason: e.to_string(),
                        }
                    })?,
                    HeaderValue::try_from(&value).map_err(|e| {
                        HttpResponseConversionError::InvalidHttpHeaderValue {
                            name,
                            reason: e.to_string(),
                        }
                    })?,
                );
            }
            headers.extend(response_headers);
        }

        Ok(builder
            .body(response.body)
            .expect("BUG: builder should have been modified only with validated data"))
    }
}

/// Error returned when converting responses with [`FilterNonSuccessfulHttpResponse`].
#[derive(Error, Clone, Debug)]
pub enum FilterNonSuccessfulHttpResponseError<T> {
    /// Response has a non-successful status code.
    #[error("HTTP response is not successful: {0:?}")]
    UnsuccessfulResponse(http::Response<T>),
}

/// Filter out non-successful responses.
#[derive(Clone, Debug)]
pub struct FilterNonSuccessfulHttpResponse;

impl<T> Filter<http::Response<T>> for FilterNonSuccessfulHttpResponse {
    type Error = FilterNonSuccessfulHttpResponseError<T>;

    fn filter(&mut self, response: http::Response<T>) -> Result<http::Response<T>, Self::Error> {
        if !response.status().is_success() {
            return Err(FilterNonSuccessfulHttpResponseError::UnsuccessfulResponse(
                response,
            ));
        }
        Ok(response)
    }
}
