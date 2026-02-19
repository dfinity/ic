//! Middleware for retrying "failed" requests.

#[cfg(test)]
mod tests;

use crate::{HttpsOutcallError, MaxResponseBytesRequestExtension};
use std::future;
use tower::retry;

// This constant comes from the IC specification:
// > If provided, the value must not exceed 2MB
const HTTP_MAX_SIZE: u64 = 2_000_000;

/// Double the request `max_response_bytes` in case the error indicates the response was too big.
///
/// The value for `max_response_bytes` will be doubled until one of the following conditions happen:
/// 1. Either the response is `Ok` or the error is not due to the response being too big;
/// 2. Or, the maximum value of 2MB (`2_000_000`) is reached.
///
/// # Examples
///
/// ```rust
/// use canhttp::{
///     Client, http::HttpRequest, HttpsOutcallError, IcError, MaxResponseBytesRequestExtension,
///     retry::DoubleMaxResponseBytes
/// };
/// use ic_error_types::RejectCode;
/// use tower::{Service, ServiceBuilder, ServiceExt};
///
/// fn response_is_too_large_error() -> IcError {
///     let error = IcError::CallRejected {
///        code: RejectCode::SysFatal,
///        message: "Http body exceeds size limit".to_string(),
///    };
///     assert!(error.is_response_too_large());
///     error
/// }
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use assert_matches::assert_matches;
/// let mut service = ServiceBuilder::new()
/// .retry(DoubleMaxResponseBytes)
/// .service_fn(|request: HttpRequest| async move {
///     match request.get_max_response_bytes() {
///         Some(max_response_bytes) if max_response_bytes >= 8192 => Ok(()),
///         _ => Err::<(), IcError>(response_is_too_large_error()),
///     }
/// });
///
/// let request = http::Request::post("https://internetcomputer.org/")
///     .max_response_bytes(0)
///     .body(vec![])
///     .unwrap();
///
/// // This will effectively do 4 calls with the following max_response_bytes values: 0, 2048, 4096, 8192.
/// let response = service.ready().await?.call(request).await;
///
/// assert_matches!(response, Ok(()));
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct DoubleMaxResponseBytes;

impl<Request, Response, Error> retry::Policy<Request, Response, Error> for DoubleMaxResponseBytes
where
    Request: MaxResponseBytesRequestExtension + Clone,
    Error: HttpsOutcallError,
{
    type Future = future::Ready<()>;

    fn retry(
        &mut self,
        req: &mut Request,
        result: &mut Result<Response, Error>,
    ) -> Option<Self::Future> {
        match result {
            Err(e) if e.is_response_too_large() => {
                if let Some(previous_estimate) = req.get_max_response_bytes() {
                    let new_estimate = previous_estimate
                        .max(1024)
                        .saturating_mul(2)
                        .min(HTTP_MAX_SIZE);
                    if new_estimate > previous_estimate {
                        req.set_max_response_bytes(new_estimate);
                        return Some(future::ready(()));
                    }
                }
                None
            }
            _ => None,
        }
    }

    fn clone_request(&mut self, req: &Request) -> Option<Request> {
        match req.get_max_response_bytes() {
            Some(max_response_bytes) if max_response_bytes < HTTP_MAX_SIZE => Some(req.clone()),
            // Not having a value is equivalent to setting `max_response_bytes` to the maximum value.
            // If there is a value, it's at least the maximum value.
            // In both cases retrying will not help.
            _ => None,
        }
    }
}
