//! Middleware to add an HTTP translation layer.
//!
//! Transforms a low-level service that uses Candid types ([`IcHttpRequest`] and [`IcHttpResponse`])
//! into one that uses types from the [http](https://crates.io/crates/http) crate.
//!
//! ```text
//!              │                     ▲              
//! http::Request│                     │http::Response
//!            ┌─┴─────────────────────┴───┐          
//!            │   HttpResponseConverter   │
//!            └─┬─────────────────────▲───┘          
//!              │                     │              
//!            ┌─▼─────────────────────┴───┐          
//!            │    HttpRequestConverter   │          
//!            └─┬─────────────────────┬───┘          
//! IcHttpRequest│                     │IcHttpResponse
//!              ▼                     │              
//!            ┌─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┐
//!            │          SERVICE          │
//!            └─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┘
//! ```
//!
//! This brings several advantages:
//!
//! * Can re-use existing types like [`http::request::Builder`] or [`http::StatusCode`].
//! * Requests are automatically sanitized and canonicalized (e.g. header names are validated and lower cased).
//! * Can re-use existing middlewares, like from the [tower-http](https://crates.io/crates/tower-http) crate.
//!
//! # Examples
//!
//! ```rust
//! use canhttp::{http::{HttpConversionLayer }, MaxResponseBytesRequestExtension};
//! use ic_cdk::management_canister::{HttpRequestArgs as IcHttpRequest, HttpRequestResult as IcHttpResponse};
//! use tower::{Service, ServiceBuilder, ServiceExt, BoxError};
//!
//! async fn always_200_ok(request: IcHttpRequest) -> Result<IcHttpResponse, BoxError> {
//!    Ok(IcHttpResponse {
//!      status: 200_u8.into(),
//!      ..Default::default()
//!    })
//! }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut service = ServiceBuilder::new()
//!   .layer(HttpConversionLayer)
//!   .service_fn(always_200_ok);
//!
//! let request = http::Request::post("https://internetcomputer.org")
//!   .max_response_bytes(42) //IC-specific concepts are added to the request as extensions.
//!   .header("Content-Type", "application/json")
//!   .body(vec![])
//!   .unwrap();
//!
//! let response = service.ready().await.unwrap().call(request).await.unwrap();
//!
//! assert_eq!(response.status(), http::StatusCode::OK);
//! # Ok(())
//! # }
//! ```
//!
//! [`IcHttpRequest`]: ic_cdk::management_canister::HttpRequestArgs
//! [`IcHttpResponse`]: ic_cdk::management_canister::HttpRequestResult

#[cfg(test)]
mod tests;

pub use request::{HttpRequest, HttpRequestConversionError, HttpRequestConverter};
pub use response::{
    FilterNonSuccessfulHttpResponse, FilterNonSuccessfulHttpResponseError, HttpResponse,
    HttpResponseConversionError, HttpResponseConverter,
};

#[cfg(feature = "json")]
pub mod json;
mod request;
mod response;

use crate::convert::{ConvertRequest, ConvertRequestLayer, ConvertResponse, ConvertResponseLayer};
use tower::Layer;

/// Middleware that combines [`HttpRequestConverter`] to convert requests
/// and [`HttpResponseConverter`] to convert responses to a [`Service`].
///
/// See the [module docs](crate::http) for an example.
///
/// [`Service`]: tower::Service
pub struct HttpConversionLayer;

impl<S> Layer<S> for HttpConversionLayer {
    type Service = ConvertResponse<ConvertRequest<S, HttpRequestConverter>, HttpResponseConverter>;

    fn layer(&self, inner: S) -> Self::Service {
        let stack = tower_layer::Stack::new(
            ConvertRequestLayer::new(HttpRequestConverter),
            ConvertResponseLayer::new(HttpResponseConverter),
        );
        stack.layer(inner)
    }
}
