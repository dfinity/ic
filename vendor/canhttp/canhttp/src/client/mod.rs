#[cfg(test)]
mod tests;

use crate::{convert::ConvertError, ConvertServiceBuilder};
use ic_cdk::call::Error as IcCdkError;
use ic_cdk::management_canister::{
    HttpRequestArgs as IcHttpRequest, HttpRequestResult as IcHttpResponse, TransformContext,
};
use ic_error_types::RejectCode;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use thiserror::Error;
use tower::{BoxError, Service, ServiceBuilder};
use tower_layer::Layer;

/// Thin wrapper around [`ic_cdk::management_canister::http_request`] that implements the
/// [`tower::Service`] trait. Its functionality can be extended by composing so-called
/// [tower middlewares](https://docs.rs/tower/latest/tower/#usage).
///
/// Middlewares from this crate:
/// * [`crate::cycles::CyclesAccounting`]: handles cycles accounting.
/// * [`crate::observability`]: add logging or metrics.
/// * [`crate::http`]: use types from the [http](https://crates.io/crates/http) crate for requests and responses.
/// * [`crate::retry::DoubleMaxResponseBytes`]: automatically retry failed requests due to the response being too big.
#[derive(Clone, Debug)]
pub struct Client;

impl Client {
    /// Create a new client returning custom errors.
    pub fn new_with_error<CustomError: From<IcError>>() -> ConvertError<Client, CustomError> {
        ServiceBuilder::new()
            .convert_error::<CustomError>()
            .service(Client)
    }

    /// Creates a new client where the error type is erased.
    pub fn new_with_box_error() -> ConvertError<Client, BoxError> {
        Self::new_with_error::<BoxError>()
    }
}

/// Error returned by the Internet Computer when making an HTTPs outcall.
#[derive(Error, Clone, Debug, PartialEq, Eq)]
pub enum IcError {
    /// The inter-canister call is rejected.
    ///
    /// Note that [`ic_cdk::call::Error::CallPerformFailed`] errors are also mapped to this variant
    /// with an [`ic_error_types::RejectCode::SysFatal`] error code.
    #[error("Error from ICP: (code {code:?}, message {message})")]
    CallRejected {
        /// Rejection code as specified [here](https://internetcomputer.org/docs/current/references/ic-interface-spec#reject-codes)
        code: RejectCode,
        /// Associated helper message.
        message: String,
    },
    /// The liquid cycle balance is insufficient to perform the call.
    #[error("Insufficient liquid cycles balance, available: {available}, required: {required}")]
    InsufficientLiquidCycleBalance {
        /// The liquid cycle balance available in the canister.
        available: u128,
        /// The required cycles to perform the call.
        required: u128,
    },
}

impl Service<IcHttpRequest> for Client {
    type Response = IcHttpResponse;
    type Error = IcError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: IcHttpRequest) -> Self::Future {
        fn convert_error(error: IcCdkError) -> IcError {
            match error {
                IcCdkError::CallRejected(e) => {
                    IcError::CallRejected {
                        // `CallRejected::reject_code()` can only return an error result if there is a
                        // new error code on ICP that the CDK is not aware of. We map it to `SysFatal`
                        // since none of the other error codes apply.
                        // In particular, note that `RejectCode::SysUnknown` is only applicable to
                        // inter-canister calls that used `ic0.call_with_best_effort_response`.
                        code: e.reject_code().unwrap_or(RejectCode::SysFatal),
                        message: e.reject_message().to_string(),
                    }
                }
                IcCdkError::CallPerformFailed(e) => {
                    IcError::CallRejected {
                        // This error indicates that the `ic0.call_perform` system API returned a non-zero code.
                        // The only possible non-zero value (2) has the same semantics as `RejectCode::SysFatal`.
                        // See the IC specifications here:
                        // https://internetcomputer.org/docs/references/ic-interface-spec#system-api-call
                        code: RejectCode::SysFatal,
                        message: e.to_string(),
                    }
                }
                IcCdkError::InsufficientLiquidCycleBalance(e) => {
                    IcError::InsufficientLiquidCycleBalance {
                        available: e.available,
                        required: e.required,
                    }
                }
                IcCdkError::CandidDecodeFailed(e) => {
                    // This can only happen if there is a bug in the CDK in the implementation
                    // of `ic_cdk::management_canister::http_request`.
                    panic!("Candid decode failed while performing HTTP outcall: {e}");
                }
            }
        }

        Box::pin(async move {
            ic_cdk::management_canister::http_request(&request)
                .await
                .map_err(convert_error)
        })
    }
}

/// Add support for max response bytes.
pub trait MaxResponseBytesRequestExtension: Sized {
    /// Set the max response bytes.
    ///
    /// If provided, the value must not exceed 2MB (2_000_000B).
    /// The call will be charged based on this parameter.
    /// If not provided, the maximum of 2MB will be used.
    fn set_max_response_bytes(&mut self, value: u64);

    /// Retrieves the current max response bytes value, if any.
    fn get_max_response_bytes(&self) -> Option<u64>;

    /// Convenience method to use the builder pattern.
    fn max_response_bytes(mut self, value: u64) -> Self {
        self.set_max_response_bytes(value);
        self
    }
}

impl MaxResponseBytesRequestExtension for IcHttpRequest {
    fn set_max_response_bytes(&mut self, value: u64) {
        self.max_response_bytes = Some(value);
    }

    fn get_max_response_bytes(&self) -> Option<u64> {
        self.max_response_bytes
    }
}

/// Add support for transform context to specify how the response will be canonicalized by the replica
/// to maximize chances of consensus.
///
/// See the [docs](https://internetcomputer.org/docs/references/https-outcalls-how-it-works#transformation-function)
/// on HTTPs outcalls for more details.
pub trait TransformContextRequestExtension: Sized {
    /// Set the transform context.
    fn set_transform_context(&mut self, value: TransformContext);

    /// Retrieve the current transform context, if any.
    fn get_transform_context(&self) -> Option<&TransformContext>;

    /// Convenience method to use the builder pattern.
    fn transform_context(mut self, value: TransformContext) -> Self {
        self.set_transform_context(value);
        self
    }
}

impl TransformContextRequestExtension for IcHttpRequest {
    fn set_transform_context(&mut self, value: TransformContext) {
        self.transform = Some(value);
    }

    fn get_transform_context(&self) -> Option<&TransformContext> {
        self.transform.as_ref()
    }
}

/// Add support for selecting replicated or non-replicated HTTP outcalls.
///
/// Warning: non-replicated outcalls are currently experimental.
/// See the [docs](https://docs.internetcomputer.org/references/ic-interface-spec/#ic-http_request) for more ditails.
pub trait IsReplicatedRequestExtension: Sized {
    /// Set the request replication mode.
    fn set_is_replicated(&mut self, value: bool);

    /// Returns the replication mode of the request, if explicitly set.
    fn get_is_replicated(&self) -> Option<bool>;

    /// Sets the replication mode using the builder pattern.
    fn replicated(mut self, value: bool) -> Self {
        self.set_is_replicated(value);
        self
    }
}

impl IsReplicatedRequestExtension for IcHttpRequest {
    fn set_is_replicated(&mut self, value: bool) {
        self.is_replicated = Some(value);
    }

    fn get_is_replicated(&self) -> Option<bool> {
        self.is_replicated
    }
}

/// Characterize errors that are specific to HTTPs outcalls.
pub trait HttpsOutcallError {
    /// Determines whether the error indicates that the response was larger than the specified
    /// [`max_response_bytes`](https://internetcomputer.org/docs/current/references/ic-interface-spec#ic-http_request) specified in the request.
    ///
    /// If true, retrying with a larger value for `max_response_bytes` may help.
    fn is_response_too_large(&self) -> bool;
}

impl HttpsOutcallError for IcError {
    fn is_response_too_large(&self) -> bool {
        match self {
            IcError::CallRejected { code, message } => {
                code == &RejectCode::SysFatal
                    && (message.contains("size limit") || message.contains("length limit"))
            }
            IcError::InsufficientLiquidCycleBalance { .. } => false,
        }
    }
}

impl HttpsOutcallError for BoxError {
    fn is_response_too_large(&self) -> bool {
        if let Some(ic_error) = self.downcast_ref::<IcError>() {
            return ic_error.is_response_too_large();
        }
        false
    }
}

/// A [`tower::Layer`] that wraps services in a [`CanisterReadyService`] middleware.
#[derive(Clone, Debug, Default)]
pub struct CanisterReadyLayer;

impl<S> Layer<S> for CanisterReadyLayer {
    type Service = CanisterReadyService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Self::Service { inner }
    }
}

/// A [`tower::Service`] that checks that the canister is running before calling the inner service.
///
/// This is useful to prevent the canister making new HTTPs outcalls when it is in the stopping state
/// (see [stop_canister](https://docs.internetcomputer.org/references/ic-interface-spec#ic-stop_canister))
/// and ensure that the canister will be promptly stopped.
pub struct CanisterReadyService<S> {
    inner: S,
}

/// Error returned by the [`CanisterReadyService`].
#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum CanisterReadyError {
    /// Canister is not running and has the given status code.
    #[error("Canister is not running and has status {0}")]
    CanisterNotRunning(u32),
}

impl<S, Req> Service<Req> for CanisterReadyService<S>
where
    S: Service<Req>,
    CanisterReadyError: Into<S::Error>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        use ic_cdk::api::CanisterStatusCode;

        match ic_cdk::api::canister_status() {
            CanisterStatusCode::Running => self.inner.poll_ready(cx),
            status => Poll::Ready(Err(CanisterReadyError::CanisterNotRunning(u32::from(
                status,
            ))
            .into())),
        }
    }

    fn call(&mut self, req: Req) -> Self::Future {
        self.inner.call(req)
    }
}
