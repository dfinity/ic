#[cfg(test)]
mod tests;

#[cfg(feature = "alloy")]
mod alloy;

use crate::RpcService;
use candid::{CandidType, Deserialize};
use ic_error_types::RejectCode;
use std::fmt::Debug;
use thiserror::Error;

pub type RpcResult<T> = Result<T, RpcError>;

#[derive(Clone, Debug, Eq, PartialEq, CandidType, Deserialize)]
pub enum MultiRpcResult<T> {
    Consistent(RpcResult<T>),
    Inconsistent(Vec<(RpcService, RpcResult<T>)>),
}

impl<T> MultiRpcResult<T> {
    /// Maps a [`MultiRpcResult`] containing values of type `T` to a [`MultiRpcResult`] containing
    /// values of type `R` by an infallible map.
    pub fn map<R: PartialEq>(self, mut f: impl FnMut(T) -> R) -> MultiRpcResult<R> {
        match self {
            MultiRpcResult::Consistent(result) => MultiRpcResult::Consistent(result.map(f)),
            MultiRpcResult::Inconsistent(results) => MultiRpcResult::Inconsistent(
                results
                    .into_iter()
                    .map(|(service, result)| {
                        (
                            service,
                            match result {
                                Ok(ok) => Ok(f(ok)),
                                Err(err) => Err(err),
                            },
                        )
                    })
                    .collect(),
            )
            .collapse(),
        }
    }

    /// Maps a [`MultiRpcResult`] containing values of type `T` to a [`MultiRpcResult`] containing
    /// values of type `R` by a fallible map.
    pub fn and_then<R: PartialEq>(self, mut f: impl FnMut(T) -> RpcResult<R>) -> MultiRpcResult<R> {
        match self {
            MultiRpcResult::Consistent(result) => MultiRpcResult::Consistent(result.and_then(f)),
            MultiRpcResult::Inconsistent(results) => MultiRpcResult::Inconsistent(
                results
                    .into_iter()
                    .map(|(service, result)| {
                        (
                            service,
                            match result {
                                Ok(ok) => f(ok),
                                Err(err) => Err(err),
                            },
                        )
                    })
                    .collect(),
            )
            .collapse(),
        }
    }
}

impl<T: PartialEq> MultiRpcResult<T> {
    /// Collapses an [`Inconsistent`](MultiRpcResult::Inconsistent) into
    /// [`Consistent`](MultiRpcResult::Consistent) if all results match.
    /// Otherwise, returns the value unchanged.
    fn collapse(self) -> MultiRpcResult<T> {
        match self {
            MultiRpcResult::Consistent(r) => MultiRpcResult::Consistent(r),
            MultiRpcResult::Inconsistent(v) => {
                if let Some((_, first)) = v.first() {
                    if v.iter().all(|(_, result)| result == first) {
                        let (_, value) = v.into_iter().next().unwrap();
                        return MultiRpcResult::Consistent(value);
                    }
                }
                MultiRpcResult::Inconsistent(v)
            }
        }
    }
}

impl<T: Debug> MultiRpcResult<T> {
    pub fn expect_consistent(self) -> RpcResult<T> {
        match self {
            MultiRpcResult::Consistent(result) => result,
            MultiRpcResult::Inconsistent(inconsistent_result) => {
                panic!("Expected consistent, but got: {:?}", inconsistent_result)
            }
        }
    }

    pub fn expect_inconsistent(self) -> Vec<(RpcService, RpcResult<T>)> {
        match self {
            MultiRpcResult::Consistent(consistent_result) => {
                panic!("Expected inconsistent:, but got: {:?}", consistent_result)
            }
            MultiRpcResult::Inconsistent(results) => results,
        }
    }
}

impl<T> From<RpcResult<T>> for MultiRpcResult<T> {
    fn from(result: RpcResult<T>) -> Self {
        MultiRpcResult::Consistent(result)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, CandidType, Deserialize, Error)]
pub enum RpcError {
    #[error("Provider error: {0}")]
    ProviderError(ProviderError),
    #[error("HTTP outcall error: {0}")]
    HttpOutcallError(HttpOutcallError),
    #[error("JSON-RPC error: {0}")]
    JsonRpcError(JsonRpcError),
    #[error("Validation error: {0}")]
    ValidationError(ValidationError),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, CandidType, Deserialize, Error)]
pub enum ProviderError {
    #[error("No permission to call this provider")]
    NoPermission,
    #[error("Not enough cycles, expected {expected}, received {received}")]
    TooFewCycles { expected: u128, received: u128 },
    #[error("Provider not found")]
    ProviderNotFound,
    #[error("Missing required provider")]
    MissingRequiredProvider,
    #[error("Invalid RPC config: {0}")]
    InvalidRpcConfig(String),
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, CandidType, Deserialize, Error)]
pub enum HttpOutcallError {
    /// Error from the IC system API.
    #[error("IC error (code: {code:?}): {message}")]
    IcError {
        code: LegacyRejectionCode,
        message: String,
    },
    /// Response is not a valid JSON-RPC response,
    /// which means that the response was not successful (status other than 2xx)
    /// or that the response body could not be deserialized into a JSON-RPC response.
    #[error("Invalid HTTP JSON-RPC response: status {status}, body: {body}, parsing error: {parsing_error:?}")]
    InvalidHttpJsonRpcResponse {
        status: u16,
        body: String,
        #[serde(rename = "parsingError")]
        parsing_error: Option<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, CandidType, Deserialize, Error)]
#[error("JSON-RPC error (code: {code}): {message}")]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, CandidType, Deserialize, Error)]
pub enum ValidationError {
    #[error("Custom: {0}")]
    Custom(String),
    #[error("Invalid hex: {0}")]
    InvalidHex(String),
}

impl From<ProviderError> for RpcError {
    fn from(err: ProviderError) -> Self {
        RpcError::ProviderError(err)
    }
}

impl From<HttpOutcallError> for RpcError {
    fn from(err: HttpOutcallError) -> Self {
        RpcError::HttpOutcallError(err)
    }
}

impl From<JsonRpcError> for RpcError {
    fn from(err: JsonRpcError) -> Self {
        RpcError::JsonRpcError(err)
    }
}

impl From<ValidationError> for RpcError {
    fn from(err: ValidationError) -> Self {
        RpcError::ValidationError(err)
    }
}

/// Rejection code from calling another canister.
///
/// This implementation was [copied](https://github.com/dfinity/cdk-rs/blob/83ba5fc7b3316a6fa4e7f704b689c95c9e677029/src/ic-cdk/src/api/call.rs#L21) from ic-cdk v0.17.
///
/// The `ic_cdk::api::call::RejectionCode` type is deprecated since ic-cdk v0.18.
/// The replacement `ic_cdk::call::RejectCode` re-exports the type defined in the `ic-error-types` crate.
/// We cannot simply switch to the replacement because the existing `RejectionCode` is a public type in evm_rpc canister's interface.
/// To maintain compatibility, we retain the "outdated" definition here.
#[allow(missing_docs)]
#[repr(i32)]
#[derive(CandidType, Deserialize, Clone, Copy, Hash, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename = "RejectionCode")]
pub enum LegacyRejectionCode {
    NoError = 0,

    SysFatal = 1,
    SysTransient = 2,
    DestinationInvalid = 3,
    CanisterReject = 4,
    CanisterError = 5,

    Unknown,
}

impl From<RejectCode> for LegacyRejectionCode {
    fn from(value: RejectCode) -> Self {
        match value {
            RejectCode::SysFatal => Self::SysFatal,
            RejectCode::SysTransient => Self::SysTransient,
            RejectCode::DestinationInvalid => Self::DestinationInvalid,
            RejectCode::CanisterReject => Self::CanisterReject,
            RejectCode::CanisterError => Self::CanisterError,
            RejectCode::SysUnknown => Self::Unknown,
        }
    }
}

impl From<u32> for LegacyRejectionCode {
    fn from(value: u32) -> Self {
        match value {
            1 => LegacyRejectionCode::SysFatal,
            2 => LegacyRejectionCode::SysTransient,
            3 => LegacyRejectionCode::DestinationInvalid,
            4 => LegacyRejectionCode::CanisterReject,
            5 => LegacyRejectionCode::CanisterError,
            _ => LegacyRejectionCode::Unknown,
        }
    }
}
