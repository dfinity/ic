#[cfg(test)]
mod tests;

use crate::RpcService;
use candid::{CandidType, Deserialize};
use ic_cdk::api::call::RejectionCode;

pub type RpcResult<T> = Result<T, RpcError>;

#[derive(Clone, Debug, Eq, PartialEq, CandidType, Deserialize)]
pub enum MultiRpcResult<T> {
    Consistent(RpcResult<T>),
    Inconsistent(Vec<(RpcService, RpcResult<T>)>),
}

impl<T> MultiRpcResult<T> {
    pub fn map<R>(self, mut f: impl FnMut(T) -> R) -> MultiRpcResult<R> {
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
            ),
        }
    }

    pub fn consistent(self) -> Option<RpcResult<T>> {
        match self {
            MultiRpcResult::Consistent(result) => Some(result),
            MultiRpcResult::Inconsistent(_) => None,
        }
    }

    pub fn inconsistent(self) -> Option<Vec<(RpcService, RpcResult<T>)>> {
        match self {
            MultiRpcResult::Consistent(_) => None,
            MultiRpcResult::Inconsistent(results) => Some(results),
        }
    }

    pub fn expect_consistent(self) -> RpcResult<T> {
        self.consistent().expect("expected consistent results")
    }

    pub fn expect_inconsistent(self) -> Vec<(RpcService, RpcResult<T>)> {
        self.inconsistent().expect("expected inconsistent results")
    }
}

impl<T> From<RpcResult<T>> for MultiRpcResult<T> {
    fn from(result: RpcResult<T>) -> Self {
        MultiRpcResult::Consistent(result)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, CandidType, Deserialize)]
pub enum RpcError {
    ProviderError(ProviderError),
    HttpOutcallError(HttpOutcallError),
    JsonRpcError(JsonRpcError),
    ValidationError(ValidationError),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, CandidType, Deserialize)]
pub enum ProviderError {
    NoPermission,
    TooFewCycles { expected: u128, received: u128 },
    ProviderNotFound,
    MissingRequiredProvider,
    InvalidRpcConfig(String),
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, CandidType, Deserialize)]
pub enum HttpOutcallError {
    /// Error from the IC system API.
    IcError {
        code: RejectionCode,
        message: String,
    },
    /// Response is not a valid JSON-RPC response,
    /// which means that the response was not successful (status other than 2xx)
    /// or that the response body could not be deserialized into a JSON-RPC response.
    InvalidHttpJsonRpcResponse {
        status: u16,
        body: String,
        #[serde(rename = "parsingError")]
        parsing_error: Option<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, CandidType, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, CandidType, Deserialize)]
pub enum ValidationError {
    Custom(String),
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
