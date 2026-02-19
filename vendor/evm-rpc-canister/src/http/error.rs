use canhttp::{
    cycles::ChargeCallerError,
    http::{
        json::{
            ConsistentResponseIdFilterError, JsonRequestConversionError,
            JsonResponseConversionError,
        },
        FilterNonSuccessfulHttpResponseError, HttpRequestConversionError,
        HttpResponseConversionError,
    },
    HttpsOutcallError, IcError,
};
use evm_rpc_types::{
    HttpOutcallError, LegacyRejectionCode, ProviderError, RpcError, ValidationError,
};
use ic_error_types::RejectCode;
use thiserror::Error;

#[derive(Clone, Debug, Error)]
pub enum HttpClientError {
    #[error("IC error: {0}")]
    IcError(IcError),
    #[error("unknown error (most likely sign of a bug): {0}")]
    NotHandledError(String),
    #[error("cycles accounting error: {0}")]
    CyclesAccountingError(ChargeCallerError),
    #[error("HTTP response was not successful: {0}")]
    UnsuccessfulHttpResponse(FilterNonSuccessfulHttpResponseError<Vec<u8>>),
    #[error("Error converting response to JSON: {0}")]
    InvalidJsonResponse(JsonResponseConversionError),
    #[error("Invalid JSON-RPC response ID: {0}")]
    InvalidJsonResponseId(ConsistentResponseIdFilterError),
}

impl From<IcError> for HttpClientError {
    fn from(value: IcError) -> Self {
        HttpClientError::IcError(value)
    }
}

impl From<HttpResponseConversionError> for HttpClientError {
    fn from(value: HttpResponseConversionError) -> Self {
        // Replica should return valid http::Response
        HttpClientError::NotHandledError(value.to_string())
    }
}

impl From<FilterNonSuccessfulHttpResponseError<Vec<u8>>> for HttpClientError {
    fn from(value: FilterNonSuccessfulHttpResponseError<Vec<u8>>) -> Self {
        HttpClientError::UnsuccessfulHttpResponse(value)
    }
}

impl From<JsonResponseConversionError> for HttpClientError {
    fn from(value: JsonResponseConversionError) -> Self {
        HttpClientError::InvalidJsonResponse(value)
    }
}

impl From<ChargeCallerError> for HttpClientError {
    fn from(value: ChargeCallerError) -> Self {
        HttpClientError::CyclesAccountingError(value)
    }
}

impl From<HttpRequestConversionError> for HttpClientError {
    fn from(value: HttpRequestConversionError) -> Self {
        HttpClientError::NotHandledError(value.to_string())
    }
}

impl From<JsonRequestConversionError> for HttpClientError {
    fn from(value: JsonRequestConversionError) -> Self {
        HttpClientError::NotHandledError(value.to_string())
    }
}

impl From<ConsistentResponseIdFilterError> for HttpClientError {
    fn from(value: ConsistentResponseIdFilterError) -> Self {
        HttpClientError::InvalidJsonResponseId(value)
    }
}

impl HttpsOutcallError for HttpClientError {
    fn is_response_too_large(&self) -> bool {
        match self {
            HttpClientError::IcError(e) => e.is_response_too_large(),
            HttpClientError::NotHandledError(_)
            | HttpClientError::CyclesAccountingError(_)
            | HttpClientError::UnsuccessfulHttpResponse(_)
            | HttpClientError::InvalidJsonResponse(_)
            | HttpClientError::InvalidJsonResponseId(_) => false,
        }
    }
}

impl From<HttpClientError> for RpcError {
    fn from(error: HttpClientError) -> Self {
        match error {
            HttpClientError::IcError(IcError::CallRejected { code, message }) => {
                RpcError::HttpOutcallError(HttpOutcallError::IcError {
                    code: LegacyRejectionCode::from(code),
                    message,
                })
            }
            e @ HttpClientError::IcError(IcError::InsufficientLiquidCycleBalance { .. }) => {
                panic!("{}", e.to_string())
            }
            HttpClientError::NotHandledError(e) => {
                RpcError::ValidationError(ValidationError::Custom(e))
            }
            HttpClientError::CyclesAccountingError(
                ChargeCallerError::InsufficientCyclesError { expected, received },
            ) => RpcError::ProviderError(ProviderError::TooFewCycles { expected, received }),
            HttpClientError::InvalidJsonResponse(
                JsonResponseConversionError::InvalidJsonResponse {
                    status,
                    body,
                    parsing_error,
                },
            ) => RpcError::HttpOutcallError(HttpOutcallError::InvalidHttpJsonRpcResponse {
                status,
                body,
                parsing_error: Some(parsing_error),
            }),
            HttpClientError::UnsuccessfulHttpResponse(
                FilterNonSuccessfulHttpResponseError::UnsuccessfulResponse(response),
            ) => RpcError::HttpOutcallError(HttpOutcallError::InvalidHttpJsonRpcResponse {
                status: response.status().as_u16(),
                body: String::from_utf8_lossy(response.body()).to_string(),
                parsing_error: None,
            }),
            HttpClientError::InvalidJsonResponseId(e) => {
                RpcError::ValidationError(ValidationError::Custom(e.to_string()))
            }
        }
    }
}

pub fn is_consensus_error(error: &IcError) -> bool {
    match error {
        IcError::CallRejected { code, message } => {
            code == &RejectCode::SysTransient && message.to_lowercase().contains("no consensus")
        }
        _ => false,
    }
}
