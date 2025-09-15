use crate::request::transaction_operation_results::TransactionOperationResults;
use crate::request::transaction_results::TransactionResults;
use crate::{convert, models::Error};
use rosetta_core::objects::ObjectMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::convert::TryFrom;
use std::num::TryFromIntError;

use ic_ledger_canister_blocks_synchronizer::blocks::BlockStoreError;

/// Each Rosetta `Error` has a "retriable" flag and optional "details"
/// Rosetta error code and message are determined by the `ApiError` variant.
///
/// When a variant is missing a "retriable" boolean it's variant is never
/// retriable.
///
/// When adding a new variant make sure to update `network_options`, and the
/// `From<Error>`.
///
/// When possible, prefer an inner type for your variant.
/// Then add a `From<ApiError>` instance to allow `?` to convert
/// your specific error to a general `ApiError`.
/// See `ICError` for an example of this pattern.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub enum ApiError {
    InternalError(bool, Details),
    InvalidRequest(bool, Details),
    InvalidNetworkId(bool, Details),
    InvalidAccountId(bool, Details),
    InvalidBlockId(bool, Details),
    InvalidPublicKey(bool, Details),
    InvalidTransactionId(bool, Details),
    MempoolTransactionMissing(bool, Details),
    BlockchainEmpty(bool, Details),
    InvalidTransaction(bool, Details),
    NotAvailableOffline(bool, Details),
    ICError(ICError),
    TransactionRejected(bool, Details),
    TransactionExpired,
    OperationsErrors(TransactionResults, String),
    InvalidTipOfChain(Details),
}

impl ApiError {
    pub fn retriable(&self) -> bool {
        match self {
            ApiError::InternalError(r, _)
            | ApiError::InvalidRequest(r, _)
            | ApiError::InvalidNetworkId(r, _)
            | ApiError::InvalidAccountId(r, _)
            | ApiError::InvalidBlockId(r, _)
            | ApiError::InvalidPublicKey(r, _)
            | ApiError::InvalidTransactionId(r, _)
            | ApiError::MempoolTransactionMissing(r, _)
            | ApiError::BlockchainEmpty(r, _)
            | ApiError::InvalidTransaction(r, _)
            | ApiError::NotAvailableOffline(r, _)
            | ApiError::ICError(ICError { retriable: r, .. })
            | ApiError::TransactionRejected(r, _) => *r,
            ApiError::OperationsErrors(e, _) => e.retriable(),
            ApiError::TransactionExpired => false,
            ApiError::InvalidTipOfChain(_) => false,
        }
    }

    pub fn is_internal_error_403(&self) -> bool {
        if let ApiError::InternalError(
            _,
            Details {
                error_message: Some(e),
                ..
            },
        ) = self
        {
            e.contains("status: 403")
        } else {
            false
        }
    }

    /// A convenience function for creating a non retriable internal error.
    pub fn internal_error<T: Into<Details>>(t: T) -> ApiError {
        ApiError::InternalError(false, t.into())
    }

    pub fn invalid_request<T: Into<Details>>(t: T) -> ApiError {
        ApiError::InvalidRequest(false, t.into())
    }

    pub fn invalid_block_id<T: Into<Details>>(t: T) -> ApiError {
        ApiError::InvalidBlockId(false, t.into())
    }

    pub fn invalid_account_id<T: Into<Details>>(t: T) -> ApiError {
        ApiError::InvalidAccountId(false, t.into())
    }

    pub fn invalid_tip_of_chain<T: Into<Details>>(t: T) -> ApiError {
        ApiError::InvalidTipOfChain(t.into())
    }

    pub fn invalid_transaction<T: Into<Details>>(t: T) -> ApiError {
        ApiError::InvalidTransaction(false, t.into())
    }
}

impl From<BlockStoreError> for ApiError {
    fn from(e: BlockStoreError) -> Self {
        match e {
            BlockStoreError::NotFound(idx) => {
                ApiError::invalid_block_id(format!("Block not found: {idx}"))
            }
            BlockStoreError::NotAvailable(idx) => {
                ApiError::invalid_block_id(format!("Block not available for query: {idx}"))
            }
            BlockStoreError::Other(msg) => ApiError::internal_error(msg),
        }
    }
}

impl From<ic_ledger_canister_blocks_synchronizer::errors::Error> for ApiError {
    fn from(e: ic_ledger_canister_blocks_synchronizer::errors::Error) -> Self {
        use ic_ledger_canister_blocks_synchronizer::errors::Error;
        match e {
            Error::InvalidBlockId(err) => ApiError::invalid_block_id(err),
            Error::InternalError(err) => ApiError::internal_error(err),
            Error::InvalidTipOfChain(err) => ApiError::invalid_tip_of_chain(err),
        }
    }
}

impl From<strum::ParseError> for ApiError {
    fn from(value: strum::ParseError) -> Self {
        ApiError::InternalError(
            false,
            Details::from(format!("Failed to parse string: {value:?}")),
        )
    }
}

impl From<TryFromIntError> for ApiError {
    fn from(value: TryFromIntError) -> Self {
        ApiError::InternalError(
            false,
            Details::from(format!("Failed conversion: {value:?}")),
        )
    }
}

pub fn convert_to_error(api_err: &ApiError) -> Error {
    let (code, msg, retriable, details) = match api_err {
        ApiError::InternalError(r, d) => (700, "Internal server error", *r, d.into()),
        ApiError::InvalidRequest(r, d) => (701, "Invalid request", *r, d.into()),
        ApiError::NotAvailableOffline(r, d) => (702, "Not available in offline mode", *r, d.into()),
        ApiError::InvalidNetworkId(r, d) => (710, "Invalid NetworkId", *r, d.into()),
        ApiError::InvalidAccountId(r, d) => (711, "Account not found", *r, d.into()),
        ApiError::InvalidBlockId(r, d) => (712, "Block not found", *r, d.into()),
        ApiError::InvalidPublicKey(r, d) => (713, "Invalid public key", *r, d.into()),
        ApiError::InvalidTransactionId(r, d) => (714, "Invalid transaction id", *r, d.into()),
        ApiError::MempoolTransactionMissing(r, d) => {
            (720, "Transaction not in the mempool", *r, d.into())
        }
        ApiError::BlockchainEmpty(r, d) => (721, "Blockchain is empty", *r, d.into()),
        ApiError::InvalidTransaction(r, d) => (
            730,
            "An invalid transaction has been detected",
            *r,
            d.into(),
        ),
        ApiError::ICError(e) => (740, "Internet Computer error", e.retriable, e.into()),
        ApiError::TransactionRejected(r, d) => (750, "Transaction rejected", *r, d.into()),
        ApiError::TransactionExpired => (760, "Transaction expired", false, ObjectMap::default()),
        ApiError::OperationsErrors(e, token_name) => {
            match TransactionOperationResults::from_transaction_results(e.clone(), token_name) {
                Ok(o) => (770, "Operation failed", e.retriable(), (&o).into()),
                Err(_) => (
                    700,
                    "Internal server error",
                    false,
                    ObjectMap::from(&Details::from(
                        "Could not convert TransactionResults to TransactionOperationResults",
                    )),
                ),
            }
        }
        ApiError::InvalidTipOfChain(d) => (715, "Invalid tip of the chain", false, d.into()),
    };
    Error(rosetta_core::miscellaneous::Error {
        message: msg.to_string(),
        details: Some(details),
        description: None,
        retriable,
        code,
    })
}

/// Convert an Error to an ApiError.
pub fn convert_to_api_error(err: Error, token_name: &str) -> ApiError {
    match err {
        Error(rosetta_core::miscellaneous::Error {
            code: 700,
            retriable,
            details,
            ..
        }) => ApiError::InternalError(retriable, details.unwrap_or_default().into()),
        Error(rosetta_core::miscellaneous::Error {
            code: 701,
            retriable,
            details,
            ..
        }) => ApiError::InvalidRequest(retriable, details.unwrap_or_default().into()),
        Error(rosetta_core::miscellaneous::Error {
            code: 702,
            retriable,
            details,
            ..
        }) => ApiError::NotAvailableOffline(retriable, details.unwrap_or_default().into()),
        Error(rosetta_core::miscellaneous::Error {
            code: 710,
            retriable,
            details,
            ..
        }) => ApiError::InvalidNetworkId(retriable, details.unwrap_or_default().into()),
        Error(rosetta_core::miscellaneous::Error {
            code: 711,
            retriable,
            details,
            ..
        }) => ApiError::InvalidAccountId(retriable, details.unwrap_or_default().into()),
        Error(rosetta_core::miscellaneous::Error {
            code: 712,
            retriable,
            details,
            ..
        }) => ApiError::InvalidBlockId(retriable, details.unwrap_or_default().into()),
        Error(rosetta_core::miscellaneous::Error {
            code: 713,
            retriable,
            details,
            ..
        }) => ApiError::InvalidPublicKey(retriable, details.unwrap_or_default().into()),
        Error(rosetta_core::miscellaneous::Error {
            code: 714,
            retriable,
            details,
            ..
        }) => ApiError::InvalidTransactionId(retriable, details.unwrap_or_default().into()),
        Error(rosetta_core::miscellaneous::Error {
            code: 720,
            retriable,
            details,
            ..
        }) => ApiError::MempoolTransactionMissing(retriable, details.unwrap_or_default().into()),
        Error(rosetta_core::miscellaneous::Error {
            code: 721,
            retriable,
            details,
            ..
        }) => ApiError::BlockchainEmpty(retriable, details.unwrap_or_default().into()),
        Error(rosetta_core::miscellaneous::Error {
            code: 730,
            retriable,
            details,
            ..
        }) => ApiError::InvalidTransaction(retriable, details.unwrap_or_default().into()),
        Error(rosetta_core::miscellaneous::Error {
            code: 740,
            retriable,
            details,
            ..
        }) => match ICError::try_from(details) {
            Ok(mut e) => {
                e.retriable = retriable;
                ApiError::ICError(e)
            }
            Err(e) => e,
        },
        Error(rosetta_core::miscellaneous::Error {
            code: 750,
            retriable,
            details,
            ..
        }) => ApiError::TransactionRejected(retriable, details.unwrap_or_default().into()),
        Error(rosetta_core::miscellaneous::Error { code: 760, .. }) => ApiError::TransactionExpired,
        Error(rosetta_core::miscellaneous::Error {
            code: 770, details, ..
        }) => match details.map(TransactionOperationResults::parse) {
            Some(Ok(e)) => convert::transaction_operation_result_to_api_error(e, token_name),
            Some(Err(e)) => e,
            None => ApiError::internal_error("OperationsErrors missing details object"),
        },
        e => ApiError::internal_error(format!(
            "Unknown error code encountered when converting RosettaError to ApiError: {e:?}"
        )),
    }
}

impl From<rosetta_core::miscellaneous::Error> for ApiError {
    fn from(err: rosetta_core::miscellaneous::Error) -> Self {
        convert_to_api_error(crate::models::Error(err), crate::DEFAULT_TOKEN_SYMBOL)
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Default, Deserialize, Serialize)]
pub struct ICError {
    #[serde(skip)]
    pub retriable: bool,
    pub error_message: String,
    pub ic_http_status: u16,
}

impl From<ICError> for ApiError {
    fn from(e: ICError) -> Self {
        ApiError::ICError(e)
    }
}

impl From<&ICError> for ObjectMap {
    fn from(e: &ICError) -> Self {
        match serde_json::to_value(e) {
            Ok(Value::Object(o)) => o,
            _ => ObjectMap::default(),
        }
    }
}

impl TryFrom<Option<ObjectMap>> for ICError {
    type Error = ApiError;

    fn try_from(o: Option<ObjectMap>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse ICError from details JSON object: {e}"
            ))
        })
    }
}

/// A arbitrary JSON object passed to `RosettaError`.
/// More specific error variants should be preferred.
#[derive(Clone, Eq, PartialEq, Debug, Default, Deserialize, Serialize)]
pub struct Details {
    /// An extra, more detailed error message.
    /// This is distinct from Rosetta `Error.message`.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    error_message: Option<String>,
    /// Arbitrary fields that will be included in the details object.
    /// The entries will be flattened when serializing.
    #[serde(flatten)]
    extra_fields: ObjectMap,
}

impl From<anyhow::Error> for Details {
    fn from(value: anyhow::Error) -> Self {
        Details::from(format!("{value:?}"))
    }
}
#[test]
fn details_serde_test() {
    let a_ser = r#"{"error_message":"foo","bar":{"bazz":1}}"#;
    let a: Details = serde_json::from_str(a_ser).unwrap();
    let b = Details {
        error_message: Some("foo".into()),
        extra_fields: std::iter::once((
            "bar".to_owned(),
            std::iter::once(("bazz".to_owned(), Value::from(1))).collect(),
        ))
        .collect(),
    };
    let b_ser = serde_json::to_string(&b).unwrap();

    assert_eq!(a, b);
    assert_eq!(a_ser, b_ser);
}

impl From<&str> for Details {
    fn from(error_message: &str) -> Self {
        Self {
            error_message: Some(error_message.to_owned()),
            extra_fields: ObjectMap::default(),
        }
    }
}

impl From<String> for Details {
    fn from(error_message: String) -> Self {
        Self {
            error_message: Some(error_message),
            extra_fields: ObjectMap::default(),
        }
    }
}

impl From<&Details> for ObjectMap {
    fn from(d: &Details) -> Self {
        match serde_json::to_value(d) {
            Ok(Value::Object(o)) => o,
            _ => ObjectMap::default(),
        }
    }
}

impl From<ObjectMap> for Details {
    fn from(o: ObjectMap) -> Self {
        serde_json::from_value(serde_json::Value::Object(o))
            .ok()
            .unwrap_or_default()
    }
}

#[test]
fn to_from_details_test() {
    let d = Details {
        error_message: Some("foo".to_owned()),
        extra_fields: ObjectMap::default(),
    };
    let o: ObjectMap = (&d).into();
    assert_eq!(d, o.into());
}
