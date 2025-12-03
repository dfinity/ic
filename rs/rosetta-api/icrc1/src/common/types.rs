use anyhow::Context;
use axum::{Json, http::StatusCode, response::IntoResponse};
use candid::Deserialize;
use num_bigint::BigInt;
use rosetta_core::identifiers::*;
use rosetta_core::objects::*;
use serde::Serialize;
use serde_bytes::ByteBuf;
use strum_macros::Display;
use strum_macros::EnumIter;
use strum_macros::{EnumString, VariantNames};

// Generated from the [Rosetta API specification v1.4.13](https://github.com/coinbase/rosetta-specifications/blob/v1.4.13/api.json)
// Documentation for the Rosetta API can be found at https://www.rosetta-api.org/docs/1.4.13/welcome.html

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct Error(pub rosetta_core::miscellaneous::Error);
const ERROR_CODE_INVALID_NETWORK_ID: u32 = 1;
const ERROR_CODE_UNABLE_TO_FIND_BLOCK: u32 = 2;
const ERROR_CODE_INVALID_BLOCK_IDENTIFIER: u32 = 3;
const ERROR_CODE_FAILED_TO_BUILD_BLOCK_RESPONSE: u32 = 4;
const ERROR_CODE_INVALID_TRANSACTION_IDENTIFIER: u32 = 5;
const ERROR_CODE_MEMPOOL_TRANSACTION_MISSING: u32 = 6;
const ERROR_CODE_PARSING_ERROR: u32 = 7;
const ERROR_CODE_UNSUPPORTED_OPERATION: u32 = 8;
const ERROR_CODE_LEDGER_COMMUNICATION: u32 = 9;
const ERROR_CODE_REQUEST_PROCESSING_ERROR: u32 = 10;
const ERROR_CODE_PROCESSING_CONSTRUCTION_FAILED: u32 = 11;
const ERROR_CODE_INVALID_METADATA: u32 = 12;
const ERROR_CODE_ACCOUNT_BALANCE_NOT_FOUND: u32 = 13;

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(self.0)).into_response()
    }
}
impl From<Error> for rosetta_core::miscellaneous::Error {
    fn from(value: Error) -> Self {
        value.0
    }
}
impl From<rosetta_core::miscellaneous::Error> for Error {
    fn from(value: rosetta_core::miscellaneous::Error) -> Self {
        Error(value)
    }
}

impl From<strum::ParseError> for Error {
    fn from(value: strum::ParseError) -> Self {
        Error::parsing_unsuccessful(&value)
    }
}

impl From<reqwest::Error> for Error {
    fn from(value: reqwest::Error) -> Self {
        Error::request_processing_error(&value)
    }
}

impl Error {
    pub fn invalid_network_id<T: std::fmt::Debug>(description: &T) -> Self {
        Self(rosetta_core::miscellaneous::Error {
            code: ERROR_CODE_INVALID_NETWORK_ID,
            message: "Invalid network identifier".into(),
            description: Some(format!("{description:?}")),
            retriable: false,
            details: None,
        })
    }

    pub fn unable_to_find_block<T: std::fmt::Debug>(description: &T) -> Self {
        Self(rosetta_core::miscellaneous::Error {
            code: ERROR_CODE_UNABLE_TO_FIND_BLOCK,
            message: "Unable to find block".into(),
            description: Some(format!("{description:?}")),
            retriable: false,
            details: None,
        })
    }

    pub fn invalid_block_identifier<T: std::fmt::Debug>(description: &T) -> Self {
        Self(rosetta_core::miscellaneous::Error {
            code: ERROR_CODE_INVALID_BLOCK_IDENTIFIER,
            message: "Invalid block identifier provided".into(),
            description: Some(format!("{description:?}")),
            retriable: false,
            details: None,
        })
    }

    pub fn failed_to_build_block_response<T: std::fmt::Debug>(description: &T) -> Self {
        Self(rosetta_core::miscellaneous::Error {
            code: ERROR_CODE_FAILED_TO_BUILD_BLOCK_RESPONSE,
            message: "Failed to build block response".into(),
            description: Some(format!("{description:?}")),
            retriable: false,
            details: None,
        })
    }

    pub fn invalid_transaction_identifier() -> Self {
        Self(rosetta_core::miscellaneous::Error {
            code: ERROR_CODE_INVALID_TRANSACTION_IDENTIFIER,
            message: "Invalid transaction identifier provided".into(),
            description: Some("Invalid transaction identifier provided.".into()),
            retriable: false,
            details: None,
        })
    }

    pub fn mempool_transaction_missing() -> Self {
        Self(rosetta_core::miscellaneous::Error {
            code: ERROR_CODE_MEMPOOL_TRANSACTION_MISSING,
            message: "Mempool transaction not found".into(),
            description: Some("Mempool transaction not found.".into()),
            retriable: false,
            details: None,
        })
    }

    pub fn parsing_unsuccessful<T: std::fmt::Debug>(description: &T) -> Self {
        Self(rosetta_core::miscellaneous::Error {
            code: ERROR_CODE_PARSING_ERROR,
            message: "Failed trying to parse types.".to_owned(),
            description: Some(format!("{description:?}")),
            retriable: false,
            details: None,
        })
    }

    pub fn unsupported_operation(op_type: OperationType) -> Self {
        Self(rosetta_core::miscellaneous::Error {
            code: ERROR_CODE_UNSUPPORTED_OPERATION,
            message: format!("The operation {op_type} is not supported by ICRC Rosetta."),
            description: None,
            retriable: false,
            details: None,
        })
    }

    pub fn ledger_communication_unsuccessful<T: std::fmt::Debug>(description: &T) -> Self {
        Self(rosetta_core::miscellaneous::Error {
            code: ERROR_CODE_LEDGER_COMMUNICATION,
            message: "Failed to communicate with the icrc1 ledger.".to_owned(),
            description: Some(format!("{description:?}")),
            retriable: false,
            details: None,
        })
    }

    pub fn unable_to_find_account_balance<T: std::fmt::Debug>(description: &T) -> Self {
        Self(rosetta_core::miscellaneous::Error {
            code: ERROR_CODE_ACCOUNT_BALANCE_NOT_FOUND,
            message: "Unable to find account balance.".to_owned(),
            description: Some(format!("{description:?}")),
            retriable: false,
            details: None,
        })
    }

    pub fn request_processing_error<T: std::fmt::Debug>(description: &T) -> Self {
        Self(rosetta_core::miscellaneous::Error {
            code: ERROR_CODE_REQUEST_PROCESSING_ERROR,
            message: "Error while processing the request.".to_owned(),
            description: Some(format!("{description:?}")),
            retriable: false,
            details: None,
        })
    }

    pub fn processing_construction_failed<T: std::fmt::Debug>(description: &T) -> Self {
        Self(rosetta_core::miscellaneous::Error {
            code: ERROR_CODE_PROCESSING_CONSTRUCTION_FAILED,
            message: "Processing of the construction request failed.".to_owned(),
            description: Some(format!("{description:?}")),
            retriable: false,
            details: None,
        })
    }

    pub fn invalid_metadata<T: std::fmt::Debug>(description: &T) -> Self {
        Self(rosetta_core::miscellaneous::Error {
            code: ERROR_CODE_INVALID_METADATA,
            message: "Invalid metadata provided.".to_owned(),
            description: Some(format!("{description:?}")),
            retriable: false,
            details: None,
        })
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Display, EnumIter, EnumString, VariantNames)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum OperationType {
    Mint,
    Burn,
    Transfer,
    Spender,
    Approve,
    Fee,
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct ApproveMetadata {
    pub allowance: Amount,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_allowance: Option<Amount>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

impl TryFrom<ApproveMetadata> for ObjectMap {
    type Error = anyhow::Error;
    fn try_from(d: ApproveMetadata) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(v) => match v {
                serde_json::Value::Object(ob) => Ok(ob),
                _ => anyhow::bail!(
                    "Could not convert ApproveMetadata to ObjectMap. Expected type Object but received: {:?}",
                    v
                ),
            },
            Err(err) => anyhow::bail!("Could not convert ApproveMetadata to ObjectMap: {:?}", err),
        }
    }
}

impl TryFrom<ObjectMap> for ApproveMetadata {
    type Error = anyhow::Error;
    fn try_from(o: ObjectMap) -> anyhow::Result<Self> {
        serde_json::from_value(serde_json::Value::Object(o.clone()))
            .with_context(|| format!("Could not parse ApproveMetadata from Object: {o:?}"))
    }
}

impl TryFrom<Option<ObjectMap>> for ApproveMetadata {
    type Error = anyhow::Error;
    fn try_from(o: Option<ObjectMap>) -> anyhow::Result<Self> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default()))
            .context("Could not parse ApproveMetadata from JSON object")
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct TransactionMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo: Option<ByteBuf>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at_time: Option<u64>,
}

impl TransactionMetadata {
    pub fn is_empty(&self) -> bool {
        self.memo.is_none() && self.created_at_time.is_none()
    }
}

impl TryFrom<TransactionMetadata> for ObjectMap {
    type Error = anyhow::Error;
    fn try_from(d: TransactionMetadata) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(v) => match v {
                serde_json::Value::Object(ob) => Ok(ob),
                _ => anyhow::bail!(
                    "Could not convert TransactionMetadata to ObjectMap. Expected type Object but received: {:?}",
                    v
                ),
            },
            Err(err) => anyhow::bail!(
                "Could not convert TransactionMetadata to ObjectMap: {:?}",
                err
            ),
        }
    }
}

impl TryFrom<Option<ObjectMap>> for TransactionMetadata {
    type Error = anyhow::Error;
    fn try_from(o: Option<ObjectMap>) -> anyhow::Result<Self> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default()))
            .context("Could not parse TransactionMetadata from JSON object")
    }
}

impl From<crate::common::storage::types::IcrcTransaction> for TransactionMetadata {
    fn from(value: crate::common::storage::types::IcrcTransaction) -> Self {
        Self {
            memo: value.memo.map(|memo| memo.0),
            created_at_time: value.created_at_time,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct BlockMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_collector_block_index: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_fee: Option<Amount>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_collector: Option<AccountIdentifier>,
    // The Rosetta API standard field for timestamp is required in milliseconds
    // To ensure a lossless conversion we need to store the nano seconds for the timestamp
    pub block_created_at_nano_seconds: u64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub btype: Option<String>,
}

impl TryFrom<BlockMetadata> for ObjectMap {
    type Error = anyhow::Error;
    fn try_from(d: BlockMetadata) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(v) => match v {
                serde_json::Value::Object(ob) => Ok(ob),
                _ => anyhow::bail!(
                    "Could not convert BlockMetadata to ObjectMap. Expected type Object but received: {:?}",
                    v
                ),
            },
            Err(err) => anyhow::bail!("Could not convert BlockMetadata to ObjectMap: {:?}", err),
        }
    }
}

impl TryFrom<Option<ObjectMap>> for BlockMetadata {
    type Error = anyhow::Error;
    fn try_from(o: Option<ObjectMap>) -> anyhow::Result<Self> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default()))
            .context("Could not parse BlockMetadata from JSON object")
    }
}

impl BlockMetadata {
    pub fn new(
        block: crate::common::storage::types::IcrcBlock,
        currency: Currency,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            fee_collector: block.fee_collector.map(|collector| collector.into()),
            fee_collector_block_index: block.fee_collector_block_index,
            block_created_at_nano_seconds: block.timestamp,
            effective_fee: block
                .effective_fee
                .map(|fee| Amount::new(BigInt::from(fee), currency)),
            btype: block.btype,
        })
    }
}

#[derive(
    Clone, Eq, PartialEq, Debug, Display, Deserialize, EnumIter, EnumString, Serialize, VariantNames,
)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum FeeSetter {
    User,
    Ledger,
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct FeeMetadata {
    pub fee_set_by: FeeSetter,
}

impl TryFrom<FeeMetadata> for ObjectMap {
    type Error = anyhow::Error;
    fn try_from(d: FeeMetadata) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(v) => match v {
                serde_json::Value::Object(ob) => Ok(ob),
                _ => anyhow::bail!(
                    "Could not convert FeeMetadata to ObjectMap. Expected type Object but received: {:?}",
                    v
                ),
            },
            Err(err) => anyhow::bail!("Could not convert FeeMetadata to ObjectMap: {:?}", err),
        }
    }
}

impl TryFrom<ObjectMap> for FeeMetadata {
    type Error = anyhow::Error;
    fn try_from(o: ObjectMap) -> anyhow::Result<Self> {
        serde_json::from_value(serde_json::Value::Object(o))
            .context("Could not parse FeeMetadata from JSON object")
    }
}
