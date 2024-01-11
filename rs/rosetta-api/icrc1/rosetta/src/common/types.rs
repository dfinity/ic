use super::storage::types::RosettaToken;
use anyhow::Context;
use axum::{http::StatusCode, response::IntoResponse, Json};
use candid::Deserialize;
use rosetta_core::identifiers::*;
use rosetta_core::objects::*;
use serde::Serialize;
use serde_bytes::ByteBuf;
use strum_macros::Display;
use strum_macros::EnumIter;
use strum_macros::{EnumString, EnumVariantNames};

// Generated from the [Rosetta API specification v1.4.13](https://github.com/coinbase/rosetta-specifications/blob/v1.4.13/api.json)
// Documentation for the Rosetta API can be found at https://www.rosetta-api.org/docs/1.4.13/welcome.html

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
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

impl Error {
    pub fn invalid_network_id<T: std::fmt::Debug>(description: &T) -> Self {
        Self(rosetta_core::miscellaneous::Error {
            code: ERROR_CODE_INVALID_NETWORK_ID,
            message: "Invalid network identifier".into(),
            description: Some(format!("{:?}", description)),
            retriable: false,
            details: None,
        })
    }

    pub fn unable_to_find_block<T: std::fmt::Debug>(description: &T) -> Self {
        Self(rosetta_core::miscellaneous::Error {
            code: ERROR_CODE_UNABLE_TO_FIND_BLOCK,
            message: "Unable to find block".into(),
            description: Some(format!("{:?}", description)),
            retriable: false,
            details: None,
        })
    }

    pub fn invalid_block_identifier<T: std::fmt::Debug>(description: &T) -> Self {
        Self(rosetta_core::miscellaneous::Error {
            code: ERROR_CODE_INVALID_BLOCK_IDENTIFIER,
            message: "Invalid block identifier provided".into(),
            description: Some(format!("{:?}", description)),
            retriable: false,
            details: None,
        })
    }

    pub fn failed_to_build_block_response<T: std::fmt::Debug>(description: &T) -> Self {
        Self(rosetta_core::miscellaneous::Error {
            code: ERROR_CODE_FAILED_TO_BUILD_BLOCK_RESPONSE,
            message: "Failed to build block response".into(),
            description: Some(format!("{:?}", description)),
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
            description: Some(format!("{:?}", description)),
            retriable: false,
            details: None,
        })
    }

    pub fn unsupported_operation(op_type: OperationType) -> Self {
        Self(rosetta_core::miscellaneous::Error {
            code: ERROR_CODE_UNSUPPORTED_OPERATION,
            message: format!(
                "The operation {} is not supported by ICRC Rosetta.",
                op_type
            ),
            description: None,
            retriable: false,
            details: None,
        })
    }

    pub fn ledger_communication_unsuccessful<T: std::fmt::Debug>(description: &T) -> Self {
        Self(rosetta_core::miscellaneous::Error {
            code: ERROR_CODE_LEDGER_COMMUNICATION,
            message: "Failed to communicate with the icrc1 ledger.".to_owned(),
            description: Some(format!("{:?}", description)),
            retriable: false,
            details: None,
        })
    }
}

#[derive(Display, Debug, Clone, PartialEq, Eq, EnumIter, EnumString, EnumVariantNames)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum OperationType {
    Mint,
    Burn,
    Transfer,
    Approve,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ApproveMetadata {
    pub approver_account: AccountIdentifier,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_allowance: Option<Amount>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_set_by_user: Option<Amount>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

impl From<ApproveMetadata> for ObjectMap {
    fn from(m: ApproveMetadata) -> Self {
        match serde_json::to_value(m) {
            Ok(serde_json::Value::Object(o)) => o,
            _ => unreachable!(),
        }
    }
}

impl TryFrom<ObjectMap> for ApproveMetadata {
    type Error = anyhow::Error;
    fn try_from(o: ObjectMap) -> anyhow::Result<Self> {
        serde_json::from_value(serde_json::Value::Object(o.clone()))
            .with_context(|| format!("Could not parse ApproveMetadata from Object: {:?}", o))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct BurnMetadata {
    pub from_account: AccountIdentifier,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub spender_account: Option<AccountIdentifier>,
}

impl From<BurnMetadata> for ObjectMap {
    fn from(m: BurnMetadata) -> Self {
        match serde_json::to_value(m) {
            Ok(serde_json::Value::Object(o)) => o,
            _ => unreachable!(),
        }
    }
}

impl TryFrom<ObjectMap> for BurnMetadata {
    type Error = anyhow::Error;
    fn try_from(o: ObjectMap) -> anyhow::Result<Self> {
        serde_json::from_value(serde_json::Value::Object(o.clone()))
            .with_context(|| format!("Could not parse BurnMetadata from Object: {:?}", o))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct TransferMetadata {
    pub from_account: AccountIdentifier,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub spender_account: Option<AccountIdentifier>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_set_by_user: Option<Amount>,
}

impl From<TransferMetadata> for ObjectMap {
    fn from(m: TransferMetadata) -> Self {
        match serde_json::to_value(m) {
            Ok(serde_json::Value::Object(o)) => o,
            _ => unreachable!(),
        }
    }
}

impl TryFrom<ObjectMap> for TransferMetadata {
    type Error = anyhow::Error;
    fn try_from(o: ObjectMap) -> anyhow::Result<Self> {
        serde_json::from_value(serde_json::Value::Object(o.clone()))
            .with_context(|| format!("Could not parse TransferMetadata from Object: {:?}", o))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
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

impl From<TransactionMetadata> for ObjectMap {
    fn from(m: TransactionMetadata) -> Self {
        match serde_json::to_value(m) {
            Ok(serde_json::Value::Object(o)) => o,
            _ => unreachable!(),
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

impl From<ic_icrc1::Transaction<RosettaToken>> for TransactionMetadata {
    fn from(value: ic_icrc1::Transaction<RosettaToken>) -> Self {
        Self {
            memo: value.memo.map(|memo| memo.0),
            created_at_time: value.created_at_time,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct BlockMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_paid_by_user: Option<Amount>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_collector: Option<AccountIdentifier>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_collector_block_index: Option<u64>,

    // The Rosetta API standard field for timestamp is required in milliseconds
    // To ensure a lossless conversion we need to store the nano seconds for the timestamp
    pub block_created_at_nano_seconds: u64,
}

impl From<BlockMetadata> for ObjectMap {
    fn from(m: BlockMetadata) -> Self {
        match serde_json::to_value(m) {
            Ok(serde_json::Value::Object(o)) => o,
            _ => unreachable!(),
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
    pub fn new(block: ic_icrc1::Block<RosettaToken>, currency: Currency) -> anyhow::Result<Self> {
        Ok(Self {
            fee_paid_by_user: match block.transaction.operation {
                ic_icrc1::Operation::Mint { .. } => None,
                ic_icrc1::Operation::Transfer { fee, .. } => fee.or(block.effective_fee),
                ic_icrc1::Operation::Approve { fee, .. } => fee.or(block.effective_fee),
                ic_icrc1::Operation::Burn { .. } => None,
            }
            .map(|fee| Amount::new(fee.to_string(), currency)),
            fee_collector: block.fee_collector.map(|collector| collector.into()),
            fee_collector_block_index: block.fee_collector_block_index,
            block_created_at_nano_seconds: block.timestamp,
        })
    }
}
