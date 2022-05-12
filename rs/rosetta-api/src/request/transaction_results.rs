use crate::errors::ApiError;
use crate::models::Object;
use crate::request::request_result::RequestResult;
use crate::transaction_id::TransactionIdentifier;
use ledger_canister::BlockHeight;
use serde_json::Value;

use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct TransactionResults {
    pub operations: Vec<RequestResult>,
}

impl TransactionResults {
    pub fn retriable(&self) -> bool {
        self.operations
            .iter()
            .filter_map(|r| r.status.failed())
            .all(|e| e.retriable())
    }

    pub fn last_block_index(&self) -> Option<BlockHeight> {
        self.operations.iter().rev().find_map(|r| r.block_index)
    }

    pub fn last_transaction_id(&self) -> Option<&TransactionIdentifier> {
        self.operations
            .iter()
            .rev()
            .find_map(|r| r.transaction_identifier.as_ref())
    }

    /// Get the last failed Request error.
    /// There should only be one, since `construction_submit` stops
    /// when it encountered an error.
    pub fn error(&self) -> Option<&ApiError> {
        self.operations.iter().rev().find_map(|r| r.status.failed())
    }
}

impl From<&TransactionResults> for Object {
    fn from(d: &TransactionResults) -> Self {
        match serde_json::to_value(d) {
            Ok(Value::Object(o)) => o,
            _ => Object::default(),
        }
    }
}

impl TryFrom<Object> for TransactionResults {
    type Error = ApiError;
    fn try_from(o: Object) -> Result<Self, ApiError> {
        serde_json::from_value(serde_json::Value::Object(o)).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse TransactionResults from Object: {}",
                e
            ))
        })
    }
}

impl From<Vec<RequestResult>> for TransactionResults {
    fn from(operations: Vec<RequestResult>) -> Self {
        Self { operations }
    }
}

impl From<TransactionResults> for Vec<RequestResult> {
    fn from(r: TransactionResults) -> Self {
        r.operations
    }
}
