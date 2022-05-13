use crate::errors::ApiError;
use crate::models::Object;
use crate::request::request_result::{convert_to_request_result_metadata, RequestResult};
use crate::request::transaction_results::TransactionResults;
use crate::request::Request;
use serde_json::Value;

use crate::models::operation::{Operation, OperationType};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct TransactionOperationResults {
    pub operations: Vec<Operation>,
}

impl TransactionOperationResults {
    /// Parse a TransactionOperationResults from a Json object.
    pub fn parse(json: Object) -> Result<Self, ApiError> {
        serde_json::from_value(serde_json::Value::Object(json)).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse TransactionOperationResults from Object: {}",
                e
            ))
        })
    }

    /// Convert TransactionResults to TransactionOperationResults.
    pub fn from_transaction_results(
        tr: TransactionResults,
        token_name: &str,
    ) -> Result<Self, ApiError> {
        let mut operations = Request::requests_to_operations(
            tr.operations
                .iter()
                .map(|rr| rr._type.clone())
                .collect::<Vec<_>>()
                .as_slice(),
            token_name,
        )?;

        let merge_metadata = |o: &mut Operation, rr: &RequestResult| {
            let mut metadata = o.metadata.take().unwrap_or_default();
            let rrmd = convert_to_request_result_metadata(rr);
            let rrmd = Object::from(rrmd);
            for (k, v) in rrmd {
                metadata.insert(k, v);
            }
            // Add optional response data (may contains content from client).
            if let Some(data) = rr.response.clone() {
                for (k, v) in data.into_iter() {
                    metadata.insert(k, v);
                }
            }
            o.metadata = if metadata.is_empty() {
                None
            } else {
                Some(metadata)
            };
            o.status = Some(rr.status.name().to_owned());
        };

        let mut op_idx = 0;
        for rr in tr.operations.iter() {
            match (rr, &mut operations[op_idx..]) {
                (
                    RequestResult {
                        _type: Request::Transfer(ledger_canister::Operation::Transfer { .. }),
                        ..
                    },
                    [withdraw, deposit, fee, ..],
                ) if withdraw._type == OperationType::Transaction
                    && deposit._type == OperationType::Transaction
                    && fee._type == OperationType::Fee =>
                {
                    merge_metadata(withdraw, rr);
                    merge_metadata(deposit, rr);
                    merge_metadata(fee, rr);
                    op_idx += 3;
                }
                (rr, [o, ..]) => {
                    merge_metadata(o, rr);
                    op_idx += 1
                }
                _ => {
                    return Err(ApiError::internal_error(format!(
                        "Too few Operations, could not match requests with operations.\n{}\n\n{}",
                        serde_json::to_string(&tr.operations).unwrap(),
                        serde_json::to_string(&operations).unwrap()
                    )))
                }
            };
        }

        Ok(TransactionOperationResults { operations })
    }
}

impl From<TransactionOperationResults> for Object {
    fn from(d: TransactionOperationResults) -> Self {
        match serde_json::to_value(d) {
            Ok(Value::Object(o)) => o,
            _ => Object::default(),
        }
    }
}

impl From<&TransactionOperationResults> for Object {
    fn from(d: &TransactionOperationResults) -> Self {
        match serde_json::to_value(d) {
            Ok(Value::Object(o)) => o,
            _ => Object::default(),
        }
    }
}
