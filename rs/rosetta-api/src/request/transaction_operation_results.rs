use crate::errors::ApiError;
use crate::request::request_result::{convert_to_request_result_metadata, RequestResult};
use crate::request::transaction_results::TransactionResults;
use crate::request::Request;
use rosetta_core::objects::ObjectMap;
use serde_json::Value;

use crate::models::operation::OperationType;
use crate::models::Operation;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TransactionOperationResults {
    pub operations: Vec<Operation>,
}

impl TryFrom<Option<ObjectMap>> for TransactionOperationResults {
    type Error = ApiError;
    fn try_from(o: Option<ObjectMap>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse TransactionOperationResults metadata from metadata JSON object: {}",
                e
            ))
        })
    }
}

impl From<&TransactionOperationResults> for ObjectMap {
    fn from(d: &TransactionOperationResults) -> Self {
        match serde_json::to_value(d) {
            Ok(Value::Object(o)) => o,
            _ => ObjectMap::default(),
        }
    }
}

impl TransactionOperationResults {
    /// Parse a TransactionOperationResults from a Json object.
    pub fn parse(json: ObjectMap) -> Result<Self, ApiError> {
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

        let merge_metadata = |o: &mut Operation, rr: &RequestResult| -> Result<(), ApiError> {
            let mut metadata = o.metadata.take().unwrap_or_default();
            let rrmd = convert_to_request_result_metadata(rr);
            let rrmd = ObjectMap::try_from(rrmd)?;
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
            Ok(())
        };

        let mut op_idx = 0;
        for rr in tr.operations.iter() {
            match (rr, &mut operations[op_idx..]) {
                (
                    RequestResult {
                        _type: Request::Transfer(icp_ledger::Operation::Transfer { .. }),
                        ..
                    },
                    [withdraw, deposit, fee, ..],
                ) if withdraw.type_.parse::<OperationType>()? == OperationType::Transaction
                    && deposit.type_.parse::<OperationType>()? == OperationType::Transaction
                    && fee.type_.parse::<OperationType>()? == OperationType::Fee =>
                {
                    merge_metadata(withdraw, rr)?;
                    merge_metadata(deposit, rr)?;
                    merge_metadata(fee, rr)?;
                    op_idx += 3;
                }
                (rr, [o, ..]) => {
                    merge_metadata(o, rr)?;
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
