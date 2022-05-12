use crate::models::Object;
use crate::request::Request;
use crate::request_types::{RequestResultMetadata, Status};
use crate::transaction_id::TransactionIdentifier;
use ledger_canister::BlockHeight;

use crate::errors;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct RequestResult {
    #[serde(rename = "type")]
    pub _type: Request,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub block_index: Option<BlockHeight>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub neuron_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub transaction_identifier: Option<TransactionIdentifier>,
    #[serde(flatten)]
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub response: Option<Object>,
}

pub fn convert_to_request_result_metadata(rr: &RequestResult) -> RequestResultMetadata {
    RequestResultMetadata {
        block_index: rr.block_index,
        neuron_id: rr.neuron_id,
        transaction_identifier: rr.transaction_identifier.clone(),
        response: rr.status.failed().map(errors::convert_to_error),
    }
}
