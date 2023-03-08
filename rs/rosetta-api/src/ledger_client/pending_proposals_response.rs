use crate::{errors::ApiError, models::Object};
use ic_nns_governance::pb::v1::ProposalInfo;
use serde_json::Value;

#[derive(serde::Serialize, serde::Deserialize, std::fmt::Debug, Clone)]
pub struct PendingProposalsResponse {
    pub pending_proposals: Vec<ProposalInfo>,
}
impl From<PendingProposalsResponse> for Object {
    fn from(r: PendingProposalsResponse) -> Self {
        match serde_json::to_value(r) {
            Ok(Value::Object(o)) => o,
            _ => Object::default(),
        }
    }
}
impl From<Vec<ProposalInfo>> for PendingProposalsResponse {
    fn from(pinf: Vec<ProposalInfo>) -> Self {
        PendingProposalsResponse {
            pending_proposals: pinf,
        }
    }
}
impl TryFrom<Option<Object>> for PendingProposalsResponse {
    type Error = ApiError;
    fn try_from(o: Option<Object>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse a `PendingProposalsResponse` from JSON object: {}",
                e
            ))
        })
    }
}
