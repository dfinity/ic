use crate::errors::ApiError;
use ic_nns_governance::pb::v1::ProposalInfo;
use rosetta_core::objects::ObjectMap;
use serde_json::Value;

#[derive(serde::Serialize, serde::Deserialize, std::fmt::Debug, Clone)]
pub struct PendingProposalsResponse {
    pub pending_proposals: Vec<ProposalInfo>,
}
impl From<PendingProposalsResponse> for ObjectMap {
    fn from(r: PendingProposalsResponse) -> Self {
        match serde_json::to_value(r) {
            Ok(Value::Object(o)) => o,
            _ => ObjectMap::default(),
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
impl TryFrom<Option<ObjectMap>> for PendingProposalsResponse {
    type Error = ApiError;
    fn try_from(o: Option<ObjectMap>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse a `PendingProposalsResponse` from JSON object: {}",
                e
            ))
        })
    }
}
