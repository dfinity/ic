use crate::{errors::ApiError, models::Object};
use ic_nns_governance::pb::v1::ProposalInfo;
use serde_json::Value;

#[derive(serde::Serialize, serde::Deserialize, std::fmt::Debug, Clone)]
pub struct ProposalInfoResponse(pub ProposalInfo);

impl From<ProposalInfoResponse> for Object {
    fn from(r: ProposalInfoResponse) -> Self {
        match serde_json::to_value(r) {
            Ok(Value::Object(o)) => o,
            _ => Object::default(),
        }
    }
}

impl From<ProposalInfo> for ProposalInfoResponse {
    fn from(pinf: ProposalInfo) -> Self {
        ProposalInfoResponse(pinf)
    }
}

impl TryFrom<Option<Object>> for ProposalInfoResponse {
    type Error = ApiError;
    fn try_from(o: Option<Object>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse a `ProposalInfoResponse` from JSON object: {}",
                e
            ))
        })
    }
}
