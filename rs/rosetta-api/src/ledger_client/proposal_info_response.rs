use crate::errors::ApiError;
use ic_nns_governance_api::pb::v1::ProposalInfo;
use rosetta_core::objects::ObjectMap;
use serde_json::Value;

#[derive(serde::Serialize, serde::Deserialize, std::fmt::Debug, Clone)]
pub struct ProposalInfoResponse(pub ProposalInfo);

impl TryFrom<ProposalInfoResponse> for ObjectMap {
    type Error = ApiError;
    fn try_from(d: ProposalInfoResponse) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(Value::Object(o)) => Ok(o),
            Ok(o) => Err(ApiError::internal_error(format!("Could not convert ProposalInfoResponse to ObjectMap. Expected type Object but received: {:?}",o))),
            Err(err) => Err(ApiError::internal_error(format!("Could not convert ProposalInfoResponse to ObjectMap: {:?}",err))),
        }
    }
}

impl From<ProposalInfo> for ProposalInfoResponse {
    fn from(pinf: ProposalInfo) -> Self {
        ProposalInfoResponse(pinf)
    }
}

impl TryFrom<Option<ObjectMap>> for ProposalInfoResponse {
    type Error = ApiError;
    fn try_from(o: Option<ObjectMap>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse a `ProposalInfoResponse` from JSON object: {}",
                e
            ))
        })
    }
}
