use crate::errors::ApiError;
use ic_nns_governance_api::pb::v1::ListNeuronsResponse as Response;
use rosetta_core::objects::ObjectMap;
use serde_json::Value;

#[derive(serde::Serialize, serde::Deserialize, std::fmt::Debug, Clone)]
pub struct ListNeuronsResponse(pub Response);

impl TryFrom<ListNeuronsResponse> for ObjectMap {
    type Error = ApiError;
    fn try_from(d: ListNeuronsResponse) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(Value::Object(o)) => Ok(o),
            Ok(o) => Err(ApiError::internal_error(format!("Could not convert ListNeuronsResponse to ObjectMap. Expected type Object but received: {:?}",o))),
            Err(err) => Err(ApiError::internal_error(format!("Could not convert ListNeuronsResponse to ObjectMap: {:?}",err))),
        }
    }
}

impl From<Response> for ListNeuronsResponse {
    fn from(pinf: Response) -> Self {
        ListNeuronsResponse(pinf)
    }
}

impl TryFrom<Option<ObjectMap>> for ListNeuronsResponse {
    type Error = ApiError;
    fn try_from(o: Option<ObjectMap>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse a `ListNeuronsResponse` from JSON object: {}",
                e
            ))
        })
    }
}
