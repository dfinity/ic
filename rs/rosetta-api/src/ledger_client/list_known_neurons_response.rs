use crate::errors::ApiError;
use ic_nns_governance_api::pb::v1::{KnownNeuron, ListKnownNeuronsResponse as Response};
use rosetta_core::objects::ObjectMap;
use serde_json::Value;

#[derive(serde::Serialize, serde::Deserialize, std::fmt::Debug, Clone)]
pub struct ListKnownNeuronsResponse {
    pub known_neurons: Vec<KnownNeuron>,
}

impl TryFrom<ListKnownNeuronsResponse> for ObjectMap {
    type Error = ApiError;
    fn try_from(d: ListKnownNeuronsResponse) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(Value::Object(o)) => Ok(o),
            Ok(o) => Err(ApiError::internal_error(format!("Could not convert ListKnownNeuronsResponse to ObjectMap. Expected type Object but received: {:?}",o))),
            Err(err) => Err(ApiError::internal_error(format!("Could not convert ListKnownNeuronsResponse to ObjectMap: {:?}",err))),
        }
    }
}

impl From<Response> for ListKnownNeuronsResponse {
    fn from(response: Response) -> Self {
        ListKnownNeuronsResponse {
            known_neurons: response.known_neurons,
        }
    }
}
impl TryFrom<Option<ObjectMap>> for ListKnownNeuronsResponse {
    type Error = ApiError;
    fn try_from(o: Option<ObjectMap>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse a `ListKnownNeuronsResponse` from JSON object: {}",
                e
            ))
        })
    }
}
