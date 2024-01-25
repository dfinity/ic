use crate::errors::ApiError;
use ic_nns_governance::pb::v1::{KnownNeuron, ListKnownNeuronsResponse as Response};
use rosetta_core::objects::ObjectMap;
use serde_json::Value;

#[derive(serde::Serialize, serde::Deserialize, std::fmt::Debug, Clone)]
pub struct ListKnownNeuronsResponse {
    pub known_neurons: Vec<KnownNeuron>,
}
impl From<ListKnownNeuronsResponse> for ObjectMap {
    fn from(r: ListKnownNeuronsResponse) -> Self {
        match serde_json::to_value(r) {
            Ok(Value::Object(o)) => o,
            _ => ObjectMap::default(),
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
