use crate::errors::ApiError;
use ic_nns_governance::pb::v1::ListNeuronsResponse as Response;
use rosetta_core::objects::ObjectMap;
use serde_json::Value;

#[derive(serde::Serialize, serde::Deserialize, std::fmt::Debug, Clone)]
pub struct ListNeuronsResponse(pub Response);

impl From<ListNeuronsResponse> for ObjectMap {
    fn from(r: ListNeuronsResponse) -> Self {
        match serde_json::to_value(r) {
            Ok(Value::Object(o)) => o,
            _ => ObjectMap::default(),
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
