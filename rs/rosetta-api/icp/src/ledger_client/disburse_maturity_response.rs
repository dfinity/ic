use crate::errors::ApiError;
use ic_nns_governance_api::manage_neuron_response::DisburseMaturityResponse as NnsDisburseMaturityResponse;
use rosetta_core::objects::ObjectMap;
use serde_json::Value;

#[derive(Clone, serde::Deserialize, serde::Serialize, std::fmt::Debug)]
pub struct DisburseMaturityResponse {
    pub amount_disbursed_e8s: Option<u64>,
}

impl TryFrom<DisburseMaturityResponse> for ObjectMap {
    type Error = ApiError;
    fn try_from(d: DisburseMaturityResponse) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(Value::Object(o)) => Ok(o),
            Ok(o) => Err(ApiError::internal_error(format!(
                "Could not convert DisburseMaturityResponse to ObjectMap. Expected type Object but received: {o:?}"
            ))),
            Err(err) => Err(ApiError::internal_error(format!(
                "Could not convert DisburseMaturityResponse to ObjectMap: {err:?}"
            ))),
        }
    }
}

impl From<NnsDisburseMaturityResponse> for DisburseMaturityResponse {
    fn from(r: NnsDisburseMaturityResponse) -> Self {
        DisburseMaturityResponse {
            amount_disbursed_e8s: r.amount_disbursed_e8s,
        }
    }
}

impl TryFrom<Option<ObjectMap>> for DisburseMaturityResponse {
    type Error = ApiError;
    fn try_from(o: Option<ObjectMap>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse a `DisburseMaturityResponse` from JSON object: {e}"
            ))
        })
    }
}
