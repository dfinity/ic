use crate::errors::ApiError;
use crate::models::{self};
use ic_types::PrincipalId;
use rosetta_core::objects::ObjectMap;
use serde_json::Value;
use std::collections::HashMap;

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct NeuronResponse {
    pub neuron_id: u64,
    pub controller: PrincipalId,
    pub kyc_verified: bool,
    pub state: models::NeuronState,
    pub maturity_e8s_equivalent: u64,
    pub neuron_fees_e8s: u64,
    pub followees: HashMap<i32, Vec<u64>>,
    pub hotkeys: Vec<PrincipalId>,
    pub staked_maturity_e8s: Option<u64>,
}

impl TryFrom<NeuronResponse> for ObjectMap {
    type Error = ApiError;
    fn try_from(d: NeuronResponse) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(Value::Object(o)) => Ok(o),
            Ok(o) => Err(ApiError::internal_error(format!(
                "Could not convert NeuronResponse to ObjectMap. Expected type Object but received: {o:?}"
            ))),
            Err(err) => Err(ApiError::internal_error(format!(
                "Could not convert NeuronResponse to ObjectMap: {err:?}"
            ))),
        }
    }
}

impl TryFrom<ObjectMap> for NeuronResponse {
    type Error = ApiError;
    fn try_from(o: ObjectMap) -> Result<NeuronResponse, Self::Error> {
        serde_json::from_value(Value::Object(o)).map_err(|err| {
            ApiError::internal_error(format!(
                "Could not convert ObjectMap to NeuronResponse: {err:?}"
            ))
        })
    }
}
