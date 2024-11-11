use crate::errors::ApiError;
use crate::models::{self};
use ic_types::PrincipalId;
use rosetta_core::objects::ObjectMap;
use serde_json::Value;
use std::collections::HashMap;

#[derive(serde::Serialize)]
pub struct NeuronResponse {
    pub(crate) neuron_id: u64,
    pub(crate) controller: PrincipalId,
    pub(crate) kyc_verified: bool,
    pub(crate) state: models::NeuronState,
    pub(crate) maturity_e8s_equivalent: u64,
    pub(crate) neuron_fees_e8s: u64,
    pub(crate) followees: HashMap<i32, Vec<u64>>,
    pub(crate) hotkeys: Vec<PrincipalId>,
    pub(crate) staked_maturity_e8s: Option<u64>,
}

impl TryFrom<NeuronResponse> for ObjectMap {
    type Error = ApiError;
    fn try_from(d: NeuronResponse) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(Value::Object(o)) => Ok(o),
            Ok(o) => Err(ApiError::internal_error(format!("Could not convert NeuronResponse to ObjectMap. Expected type Object but received: {:?}",o))),
            Err(err) => Err(ApiError::internal_error(format!("Could not convert NeuronResponse to ObjectMap: {:?}",err))),
        }
    }
}
