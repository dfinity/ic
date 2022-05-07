use crate::models::{self, Object};
use ic_types::PrincipalId;
use serde_json::Value;

#[derive(serde::Serialize)]
pub struct NeuronResponse {
    pub(crate) neuron_id: u64,
    pub(crate) controller: PrincipalId,
    pub(crate) kyc_verified: bool,
    pub(crate) state: models::NeuronState,
    pub(crate) maturity_e8s_equivalent: u64,
    pub(crate) neuron_fees_e8s: u64,
}

impl From<NeuronResponse> for Object {
    fn from(r: NeuronResponse) -> Self {
        match serde_json::to_value(r) {
            Ok(Value::Object(o)) => o,
            _ => Object::default(),
        }
    }
}
