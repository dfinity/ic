use crate::errors::ApiError;
use ic_nns_governance_api::NetworkEconomics;
use rosetta_core::objects::ObjectMap;
use serde_json::Value;

#[derive(Clone, serde::Deserialize, serde::Serialize, std::fmt::Debug)]
pub struct MinimumDissolveDelayResponse {
    pub neuron_minimum_dissolve_delay_to_vote_seconds: Option<u64>,
}

impl TryFrom<MinimumDissolveDelayResponse> for ObjectMap {
    type Error = ApiError;
    fn try_from(d: MinimumDissolveDelayResponse) -> Result<ObjectMap, Self::Error> {
        match serde_json::to_value(d) {
            Ok(Value::Object(o)) => Ok(o),
            Ok(o) => Err(ApiError::internal_error(format!(
                "Could not convert MinimumDissolveDelayResponse to ObjectMap. Expected type Object but received: {o:?}"
            ))),
            Err(err) => Err(ApiError::internal_error(format!(
                "Could not convert MinimumDissolveDelayResponse to ObjectMap: {err:?}"
            ))),
        }
    }
}

impl From<NetworkEconomics> for MinimumDissolveDelayResponse {
    fn from(network_economics: NetworkEconomics) -> Self {
        let dissolve_delay = match network_economics.voting_power_economics {
            Some(vpe) => vpe.neuron_minimum_dissolve_delay_to_vote_seconds,
            None => None,
        };
        MinimumDissolveDelayResponse {
            neuron_minimum_dissolve_delay_to_vote_seconds: dissolve_delay,
        }
    }
}
impl TryFrom<Option<ObjectMap>> for MinimumDissolveDelayResponse {
    type Error = ApiError;
    fn try_from(o: Option<ObjectMap>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse a `MinimumDissolveDelayResponse` from JSON object: {e}"
            ))
        })
    }
}
