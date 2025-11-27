use crate::{
    errors::ApiError,
    ledger_client::{OperationOutput, neuron_response::NeuronResponse},
    models,
};
use ic_nns_governance_api::{GovernanceError, Neuron, NeuronState};
use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

pub fn handle_neuron_info(
    bytes: Vec<u8>,
) -> Result<Result<Option<OperationOutput>, ApiError>, String> {
    // Check the response from governance call.
    let response: Result<Neuron, GovernanceError> = candid::decode_one(bytes.as_ref())
        .map_err(|err| format!("Could not decode NEURON_INFO response: {err}"))?;
    match response {
        Err(e) => Ok(Err(ApiError::InvalidRequest(
            false,
            format!("Could not retrieve neuron information: {}", e.error_message).into(),
        ))),
        Ok(neuron) => {
            let output = OperationOutput::NeuronResponse(NeuronResponse {
                neuron_id: neuron.id.as_ref().unwrap().id,
                controller: neuron.controller.unwrap(),
                kyc_verified: neuron.kyc_verified,
                state: neuron_state(&neuron),
                maturity_e8s_equivalent: neuron.maturity_e8s_equivalent,
                neuron_fees_e8s: neuron.neuron_fees_e8s,
                followees: neuron_followees(&neuron),
                hotkeys: neuron.hot_keys,
                staked_maturity_e8s: neuron.staked_maturity_e8s_equivalent,
            });
            Ok(Ok(Some(output)))
        }
    }
}

fn neuron_state(neuron: &Neuron) -> models::NeuronState {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    match neuron.state(now) {
        NeuronState::NotDissolving => models::NeuronState::NotDissolving,
        NeuronState::Spawning => models::NeuronState::Spawning,
        NeuronState::Dissolving => models::NeuronState::Dissolving,
        NeuronState::Dissolved => models::NeuronState::Dissolved,
        NeuronState::Unspecified => models::NeuronState::Dissolved,
    }
}

fn neuron_followees(neuron: &Neuron) -> HashMap<i32, Vec<u64>> {
    let mut followees: HashMap<i32, Vec<u64>> = HashMap::new();
    neuron.followees.iter().for_each(|rule| {
        let topic = *rule.0;
        let topic_followees = rule.1.followees.iter().map(|x| x.id).collect();
        followees.insert(topic, topic_followees);
    });
    followees
}
