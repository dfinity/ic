use crate::errors::ApiError;
use crate::ledger_client::neuron_response::NeuronResponse;
use crate::ledger_client::OperationOutput;
use crate::models;
use ic_nns_governance::pb::v1::{GovernanceError, Neuron, NeuronState};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn handle_neuron_info(
    bytes: Vec<u8>,
) -> Result<Result<Option<OperationOutput>, ApiError>, String> {
    // Check the response from governance call.
    let response: Result<Neuron, GovernanceError> = candid::decode_one(bytes.as_ref())
        .map_err(|err| format!("Could not decode NEURON_INFO response: {}", err))?;
    return match response {
        Err(e) => Ok(Err(ApiError::InvalidRequest(
            false,
            format!("Could not retrieve neuron information: {}", e.error_message).into(),
        ))),
        Ok(neuron) => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let state = neuron.state(now);
            let state = match state {
                NeuronState::NotDissolving => models::NeuronState::NotDissolving,
                NeuronState::Dissolving => models::NeuronState::Dissolving,
                NeuronState::Dissolved => models::NeuronState::Dissolved,
                NeuronState::Unspecified => models::NeuronState::Dissolved,
            };

            let output = OperationOutput::NeuronResponse(NeuronResponse {
                neuron_id: neuron.id.as_ref().unwrap().id,
                controller: neuron.controller.unwrap(),
                kyc_verified: neuron.kyc_verified,
                state,
                maturity_e8s_equivalent: neuron.maturity_e8s_equivalent,
                neuron_fees_e8s: neuron.neuron_fees_e8s,
            });
            return Ok(Ok(Some(output)));
        }
    };
}
