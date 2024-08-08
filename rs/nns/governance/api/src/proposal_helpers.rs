use crate::pb::v1::{
    manage_neuron_response::Command as CommandResponse, ExecuteNnsFunction,
    ManageNeuronCommandInput, ManageNeuronInput, ManageNeuronResponse, NnsFunction,
    ProposalActionInput, ProposalInput,
};
use candid::{CandidType, Decode, Encode};
use ic_nns_common::types::{NeuronId, ProposalId};

/// Simplified the process of creating an ExternalUpdate proposal.
pub fn create_external_update_proposal_candid<T: CandidType>(
    title: &str,
    summary: &str,
    url: &str,
    nns_function: NnsFunction,
    payload: T,
) -> ProposalInput {
    create_external_update_proposal_binary(
        title,
        summary,
        url,
        nns_function,
        Encode!(&payload).expect("Error encoding proposal payload"),
    )
}

pub fn create_external_update_proposal_binary(
    title: &str,
    summary: &str,
    url: &str,
    nns_function: NnsFunction,
    payload: Vec<u8>,
) -> ProposalInput {
    ProposalInput {
        title: Some(title.to_string()),
        summary: summary.to_string(),
        url: url.to_string(),
        action: Some(ProposalActionInput::ExecuteNnsFunction(
            ExecuteNnsFunction {
                nns_function: nns_function as i32,
                payload,
            },
        )),
    }
}

/// Wraps the given proposal into a MakeProposal command, and wraps the command
/// into a payload to call `manage_neuron`.
pub fn create_make_proposal_payload(
    proposal: ProposalInput,
    proposer_neuron_id: &NeuronId,
) -> ManageNeuronInput {
    ManageNeuronInput {
        id: Some((*proposer_neuron_id).into()),
        neuron_id_or_subaccount: None,
        command: Some(ManageNeuronCommandInput::MakeProposal(Box::new(proposal))),
    }
}

pub fn decode_make_proposal_response(response: Vec<u8>) -> Result<ProposalId, String> {
    match Decode!(&response, ManageNeuronResponse)
        .map_err(|e| {
            format!(
                "Cannot candid-deserialize the response from manage_neuron: {}",
                e
            )
        })?
        .command
    {
        Some(CommandResponse::MakeProposal(resp)) => {
            Ok(ProposalId::from(resp.proposal_id.unwrap()))
        }
        Some(CommandResponse::Error(e)) => Err(e.to_string()),
        _ => Err("Unexpected ManageNeuronResponse".to_string()),
    }
}
