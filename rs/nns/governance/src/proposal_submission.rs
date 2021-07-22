use crate::pb::v1::{
    manage_neuron::Command, manage_neuron_response::Command as CommandResponse, proposal,
    ExecuteNnsFunction, ManageNeuron, ManageNeuronResponse, NnsFunction, Proposal,
};
use candid::{CandidType, Decode, Encode};
use ic_nns_common::types::{NeuronId, ProposalId};

/// Simplified the process of creating an ExternalUpdate proposal.
pub fn create_external_update_proposal_candid<T: CandidType>(
    summary: String,
    url: String,
    nns_function: NnsFunction,
    payload: T,
) -> Proposal {
    create_external_update_proposal_binary(
        summary,
        url,
        nns_function,
        Encode!(&payload).expect("Error encoding proposal payload"),
    )
}

pub fn create_external_update_proposal_binary(
    summary: String,
    url: String,
    nns_function: NnsFunction,
    payload: Vec<u8>,
) -> Proposal {
    Proposal {
        summary,
        url,
        action: Some(proposal::Action::ExecuteNnsFunction(ExecuteNnsFunction {
            nns_function: nns_function as i32,
            payload,
        })),
    }
}

/// Wraps the given proposal into a MakeProposal command, and wraps the command
/// into a payload to call `manage_neuron`.
pub fn create_make_proposal_payload(
    proposal: Proposal,
    proposer_neuron_id: &NeuronId,
) -> ManageNeuron {
    ManageNeuron {
        id: Some((*proposer_neuron_id).into()),
        neuron_id_or_subaccount: None,
        command: Some(Command::MakeProposal(Box::new(proposal))),
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
        _ => Err("Unexpectd ManageNeuronResponse".to_string()),
    }
}
