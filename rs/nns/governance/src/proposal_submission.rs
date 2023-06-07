use crate::pb::v1::{
    manage_neuron::Command, manage_neuron_response::Command as CommandResponse, proposal,
    CreateServiceNervousSystem, ExecuteNnsFunction, ManageNeuron, ManageNeuronResponse,
    NnsFunction, Proposal,
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
) -> Proposal {
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
) -> Proposal {
    Proposal {
        title: Some(title.to_string()),
        summary: summary.to_string(),
        url: url.to_string(),
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

impl CreateServiceNervousSystem {
    pub fn upgrade_to_proposal(self) -> Proposal {
        let Self {
            name,
            url,
            description,
            ..
        } = &self;

        let name = name.clone().unwrap_or_else(|| "A Profound".to_string());
        let title = Some(format!("Create {} Service Nervous System", name));

        let description = description.clone().unwrap_or_else(|| {
            "Ladies and gentlemen,
             it is with great pleasure that present to you, \
             a fabulous new SNS for the good of all humankind. \
             You will surely be in awe of its grandeur, \
             once your eyes have beheld is glorious majesty."
                .to_string()
        });

        let url = url.clone().unwrap_or_default();

        let summary = {
            let url_line = if url.is_empty() {
                "".to_string()
            } else {
                format!("URL: {}\n", url)
            };

            format!(
                "Name: {}\n\
                 {}\
                 \n\
                 ## Description\n\
                 \n\
                 {}",
                name, url_line, description,
            )
        };

        let action = Some(proposal::Action::CreateServiceNervousSystem(self));

        Proposal {
            title,
            summary,
            url,
            action,
        }
    }
}
