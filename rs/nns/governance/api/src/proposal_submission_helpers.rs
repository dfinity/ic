use crate::types::{
    ExecuteNnsFunction, InstallCodeRequest, MakeProposalRequest, ManageNeuronCommandRequest,
    ManageNeuronRequest, ManageNeuronResponse, NnsFunction, ProposalActionRequest,
    manage_neuron_response::Command as CommandResponse,
};
use candid::{CandidType, Decode, Encode};
use ic_crypto_sha2::Sha256;
use ic_nns_common::types::{NeuronId, ProposalId};

/// Simplified the process of creating an ExternalUpdate proposal.
pub fn create_external_update_proposal_candid<T: CandidType>(
    title: &str,
    summary: &str,
    url: &str,
    nns_function: NnsFunction,
    payload: T,
) -> MakeProposalRequest {
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
) -> MakeProposalRequest {
    MakeProposalRequest {
        title: Some(title.to_string()),
        summary: summary.to_string(),
        url: url.to_string(),
        action: Some(ProposalActionRequest::ExecuteNnsFunction(
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
    proposal: MakeProposalRequest,
    proposer_neuron_id: &NeuronId,
) -> ManageNeuronRequest {
    ManageNeuronRequest {
        id: Some((*proposer_neuron_id).into()),
        neuron_id_or_subaccount: None,
        command: Some(ManageNeuronCommandRequest::MakeProposal(Box::new(proposal))),
    }
}

pub fn decode_make_proposal_response(response: Vec<u8>) -> Result<ProposalId, String> {
    match Decode!(&response, ManageNeuronResponse)
        .map_err(|e| format!("Cannot candid-deserialize the response from manage_neuron: {e}"))?
        .command
    {
        Some(CommandResponse::MakeProposal(resp)) => {
            Ok(ProposalId::from(resp.proposal_id.unwrap()))
        }
        Some(CommandResponse::Error(e)) => Err(e.to_string()),
        _ => Err("Unexpected ManageNeuronResponse".to_string()),
    }
}

fn calculate_and_encode_hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::hash(bytes))
}

impl std::fmt::Debug for InstallCodeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstallCodeRequest")
            .field("canister_id", &self.canister_id)
            .field("install_mode", &self.install_mode)
            .field(
                "skip_stopping_before_installing",
                &self.skip_stopping_before_installing,
            )
            .field(
                "wasm_module_hash",
                &self
                    .wasm_module
                    .as_ref()
                    .map(|wasm_module| calculate_and_encode_hash(wasm_module)),
            )
            .field(
                "arg_hash",
                &self.arg.as_ref().map(|arg| {
                    if arg.is_empty() {
                        "".to_string()
                    } else {
                        calculate_and_encode_hash(arg)
                    }
                }),
            )
            .finish()
    }
}
