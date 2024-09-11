use crate::pb::v1::{
    manage_neuron::Command, manage_neuron_response::Command as CommandResponse, proposal::Action,
    ExecuteNnsFunction, InstallCode, InstallCodeRequest, MakeProposalRequest, ManageNeuron,
    ManageNeuronCommandRequest, ManageNeuronRequest, ManageNeuronResponse, NnsFunction, Proposal,
    ProposalActionRequest,
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

// The code below exists only because the API types cannot define its own `Debug` trait while still
// being `prost::Message`. The API types still are `prost::Message` because we have some legacy pb
// endpoints. The conversions make it possible for ic-admin to print the proposal in the format of
// the response API types.
//
// TODO: Remove this after defining the `Debug` trait in the API types and using them to print
// proposals in ic-admin.
fn calculate_hash(bytes: &[u8]) -> [u8; 32] {
    let mut wasm_sha = Sha256::new();
    wasm_sha.write(bytes);
    wasm_sha.finish()
}

impl From<ProposalActionRequest> for Action {
    fn from(action: ProposalActionRequest) -> Self {
        match action {
            ProposalActionRequest::ManageNeuron(v) => Action::ManageNeuron(Box::new((*v).into())),
            ProposalActionRequest::ManageNetworkEconomics(v) => Action::ManageNetworkEconomics(v),
            ProposalActionRequest::Motion(v) => Action::Motion(v),
            ProposalActionRequest::ExecuteNnsFunction(v) => Action::ExecuteNnsFunction(v),
            ProposalActionRequest::ApproveGenesisKyc(v) => Action::ApproveGenesisKyc(v),
            ProposalActionRequest::AddOrRemoveNodeProvider(v) => Action::AddOrRemoveNodeProvider(v),
            ProposalActionRequest::RewardNodeProvider(v) => Action::RewardNodeProvider(v),
            ProposalActionRequest::RewardNodeProviders(v) => Action::RewardNodeProviders(v),
            ProposalActionRequest::RegisterKnownNeuron(v) => Action::RegisterKnownNeuron(v),
            ProposalActionRequest::CreateServiceNervousSystem(v) => {
                Action::CreateServiceNervousSystem(v)
            }
            ProposalActionRequest::InstallCode(v) => Action::InstallCode(v.into()),
            ProposalActionRequest::StopOrStartCanister(v) => Action::StopOrStartCanister(v),
            ProposalActionRequest::UpdateCanisterSettings(v) => Action::UpdateCanisterSettings(v),
        }
    }
}

impl From<ManageNeuronRequest> for ManageNeuron {
    fn from(manage_neuron_request: ManageNeuronRequest) -> Self {
        Self {
            id: manage_neuron_request.id,
            neuron_id_or_subaccount: manage_neuron_request.neuron_id_or_subaccount,
            command: manage_neuron_request.command.map(|x| x.into()),
        }
    }
}

impl From<ManageNeuronCommandRequest> for Command {
    fn from(item: ManageNeuronCommandRequest) -> Self {
        match item {
            ManageNeuronCommandRequest::Configure(v) => Command::Configure(v),
            ManageNeuronCommandRequest::Disburse(v) => Command::Disburse(v),
            ManageNeuronCommandRequest::Spawn(v) => Command::Spawn(v),
            ManageNeuronCommandRequest::Follow(v) => Command::Follow(v),
            ManageNeuronCommandRequest::MakeProposal(v) => {
                Command::MakeProposal(Box::new((*v).into()))
            }
            ManageNeuronCommandRequest::RegisterVote(v) => Command::RegisterVote(v),
            ManageNeuronCommandRequest::Split(v) => Command::Split(v),
            ManageNeuronCommandRequest::DisburseToNeuron(v) => Command::DisburseToNeuron(v),
            ManageNeuronCommandRequest::ClaimOrRefresh(v) => Command::ClaimOrRefresh(v),
            ManageNeuronCommandRequest::MergeMaturity(v) => Command::MergeMaturity(v),
            ManageNeuronCommandRequest::Merge(v) => Command::Merge(v),
            ManageNeuronCommandRequest::StakeMaturity(v) => Command::StakeMaturity(v),
        }
    }
}

impl From<MakeProposalRequest> for Proposal {
    fn from(item: MakeProposalRequest) -> Self {
        Self {
            title: item.title,
            summary: item.summary,
            url: item.url,
            action: item.action.map(|x| x.into()),
        }
    }
}

impl From<InstallCodeRequest> for InstallCode {
    fn from(item: InstallCodeRequest) -> Self {
        let wasm_module_hash = item
            .wasm_module
            .map(|wasm_module| calculate_hash(&wasm_module).to_vec());
        let arg = item.arg.unwrap_or_default();
        let arg_hash = if arg.is_empty() {
            Some(vec![])
        } else {
            Some(calculate_hash(&arg).to_vec())
        };

        Self {
            canister_id: item.canister_id,
            install_mode: item.install_mode,
            skip_stopping_before_installing: item.skip_stopping_before_installing,
            wasm_module_hash,
            arg_hash,
        }
    }
}
