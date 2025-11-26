use crate::CallCanisters;
use crate::nns::governance::requests::{GetNetworkEconomicsParameters, GetProposalInfo};
use ic_base_types::CanisterId;
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance_api::{
    ExecuteNnsFunction, GetNeuronsFundAuditInfoRequest, GetNeuronsFundAuditInfoResponse,
    ListNeurons, ListNeuronsResponse, MakeProposalRequest, ManageNeuronCommandRequest,
    ManageNeuronRequest, ManageNeuronResponse, NnsFunction, ProposalActionRequest, ProposalInfo,
    manage_neuron_response,
};
use ic_sns_governance_api::format_full_hash;
use ic_sns_wasm::pb::v1::{
    AddWasmRequest, InsertUpgradePathEntriesRequest, SnsCanisterType, SnsUpgrade, SnsWasm,
};

pub mod requests;

pub async fn get_neurons_fund_audit_info<C: CallCanisters>(
    agent: &C,
    nns_proposal_id: ProposalId,
) -> Result<GetNeuronsFundAuditInfoResponse, C::Error> {
    let request = GetNeuronsFundAuditInfoRequest {
        nns_proposal_id: Some(nns_proposal_id),
    };
    agent.call(GOVERNANCE_CANISTER_ID, request).await
}

pub async fn manage_neuron<C: CallCanisters>(
    agent: &C,
    neuron_id: NeuronId,
    request: ManageNeuronCommandRequest,
) -> Result<ManageNeuronResponse, C::Error> {
    let request = ManageNeuronRequest {
        id: Some(neuron_id),
        command: Some(request),
        neuron_id_or_subaccount: None,
    };
    agent.call(GOVERNANCE_CANISTER_ID, request).await
}

pub async fn make_proposal<C: CallCanisters>(
    agent: &C,
    neuron_id: NeuronId,
    proposal: MakeProposalRequest,
) -> Result<ProposalId, C::Error> {
    let command = ManageNeuronCommandRequest::MakeProposal(Box::new(proposal));
    let response = manage_neuron(agent, neuron_id, command).await;
    response.map(|response| {
        let command = response
            .command
            .expect("ManageNeuronResponse.command must be set");
        let manage_neuron_response::Command::MakeProposal(make_proposal_response) = command else {
            panic!("Unexpected response while making proposal: {command:?}");
        };
        make_proposal_response
            .proposal_id
            .expect("ManageNeuronResponse must specify proposal_id")
    })
}

fn sns_canister_type_code_to_name(sns_canister_type: i32) -> String {
    let Ok(sns_canister_type) = SnsCanisterType::try_from(sns_canister_type) else {
        return format!("Unknown ({sns_canister_type})");
    };
    match sns_canister_type {
        SnsCanisterType::Unspecified => "Unspecified".to_string(),
        SnsCanisterType::Root => "Root".to_string(),
        SnsCanisterType::Governance => "Governance".to_string(),
        SnsCanisterType::Swap => "Swap".to_string(),
        SnsCanisterType::Index => "Index".to_string(),
        SnsCanisterType::Ledger => "Ledger".to_string(),
        SnsCanisterType::Archive => "Archive".to_string(),
    }
}

pub async fn add_sns_wasm<C: CallCanisters>(
    agent: &C,
    neuron_id: NeuronId,
    wasm: SnsWasm,
    url: &str,
) -> Result<ProposalId, C::Error> {
    let hash = wasm.sha256_hash();

    let payload = AddWasmRequest {
        hash: hash.to_vec(),
        wasm: Some(wasm.clone()),
        skip_update_latest_version: Some(false),
    };

    let proposal = MakeProposalRequest {
        title: Some("Add SNS Wasm".into()),
        summary: format!(
            "Add SNS Wasm (+ {}; module hash {})",
            sns_canister_type_code_to_name(wasm.canister_type),
            format_full_hash(&hash),
        ),
        url: url.to_string(),
        action: Some(ProposalActionRequest::ExecuteNnsFunction(
            ExecuteNnsFunction {
                nns_function: NnsFunction::AddSnsWasm as i32,
                payload: candid::encode_one(&payload).expect("Error encoding proposal payload"),
            },
        )),
    };

    make_proposal(agent, neuron_id, proposal).await
}

pub async fn insert_sns_wasm_upgrade_path_entries<C: CallCanisters>(
    agent: &C,
    neuron_id: NeuronId,
    upgrade_path: Vec<SnsUpgrade>,
    sns_governance_canister_id: Option<CanisterId>,
    url: &str,
) -> Result<ProposalId, C::Error> {
    let sns_governance_canister_id =
        sns_governance_canister_id.map(|canister_id| canister_id.get());

    // TODO: Use a more descriptive rendering of `upgrade_path`.
    let upgrade_path_summary_str = format!("with {} steps", upgrade_path.len());

    let payload = InsertUpgradePathEntriesRequest {
        upgrade_path,
        sns_governance_canister_id,
    };

    let sns_selector_str = if let Some(canister_id) = sns_governance_canister_id {
        format!("SNS with Governance canister ID {canister_id}")
    } else {
        "all SNSs".to_string()
    };

    let proposal = MakeProposalRequest {
        title: Some("Insert SNS-Wasm upgrade path entries".into()),
        summary: format!(
            "Insert SNS-Wasm upgrade path entries {upgrade_path_summary_str} for {sns_selector_str}.",
        ),
        url: url.to_string(),
        action: Some(ProposalActionRequest::ExecuteNnsFunction(
            ExecuteNnsFunction {
                nns_function: NnsFunction::InsertSnsWasmUpgradePathEntries as i32,
                payload: candid::encode_one(&payload).expect("Error encoding proposal payload"),
            },
        )),
    };

    make_proposal(agent, neuron_id, proposal).await
}

pub async fn list_neurons<C: CallCanisters>(
    agent: &C,
    list_neurons: ListNeurons,
) -> Result<ListNeuronsResponse, C::Error> {
    agent.call(GOVERNANCE_CANISTER_ID, list_neurons).await
}

pub async fn get_proposal_info<C: CallCanisters>(
    agent: &C,
    proposal_id: ProposalId,
) -> Result<Option<ProposalInfo>, C::Error> {
    agent
        .call(GOVERNANCE_CANISTER_ID, GetProposalInfo(proposal_id))
        .await
}

pub async fn get_network_economics_parameters<C: CallCanisters>(
    agent: &C,
) -> Result<ic_nns_governance_api::NetworkEconomics, C::Error> {
    agent
        .call(GOVERNANCE_CANISTER_ID, GetNetworkEconomicsParameters())
        .await
}
