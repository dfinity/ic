use std::time::Duration;

use candid::Encode;
use cycles_minting_canister::{MEMO_MINT_CYCLES, NotifyMintCyclesSuccess};
use ic_base_types::PrincipalId;
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_nns_constants::CYCLES_MINTING_CANISTER_ID;
use ic_nns_governance_api::{
    CreateServiceNervousSystem, ExecuteNnsFunction, ListNeurons, MakeProposalRequest,
    ManageNeuronCommandRequest, Neuron, NnsFunction, ProposalActionRequest, ProposalInfo, Topic,
    manage_neuron_response::Command,
};
use ic_sns_wasm::pb::v1::get_deployed_sns_by_proposal_id_response::GetDeployedSnsByProposalIdResult;
use ic_sns_wasm::pb::v1::{AddWasmRequest, SnsWasm};
use icp_ledger::{AccountIdentifier, Subaccount, Tokens, TransferArgs};

use crate::nns::governance::{get_proposal_info, list_neurons, manage_neuron};
use crate::nns::sns_wasm::get_deployed_sns_by_proposal_id;
use crate::sns::Sns;
use crate::{CallCanisters, CallCanistersWithStoppedCanisterError, ProgressNetwork};

// TODO @rvem: we probably need more meaningful error type rather than just 'String'

pub async fn propose_and_wait<C: CallCanistersWithStoppedCanisterError + ProgressNetwork>(
    agent: &C,
    neuron_id: NeuronId,
    proposal: MakeProposalRequest,
) -> Result<ProposalInfo, String> {
    let command = ManageNeuronCommandRequest::MakeProposal(Box::new(proposal));
    let response = manage_neuron(agent, neuron_id, command)
        .await
        .map_err(|err| format!("Error making proposal: {err:#?}"))?;
    let response = match response.command {
        Some(Command::MakeProposal(response)) => response,
        _ => return Err(format!("Proposal failed: {response:#?}")),
    };
    match response.proposal_id {
        Some(proposal_id) => wait_for_proposal_execution(agent, proposal_id).await,
        None => Err(format!(
            "Proposal response does not contain a proposal_id: {response:#?}"
        )),
    }
}

pub async fn propose_to_deploy_sns_and_wait<
    C: CallCanistersWithStoppedCanisterError + ProgressNetwork,
>(
    agent: &C,
    neuron_id: NeuronId,
    create_service_nervous_system: CreateServiceNervousSystem,
    title: String,
    summary: String,
    url: String,
) -> Result<(Sns, ProposalId), String> {
    let proposal = MakeProposalRequest {
        title: Some(title.clone()),
        summary,
        url,
        action: Some(ProposalActionRequest::CreateServiceNervousSystem(
            create_service_nervous_system,
        )),
    };
    let proposal_info = propose_and_wait(agent, neuron_id, proposal).await?;
    let nns_proposal_id = proposal_info.id.ok_or("Proposal ID not set")?;
    let Some(GetDeployedSnsByProposalIdResult::DeployedSns(deployed_sns)) =
        get_deployed_sns_by_proposal_id(agent, nns_proposal_id)
            .await
            .map_err(|err| format!("Error getting deployed SNS: {err:#?}"))?
            .get_deployed_sns_by_proposal_id_result
    else {
        return Err(format!(
            "NNS proposal '{title}' {nns_proposal_id:?} did not result in a successfully deployed SNS.",
        ));
    };
    let sns = Sns::try_from(deployed_sns).expect("Failed to convert DeployedSns to Sns");
    Ok((sns, nns_proposal_id))
}

pub async fn wait_for_proposal_execution<
    C: CallCanistersWithStoppedCanisterError + ProgressNetwork,
>(
    agent: &C,
    proposal_id: ProposalId,
) -> Result<ProposalInfo, String> {
    // We progress the network until the proposal is executed
    let mut last_proposal_info = None;
    for _attempt_count in 1..=100 {
        agent.progress(Duration::from_secs(1)).await;
        let proposal_info_result = get_proposal_info(agent, proposal_id).await;

        let proposal_info = match proposal_info_result {
            Ok(Some(proposal_info)) => proposal_info,
            Ok(None) => {
                return Err(format!(
                    "Proposal {proposal_id:?} doesn't have ProposalInfo"
                ));
            }
            Err(user_error) => {
                // Upgrading NNS Governance results in the proposal info temporarily not
                // being available due to the canister being stopped. This requires
                // more attempts to get the proposal info to find out if the proposal
                // actually got executed.
                if agent.is_canister_stopped_error(&user_error) {
                    continue;
                } else {
                    return Err(format!("Error getting proposal info: {user_error:#?}"));
                }
            }
        };

        if proposal_info.executed_timestamp_seconds > 0 {
            return Ok(proposal_info);
        }
        if let Some(failure_reason) = &proposal_info.failure_reason {
            return Err(format!(
                "Execution failed for {:?} proposal '{}': {:#?}",
                Topic::from_repr(proposal_info.topic).unwrap(),
                proposal_info
                    .proposal
                    .unwrap()
                    .title
                    .unwrap_or("<no-title>".to_string()),
                failure_reason
            ));
        }
        last_proposal_info = Some(proposal_info);
    }
    Err(format!(
        "Looks like proposal {proposal_id:?} is never going to be executed: {last_proposal_info:#?}",
    ))
}

pub async fn convert_icp_to_cycles<C: CallCanisters>(benecificary_agent: &C, amount: Tokens) {
    let beneficiary_principal_id: PrincipalId = benecificary_agent.caller().unwrap().into();
    let beneficiary_cmc_account = AccountIdentifier::new(
        CYCLES_MINTING_CANISTER_ID.into(),
        Some(Subaccount::from(&beneficiary_principal_id)),
    );
    let transfer_args = TransferArgs {
        memo: MEMO_MINT_CYCLES,
        amount,
        fee: Tokens::from_e8s(10_000),
        from_subaccount: None,
        to: beneficiary_cmc_account.to_address(),
        created_at_time: None,
    };

    let block_index = crate::nns::ledger::transfer(benecificary_agent, transfer_args)
        .await
        .unwrap()
        .unwrap();

    let NotifyMintCyclesSuccess {
        block_index: _,
        minted: _,
        balance: _,
    } = crate::nns::cmc::notify_mint_cycles(benecificary_agent, block_index, None, None)
        .await
        .unwrap()
        .unwrap();
}

pub async fn add_wasm_via_nns_proposal<
    C: CallCanistersWithStoppedCanisterError + ProgressNetwork,
>(
    agent: &C,
    neuron_id: NeuronId,
    wasm: SnsWasm,
) -> Result<ProposalInfo, String> {
    let hash = wasm.sha256_hash();
    let canister_type = wasm.canister_type;
    let payload = AddWasmRequest {
        hash: hash.to_vec(),
        wasm: Some(wasm),
        skip_update_latest_version: Some(false),
    };

    let proposal = MakeProposalRequest {
        title: Some(format!("Add WASM for SNS canister type {canister_type}")),
        summary: "summary".to_string(),
        url: "".to_string(),
        action: Some(ProposalActionRequest::ExecuteNnsFunction(
            ExecuteNnsFunction {
                nns_function: NnsFunction::AddSnsWasm as i32,
                payload: Encode!(&payload).expect("Error encoding proposal payload"),
            },
        )),
    };
    propose_and_wait(agent, neuron_id, proposal).await
}

pub async fn get_nns_neuron_controller<C: CallCanisters>(
    agent: &C,
    neuron_id: NeuronId,
) -> Result<Option<PrincipalId>, String> {
    let request = ListNeurons {
        neuron_ids: vec![neuron_id.id],
        ..Default::default()
    };
    let response = list_neurons(agent, request)
        .await
        .map_err(|err| format!("Failed to list neurons {err}"))?;
    let neurons = response
        .full_neurons
        .into_iter()
        .filter(|n| n.id == Some(neuron_id))
        .collect::<Vec<Neuron>>();
    let neuron = neurons.first();
    let controller = neuron
        .ok_or_else(|| format!("Failed to get neuron {} full info", neuron_id.id))?
        .controller;
    Ok(controller)
}
