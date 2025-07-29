use crate::{governance::EXECUTE_NNS_FUNCTION_PAYLOAD_LISTING_BYTES_MAX, pb::v1 as pb};

use ic_nns_common::pb::v1::NeuronId;
use ic_nns_governance_api as pb_api;
use std::collections::{BTreeSet, HashMap};

fn convert_execute_nns_function(
    item: &pb::ExecuteNnsFunction,
    omit_large_fields: bool,
) -> pb_api::ExecuteNnsFunction {
    let pb::ExecuteNnsFunction {
        nns_function,
        payload,
    } = item;

    let nns_function = *nns_function;
    let payload =
        if omit_large_fields && payload.len() > EXECUTE_NNS_FUNCTION_PAYLOAD_LISTING_BYTES_MAX {
            vec![]
        } else {
            payload.clone()
        };

    pb_api::ExecuteNnsFunction {
        nns_function,
        payload,
    }
}

fn convert_install_code(item: &pb::InstallCode) -> pb_api::InstallCode {
    let pb::InstallCode {
        canister_id,
        install_mode,
        wasm_module: _,
        arg: _,
        skip_stopping_before_installing,
        wasm_module_hash,
        arg_hash,
    } = item;

    let canister_id = *canister_id;
    let install_mode = *install_mode;
    let skip_stopping_before_installing = *skip_stopping_before_installing;
    let wasm_module_hash = wasm_module_hash.clone();
    let arg_hash = arg_hash.clone();

    pb_api::InstallCode {
        canister_id,
        install_mode,
        skip_stopping_before_installing,
        wasm_module_hash,
        arg_hash,
    }
}

fn convert_ledger_parameters(
    item: &pb::create_service_nervous_system::LedgerParameters,
    omit_large_fields: bool,
) -> pb_api::create_service_nervous_system::LedgerParameters {
    let pb::create_service_nervous_system::LedgerParameters {
        transaction_fee,
        token_name,
        token_symbol,
        token_logo,
    } = item;

    let transaction_fee = *transaction_fee;
    let token_name = token_name.clone();
    let token_symbol = token_symbol.clone();

    let token_logo = if omit_large_fields {
        None
    } else {
        token_logo.clone()
    };

    pb_api::create_service_nervous_system::LedgerParameters {
        transaction_fee,
        token_name,
        token_symbol,
        token_logo,
    }
}

fn convert_create_service_nervous_system(
    item: &pb::CreateServiceNervousSystem,
    omit_large_fields: bool,
) -> pb_api::CreateServiceNervousSystem {
    let pb::CreateServiceNervousSystem {
        name,
        description,
        url,
        logo,
        fallback_controller_principal_ids,
        dapp_canisters,
        initial_token_distribution,
        swap_parameters,
        ledger_parameters,
        governance_parameters,
    } = item;

    let name = name.clone();
    let description = description.clone();
    let url = url.clone();
    let fallback_controller_principal_ids = fallback_controller_principal_ids.clone();
    let dapp_canisters = dapp_canisters.clone();
    let initial_token_distribution = initial_token_distribution.clone().map(|x| x.into());
    let swap_parameters = swap_parameters.clone().map(|x| x.into());
    let governance_parameters = governance_parameters.map(|x| x.into());

    let logo = if omit_large_fields {
        None
    } else {
        logo.clone()
    };
    let ledger_parameters = ledger_parameters
        .as_ref()
        .map(|ledger_parameters| convert_ledger_parameters(ledger_parameters, omit_large_fields));

    pb_api::CreateServiceNervousSystem {
        name,
        description,
        url,
        logo,
        fallback_controller_principal_ids,
        dapp_canisters,
        initial_token_distribution,
        swap_parameters,
        ledger_parameters,
        governance_parameters,
    }
}

fn convert_action(
    item: &pb::proposal::Action,
    omit_large_fields: bool,
) -> pb_api::proposal::Action {
    match item {
        // Trivial conversions
        pb::proposal::Action::ManageNeuron(v) => {
            pb_api::proposal::Action::ManageNeuron(Box::new(v.as_ref().clone().into()))
        }
        pb::proposal::Action::ManageNetworkEconomics(v) => {
            pb_api::proposal::Action::ManageNetworkEconomics(v.clone().into())
        }
        pb::proposal::Action::Motion(v) => pb_api::proposal::Action::Motion(v.clone().into()),
        pb::proposal::Action::ApproveGenesisKyc(v) => {
            pb_api::proposal::Action::ApproveGenesisKyc(v.clone().into())
        }
        pb::proposal::Action::AddOrRemoveNodeProvider(v) => {
            pb_api::proposal::Action::AddOrRemoveNodeProvider(v.clone().into())
        }
        pb::proposal::Action::RewardNodeProvider(v) => {
            pb_api::proposal::Action::RewardNodeProvider(v.clone().into())
        }
        pb::proposal::Action::SetDefaultFollowees(v) => {
            pb_api::proposal::Action::SetDefaultFollowees(v.clone().into())
        }
        pb::proposal::Action::RewardNodeProviders(v) => {
            pb_api::proposal::Action::RewardNodeProviders(v.clone().into())
        }
        pb::proposal::Action::RegisterKnownNeuron(v) => {
            pb_api::proposal::Action::RegisterKnownNeuron(v.clone().into())
        }
        pb::proposal::Action::SetSnsTokenSwapOpenTimeWindow(v) => {
            pb_api::proposal::Action::SetSnsTokenSwapOpenTimeWindow(v.clone().into())
        }
        pb::proposal::Action::OpenSnsTokenSwap(v) => {
            pb_api::proposal::Action::OpenSnsTokenSwap(v.clone().into())
        }
        pb::proposal::Action::StopOrStartCanister(v) => {
            pb_api::proposal::Action::StopOrStartCanister(v.clone().into())
        }
        pb::proposal::Action::UpdateCanisterSettings(v) => {
            pb_api::proposal::Action::UpdateCanisterSettings(v.clone().into())
        }
        pb::proposal::Action::FulfillSubnetRentalRequest(v) => {
            pb_api::proposal::Action::FulfillSubnetRentalRequest(v.clone().into())
        }

        // The action types with potentially large fields need to be converted in a way that avoids
        // cloning the action first.
        pb::proposal::Action::InstallCode(v) => {
            pb_api::proposal::Action::InstallCode(convert_install_code(v))
        }
        pb::proposal::Action::ExecuteNnsFunction(v) => {
            pb_api::proposal::Action::ExecuteNnsFunction(convert_execute_nns_function(
                v,
                omit_large_fields,
            ))
        }
        pb::proposal::Action::CreateServiceNervousSystem(v) => {
            pb_api::proposal::Action::CreateServiceNervousSystem(
                convert_create_service_nervous_system(v, omit_large_fields),
            )
        }
    }
}

pub fn convert_proposal(item: &pb::Proposal, omit_large_fields: bool) -> pb_api::Proposal {
    let pb::Proposal {
        title,
        summary,
        url,
        action,
    } = item;

    // Convert (relatively) small fields
    let title = title.clone();
    let summary = summary.clone();
    let url = url.clone();

    // Convert action which is potentially large.
    let action = action
        .as_ref()
        .map(|x| convert_action(x, omit_large_fields));

    pb_api::Proposal {
        title,
        summary,
        url,
        action,
    }
}

fn convert_ballots(
    all_ballots: &HashMap<u64, pb::Ballot>,
    caller_neurons: &BTreeSet<NeuronId>,
) -> HashMap<u64, pb_api::Ballot> {
    let mut ballots = HashMap::new();
    for neuron_id in caller_neurons.iter() {
        if let Some(v) = all_ballots.get(&neuron_id.id) {
            ballots.insert(neuron_id.id, (*v).into());
        }
    }
    ballots
}

pub fn proposal_data_to_info(
    data: &pb::ProposalData,
    multi_query: bool,
    omit_large_fields_requested: bool,
    caller_neurons: &BTreeSet<NeuronId>,
    now_seconds: u64,
    voting_period_seconds: impl Fn(pb::Topic) -> u64,
) -> pb_api::ProposalInfo {
    // Calculate derived fields
    let status = data.status() as i32;
    let reward_status = data.reward_status(now_seconds, voting_period_seconds(data.topic())) as i32;
    let deadline_timestamp_seconds =
        Some(data.get_deadline_timestamp_seconds(voting_period_seconds(data.topic())));

    // Trivially convert fields
    let id = data.id;
    let proposer = data.proposer;
    let topic = data.topic() as i32;
    let reject_cost_e8s = data.reject_cost_e8s;
    let proposal_timestamp_seconds = data.proposal_timestamp_seconds;
    let latest_tally = data.latest_tally.map(|x| x.into());
    let decided_timestamp_seconds = data.decided_timestamp_seconds;
    let executed_timestamp_seconds = data.executed_timestamp_seconds;
    let failed_timestamp_seconds = data.failed_timestamp_seconds;
    let failure_reason = data.failure_reason.clone().map(|x| x.into());
    let reward_event_round = data.reward_event_round;
    let derived_proposal_information = data.derived_proposal_information.clone().map(|x| x.into());
    let total_potential_voting_power = data.total_potential_voting_power;

    // Convert proposal which is potentially large.
    let proposal_action = data
        .proposal
        .as_ref()
        .and_then(|proposal| proposal.action.as_ref());
    let omit_large_fields = match (multi_query, proposal_action) {
        // When not doing a multi-query (i.e. querying a single proposal), we never omit large
        // fields.
        (false, _) => false,
        // Proposals which might contain WASM code are always omitted in multi-queries.
        (true, Some(pb::proposal::Action::ExecuteNnsFunction(_))) => true,
        // Otherwise, we respect the request for omitting large fields.
        (true, _) => omit_large_fields_requested,
    };
    let proposal = data
        .proposal
        .as_ref()
        .map(|x| convert_proposal(x, omit_large_fields));

    // Convert ballots which are potentially large.
    let ballots = convert_ballots(&data.ballots, caller_neurons);

    pb_api::ProposalInfo {
        id,
        proposer,
        reject_cost_e8s,
        proposal,
        proposal_timestamp_seconds,
        ballots,
        latest_tally,
        decided_timestamp_seconds,
        executed_timestamp_seconds,
        failed_timestamp_seconds,
        failure_reason,
        reward_event_round,
        topic,
        status,
        reward_status,
        deadline_timestamp_seconds,
        derived_proposal_information,
        total_potential_voting_power,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ic_base_types::PrincipalId;
    use ic_crypto_sha2::Sha256;

    #[test]
    fn install_code_request_to_internal() {
        let test_cases = vec![
            (
                pb_api::InstallCodeRequest {
                    canister_id: Some(PrincipalId::new_user_test_id(1)),
                    install_mode: Some(pb::install_code::CanisterInstallMode::Install as i32),
                    skip_stopping_before_installing: None,
                    wasm_module: Some(vec![1, 2, 3]),
                    arg: Some(vec![]),
                },
                pb::InstallCode {
                    canister_id: Some(PrincipalId::new_user_test_id(1)),
                    install_mode: Some(pb_api::install_code::CanisterInstallMode::Install as i32),
                    skip_stopping_before_installing: None,
                    wasm_module: Some(vec![1, 2, 3]),
                    arg: Some(vec![]),
                    wasm_module_hash: Some(Sha256::hash(&[1, 2, 3]).to_vec()),
                    arg_hash: Some(vec![]),
                },
            ),
            (
                pb_api::InstallCodeRequest {
                    canister_id: Some(PrincipalId::new_user_test_id(1)),
                    install_mode: Some(pb::install_code::CanisterInstallMode::Upgrade as i32),
                    skip_stopping_before_installing: Some(true),
                    wasm_module: Some(vec![1, 2, 3]),
                    arg: Some(vec![4, 5, 6]),
                },
                pb::InstallCode {
                    canister_id: Some(PrincipalId::new_user_test_id(1)),
                    install_mode: Some(pb_api::install_code::CanisterInstallMode::Upgrade as i32),
                    skip_stopping_before_installing: Some(true),
                    wasm_module: Some(vec![1, 2, 3]),
                    arg: Some(vec![4, 5, 6]),
                    wasm_module_hash: Some(Sha256::hash(&[1, 2, 3]).to_vec()),
                    arg_hash: Some(Sha256::hash(&[4, 5, 6]).to_vec()),
                },
            ),
        ];

        for (request, internal) in test_cases {
            assert_eq!(pb::InstallCode::from(request), internal);
        }
    }
}
