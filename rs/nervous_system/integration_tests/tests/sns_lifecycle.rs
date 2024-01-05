use candid::{Decode, Encode, Nat, Principal};
use canister_test::Wasm;
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_ledger_core::Tokens;
use ic_nervous_system_common::{E8, SECONDS_PER_DAY};
use ic_nervous_system_common_test_keys::TEST_NEURON_1_OWNER_PRINCIPAL;
use ic_nervous_system_integration_tests::create_service_nervous_system_builder::CreateServiceNervousSystemBuilder;
use ic_nervous_system_proto::pb::v1::{Duration as DurationPb, Tokens as TokensPb};
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_nns_constants::{
    GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID, ROOT_CANISTER_ID, SNS_WASM_CANISTER_ID,
};
use ic_nns_governance::pb::v1::{
    create_service_nervous_system::initial_token_distribution::developer_distribution::NeuronDistribution,
    manage_neuron, manage_neuron_response, proposal, CreateServiceNervousSystem,
    ExecuteNnsFunction, ManageNeuron, ManageNeuronResponse, NnsFunction, Proposal, ProposalInfo,
};
use ic_nns_test_utils::{
    common::{
        build_ledger_wasm, build_root_wasm, build_sns_wasms_wasm, build_test_governance_wasm,
        NnsInitPayloadsBuilder,
    },
    ids::TEST_NEURON_1_ID,
    sns_wasm::{
        build_archive_sns_wasm, build_governance_sns_wasm, build_index_sns_wasm,
        build_ledger_sns_wasm, build_root_sns_wasm, build_swap_sns_wasm,
    },
};
use ic_sns_governance::pb::v1::{governance::Mode, GetMode, GetModeResponse};
use ic_sns_init::distributions::MAX_DEVELOPER_DISTRIBUTION_COUNT;
use ic_sns_swap::{
    pb::v1::{
        FinalizeSwapResponse, GetAutoFinalizationStatusRequest, GetAutoFinalizationStatusResponse,
        GetDerivedStateRequest, GetDerivedStateResponse, GetLifecycleRequest, GetLifecycleResponse,
        Lifecycle, RefreshBuyerTokensRequest, RefreshBuyerTokensResponse,
    },
    swap::principal_to_subaccount,
};
use ic_sns_wasm::pb::v1::{
    get_deployed_sns_by_proposal_id_response::GetDeployedSnsByProposalIdResult, AddWasmRequest,
    GetDeployedSnsByProposalIdRequest, GetDeployedSnsByProposalIdResponse, SnsCanisterType,
    SnsWasm,
};
use icp_ledger::{AccountIdentifier, BinaryAccountBalanceArgs};
use icrc_ledger_types::icrc1::{
    account::Account,
    transfer::{TransferArg, TransferError},
};
use maplit::hashmap;
use pocket_ic::{PocketIc, PocketIcBuilder, WasmResult};
use prost::Message;
use std::{collections::HashMap, time::Duration};

const STARTING_CYCLES_PER_CANISTER: u128 = 2_000_000_000_000_000;

fn manage_neuron(
    pocket_ic: &PocketIc,
    sender: PrincipalId,
    neuron_id: NeuronId,
    command: manage_neuron::Command,
) -> ManageNeuronResponse {
    let result = pocket_ic
        .update_call(
            GOVERNANCE_CANISTER_ID.into(),
            Principal::from(sender),
            "manage_neuron",
            Encode!(&ManageNeuron {
                id: Some(neuron_id),
                command: Some(command),
                neuron_id_or_subaccount: None
            })
            .unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to manage_neuron failed: {:#?}", s),
    };
    Decode!(&result, ManageNeuronResponse).unwrap()
}

fn refresh_buyer_tokens(
    pocket_ic: &PocketIc,
    swap_canister_id: PrincipalId,
    buyer: PrincipalId,
    confirmation_text: Option<String>,
) -> RefreshBuyerTokensResponse {
    let result = pocket_ic
        .update_call(
            swap_canister_id.into(),
            Principal::anonymous(),
            "refresh_buyer_tokens",
            Encode!(&RefreshBuyerTokensRequest {
                buyer: buyer.to_string(),
                confirmation_text,
            })
            .unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to refresh_buyer_tokens failed: {:#?}", s),
    };
    Decode!(&result, RefreshBuyerTokensResponse).unwrap()
}

fn get_derived_state(
    pocket_ic: &PocketIc,
    swap_canister_id: PrincipalId,
) -> GetDerivedStateResponse {
    let result = pocket_ic
        .update_call(
            swap_canister_id.into(),
            Principal::anonymous(),
            "get_derived_state",
            Encode!(&GetDerivedStateRequest {}).unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to get_derived_state failed: {:#?}", s),
    };
    Decode!(&result, GetDerivedStateResponse).unwrap()
}

fn get_lifecycle(pocket_ic: &PocketIc, swap_canister_id: PrincipalId) -> GetLifecycleResponse {
    let result = pocket_ic
        .update_call(
            swap_canister_id.into(),
            Principal::anonymous(),
            "get_lifecycle",
            Encode!(&GetLifecycleRequest {}).unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to get_lifecycle failed: {:#?}", s),
    };
    Decode!(&result, GetLifecycleResponse).unwrap()
}

fn await_swap_lifecycle(
    pocket_ic: &PocketIc,
    swap_canister_id: PrincipalId,
    expected_lifecycle: Lifecycle,
) -> Result<(), String> {
    let mut last_lifecycle = None;
    for _attempt_count in 1..=50 {
        pocket_ic.tick();
        let lifecycle = get_lifecycle(pocket_ic, swap_canister_id);
        let lifecycle = lifecycle.lifecycle.unwrap();
        if lifecycle == expected_lifecycle as i32 {
            return Ok(());
        }
        last_lifecycle = Some(lifecycle);
        pocket_ic.advance_time(Duration::from_millis(100));
    }
    Err(format!(
        "Looks like the SNS lifecycle {:?} is never going to be reached: {:#?}",
        expected_lifecycle, last_lifecycle,
    ))
}

/// Returns:
/// * `Ok(None)` if any of the top-level fields of this `auto_finalization_status` are unset, i.e.:
///   `has_auto_finalize_been_attempted`, `is_auto_finalize_enabled`,
///   or `auto_finalize_swap_response`.
/// * `Err` if `auto_finalize_swap_response` contains any errors.
/// * `Ok(Some(response))` -- otherwise.
fn validate_auto_finalization_status(
    auto_finalization_status: &GetAutoFinalizationStatusResponse,
) -> Result<Option<&FinalizeSwapResponse>, String> {
    if auto_finalization_status
        .has_auto_finalize_been_attempted
        .is_none()
        || auto_finalization_status.is_auto_finalize_enabled.is_none()
    {
        return Ok(None);
    }
    let Some(ref auto_finalize_swap_response) =
        auto_finalization_status.auto_finalize_swap_response
    else {
        return Ok(None);
    };
    if let Some(ref error_message) = auto_finalize_swap_response.error_message {
        // If auto_finalization_status contains an error, we return that error.
        return Err(error_message.clone());
    }
    Ok(Some(auto_finalize_swap_response))
}

/// Returns:
/// * `Ok(true)` if auto-finalization completed, reaching `Lifecycle::Committed`.
/// * `Ok(false)` if auto-finalization is still happening (or swap lifecycle reached a final state
///   other than Committed), i.e., one of the following conditions holds:
///     1. Any of the top-level fields of this `auto_finalization_status` are unset:
///       `has_auto_finalize_been_attempted`, `is_auto_finalize_enabled`,
///        or `auto_finalize_swap_response`.
///     2. `auto_finalize_swap_response` does not match the expected pattern for a *committed* SNS
///        Swap's `auto_finalize_swap_response`. In particular:
///        - `set_dapp_controllers_call_result` must be `None`,
///        - `sweep_sns_result` must be `Some`.
/// * `Err` if `auto_finalize_swap_response` contains any errors.
fn is_auto_finalization_status_committed_or_err(
    auto_finalization_status: &GetAutoFinalizationStatusResponse,
) -> Result<bool, String> {
    let Some(auto_finalize_swap_response) =
        validate_auto_finalization_status(auto_finalization_status)?
    else {
        return Ok(false);
    };
    // Otherwise, either `auto_finalization_status` matches the expected structure of it does not
    // indicate that the swap has been committed yet.
    Ok(matches!(
        auto_finalize_swap_response,
        FinalizeSwapResponse {
            sweep_icp_result: Some(_),
            create_sns_neuron_recipes_result: Some(_),
            settle_neurons_fund_participation_result: Some(_),
            sweep_sns_result: Some(_),
            claim_neuron_result: Some(_),
            set_mode_call_result: Some(_),
            set_dapp_controllers_call_result: None,
            settle_community_fund_participation_result: None,
            error_message: None,
        }
    ))
}

/// Returns:
/// * `Ok(true)` if auto-finalization completed, reaching `Lifecycle::Aborted`.
/// * `Ok(false)` if auto-finalization is still happening (or swap lifecycle reached a final state
///   other than Aborted), i.e., one of the following conditions holds:
///     1. Any of the top-level fields of this `auto_finalization_status` are unset:
///       `has_auto_finalize_been_attempted`, `is_auto_finalize_enabled`,
///        or `auto_finalize_swap_response`.
///     2. `auto_finalize_swap_response` does not match the expected pattern for an *aborted* SNS
///        Swap's `auto_finalize_swap_response`. In particular:
///        - `set_dapp_controllers_call_result` must be `Some`,
///        - `sweep_sns_result` must be `None`.
/// * `Err` if `auto_finalize_swap_response` contains any errors.
fn is_auto_finalization_status_aborted_or_err(
    auto_finalization_status: &GetAutoFinalizationStatusResponse,
) -> Result<bool, String> {
    let Some(auto_finalize_swap_response) =
        validate_auto_finalization_status(auto_finalization_status)?
    else {
        return Ok(false);
    };
    // Otherwise, either `auto_finalization_status` matches the expected structure of it does not
    // indicate that the swap has been aborted yet.
    Ok(matches!(
        auto_finalize_swap_response,
        FinalizeSwapResponse {
            sweep_icp_result: Some(_),
            set_dapp_controllers_call_result: Some(_),
            settle_neurons_fund_participation_result: Some(_),
            create_sns_neuron_recipes_result: None,
            sweep_sns_result: None,
            claim_neuron_result: None,
            set_mode_call_result: None,
            settle_community_fund_participation_result: None,
            error_message: None,
        }
    ))
}

/// Subset of `Lifecycle` indicating terminal statuses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SwapFinalizationStatus {
    Aborted,
    Committed,
}

fn await_swap_finalization_status(
    pocket_ic: &PocketIc,
    swap_canister_id: PrincipalId,
    status: SwapFinalizationStatus,
) -> Result<GetAutoFinalizationStatusResponse, String> {
    let mut last_auto_finalization_status = None;
    for _attempt_count in 1..=100 {
        pocket_ic.tick();
        let auto_finalization_status = get_auto_finalization_status(pocket_ic, swap_canister_id);
        match status {
            SwapFinalizationStatus::Aborted => {
                if is_auto_finalization_status_aborted_or_err(&auto_finalization_status)? {
                    return Ok(auto_finalization_status);
                }
            }
            SwapFinalizationStatus::Committed => {
                if is_auto_finalization_status_committed_or_err(&auto_finalization_status)? {
                    return Ok(auto_finalization_status);
                }
            }
        }
        last_auto_finalization_status = Some(auto_finalization_status);
        pocket_ic.advance_time(Duration::from_millis(100));
    }
    Err(format!(
        "Looks like the expected SNS auto-finalization status is never going to be reached: {:#?}",
        last_auto_finalization_status,
    ))
}

fn get_auto_finalization_status(
    pocket_ic: &PocketIc,
    swap_canister_id: PrincipalId,
) -> GetAutoFinalizationStatusResponse {
    let result = pocket_ic
        .update_call(
            swap_canister_id.into(),
            Principal::anonymous(),
            "get_auto_finalization_status",
            Encode!(&GetAutoFinalizationStatusRequest {}).unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to get_auto_finalization_status failed: {:#?}", s),
    };
    Decode!(&result, GetAutoFinalizationStatusResponse).unwrap()
}

fn get_mode(pocket_ic: &PocketIc, sns_governance_canister_id: PrincipalId) -> GetModeResponse {
    let result = pocket_ic
        .update_call(
            sns_governance_canister_id.into(),
            Principal::anonymous(),
            "get_mode",
            Encode!(&GetMode {}).unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to get_mode failed: {:#?}", s),
    };
    Decode!(&result, GetModeResponse).unwrap()
}

fn get_deployed_sns_by_proposal_id(
    pocket_ic: &PocketIc,
    proposal_id: ProposalId,
) -> GetDeployedSnsByProposalIdResponse {
    let result = pocket_ic
        .update_call(
            SNS_WASM_CANISTER_ID.into(),
            Principal::anonymous(),
            "get_deployed_sns_by_proposal_id",
            Encode!(&GetDeployedSnsByProposalIdRequest {
                proposal_id: proposal_id.id
            })
            .unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to get_deployed_sns_by_proposal_id failed: {:#?}", s),
    };
    Decode!(&result, GetDeployedSnsByProposalIdResponse).unwrap()
}

fn account_balance(pocket_ic: &PocketIc, account: &AccountIdentifier) -> Tokens {
    let result = pocket_ic
        .update_call(
            LEDGER_CANISTER_ID.into(),
            Principal::from(*TEST_NEURON_1_OWNER_PRINCIPAL),
            "account_balance",
            Encode!(&BinaryAccountBalanceArgs {
                account: account.to_address(),
            })
            .unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to account_balance failed: {:#?}", s),
    };
    Decode!(&result, Tokens).unwrap()
}

fn icrc1_transfer(
    pocket_ic: &PocketIc,
    sender: PrincipalId,
    transfer_arg: TransferArg,
) -> Result<Nat, TransferError> {
    let result = pocket_ic
        .update_call(
            LEDGER_CANISTER_ID.into(),
            Principal::from(sender),
            "icrc1_transfer",
            Encode!(&transfer_arg).unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to icrc1_transfer failed: {:#?}", s),
    };
    Decode!(&result, Result<Nat, TransferError>).unwrap()
}

fn nns_governance_get_proposal_info(
    pocket_ic: &PocketIc,
    proposal_id: u64,
    sender: PrincipalId,
) -> ProposalInfo {
    let result = pocket_ic
        .update_call(
            GOVERNANCE_CANISTER_ID.into(),
            Principal::from(sender),
            "get_proposal_info",
            Encode!(&proposal_id).unwrap(),
        )
        .unwrap();

    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!(
                "get_proposal_info was rejected by the NNS governance canister: {:#?}",
                reject
            )
        }
    };
    Decode!(&result, Option<ProposalInfo>).unwrap().unwrap()
}

fn propose_and_wait(pocket_ic: &PocketIc, proposal: Proposal) -> Result<ProposalInfo, String> {
    let neuron_id = NeuronId {
        id: TEST_NEURON_1_ID,
    };
    let command: manage_neuron::Command = manage_neuron::Command::MakeProposal(Box::new(proposal));
    let response = manage_neuron(
        pocket_ic,
        *TEST_NEURON_1_OWNER_PRINCIPAL,
        neuron_id,
        command,
    );
    let response = match response.command {
        Some(manage_neuron_response::Command::MakeProposal(response)) => response,
        _ => panic!("Proposal failed: {:#?}", response),
    };
    let proposal_id = response
        .proposal_id
        .unwrap_or_else(|| {
            panic!(
                "First proposal response did not contain a proposal_id: {:#?}",
                response
            )
        })
        .id;
    nns_wait_for_proposal_execution(pocket_ic, proposal_id)
}

fn nns_wait_for_proposal_execution(
    pocket_ic: &PocketIc,
    proposal_id: u64,
) -> Result<ProposalInfo, String> {
    // We create some blocks until the proposal has finished executing (machine.tick())
    let mut last_proposal_info = None;
    for _attempt_count in 1..=50 {
        pocket_ic.tick();
        let proposal_info =
            nns_governance_get_proposal_info(pocket_ic, proposal_id, PrincipalId::new_anonymous());
        if proposal_info.executed_timestamp_seconds > 0 {
            return Ok(proposal_info);
        }
        assert_eq!(
            proposal_info.failure_reason, None,
            "Proposal execution failed: {:#?}",
            proposal_info
        );
        last_proposal_info = Some(proposal_info);
        pocket_ic.advance_time(Duration::from_millis(100));
    }
    Err(format!(
        "Looks like proposal {:?} is never going to be executed: {:#?}",
        proposal_id, last_proposal_info,
    ))
}

fn add_wasm(pocket_ic: &PocketIc, wasm: SnsWasm) -> Result<ProposalInfo, String> {
    let hash = wasm.sha256_hash();
    let canister_type = wasm.canister_type;
    let payload = AddWasmRequest {
        hash: hash.to_vec(),
        wasm: Some(wasm),
    };
    let proposal = Proposal {
        title: Some(format!("Add WASM for SNS canister type {}", canister_type)),
        summary: "summary".to_string(),
        url: "".to_string(),
        action: Some(proposal::Action::ExecuteNnsFunction(ExecuteNnsFunction {
            nns_function: NnsFunction::AddSnsWasm as i32,
            payload: Encode!(&payload).expect("Error encoding proposal payload"),
        })),
    };
    propose_and_wait(pocket_ic, proposal)
}

fn add_real_wasms_to_sns_wasm(
    pocket_ic: &PocketIc,
) -> Result<HashMap<SnsCanisterType, (ProposalInfo, SnsWasm)>, String> {
    let root_wasm = build_root_sns_wasm();
    let root_proposal_info = add_wasm(pocket_ic, root_wasm.clone())?;

    let gov_wasm = build_governance_sns_wasm();
    let gov_proposal_info = add_wasm(pocket_ic, gov_wasm.clone())?;

    let ledger_wasm = build_ledger_sns_wasm();
    let ledger_proposal_info = add_wasm(pocket_ic, ledger_wasm.clone())?;

    let swap_wasm = build_swap_sns_wasm();
    let swap_proposal_info = add_wasm(pocket_ic, swap_wasm.clone())?;

    let archive_wasm = build_archive_sns_wasm();
    let archive_proposal_info = add_wasm(pocket_ic, archive_wasm.clone())?;

    let index_wasm = build_index_sns_wasm();
    let index_proposal_info = add_wasm(pocket_ic, index_wasm.clone())?;

    Ok(hashmap! {
        SnsCanisterType::Root => (root_proposal_info, root_wasm),
        SnsCanisterType::Governance => (gov_proposal_info, gov_wasm),
        SnsCanisterType::Ledger => (ledger_proposal_info, ledger_wasm),
        SnsCanisterType::Swap => (swap_proposal_info, swap_wasm),
        SnsCanisterType::Archive => (archive_proposal_info, archive_wasm),
        SnsCanisterType::Index => (index_proposal_info, index_wasm),
    })
}

fn install_canister(pocket_ic: &PocketIc, name: &str, id: CanisterId, arg: Vec<u8>, wasm: Wasm) {
    let canister_id = pocket_ic
        .create_canister_with_id(None, None, id.into())
        .unwrap();
    pocket_ic.install_canister(canister_id, wasm.bytes(), arg, None);
    pocket_ic.add_cycles(canister_id, STARTING_CYCLES_PER_CANISTER);
    let subnet_id = pocket_ic.get_subnet(canister_id).unwrap();
    println!(
        "Installed the {} canister ({}) onto {:?}",
        name, canister_id, subnet_id
    );
}

fn install_nns_canisters(
    pocket_ic: &PocketIc,
    test_user_icp_ledger_account: AccountIdentifier,
    test_user_icp_ledger_initial_balance: Tokens,
) {
    let topology = pocket_ic.topology();

    let sns_subnet_id = topology.get_sns().unwrap();
    let sns_subnet_id = PrincipalId::from(sns_subnet_id);
    let sns_subnet_id = SubnetId::from(sns_subnet_id);
    println!("sns_subnet_id = {:?}", sns_subnet_id);
    let nns_init_payload = NnsInitPayloadsBuilder::new()
        .with_initial_invariant_compliant_mutations()
        .with_test_neurons_fund_neurons(1_500_000 * E8)
        .with_sns_dedicated_subnets(vec![sns_subnet_id])
        .with_sns_wasm_access_controls(true)
        .with_ledger_account(
            test_user_icp_ledger_account,
            test_user_icp_ledger_initial_balance,
        )
        .build();
    install_canister(
        pocket_ic,
        "ICP Ledger",
        LEDGER_CANISTER_ID,
        Encode!(&nns_init_payload.ledger).unwrap(),
        build_ledger_wasm(),
    );
    install_canister(
        pocket_ic,
        "NNS Root",
        ROOT_CANISTER_ID,
        Encode!(&nns_init_payload.root).unwrap(),
        build_root_wasm(),
    );
    install_canister(
        pocket_ic,
        "NNS Governance",
        GOVERNANCE_CANISTER_ID,
        nns_init_payload.governance.encode_to_vec(),
        build_test_governance_wasm(),
    );
    install_canister(
        pocket_ic,
        "NNS SNS-W",
        SNS_WASM_CANISTER_ID,
        Encode!(&nns_init_payload.sns_wasms).unwrap(),
        build_sns_wasms_wasm(),
    );
    add_real_wasms_to_sns_wasm(pocket_ic).unwrap();
}

fn test_sns_lifecycle(
    ensure_swap_time_run_out_without_sufficient_direct_participation: bool,
    create_service_nervous_system_proposal: CreateServiceNervousSystem,
) {
    // 1. Prepare the world
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .build();

    let direct_participant = PrincipalId::new_user_test_id(1);
    let direct_participant_icp_account = AccountIdentifier::new(direct_participant, None);
    install_nns_canisters(
        &pocket_ic,
        direct_participant_icp_account,
        Tokens::from_e8s(1_000_000 * E8),
    );

    // 2. Create an SNS instance
    let swap_parameters = create_service_nervous_system_proposal
        .swap_parameters
        .clone()
        .unwrap();
    let proposal_info = propose_and_wait(
        &pocket_ic,
        Proposal {
            title: Some(format!("Create SNS #{}", 1)),
            summary: "".to_string(),
            url: "".to_string(),
            action: Some(proposal::Action::CreateServiceNervousSystem(
                create_service_nervous_system_proposal,
            )),
        },
    )
    .unwrap();
    let proposal_id = proposal_info.id.unwrap();

    let Some(GetDeployedSnsByProposalIdResult::DeployedSns(deployed_sns)) =
        get_deployed_sns_by_proposal_id(&pocket_ic, proposal_id)
            .get_deployed_sns_by_proposal_id_result
    else {
        panic!(
            "Proposal {:?} did not result in a successfully deployed SNS",
            proposal_id
        );
    };

    // The proposal created a Swap and SNS Governance canisters that we can now start
    // interacting with.
    let sns_governance_canister_id = deployed_sns.governance_canister_id.unwrap();
    let swap_canister_id = deployed_sns.swap_canister_id.unwrap();

    // Assert that the mode of SNS Governance is not PreInitializationSwap
    assert_eq!(
        get_mode(&pocket_ic, sns_governance_canister_id)
            .mode
            .unwrap(),
        Mode::PreInitializationSwap as i32
    );

    await_swap_lifecycle(&pocket_ic, swap_canister_id, Lifecycle::Open).unwrap();
    let derived_state = get_derived_state(&pocket_ic, swap_canister_id);
    assert_eq!(derived_state.direct_participation_icp_e8s.unwrap(), 0);
    assert_eq!(derived_state.neurons_fund_participation_icp_e8s.unwrap(), 0);

    // 3. Transfer ICP to our participant's SNSes subaccount
    let direct_participant_sns_subaccount = Some(principal_to_subaccount(&direct_participant));
    let direct_participant_sns_account = Account {
        owner: swap_canister_id.0,
        subaccount: direct_participant_sns_subaccount,
    };
    // Participate with as much as we have minus the transfer fee
    assert_eq!(
        account_balance(&pocket_ic, &direct_participant_icp_account),
        Tokens::from_e8s(1_000_000 * E8)
    );
    let effective_participation_amount_e8s = 1_000_000 * E8 - 10_000;
    icrc1_transfer(
        &pocket_ic,
        direct_participant,
        TransferArg {
            from_subaccount: None,
            to: direct_participant_sns_account,
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(effective_participation_amount_e8s),
        },
    )
    .unwrap();
    assert_eq!(
        account_balance(&pocket_ic, &direct_participant_icp_account),
        Tokens::from_e8s(0)
    );

    // 4. Force the swap to reach either Aborted, or Committed.
    if ensure_swap_time_run_out_without_sufficient_direct_participation {
        // ... either by advancing the time
        pocket_ic.advance_time(Duration::from_secs(30 * SECONDS_PER_DAY)); // 30 days
        await_swap_lifecycle(&pocket_ic, swap_canister_id, Lifecycle::Aborted).unwrap();
    } else {
        // ... or by participating in the swap
        refresh_buyer_tokens(&pocket_ic, swap_canister_id, direct_participant, None);
        await_swap_lifecycle(&pocket_ic, swap_canister_id, Lifecycle::Committed).unwrap();
    }

    // Double check that auto-finalization worked as expected, i.e.,
    // `Swap.get_auto_finalization_status` returns a structure with the top-level fields being set,
    // no errors, and matching the expected pattern (different for `Aborted` and `Committed`).
    // It may take some time for the process to complete, so we should await (implemented via a busy
    // loop) rather than try just once.
    let expected_swap_finalization_status =
        if ensure_swap_time_run_out_without_sufficient_direct_participation {
            SwapFinalizationStatus::Aborted
        } else {
            SwapFinalizationStatus::Committed
        };
    if let Err(err) = await_swap_finalization_status(
        &pocket_ic,
        swap_canister_id,
        expected_swap_finalization_status,
    ) {
        println!("{}", err);
        panic!(
            "Awaiting Swap finalization status {:?} failed.",
            expected_swap_finalization_status
        );
    }

    // Inspect the final derived state
    let derived_state = get_derived_state(&pocket_ic, swap_canister_id);
    if ensure_swap_time_run_out_without_sufficient_direct_participation {
        assert_eq!(derived_state.direct_participation_icp_e8s.unwrap(), 0);
    } else {
        assert_eq!(
            derived_state.direct_participation_icp_e8s.unwrap(),
            650_000 * E8
        );
    }

    // Assert that the mode of SNS Governance is correct
    if ensure_swap_time_run_out_without_sufficient_direct_participation {
        assert_eq!(
            get_mode(&pocket_ic, sns_governance_canister_id)
                .mode
                .unwrap(),
            Mode::PreInitializationSwap as i32,
        );
    } else {
        assert_eq!(
            get_mode(&pocket_ic, sns_governance_canister_id)
                .mode
                .unwrap(),
            Mode::Normal as i32
        );
    }

    if swap_parameters
        .neurons_fund_participation
        .unwrap_or_default()
    {
        if ensure_swap_time_run_out_without_sufficient_direct_participation {
            assert_eq!(
                derived_state.neurons_fund_participation_icp_e8s.unwrap(),
                0,
                "Neurons' Fund participation should not be provided to an aborted SNS swap.",
            );
        } else {
            assert_eq!(
                derived_state.neurons_fund_participation_icp_e8s.unwrap(),
                150_000 * E8,
                "Neurons' Fund participation is expected to be at 10% of its total maturity.",
            );
        }
    } else {
        assert_eq!(
            derived_state.neurons_fund_participation_icp_e8s.unwrap(),
            0,
            "Neurons' Fund participation has not been requested, yet there is some.",
        );
    }
}

#[test]
fn test_sns_lifecycle_happy_scenario_with_neurons_fund_participation() {
    test_sns_lifecycle(
        true,
        CreateServiceNervousSystemBuilder::default()
            .neurons_fund_participation(false)
            .build(),
    );
}

#[test]
fn test_sns_lifecycle_happy_scenario_without_neurons_fund_participation() {
    test_sns_lifecycle(
        false,
        CreateServiceNervousSystemBuilder::default()
            .neurons_fund_participation(false)
            .build(),
    );
}

#[test]
fn test_sns_lifecycle_swap_timeout_with_neurons_fund_participation() {
    test_sns_lifecycle(
        true,
        CreateServiceNervousSystemBuilder::default()
            .neurons_fund_participation(true)
            .build(),
    );
}

#[test]
fn test_sns_lifecycle_swap_timeout_without_neurons_fund_participation() {
    test_sns_lifecycle(
        false,
        CreateServiceNervousSystemBuilder::default()
            .neurons_fund_participation(true)
            .build(),
    );
}

#[test]
fn test_sns_lifecycle_happy_scenario_with_lots_of_dev_neurons() {
    let developer_neurons = (0..MAX_DEVELOPER_DISTRIBUTION_COUNT)
        .map(|i| NeuronDistribution {
            controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
            memo: Some(i as u64),
            // Set the dissolve delay to ~10 days, which is somewhat arbitrary.
            // It just needs to be not greater than the maximum dissolve delay set elsewhere in the CreateServiceNervousSystem proposal,
            // but high enough that it still has voting power
            dissolve_delay: Some(DurationPb::from_secs(927391)),
            stake: Some(TokensPb::from_e8s(E8)),
            vesting_period: Some(DurationPb::from_secs(0)),
        })
        .collect();

    let create_service_nervous_system_proposal = CreateServiceNervousSystemBuilder::default()
        .neurons_fund_participation(false)
        .initial_token_distribution_developer_neurons(developer_neurons)
        .initial_token_distribution_total(TokensPb::from_e8s(
            MAX_DEVELOPER_DISTRIBUTION_COUNT as u64 * E8,
        ))
        .build();

    test_sns_lifecycle(true, create_service_nervous_system_proposal);
}
