use candid::{Decode, Encode, Nat, Principal};
use canister_test::Wasm;
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_ledger_core::Tokens;
use ic_nervous_system_common::E8;
use ic_nervous_system_common_test_keys::TEST_NEURON_1_OWNER_PRINCIPAL;
use ic_nervous_system_proto::pb::v1::Tokens as TokensPb;
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_nns_constants::{
    GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID, ROOT_CANISTER_ID, SNS_WASM_CANISTER_ID,
};
use ic_nns_governance::{
    governance::test_data::CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING,
    pb::v1::{
        create_service_nervous_system::SwapParameters, manage_neuron, manage_neuron_response,
        proposal, CreateServiceNervousSystem, ExecuteNnsFunction, ManageNeuron,
        ManageNeuronResponse, NnsFunction, Proposal, ProposalInfo,
    },
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
use ic_sns_swap::{
    pb::v1::{
        GetAutoFinalizationStatusRequest, GetAutoFinalizationStatusResponse,
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
    pic: &PocketIc,
    sender: PrincipalId,
    neuron_id: NeuronId,
    command: manage_neuron::Command,
) -> ManageNeuronResponse {
    let result = pic
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
    pic: &PocketIc,
    swap_canister_id: PrincipalId,
    buyer: PrincipalId,
    confirmation_text: Option<String>,
) -> RefreshBuyerTokensResponse {
    let result = pic
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

fn get_derived_state(pic: &PocketIc, swap_canister_id: PrincipalId) -> GetDerivedStateResponse {
    let result = pic
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

fn get_lifecycle(pic: &PocketIc, swap_canister_id: PrincipalId) -> GetLifecycleResponse {
    let result = pic
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
    pic: &PocketIc,
    swap_canister_id: PrincipalId,
    expected_lifecycle: Lifecycle,
) -> Result<(), String> {
    let mut attempt_count = 0;
    let mut last_lifecycle = None;
    while attempt_count < 50 {
        attempt_count += 1;
        pic.tick();
        let lifecycle = get_lifecycle(pic, swap_canister_id);
        let lifecycle = lifecycle.lifecycle.unwrap();
        if lifecycle == expected_lifecycle as i32 {
            return Ok(());
        }
        last_lifecycle = Some(lifecycle);
        pic.advance_time(Duration::from_millis(100));
    }
    Err(format!(
        "Looks like the SNS lifecycle {:?} is never going to be reached: {:#?}",
        expected_lifecycle, last_lifecycle,
    ))
}

fn await_swap_finalization(
    pic: &PocketIc,
    swap_canister_id: PrincipalId,
) -> Result<GetAutoFinalizationStatusResponse, String> {
    let mut attempt_count = 0;
    let mut last_auto_finalization_status = None;
    while attempt_count < 500 {
        attempt_count += 1;
        pic.tick();
        let auto_finalization_status = get_auto_finalization_status(pic, swap_canister_id);
        if auto_finalization_status
            .has_auto_finalize_been_attempted
            .unwrap_or(false)
            && auto_finalization_status
                .is_auto_finalize_enabled
                .unwrap_or(false)
        {
            if let Some(ref auto_finalize_swap_response) =
                auto_finalization_status.auto_finalize_swap_response
            {
                if let Some(ref error_message) = auto_finalize_swap_response.error_message {
                    return Err(error_message.clone());
                } else if auto_finalize_swap_response.sweep_icp_result.is_some()
                    && auto_finalize_swap_response.sweep_sns_result.is_some()
                    && auto_finalize_swap_response.claim_neuron_result.is_some()
                    && auto_finalize_swap_response.set_mode_call_result.is_some()
                    && auto_finalize_swap_response
                        .create_sns_neuron_recipes_result
                        .is_some()
                    && auto_finalize_swap_response
                        .settle_neurons_fund_participation_result
                        .is_some()
                    // Legacy field, expected to be unset.
                    && auto_finalize_swap_response
                        .settle_community_fund_participation_result
                        .is_none()
                {
                    // Wo do not check auto_finalize_swap_response.set_dapp_controllers_call_result
                    // as that is supposed to be set only if the swap is aborted.
                    return Ok(auto_finalization_status);
                }
            }
        }
        last_auto_finalization_status = Some(auto_finalization_status);
        pic.advance_time(Duration::from_millis(100));
    }
    Err(format!(
        "Looks like the expected SNS auto-finalization status is never going to be reached: {:#?}",
        last_auto_finalization_status,
    ))
}

fn get_auto_finalization_status(
    pic: &PocketIc,
    swap_canister_id: PrincipalId,
) -> GetAutoFinalizationStatusResponse {
    let result = pic
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

fn get_mode(pic: &PocketIc, sns_governance_canister_id: PrincipalId) -> GetModeResponse {
    let result = pic
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
    pic: &PocketIc,
    proposal_id: ProposalId,
) -> GetDeployedSnsByProposalIdResponse {
    let result = pic
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

fn account_balance(pic: &PocketIc, account: &AccountIdentifier) -> Tokens {
    let result = pic
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
    pic: &PocketIc,
    sender: PrincipalId,
    transfer_arg: TransferArg,
) -> Result<Nat, TransferError> {
    let result = pic
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
    pic: &PocketIc,
    proposal_id: u64,
    sender: PrincipalId,
) -> ProposalInfo {
    let result = pic
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

fn propose_and_wait(pic: &PocketIc, proposal: Proposal) -> Result<ProposalInfo, String> {
    let neuron_id = NeuronId {
        id: TEST_NEURON_1_ID,
    };
    let command: manage_neuron::Command = manage_neuron::Command::MakeProposal(Box::new(proposal));
    let response = manage_neuron(pic, *TEST_NEURON_1_OWNER_PRINCIPAL, neuron_id, command);
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
    nns_wait_for_proposal_execution(pic, proposal_id)
}

fn nns_wait_for_proposal_execution(
    pic: &PocketIc,
    proposal_id: u64,
) -> Result<ProposalInfo, String> {
    // We create some blocks until the proposal has finished executing (machine.tick())
    let mut attempt_count = 0;
    let mut last_proposal_info = None;
    while attempt_count < 50 {
        attempt_count += 1;
        pic.tick();
        let proposal_info =
            nns_governance_get_proposal_info(pic, proposal_id, PrincipalId::new_anonymous());
        if proposal_info.executed_timestamp_seconds > 0 {
            return Ok(proposal_info);
        }
        assert_eq!(
            proposal_info.failure_reason, None,
            "Proposal execution failed: {:#?}",
            proposal_info
        );
        last_proposal_info = Some(proposal_info);
        pic.advance_time(Duration::from_millis(100));
    }
    Err(format!(
        "Looks like proposal {:?} is never going to be executed: {:#?}",
        proposal_id, last_proposal_info,
    ))
}

fn add_wasm(pic: &PocketIc, wasm: SnsWasm) -> Result<ProposalInfo, String> {
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
    propose_and_wait(pic, proposal)
}

fn add_real_wasms_to_sns_wasm(
    pic: &PocketIc,
) -> Result<HashMap<SnsCanisterType, (ProposalInfo, SnsWasm)>, String> {
    let root_wasm = build_root_sns_wasm();
    let root_proposal_info = add_wasm(pic, root_wasm.clone())?;

    let gov_wasm = build_governance_sns_wasm();
    let gov_proposal_info = add_wasm(pic, gov_wasm.clone())?;

    let ledger_wasm = build_ledger_sns_wasm();
    let ledger_proposal_info = add_wasm(pic, ledger_wasm.clone())?;

    let swap_wasm = build_swap_sns_wasm();
    let swap_proposal_info = add_wasm(pic, swap_wasm.clone())?;

    let archive_wasm = build_archive_sns_wasm();
    let archive_proposal_info = add_wasm(pic, archive_wasm.clone())?;

    let index_wasm = build_index_sns_wasm();
    let index_proposal_info = add_wasm(pic, index_wasm.clone())?;

    Ok(hashmap! {
        SnsCanisterType::Root => (root_proposal_info, root_wasm),
        SnsCanisterType::Governance => (gov_proposal_info, gov_wasm),
        SnsCanisterType::Ledger => (ledger_proposal_info, ledger_wasm),
        SnsCanisterType::Swap => (swap_proposal_info, swap_wasm),
        SnsCanisterType::Archive => (archive_proposal_info, archive_wasm),
        SnsCanisterType::Index => (index_proposal_info, index_wasm),
    })
}

fn install_canister(pic: &PocketIc, name: &str, id: CanisterId, arg: Vec<u8>, wasm: Wasm) {
    let canister_id = pic.create_canister_with_id(None, None, id.into()).unwrap();
    pic.install_canister(canister_id, wasm.bytes(), arg, None);
    pic.add_cycles(canister_id, STARTING_CYCLES_PER_CANISTER);
    let subnet_id = pic.get_subnet(canister_id).unwrap();
    println!(
        "Installed the {} canister ({}) onto {:?}",
        name, canister_id, subnet_id
    );
}

fn test_sns_lifecycle(neurons_fund_participation: bool) {
    // 0. Prepare the world
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .build();
    let direct_participant = PrincipalId::new_user_test_id(1);
    let direct_participant_icp_account = AccountIdentifier::new(direct_participant, None);

    // 1. Install the NNS canisters
    let topology = pic.topology();
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
            direct_participant_icp_account,
            Tokens::from_e8s(1_000_000 * E8),
        )
        .build();

    install_canister(
        &pic,
        "ICP Ledger",
        LEDGER_CANISTER_ID,
        Encode!(&nns_init_payload.ledger).unwrap(),
        build_ledger_wasm(),
    );
    install_canister(
        &pic,
        "NNS Root",
        ROOT_CANISTER_ID,
        Encode!(&nns_init_payload.root).unwrap(),
        build_root_wasm(),
    );
    install_canister(
        &pic,
        "NNS Governance",
        GOVERNANCE_CANISTER_ID,
        nns_init_payload.governance.encode_to_vec(),
        build_test_governance_wasm(),
    );
    install_canister(
        &pic,
        "NNS SNS-W",
        SNS_WASM_CANISTER_ID,
        Encode!(&nns_init_payload.sns_wasms).unwrap(),
        build_sns_wasms_wasm(),
    );
    add_real_wasms_to_sns_wasm(&pic).unwrap();

    // 2. Create an SNS instance
    let swap_parameters = CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING
        .swap_parameters
        .clone()
        .unwrap();
    let swap_parameters = SwapParameters {
        // This is the essential flag toggled by proptest
        neurons_fund_participation: Some(neurons_fund_participation),
        // Ensure just one huge direct participant can finalize the swap.
        minimum_participants: Some(1),
        minimum_participant_icp: Some(TokensPb::from_e8s(150_000 * E8)),
        maximum_participant_icp: Some(TokensPb::from_e8s(650_000 * E8)),
        minimum_direct_participation_icp: Some(TokensPb::from_e8s(150_000 * E8)),
        maximum_direct_participation_icp: Some(TokensPb::from_e8s(650_000 * E8)),
        // Instantly transit from Lifecycle::Adopted to Lifecycle::Open.
        start_time: None,
        // Avoid the need to say that we're human.
        confirmation_text: None,
        ..swap_parameters
    };
    let csns = CreateServiceNervousSystem {
        dapp_canisters: vec![],
        swap_parameters: Some(swap_parameters),
        ..CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING.clone()
    };
    let proposal_info = propose_and_wait(
        &pic,
        Proposal {
            title: Some(format!("Create SNS #{}", 1)),
            summary: "".to_string(),
            url: "".to_string(),
            action: Some(proposal::Action::CreateServiceNervousSystem(csns)),
        },
    )
    .unwrap();
    let proposal_id = proposal_info.id.unwrap();

    let Some(GetDeployedSnsByProposalIdResult::DeployedSns(deployed_sns)) =
        get_deployed_sns_by_proposal_id(&pic, proposal_id).get_deployed_sns_by_proposal_id_result
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
        get_mode(&pic, sns_governance_canister_id).mode.unwrap(),
        Mode::PreInitializationSwap as i32
    );

    await_swap_lifecycle(&pic, swap_canister_id, Lifecycle::Open).unwrap();
    let derived_state = get_derived_state(&pic, swap_canister_id);
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
        account_balance(&pic, &direct_participant_icp_account),
        Tokens::from_e8s(1_000_000 * E8)
    );
    let effective_participation_amount_e8s = 1_000_000 * E8 - 10_000;
    icrc1_transfer(
        &pic,
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
        account_balance(&pic, &direct_participant_icp_account),
        Tokens::from_e8s(0)
    );

    // 4. Participate in the swap
    refresh_buyer_tokens(&pic, swap_canister_id, direct_participant, None);

    // Wait Swap's auto-finalization (since maximum direct participation should have been reached)
    await_swap_lifecycle(&pic, swap_canister_id, Lifecycle::Committed).unwrap();

    // Double check that auto-finalization worked as expected. It takes many more blocks to fully
    // finalize.
    if let Err(err) = await_swap_finalization(&pic, swap_canister_id) {
        println!("{}", err);
        panic!("Awaiting Swap finalization failed.");
    }

    // Inspect the final derived state
    let derived_state = get_derived_state(&pic, swap_canister_id);
    assert_eq!(
        derived_state.direct_participation_icp_e8s.unwrap(),
        650_000 * E8
    );

    // Assert that the mode of SNS Governance is not Normal
    assert_eq!(
        get_mode(&pic, sns_governance_canister_id).mode.unwrap(),
        Mode::Normal as i32
    );

    // Assert the input-dependent postcondition
    if neurons_fund_participation {
        // 10% of the total maturity_equalivaltn_icp_e8s of the Neurons' Fund.
        assert_eq!(
            derived_state.neurons_fund_participation_icp_e8s.unwrap(),
            150_000 * E8
        );
    } else {
        // The Neurons' Fund did not participate anything.
        assert_eq!(derived_state.neurons_fund_participation_icp_e8s.unwrap(), 0);
    }
}

#[test]
fn test_sns_lifecycle_with_neurons_fund_participation() {
    test_sns_lifecycle(true);
}

#[test]
fn test_sns_lifecycle_without_neurons_fund_participation() {
    test_sns_lifecycle(false);
}
