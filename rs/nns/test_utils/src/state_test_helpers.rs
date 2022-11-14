use crate::common::{
    build_cmc_wasm, build_genesis_token_wasm, build_governance_wasm, build_ledger_wasm,
    build_lifeline_wasm, build_registry_wasm, build_root_wasm, build_sns_wasms_wasm,
    NnsInitPayloads,
};
use candid::{Decode, Encode, Nat};
use canister_test::Wasm;
use dfn_candid::candid_one;
use ic_base_types::{CanisterId, PrincipalId};
use ic_ic00_types::{CanisterInstallMode, CanisterSettingsArgs, UpdateSettingsArgs};
use ic_icrc1::endpoints::{TransferArg, TransferError};
use ic_icrc1::Account;
use ic_nervous_system_common::ledger::compute_neuron_staking_subaccount;
use ic_nns_constants::{
    memory_allocation_of, CYCLES_MINTING_CANISTER_ID, GENESIS_TOKEN_CANISTER_ID,
    GOVERNANCE_CANISTER_ID, GOVERNANCE_CANISTER_INDEX_IN_NNS_SUBNET, IDENTITY_CANISTER_ID,
    LEDGER_CANISTER_ID, LIFELINE_CANISTER_ID, NNS_UI_CANISTER_ID, REGISTRY_CANISTER_ID,
    ROOT_CANISTER_ID, SNS_WASM_CANISTER_ID, SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET,
};
use ic_nns_governance::pb::v1::Governance;
use ic_sns_wasm::init::SnsWasmCanisterInitPayload;
use ic_state_machine_tests::StateMachine;
use ic_test_utilities::universal_canister::{
    call_args, wasm as universal_canister_argument_builder, UNIVERSAL_CANISTER_WASM,
};
use ic_types::ingress::WasmResult;
use ic_types::Cycles;
use num_traits::ToPrimitive;
use on_wire::{FromWire, IntoWire, NewType};
use prost::Message;
use std::convert::TryInto;
use std::default::Default;
use std::env;
use std::time::Duration;

use ic_nns_common::pb::v1::NeuronId;
use ic_nns_governance::pb::v1::manage_neuron::configure::Operation;
use ic_nns_governance::pb::v1::manage_neuron::{AddHotKey, Configure, RemoveHotKey};
use ic_nns_governance::pb::v1::{
    manage_neuron::{self},
    ListNeurons, ListNeuronsResponse, ManageNeuron, ManageNeuronResponse, Proposal,
};
use ic_sns_governance::pb::v1;
use ic_sns_governance::pb::v1 as sns_pb;
use ic_sns_governance::pb::v1::manage_neuron_response::Command as SnsCommandResponse;
use ic_sns_governance::types::DEFAULT_TRANSFER_FEE;
use icp_ledger::{BlockIndex, Tokens};

/// Turn down state machine logging to just errors to reduce noise in tests where this is not relevant
pub fn reduce_state_machine_logging_unless_env_set() {
    match env::var("RUST_LOG") {
        Ok(_) => {}
        Err(_) => env::set_var("RUST_LOG", "ERROR"),
    }
}

/// Creates a canister with a wasm, paylaod, and optionally settings on a StateMachine
pub fn create_canister(
    machine: &StateMachine,
    wasm: Wasm,
    initial_payload: Option<Vec<u8>>,
    canister_settings: Option<CanisterSettingsArgs>,
) -> CanisterId {
    machine
        .install_canister(
            wasm.bytes(),
            initial_payload.unwrap_or_default(),
            canister_settings,
        )
        .unwrap()
}

/// Creates a canister with cycles, wasm, paylaod, and optionally settings on a StateMachine
pub fn create_canister_with_cycles(
    machine: &StateMachine,
    wasm: Wasm,
    initial_payload: Option<Vec<u8>>,
    cycles: Cycles,
    canister_settings: Option<CanisterSettingsArgs>,
) -> CanisterId {
    let canister_id = machine.create_canister_with_cycles(cycles, canister_settings);
    machine
        .install_wasm_in_mode(
            canister_id,
            CanisterInstallMode::Install,
            wasm.bytes(),
            initial_payload.unwrap_or_else(|| Encode!().unwrap()),
        )
        .unwrap();
    canister_id
}

/// Make an update request to a canister on StateMachine (with no sender)
pub fn update(
    machine: &StateMachine,
    canister_target: CanisterId,
    method_name: &str,
    payload: Vec<u8>,
) -> Result<Vec<u8>, String> {
    // move time forward
    machine.advance_time(Duration::from_secs(2));
    let result = machine
        .execute_ingress(canister_target, method_name, payload)
        .map_err(|e| e.to_string())?;
    match result {
        WasmResult::Reply(v) => Ok(v),
        WasmResult::Reject(s) => Err(format!("Canister rejected with message: {}", s)),
    }
}

pub fn update_with_sender<Payload, ReturnType, Witness>(
    machine: &StateMachine,
    canister_target: CanisterId,
    method_name: &str,
    _: Witness,
    payload: Payload::Inner,
    sender: PrincipalId,
) -> Result<ReturnType::Inner, String>
where
    Payload: IntoWire + NewType,
    Witness: FnOnce(ReturnType, Payload::Inner) -> (ReturnType::Inner, Payload),
    ReturnType: FromWire + NewType,
{
    // move time forward
    machine.advance_time(Duration::from_secs(2));
    let payload = Payload::from_inner(payload);
    let result = machine
        .execute_ingress_as(
            sender,
            canister_target,
            method_name,
            payload.into_bytes().unwrap(),
        )
        .map_err(|e| e.to_string())?;

    match result {
        WasmResult::Reply(v) => FromWire::from_bytes(v).map(|x: ReturnType| x.into_inner()),
        WasmResult::Reject(s) => Err(format!("Canister rejected with message: {}", s)),
    }
}

/// Internal impl of querying canister
fn query_impl(
    machine: &StateMachine,
    canister: CanisterId,
    method_name: &str,
    payload: Vec<u8>,
    sender: Option<PrincipalId>,
) -> Result<Vec<u8>, String> {
    // move time forward
    machine.advance_time(Duration::from_secs(2));
    let result = match sender {
        Some(sender) => machine.execute_ingress_as(sender, canister, method_name, payload),
        None => machine.query(canister, method_name, payload),
    }
    .map_err(|e| e.to_string())?;
    match result {
        WasmResult::Reply(v) => Ok(v),
        WasmResult::Reject(s) => Err(format!("Canister rejected with message: {}", s)),
    }
}

/// Make a query reqeust to a canister on a StateMachine (with no sender)
pub fn query(
    machine: &StateMachine,
    canister: CanisterId,
    method_name: &str,
    payload: Vec<u8>,
) -> Result<Vec<u8>, String> {
    query_impl(machine, canister, method_name, payload, None)
}

/// Make a query reqeust to a canister on a StateMachine (with sender)
pub fn query_with_sender(
    machine: &StateMachine,
    canister: CanisterId,
    method_name: &str,
    payload: Vec<u8>,
    sender: PrincipalId,
) -> Result<Vec<u8>, String> {
    query_impl(machine, canister, method_name, payload, Some(sender))
}

/// Set controllers for a canister.  Because we have no verification in StateMachine tests
/// this can be used if you know the current controller PrincipalId
pub fn set_controllers(
    machine: &StateMachine,
    sender: PrincipalId,
    target: CanisterId,
    controllers: Vec<PrincipalId>,
) {
    update_with_sender(
        machine,
        CanisterId::ic_00(),
        "update_settings",
        candid_one,
        UpdateSettingsArgs {
            canister_id: target.into(),
            settings: CanisterSettingsArgs::new(None, Some(controllers), None, None, None),
        },
        sender,
    )
    .unwrap()
}

/// Compiles the universal canister, builds it's initial payload and installs it with cycles
pub fn set_up_universal_canister(machine: &StateMachine, cycles: Option<Cycles>) -> CanisterId {
    let canister_id = match cycles {
        None => machine.create_canister(None),
        Some(cycles) => machine.create_canister_with_cycles(cycles, None),
    };
    machine
        .install_wasm_in_mode(
            canister_id,
            CanisterInstallMode::Install,
            Wasm::from_bytes(UNIVERSAL_CANISTER_WASM).bytes(),
            vec![],
        )
        .unwrap();

    canister_id
}

pub async fn try_call_via_universal_canister(
    machine: &StateMachine,
    sender: CanisterId,
    receiver: CanisterId,
    method: &str,
    payload: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let universal_canister_payload = universal_canister_argument_builder()
        .call_simple(
            receiver,
            method,
            call_args()
                .other_side(payload)
                .on_reply(
                    universal_canister_argument_builder()
                        .message_payload()
                        .reply_data_append()
                        .reply(),
                )
                .on_reject(
                    universal_canister_argument_builder()
                        .reject_message()
                        .reject(),
                ),
        )
        .build();

    update(machine, sender, "update", universal_canister_payload)
}

pub fn try_call_with_cycles_via_universal_canister(
    machine: &StateMachine,
    sender: CanisterId,
    receiver: CanisterId,
    method: &str,
    payload: Vec<u8>,
    cycles: u128,
) -> Result<Vec<u8>, String> {
    let universal_canister_payload = universal_canister_argument_builder()
        .call_with_cycles(
            receiver,
            method,
            call_args()
                .other_side(payload)
                .on_reply(
                    universal_canister_argument_builder()
                        .message_payload()
                        .reply_data_append()
                        .reply(),
                )
                .on_reject(
                    universal_canister_argument_builder()
                        .reject_message()
                        .reject(),
                ),
            ((cycles >> 64) as u64, cycles as u64),
        )
        .build();

    update(machine, sender, "update", universal_canister_payload)
}
/// Converts a canisterID to a u64 by relying on an implementation detail.
pub fn canister_id_to_u64(canister_id: CanisterId) -> u64 {
    let bytes: [u8; 8] = canister_id.get().to_vec()[0..8]
        .try_into()
        .expect("Could not convert vector to [u8; 8]");

    u64::from_be_bytes(bytes)
}

/// Create a canister at 0-indexed position (assuming canisters are created sequentially)
/// This also creates all intermediate canisters
fn create_canister_id_at_position(machine: &StateMachine, position: u64) -> CanisterId {
    let mut canister_id = machine.create_canister(None);
    while canister_id_to_u64(canister_id) < position {
        canister_id = machine.create_canister(None);
    }

    // In case we tried using this when we are already past the sequence
    assert_eq!(canister_id_to_u64(canister_id), position);

    canister_id
}

pub fn setup_nns_governance_with_correct_canister_id(
    machine: &StateMachine,
    init_payload: Governance,
) {
    let canister_id =
        create_canister_id_at_position(machine, GOVERNANCE_CANISTER_INDEX_IN_NNS_SUBNET);

    assert_eq!(canister_id, GOVERNANCE_CANISTER_ID);

    machine
        .install_wasm_in_mode(
            canister_id,
            CanisterInstallMode::Install,
            build_governance_wasm().bytes(),
            init_payload.encode_to_vec(),
        )
        .unwrap();
}

/// Creates empty canisters up until the correct SNS-WASM id, then installs SNS-WASMs with payload
/// This allows creating a few canisters before calling this.
pub fn setup_nns_sns_wasms_with_correct_canister_id(
    machine: &StateMachine,
    init_payload: SnsWasmCanisterInitPayload,
) {
    let canister_id =
        create_canister_id_at_position(machine, SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET);

    assert_eq!(canister_id, SNS_WASM_CANISTER_ID);

    machine
        .install_wasm_in_mode(
            canister_id,
            CanisterInstallMode::Install,
            build_sns_wasms_wasm().bytes(),
            Encode!(&init_payload).unwrap(),
        )
        .unwrap();
}

/// Sets up the NNS for StateMachine tests.
pub fn setup_nns_canisters(machine: &StateMachine, init_payloads: NnsInitPayloads) {
    let registry_canister_id = create_canister(
        machine,
        build_registry_wasm(),
        Some(Encode!(&init_payloads.registry).unwrap()),
        Some(CanisterSettingsArgs {
            memory_allocation: Some(memory_allocation_of(REGISTRY_CANISTER_ID).into()),
            ..Default::default()
        }),
    );
    assert_eq!(registry_canister_id, REGISTRY_CANISTER_ID);

    setup_nns_governance_with_correct_canister_id(machine, init_payloads.governance);

    let ledger_canister_id = create_canister(
        machine,
        build_ledger_wasm(),
        Some(Encode!(&init_payloads.ledger).unwrap()),
        Some(CanisterSettingsArgs {
            memory_allocation: Some(memory_allocation_of(LEDGER_CANISTER_ID).into()),
            ..Default::default()
        }),
    );
    assert_eq!(ledger_canister_id, LEDGER_CANISTER_ID);

    let root_canister_id = create_canister(
        machine,
        build_root_wasm(),
        Some(Encode!(&init_payloads.root).unwrap()),
        Some(CanisterSettingsArgs {
            memory_allocation: Some(memory_allocation_of(ROOT_CANISTER_ID).into()),
            ..Default::default()
        }),
    );
    assert_eq!(root_canister_id, ROOT_CANISTER_ID);

    let cmc_canister_id = create_canister(
        machine,
        build_cmc_wasm(),
        Some(Encode!(&init_payloads.cycles_minting).unwrap()),
        Some(CanisterSettingsArgs {
            memory_allocation: Some(memory_allocation_of(CYCLES_MINTING_CANISTER_ID).into()),
            ..Default::default()
        }),
    );
    assert_eq!(cmc_canister_id, CYCLES_MINTING_CANISTER_ID);

    let lifeline_canister_id = create_canister(
        machine,
        build_lifeline_wasm(),
        Some(Encode!(&init_payloads.lifeline).unwrap()),
        Some(CanisterSettingsArgs {
            memory_allocation: Some(memory_allocation_of(LIFELINE_CANISTER_ID).into()),
            ..Default::default()
        }),
    );
    assert_eq!(lifeline_canister_id, LIFELINE_CANISTER_ID);

    let genesis_token_canister_id = create_canister(
        machine,
        build_genesis_token_wasm(),
        Some(init_payloads.genesis_token.encode_to_vec()),
        Some(CanisterSettingsArgs {
            memory_allocation: Some(memory_allocation_of(GENESIS_TOKEN_CANISTER_ID).into()),
            ..Default::default()
        }),
    );
    assert_eq!(genesis_token_canister_id, GENESIS_TOKEN_CANISTER_ID);

    // We need to fill in 2 CanisterIds, but don't use Identity or NNS-UI canisters in our tests
    let identity_canister_id = machine.create_canister(None);
    assert_eq!(identity_canister_id, IDENTITY_CANISTER_ID);

    let nns_ui_canister_id = machine.create_canister(None);
    assert_eq!(nns_ui_canister_id, NNS_UI_CANISTER_ID);

    setup_nns_sns_wasms_with_correct_canister_id(machine, init_payloads.sns_wasms);
}

fn manage_neuron(
    state_machine: &mut StateMachine,
    sender: PrincipalId,
    neuron_id: NeuronId,
    command: manage_neuron::Command,
) -> ManageNeuronResponse {
    let result = state_machine
        .execute_ingress_as(
            sender,
            GOVERNANCE_CANISTER_ID,
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

pub fn nns_governance_make_proposal(
    state_machine: &mut StateMachine,
    sender: PrincipalId,
    neuron_id: NeuronId,
    proposal: &Proposal,
) -> ManageNeuronResponse {
    let command = manage_neuron::Command::MakeProposal(Box::new(proposal.clone()));

    manage_neuron(state_machine, sender, neuron_id, command)
}

pub fn nns_add_hot_key(
    state_machine: &mut StateMachine,
    sender: PrincipalId,
    neuron_id: NeuronId,
    new_hot_key: PrincipalId,
) -> ManageNeuronResponse {
    let command = manage_neuron::Command::Configure(Configure {
        operation: Some(Operation::AddHotKey(AddHotKey {
            new_hot_key: Some(new_hot_key),
        })),
    });

    manage_neuron(state_machine, sender, neuron_id, command)
}

pub fn nns_remove_hot_key(
    state_machine: &mut StateMachine,
    sender: PrincipalId,
    neuron_id: NeuronId,
    hot_key_to_remove: PrincipalId,
) -> ManageNeuronResponse {
    let command = manage_neuron::Command::Configure(Configure {
        operation: Some(Operation::RemoveHotKey(RemoveHotKey {
            hot_key_to_remove: Some(hot_key_to_remove),
        })),
    });

    manage_neuron(state_machine, sender, neuron_id, command)
}

pub fn list_neurons(state_machine: &mut StateMachine, sender: PrincipalId) -> ListNeuronsResponse {
    let result = state_machine
        .execute_ingress_as(
            sender,
            GOVERNANCE_CANISTER_ID,
            "list_neurons",
            Encode!(&ListNeurons {
                neuron_ids: vec![],
                include_neurons_readable_by_caller: true,
            })
            .unwrap(),
        )
        .unwrap();

    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to list_neurons failed: {:#?}", s),
    };

    Decode!(&result, ListNeuronsResponse).unwrap()
}

pub fn sns_stake_neuron(
    machine: &StateMachine,
    governance_canister_id: CanisterId,
    ledger_canister_id: CanisterId,
    sender: PrincipalId,
    amount: Tokens,
    nonce: u64,
) -> BlockIndex {
    // Compute neuron staking subaccount
    let to_subaccount = compute_neuron_staking_subaccount(sender, nonce);

    icrc1_transfer(
        machine,
        ledger_canister_id,
        sender,
        TransferArg {
            from_subaccount: None,
            to: Account {
                owner: governance_canister_id.get(),
                subaccount: Some(to_subaccount.0),
            },
            fee: Some(Nat::from(DEFAULT_TRANSFER_FEE.get_e8s())),
            created_at_time: None,
            memo: None,
            amount: Nat::from(amount.get_e8s()),
        },
    )
    .unwrap()
}

pub fn icrc1_balance(machine: &StateMachine, ledger_id: CanisterId, account: Account) -> Tokens {
    let result = query(
        machine,
        ledger_id,
        "icrc1_balance_of",
        Encode!(&account).unwrap(),
    )
    .unwrap();
    Tokens::from_e8s(Decode!(&result, Nat).unwrap().0.to_u64().unwrap())
}

pub fn icrc1_transfer(
    machine: &StateMachine,
    ledger_id: CanisterId,
    sender: PrincipalId,
    args: TransferArg,
) -> Result<BlockIndex, String> {
    let result: Result<Result<Nat, TransferError>, String> = update_with_sender(
        machine,
        ledger_id,
        "icrc1_transfer",
        candid_one,
        args,
        sender,
    );

    let result = result.unwrap();
    match result {
        Ok(n) => Ok(n.0.to_u64().unwrap()),
        Err(e) => Err(format!("{:?}", e)),
    }
}

/// Claim a staked neuron for an SNS StateMachine test
// Note: Should be moved to sns/test_helpers/state_test_helpers.rs when dependency graph is cleaned up
pub fn sns_claim_staked_neuron(
    machine: &StateMachine,
    governance_canister_id: CanisterId,
    sender: PrincipalId,
    nonce: u64,
    dissolve_delay: Option<u32>,
) -> sns_pb::NeuronId {
    // Find the neuron staked
    let to_subaccount = compute_neuron_staking_subaccount(sender, nonce);

    // Claim the neuron on the governance canister.
    let claim_response: sns_pb::ManageNeuronResponse = update_with_sender(
        machine,
        governance_canister_id,
        "manage_neuron",
        candid_one,
        v1::ManageNeuron {
            subaccount: to_subaccount.to_vec(),
            command: Some(sns_pb::manage_neuron::Command::ClaimOrRefresh(
                sns_pb::manage_neuron::ClaimOrRefresh {
                    by: Some(
                        sns_pb::manage_neuron::claim_or_refresh::By::MemoAndController(
                            sns_pb::manage_neuron::claim_or_refresh::MemoAndController {
                                memo: nonce,
                                controller: None,
                            },
                        ),
                    ),
                },
            )),
        },
        sender,
    )
    .expect("Error calling the manage_neuron API.");

    let neuron_id = match claim_response.command.unwrap() {
        SnsCommandResponse::ClaimOrRefresh(response) => {
            println!("User {} successfully claimed neuron", sender);

            response.refreshed_neuron_id.unwrap()
        }
        SnsCommandResponse::Error(error) => panic!(
            "Unexpected error when claiming neuron for user {}: {}",
            sender, error
        ),
        _ => panic!(
            "Unexpected command response when claiming neuron for user {}.",
            sender
        ),
    };

    // Increase dissolve delay
    if let Some(dissolve_delay) = dissolve_delay {
        sns_increase_dissolve_delay(
            machine,
            governance_canister_id,
            sender,
            &to_subaccount.0,
            dissolve_delay,
        );
    }

    neuron_id
}

/// Increase neuron's dissolve delay on an SNS
// Note: Should be moved to sns/test_helpers/state_test_helpers.rs when dependency graph is cleaned up
pub fn sns_increase_dissolve_delay(
    machine: &StateMachine,
    governance_canister_id: CanisterId,
    sender: PrincipalId,
    subaccount: &[u8],
    dissolve_delay: u32,
) {
    let payload = sns_pb::ManageNeuron {
        subaccount: subaccount.to_vec(),
        command: Some(sns_pb::manage_neuron::Command::Configure(
            sns_pb::manage_neuron::Configure {
                operation: Some(
                    sns_pb::manage_neuron::configure::Operation::IncreaseDissolveDelay(
                        sns_pb::manage_neuron::IncreaseDissolveDelay {
                            additional_dissolve_delay_seconds: dissolve_delay,
                        },
                    ),
                ),
            },
        )),
    };
    let increase_response: sns_pb::ManageNeuronResponse = update_with_sender(
        machine,
        governance_canister_id,
        "manage_neuron",
        candid_one,
        payload,
        sender,
    )
    .expect("Error calling the manage_neuron API.");

    match increase_response.command.unwrap() {
        SnsCommandResponse::Configure(_) => (),
        SnsCommandResponse::Error(error) => panic!(
            "Unexpected error when increasing dissolve delay for user {}: {}",
            sender, error
        ),
        _ => panic!(
            "Unexpected command response when increasing dissolve delay for user {}.",
            sender
        ),
    };
}

/// Make a Governance proposal on an SNS
// Note: Should be moved to sns/test_helpers/state_test_helpers.rs when dependency graph is cleaned up
pub fn sns_make_proposal(
    machine: &StateMachine,
    sns_governance_canister_id: CanisterId,
    sender: PrincipalId,
    // subaccount: &[u8],
    neuron_id: sns_pb::NeuronId,
    proposal: v1::Proposal,
) -> Result<sns_pb::ProposalId, sns_pb::GovernanceError> {
    let sub_account = neuron_id.subaccount().unwrap();

    let manage_neuron_response: sns_pb::ManageNeuronResponse = update_with_sender(
        machine,
        sns_governance_canister_id,
        "manage_neuron",
        candid_one,
        sns_pb::ManageNeuron {
            subaccount: sub_account.to_vec(),
            command: Some(sns_pb::manage_neuron::Command::MakeProposal(proposal)),
        },
        sender,
    )
    .expect("Error calling manage_neuron");

    match manage_neuron_response.command.unwrap() {
        SnsCommandResponse::Error(e) => Err(e),
        SnsCommandResponse::MakeProposal(make_proposal_response) => {
            Ok(make_proposal_response.proposal_id.unwrap())
        }
        _ => panic!("Unexpected MakeProposal response"),
    }
}

/// Get a proposal from an SNS
// Note: Should be moved to sns/test_helpers/state_test_helpers.rs when dependency graph is cleaned up
pub fn sns_get_proposal(
    machine: &StateMachine,
    governance_canister_id: CanisterId,
    proposal_id: sns_pb::ProposalId,
) -> Result<sns_pb::ProposalData, String> {
    let get_proposal_response = query(
        machine,
        governance_canister_id,
        "get_proposal",
        Encode!(&sns_pb::GetProposal {
            proposal_id: Some(proposal_id),
        })
        .unwrap(),
    )
    .map_err(|e| format!("Error calling get_proposal: {}", e))?;

    let get_proposal_response =
        Decode!(&get_proposal_response, sns_pb::GetProposalResponse).unwrap();
    match get_proposal_response
        .result
        .expect("Empty get_proposal_response")
    {
        sns_pb::get_proposal_response::Result::Error(e) => {
            panic!("get_proposal error: {}", e);
        }
        sns_pb::get_proposal_response::Result::Proposal(proposal) => Ok(proposal),
    }
}

/// Wait for an SNS proposal to be executed
// Note: Should be moved to sns/test_helpers/state_test_helpers.rs when dependency graph is cleaned up
pub fn sns_wait_for_proposal_execution(
    machine: &StateMachine,
    governance: CanisterId,
    proposal_id: sns_pb::ProposalId,
) {
    // We create some blocks until the proposal has finished executing (machine.tick())
    let mut attempt_count = 0;
    let mut proposal_executed = false;
    while !proposal_executed {
        attempt_count += 1;
        machine.tick();

        let proposal = sns_get_proposal(machine, governance, proposal_id);
        assert!(
            attempt_count < 50,
            "proposal {:?} not executed after {} attempts",
            proposal_id,
            attempt_count
        );

        if let Ok(p) = proposal {
            proposal_executed = p.executed_timestamp_seconds != 0;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}
