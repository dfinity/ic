use crate::common::{
    build_cmc_wasm, build_genesis_token_wasm, build_governance_wasm_with_features,
    build_ledger_wasm, build_lifeline_wasm, build_registry_wasm, build_root_wasm,
    build_sns_wasms_wasm, NnsInitPayloads,
};
use candid::{CandidType, Decode, Encode, Nat};
use canister_test::Wasm;
use cycles_minting_canister::{
    IcpXdrConversionRateCertifiedResponse, SetAuthorizedSubnetworkListArgs,
    CYCLES_LEDGER_CANISTER_ID,
};
use dfn_candid::candid_one;
use dfn_http::types::{HttpRequest, HttpResponse};
use dfn_protobuf::ToProto;
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_config::{execution_environment::Config, subnet_config::SubnetConfig};
use ic_management_canister_types::{
    CanisterInstallMode, CanisterSettingsArgs, CanisterSettingsArgsBuilder, CanisterStatusResultV2,
    UpdateSettingsArgs,
};
use ic_nervous_system_clients::{
    canister_id_record::CanisterIdRecord, canister_status::CanisterStatusResult,
};
use ic_nervous_system_common::{
    ledger::{compute_neuron_staking_subaccount, compute_neuron_staking_subaccount_bytes},
    DEFAULT_TRANSFER_FEE, ONE_DAY_SECONDS,
};
use ic_nervous_system_root::change_canister::ChangeCanisterRequest;
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_nns_constants::{
    memory_allocation_of, CYCLES_MINTING_CANISTER_ID, GENESIS_TOKEN_CANISTER_ID,
    GOVERNANCE_CANISTER_ID, GOVERNANCE_CANISTER_INDEX_IN_NNS_SUBNET, IDENTITY_CANISTER_ID,
    LEDGER_CANISTER_ID, LIFELINE_CANISTER_ID, NNS_UI_CANISTER_ID, REGISTRY_CANISTER_ID,
    ROOT_CANISTER_ID, ROOT_CANISTER_INDEX_IN_NNS_SUBNET, SNS_WASM_CANISTER_ID,
    SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET, SUBNET_RENTAL_CANISTER_ID,
    SUBNET_RENTAL_CANISTER_INDEX_IN_NNS_SUBNET,
};
use ic_nns_governance::pb::v1::{
    self as nns_governance_pb,
    governance::Migrations,
    manage_neuron::{
        self,
        claim_or_refresh::{self, MemoAndController},
        configure::Operation,
        AddHotKey, ClaimOrRefresh, Configure, Follow, IncreaseDissolveDelay, JoinCommunityFund,
        LeaveCommunityFund, RegisterVote, RemoveHotKey, Split, StakeMaturity,
    },
    manage_neuron_response::{self, ClaimOrRefreshResponse},
    proposal::{self, Action},
    Empty, ExecuteNnsFunction, Governance, GovernanceError, ListNeurons, ListNeuronsResponse,
    ListProposalInfo, ListProposalInfoResponse, ManageNeuron, ManageNeuronResponse,
    MostRecentMonthlyNodeProviderRewards, NetworkEconomics, NnsFunction, Proposal, ProposalInfo,
    RewardNodeProviders, Vote,
};
use ic_nns_handler_root::init::RootCanisterInitPayload;
use ic_registry_subnet_type::SubnetType;
use ic_sns_governance::pb::v1::{
    self as sns_pb, manage_neuron_response::Command as SnsCommandResponse, GetModeResponse,
};
use ic_sns_swap::pb::v1::{GetAutoFinalizationStatusRequest, GetAutoFinalizationStatusResponse};
use ic_sns_wasm::{
    init::SnsWasmCanisterInitPayload,
    pb::v1::{ListDeployedSnsesRequest, ListDeployedSnsesResponse},
};
use ic_state_machine_tests::{StateMachine, StateMachineBuilder, StateMachineConfig};
use ic_test_utilities::universal_canister::{
    call_args, wasm as universal_canister_argument_builder, UNIVERSAL_CANISTER_WASM,
};
use ic_types::{ingress::WasmResult, Cycles, NumInstructions};
use icp_ledger::{AccountIdentifier, BinaryAccountBalanceArgs, BlockIndex, Memo, SendArgs, Tokens};
use icrc_ledger_types::icrc1::{
    account::Account,
    transfer::{TransferArg, TransferError},
};
use num_traits::ToPrimitive;
use on_wire::{FromWire, IntoWire, NewType};
use prost::Message;
use serde::Serialize;
use std::{convert::TryInto, env, time::Duration};

/// A `StateMachine` builder setting the IC time to the current time
/// and using the canister ranges of both the NNS and II subnets.
/// Note. The last canister ID in the canister range of the II subnet
/// is omitted so that the canister range of the II subnet is not used
/// for automatic generation of new canister IDs.
pub fn state_machine_builder_for_nns_tests() -> StateMachineBuilder {
    // TODO, remove when this is the value set in the normal IC build
    // This is to uncover issues in testing that might affect performance in production
    const MAX_INSTRUCTIONS_PER_SLICE: NumInstructions = NumInstructions::new(2_000_000_000); // 2 Billion is the value used in app subnets

    let mut subnet_config = SubnetConfig::new(SubnetType::System);
    subnet_config.scheduler_config.max_instructions_per_slice = MAX_INSTRUCTIONS_PER_SLICE;

    StateMachineBuilder::new()
        .with_current_time()
        .with_extra_canister_range(std::ops::RangeInclusive::<CanisterId>::new(
            CanisterId::from_u64(0x2100000),
            CanisterId::from_u64(0x21FFFFE),
        ))
        .with_config(Some(StateMachineConfig::new(
            subnet_config,
            Config::default(),
        )))
}

/// Turn down state machine logging to just errors to reduce noise in tests where this is not relevant
pub fn reduce_state_machine_logging_unless_env_set() {
    match env::var("RUST_LOG") {
        Ok(_) => {}
        Err(_) => env::set_var("RUST_LOG", "ERROR"),
    }
}

/// Creates a canister with a wasm, payload, and optionally settings on a StateMachine
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

/// Creates a canister with a specified canister ID, wasm, payload, and optionally settings on a StateMachine
/// DO NOT USE this function for specified canister IDs within the main (NNS) subnet canister range:
/// `CanisterId::from_u64(0x00000)` until `CanisterId::from_u64(0xFFFFF)`.
/// Use the function `create_canister_id_at_position` for that canister range instead.
pub fn create_canister_at_specified_id(
    machine: &StateMachine,
    specified_id: u64,
    wasm: Wasm,
    initial_payload: Option<Vec<u8>>,
    canister_settings: Option<CanisterSettingsArgs>,
) {
    assert!(specified_id >= 0x100000);
    let canister_id = CanisterId::from_u64(specified_id);
    machine.create_canister_with_cycles(
        Some(canister_id.into()),
        Cycles::zero(),
        canister_settings,
    );
    machine
        .install_existing_canister(
            canister_id,
            wasm.bytes(),
            initial_payload.unwrap_or_default(),
        )
        .unwrap();
}

/// Creates a canister with cycles, wasm, payload, and optionally settings on a StateMachine
pub fn create_canister_with_cycles(
    machine: &StateMachine,
    wasm: Wasm,
    initial_payload: Option<Vec<u8>>,
    cycles: Cycles,
    canister_settings: Option<CanisterSettingsArgs>,
) -> CanisterId {
    let canister_id = machine.create_canister_with_cycles(None, cycles, canister_settings);
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

/// Make a query request to a canister on a StateMachine (with no sender)
pub fn query(
    machine: &StateMachine,
    canister: CanisterId,
    method_name: &str,
    payload: Vec<u8>,
) -> Result<Vec<u8>, String> {
    query_impl(machine, canister, method_name, payload, None)
}

/// Make a query request to a canister on a StateMachine (with sender)
pub fn query_with_sender(
    machine: &StateMachine,
    canister: CanisterId,
    method_name: &str,
    payload: Vec<u8>,
    sender: PrincipalId,
) -> Result<Vec<u8>, String> {
    query_impl(machine, canister, method_name, payload, Some(sender))
}

pub fn scrape_metrics(
    state_machine: &mut StateMachine,
    canister_id: CanisterId,
) -> prometheus_parse::Scrape {
    let http_response = make_http_request(
        state_machine,
        canister_id,
        &HttpRequest {
            method: "GET".to_string(),
            url: "/metrics".to_string(),
            headers: vec![],
            body: Default::default(),
        },
    );

    assert_eq!(http_response.status_code, 200, "{:#?}", http_response);

    let body = String::from_utf8(http_response.body.to_vec())
        .unwrap()
        .lines()
        .map(|s| Ok(s.to_owned()))
        .collect::<Vec<_>>()
        .into_iter();

    prometheus_parse::Scrape::parse(body).unwrap()
}

pub fn get_counter(scrape: &prometheus_parse::Scrape, name: &str) -> f64 {
    match get_sample(scrape, name).value {
        prometheus_parse::Value::Counter(value) => value,
        value => panic!("Metric found, but not a counter: {:?}", value),
    }
}

pub fn get_gauge(scrape: &prometheus_parse::Scrape, name: &str) -> f64 {
    match get_sample(scrape, name).value {
        prometheus_parse::Value::Gauge(value) => value,
        value => panic!("Metric found, but not a gauge: {:?}", value),
    }
}

pub fn get_sample(scrape: &prometheus_parse::Scrape, name: &str) -> prometheus_parse::Sample {
    for sample in &scrape.samples {
        if sample.metric == name {
            return sample.clone();
        }
    }
    panic!("Metric not found: {}", name);
}

pub fn make_http_request(
    state_machine: &mut StateMachine,
    canister_id: CanisterId,
    request: &HttpRequest,
) -> HttpResponse {
    let reply = query(
        state_machine,
        canister_id,
        "http_request",
        Encode!(request).unwrap(),
    )
    .unwrap();

    Decode!(&reply, HttpResponse).unwrap()
}

/// Set controllers for a canister. Because we have no verification in StateMachine tests
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
            settings: CanisterSettingsArgsBuilder::new()
                .with_controllers(controllers)
                .build(),
            sender_canister_version: None,
        },
        sender,
    )
    .unwrap()
}

/// Gets controllers for a canister.
pub fn get_controllers(
    machine: &StateMachine,
    sender: PrincipalId,
    target: CanisterId,
) -> Vec<PrincipalId> {
    let result: CanisterStatusResultV2 = update_with_sender(
        machine,
        CanisterId::ic_00(),
        "canister_status",
        candid_one,
        &CanisterIdRecord::from(target),
        sender,
    )
    .unwrap();
    result.controllers()
}

/// Get status for a canister.
pub fn get_canister_status(
    machine: &StateMachine,
    sender: PrincipalId,
    target: CanisterId,
    canister_target: CanisterId,
) -> Result<CanisterStatusResult, String> {
    update_with_sender(
        machine,
        canister_target,
        "canister_status",
        candid_one,
        &CanisterIdRecord::from(target),
        sender,
    )
}

pub fn get_root_canister_status(machine: &StateMachine) -> Result<CanisterStatusResultV2, String> {
    machine
        .canister_status_as(PrincipalId::from(ROOT_CANISTER_ID), ROOT_CANISTER_ID)
        .unwrap()
}

pub fn get_canister_status_from_root(
    machine: &StateMachine,
    target: CanisterId,
) -> CanisterStatusResult {
    update_with_sender(
        machine,
        ROOT_CANISTER_ID,
        "canister_status",
        candid_one,
        &CanisterIdRecord::from(target),
        PrincipalId::new_anonymous(),
    )
    .unwrap()
}

/// Compiles the universal canister, builds it's initial payload and installs it with cycles
pub fn set_up_universal_canister(machine: &StateMachine, cycles: Option<Cycles>) -> CanisterId {
    let canister_id = match cycles {
        None => machine.create_canister(None),
        Some(cycles) => machine.create_canister_with_cycles(None, cycles, None),
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
            Cycles::from(cycles),
        )
        .build();

    update(machine, sender, "update", universal_canister_payload)
}
/// Converts a canisterID to a u64 by relying on an implementation detail.
fn canister_id_to_u64(canister_id: CanisterId) -> u64 {
    let bytes: [u8; 8] = canister_id.get().to_vec()[0..8]
        .try_into()
        .expect("Could not convert vector to [u8; 8]");

    u64::from_be_bytes(bytes)
}

/// Create a canister at 0-indexed position (assuming canisters are created sequentially)
/// This also creates all intermediate canisters
pub fn create_canister_id_at_position(
    machine: &StateMachine,
    position: u64,
    canister_settings: Option<CanisterSettingsArgs>,
) -> CanisterId {
    let mut canister_id = machine.create_canister(canister_settings.clone());
    while canister_id_to_u64(canister_id) < position {
        canister_id = machine.create_canister(canister_settings.clone());
    }

    // In case we tried using this when we are already past the sequence
    assert_eq!(canister_id_to_u64(canister_id), position);

    canister_id
}

pub fn setup_nns_governance_with_correct_canister_id(
    machine: &StateMachine,
    init_payload: Governance,
    features: &[&str],
) {
    let canister_id = create_canister_id_at_position(
        machine,
        GOVERNANCE_CANISTER_INDEX_IN_NNS_SUBNET,
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_controllers(vec![ROOT_CANISTER_ID.get()])
                .build(),
        ),
    );

    assert_eq!(canister_id, GOVERNANCE_CANISTER_ID);
    let governance_wasm = build_governance_wasm_with_features(features);
    machine
        .install_wasm_in_mode(
            canister_id,
            CanisterInstallMode::Install,
            governance_wasm.bytes(),
            init_payload.encode_to_vec(),
        )
        .unwrap();
}

pub fn setup_nns_root_with_correct_canister_id(
    machine: &StateMachine,
    init_payload: RootCanisterInitPayload,
) {
    let root_canister_id = create_canister_id_at_position(
        machine,
        ROOT_CANISTER_INDEX_IN_NNS_SUBNET,
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_memory_allocation(memory_allocation_of(ROOT_CANISTER_ID))
                .with_controllers(vec![LIFELINE_CANISTER_ID.get()])
                .build(),
        ),
    );

    assert_eq!(root_canister_id, ROOT_CANISTER_ID);

    machine
        .install_wasm_in_mode(
            root_canister_id,
            CanisterInstallMode::Install,
            build_root_wasm().bytes(),
            Encode!(&init_payload).unwrap(),
        )
        .unwrap();
}

/// Creates empty canisters up until the correct SNS-WASM id, then installs SNS-WASMs with payload
/// This allows creating a few canisters before calling this.
pub fn setup_nns_sns_wasms_with_correct_canister_id(
    machine: &StateMachine,
    init_payload: SnsWasmCanisterInitPayload,
) {
    let canister_id = create_canister_id_at_position(
        machine,
        SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET,
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_controllers(vec![ROOT_CANISTER_ID.get()])
                .build(),
        ),
    );

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
    setup_nns_canisters_with_features(machine, init_payloads, &["test"])
}

pub fn setup_nns_canisters_with_features(
    machine: &StateMachine,
    init_payloads: NnsInitPayloads,
    features: &[&str],
) {
    let registry_canister_id = create_canister(
        machine,
        build_registry_wasm(),
        Some(Encode!(&init_payloads.registry).unwrap()),
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_memory_allocation(memory_allocation_of(REGISTRY_CANISTER_ID))
                .with_controllers(vec![ROOT_CANISTER_ID.get()])
                .build(),
        ),
    );
    assert_eq!(registry_canister_id, REGISTRY_CANISTER_ID);

    setup_nns_governance_with_correct_canister_id(machine, init_payloads.governance, features);

    let ledger_canister_id = create_canister(
        machine,
        build_ledger_wasm(),
        Some(Encode!(&init_payloads.ledger).unwrap()),
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_memory_allocation(memory_allocation_of(LEDGER_CANISTER_ID))
                .with_controllers(vec![ROOT_CANISTER_ID.get()])
                .build(),
        ),
    );
    assert_eq!(ledger_canister_id, LEDGER_CANISTER_ID);

    setup_nns_root_with_correct_canister_id(machine, init_payloads.root);

    let cmc_canister_id = create_canister(
        machine,
        build_cmc_wasm(),
        Some(Encode!(&init_payloads.cycles_minting).unwrap()),
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_memory_allocation(memory_allocation_of(CYCLES_MINTING_CANISTER_ID))
                .with_controllers(vec![ROOT_CANISTER_ID.get()])
                .build(),
        ),
    );
    assert_eq!(cmc_canister_id, CYCLES_MINTING_CANISTER_ID);

    let lifeline_canister_id = create_canister(
        machine,
        build_lifeline_wasm(),
        Some(Encode!(&init_payloads.lifeline).unwrap()),
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_memory_allocation(memory_allocation_of(LIFELINE_CANISTER_ID))
                .with_controllers(vec![ROOT_CANISTER_ID.get()])
                .build(),
        ),
    );
    assert_eq!(lifeline_canister_id, LIFELINE_CANISTER_ID);

    let genesis_token_canister_id = create_canister(
        machine,
        build_genesis_token_wasm(),
        Some(init_payloads.genesis_token.encode_to_vec()),
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_memory_allocation(memory_allocation_of(GENESIS_TOKEN_CANISTER_ID))
                .with_controllers(vec![ROOT_CANISTER_ID.get()])
                .build(),
        ),
    );
    assert_eq!(genesis_token_canister_id, GENESIS_TOKEN_CANISTER_ID);

    // We need to fill in 2 CanisterIds, but don't use Identity or NNS-UI canisters in our tests
    let identity_canister_id = machine.create_canister(None);
    assert_eq!(identity_canister_id, IDENTITY_CANISTER_ID);

    let nns_ui_canister_id = machine.create_canister(None);
    assert_eq!(nns_ui_canister_id, NNS_UI_CANISTER_ID);

    setup_nns_sns_wasms_with_correct_canister_id(machine, init_payloads.sns_wasms);
}

pub fn mint_icp(state_machine: &mut StateMachine, destination: AccountIdentifier, amount: Tokens) {
    // Construct request.
    let mut transfer_request = vec![];
    SendArgs {
        to: destination,
        // An overwhelmingly large number, but not so large as to cause serious risk of
        // addition overflow.
        amount,

        // Non-Operative
        // -------------
        fee: Tokens::ZERO, // Because we are minting.
        memo: Memo(0),
        from_subaccount: None,
        created_at_time: None,
    }
    .into_proto()
    .encode(&mut transfer_request)
    .unwrap();

    // Call ledger.
    let result = state_machine.execute_ingress_as(
        PrincipalId::from(GOVERNANCE_CANISTER_ID),
        LEDGER_CANISTER_ID,
        "send_pb",
        transfer_request,
    );

    // Assert result is ok.
    match result {
        Ok(WasmResult::Reply(_reply)) => (), // Ok,
        _ => panic!("{:?}", result),
    }
}

pub fn nns_governance_get_full_neuron(
    state_machine: &mut StateMachine,
    sender: PrincipalId,
    neuron_id: u64,
) -> Result<nns_governance_pb::Neuron, GovernanceError> {
    let result = state_machine
        .execute_ingress_as(
            sender,
            GOVERNANCE_CANISTER_ID,
            "get_full_neuron",
            Encode!(&neuron_id).unwrap(),
        )
        .unwrap();

    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!(
                "get_full_neuron was rejected by the NNS governance canister: {:#?}",
                reject
            )
        }
    };
    Decode!(&result, Result<nns_governance_pb::Neuron, GovernanceError>).unwrap()
}

pub fn nns_governance_get_neuron_info(
    state_machine: &mut StateMachine,
    sender: PrincipalId,
    neuron_id: u64,
) -> Result<nns_governance_pb::NeuronInfo, GovernanceError> {
    let result = state_machine
        .execute_ingress_as(
            sender,
            GOVERNANCE_CANISTER_ID,
            "get_neuron_info",
            Encode!(&neuron_id).unwrap(),
        )
        .unwrap();

    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!(
                "get_neuron_info was rejected by the NNS governance canister: {:#?}",
                reject
            )
        }
    };
    Decode!(&result, Result<nns_governance_pb::NeuronInfo, GovernanceError>).unwrap()
}

pub fn nns_governance_get_proposal_info_as_anonymous(
    state_machine: &mut StateMachine,
    proposal_id: u64,
) -> ProposalInfo {
    nns_governance_get_proposal_info(state_machine, proposal_id, PrincipalId::new_anonymous())
}

pub fn nns_governance_get_proposal_info(
    state_machine: &mut StateMachine,
    proposal_id: u64,
    sender: PrincipalId,
) -> ProposalInfo {
    let result = state_machine
        .execute_ingress_as(
            sender,
            GOVERNANCE_CANISTER_ID,
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

pub fn nns_send_icp_to_claim_or_refresh_neuron(
    state_machine: &StateMachine,
    sender: PrincipalId,
    amount: Tokens,
    destination_neuron_nonce: u64,
) {
    icrc1_transfer(
        state_machine,
        LEDGER_CANISTER_ID,
        sender,
        TransferArg {
            amount: amount.into(),
            fee: Some(Nat::from(DEFAULT_TRANSFER_FEE)),
            from_subaccount: None,
            to: Account {
                owner: PrincipalId::from(GOVERNANCE_CANISTER_ID).into(),
                subaccount: Some(compute_neuron_staking_subaccount_bytes(
                    sender,
                    destination_neuron_nonce,
                )),
            },
            created_at_time: None,
            memo: None,
        },
    )
    .unwrap();
}

#[must_use]
fn manage_neuron(
    state_machine: &mut StateMachine,
    sender: PrincipalId,
    neuron_id: NeuronId,
    command: nns_governance_pb::manage_neuron::Command,
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

trait NnsManageNeuronConfigureOperation {
    fn into_operation(self) -> Operation;
}

impl NnsManageNeuronConfigureOperation for IncreaseDissolveDelay {
    fn into_operation(self) -> Operation {
        Operation::IncreaseDissolveDelay(self)
    }
}

trait NnsManageNeuronCommand {
    fn into_command(self) -> nns_governance_pb::manage_neuron::Command;
}

impl NnsManageNeuronCommand for nns_governance_pb::manage_neuron::Configure {
    fn into_command(self) -> nns_governance_pb::manage_neuron::Command {
        nns_governance_pb::manage_neuron::Command::Configure(self)
    }
}

fn nns_configure_neuron(
    state_machine: &mut StateMachine,
    sender: PrincipalId,
    neuron_id: NeuronId,
    operation: nns_governance_pb::manage_neuron::configure::Operation,
) -> Result<
    // No useful information here (currently).
    nns_governance_pb::manage_neuron_response::ConfigureResponse,
    nns_governance_pb::GovernanceError,
> {
    let result = manage_neuron(
        state_machine,
        sender,
        neuron_id,
        nns_governance_pb::manage_neuron::Configure {
            operation: Some(operation),
        }
        .into_command(),
    );

    // Convert result into a Result.
    match result.command {
        Some(nns_governance_pb::manage_neuron_response::Command::Configure(configure)) => {
            Ok(configure)
        }
        Some(nns_governance_pb::manage_neuron_response::Command::Error(error)) => Err(error),
        _ => panic!("{:#?}", result),
    }
}

#[must_use]
pub fn nns_create_super_powerful_neuron(
    state_machine: &mut StateMachine,
    controller: PrincipalId,
) -> NeuronId {
    let memo = 0xCAFE_F00D;

    // Mint ICP for new Neuron.
    let destination = AccountIdentifier::new(
        PrincipalId::from(GOVERNANCE_CANISTER_ID),
        Some(compute_neuron_staking_subaccount(controller, memo)),
    );
    // "Overwhelmingly" large, but still small enough to avoid addition overflow.
    let amount = Tokens::from_e8s(u64::MAX / 4);
    mint_icp(state_machine, destination, amount);

    // Create the Neuron.
    let neuron_id = nns_claim_or_refresh_neuron(state_machine, controller, memo);

    // Make it eligible to vote.
    let increase_dissolve_delay_result = nns_increase_dissolve_delay(
        state_machine,
        controller,
        neuron_id,
        8 * 365 * ONE_DAY_SECONDS,
    );
    // assert ok.
    match increase_dissolve_delay_result {
        Ok(nns_governance_pb::manage_neuron_response::ConfigureResponse {}) => (),
        _ => panic!("{:#?}", increase_dissolve_delay_result),
    }

    neuron_id
}

#[must_use]
pub fn nns_claim_or_refresh_neuron(
    state_machine: &mut StateMachine,
    controller: PrincipalId,
    memo: u64,
) -> NeuronId {
    // Construct request.
    let command = Some(manage_neuron::Command::ClaimOrRefresh(ClaimOrRefresh {
        by: Some(claim_or_refresh::By::MemoAndController(MemoAndController {
            memo,
            controller: Some(controller),
        })),
    }));
    let manage_neuron = ManageNeuron {
        id: None,
        command,
        neuron_id_or_subaccount: None,
    };
    let manage_neuron = Encode!(&manage_neuron).unwrap();

    // Call governance.
    let result = state_machine
        .execute_ingress_as(
            controller,
            GOVERNANCE_CANISTER_ID,
            "manage_neuron",
            manage_neuron,
        )
        .unwrap();

    // Unpack and return result.
    let result = match result {
        WasmResult::Reply(reply) => Decode!(&reply, ManageNeuronResponse).unwrap(),
        _ => panic!("{:?}", result),
    };
    let neuron_id = match &result.command {
        Some(manage_neuron_response::Command::ClaimOrRefresh(ClaimOrRefreshResponse {
            refreshed_neuron_id: Some(neuron_id),
        })) => neuron_id,
        _ => panic!("{:?}", result),
    };
    *neuron_id
}

pub fn nns_increase_dissolve_delay(
    state_machine: &mut StateMachine,
    sender: PrincipalId,
    neuron_id: NeuronId,
    additional_dissolve_delay_seconds: u64,
) -> Result<
    nns_governance_pb::manage_neuron_response::ConfigureResponse,
    nns_governance_pb::GovernanceError,
> {
    let additional_dissolve_delay_seconds =
        u32::try_from(additional_dissolve_delay_seconds).unwrap();

    nns_configure_neuron(
        state_machine,
        sender,
        neuron_id,
        nns_governance_pb::manage_neuron::IncreaseDissolveDelay {
            additional_dissolve_delay_seconds,
        }
        .into_operation(),
    )
}

#[must_use]
pub fn nns_propose_upgrade_nns_canister(
    state_machine: &mut StateMachine,
    neuron_controller: PrincipalId,
    proposer_neuron_id: NeuronId,
    target_canister_id: CanisterId,
    wasm_content: Vec<u8>,
) -> ProposalId {
    assert_ne!(
        target_canister_id, ROOT_CANISTER_ID,
        "Upgrading root via proposal is not supported yet."
    );
    let wasm_len = wasm_content.len();

    // Construct main proposal content. To wit, specify that the WASM is to be installed in the
    // target canister.
    let payload = Encode!(&ChangeCanisterRequest::new(
        true, // stop_before_installing,
        CanisterInstallMode::Upgrade,
        target_canister_id,
    )
    .with_memory_allocation(memory_allocation_of(target_canister_id))
    .with_wasm(wasm_content))
    .unwrap();

    // Call governance. (Use the specified Neuron.)
    let manage_neuron_response = nns_governance_make_proposal(
        state_machine,
        neuron_controller, // sender
        proposer_neuron_id,
        &Proposal {
            title: Some(format!(
                "Upgrade {} (wasm len = {})",
                target_canister_id, wasm_len
            )),
            action: Some(proposal::Action::ExecuteNnsFunction(ExecuteNnsFunction {
                nns_function: NnsFunction::NnsCanisterUpgrade as i32,
                payload,
            })),
            ..Default::default()
        },
    );

    // Unpack response.
    match manage_neuron_response {
        nns_governance_pb::ManageNeuronResponse {
            command:
                Some(nns_governance_pb::manage_neuron_response::Command::MakeProposal(
                    nns_governance_pb::manage_neuron_response::MakeProposalResponse {
                        proposal_id: Some(proposal_id),
                        ..
                    },
                )),
        } => proposal_id,

        _ => panic!("{:#?}", manage_neuron_response),
    }
}

pub fn nns_cast_vote(
    state_machine: &mut StateMachine,
    sender: PrincipalId,
    neuron_id: NeuronId,
    proposal_id: u64,
    vote: Vote,
) -> ManageNeuronResponse {
    let command = manage_neuron::Command::RegisterVote(RegisterVote {
        proposal: Some(ic_nns_common::pb::v1::ProposalId { id: proposal_id }),
        vote: vote as i32,
    });

    manage_neuron(state_machine, sender, neuron_id, command)
}

pub fn nns_split_neuron(
    state_machine: &mut StateMachine,
    sender: PrincipalId,
    neuron_id: NeuronId,
    amount: u64,
) -> ManageNeuronResponse {
    let command = manage_neuron::Command::Split(Split { amount_e8s: amount });

    manage_neuron(state_machine, sender, neuron_id, command)
}

pub fn get_neuron_ids(state_machine: &mut StateMachine, sender: PrincipalId) -> Vec<u64> {
    let result = state_machine
        .execute_ingress_as(
            sender,
            GOVERNANCE_CANISTER_ID,
            "get_neuron_ids",
            Encode!(&Empty {}).unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to get_neuron_ids failed: {:#?}", s),
    };

    Decode!(&result, Vec<u64>).unwrap()
}

pub fn get_pending_proposals(state_machine: &mut StateMachine) -> Vec<ProposalInfo> {
    let result = state_machine
        .execute_ingress(
            GOVERNANCE_CANISTER_ID,
            "get_pending_proposals",
            Encode!(&Empty {}).unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to get_pending_proposals failed: {:#?}", s),
    };

    Decode!(&result, Vec<ProposalInfo>).unwrap()
}

pub fn nns_join_community_fund(
    state_machine: &mut StateMachine,
    sender: PrincipalId,
    neuron_id: NeuronId,
) -> ManageNeuronResponse {
    let command = manage_neuron::Command::Configure(Configure {
        operation: Some(Operation::JoinCommunityFund(JoinCommunityFund {})),
    });

    manage_neuron(state_machine, sender, neuron_id, command)
}

pub fn nns_leave_community_fund(
    state_machine: &mut StateMachine,
    sender: PrincipalId,
    neuron_id: NeuronId,
) -> ManageNeuronResponse {
    let command = manage_neuron::Command::Configure(Configure {
        operation: Some(Operation::LeaveCommunityFund(LeaveCommunityFund {})),
    });

    manage_neuron(state_machine, sender, neuron_id, command)
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

pub fn nns_set_followees_for_neuron(
    state_machine: &mut StateMachine,
    sender: PrincipalId,
    neuron_id: NeuronId,
    followees: &[NeuronId],
    topic: i32,
) -> ManageNeuronResponse {
    let command = manage_neuron::Command::Follow(Follow {
        topic,
        followees: followees
            .iter()
            .map(|leader| NeuronId { id: leader.id })
            .collect(),
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

pub fn nns_stake_maturity(
    state_machine: &mut StateMachine,
    sender: PrincipalId,
    neuron_id: NeuronId,
    percentage_to_stake: Option<u32>,
) -> ManageNeuronResponse {
    let command = manage_neuron::Command::StakeMaturity(StakeMaturity {
        percentage_to_stake,
    });

    manage_neuron(state_machine, sender, neuron_id, command)
}

pub fn nns_get_migrations(state_machine: &mut StateMachine) -> Migrations {
    let reply = query(
        state_machine,
        GOVERNANCE_CANISTER_ID,
        "get_migrations",
        Encode!(&Empty {}).unwrap(),
    )
    .unwrap();

    Decode!(&reply, Migrations).unwrap()
}

pub fn nns_list_proposals(state_machine: &mut StateMachine) -> ListProposalInfoResponse {
    let result = state_machine
        .execute_ingress(
            GOVERNANCE_CANISTER_ID,
            "list_proposals",
            Encode!(&ListProposalInfo::default()).unwrap(),
        )
        .unwrap();

    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to list_proposals failed: {:#?}", s),
    };

    Decode!(&result, ListProposalInfoResponse).unwrap()
}

/// Return the monthly Node Provider rewards
pub fn nns_get_monthly_node_provider_rewards(
    state_machine: &mut StateMachine,
) -> Result<RewardNodeProviders, GovernanceError> {
    let result = state_machine
        .execute_ingress(
            GOVERNANCE_CANISTER_ID,
            "get_monthly_node_provider_rewards",
            Encode!(&()).unwrap(),
        )
        .unwrap();

    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => {
            panic!("Call to get_monthly_node_provider_rewards failed: {:#?}", s)
        }
    };

    Decode!(&result, Result<RewardNodeProviders, GovernanceError>).unwrap()
}

/// Return the most recent monthly Node Provider rewards
pub fn nns_get_most_recent_monthly_node_provider_rewards(
    state_machine: &mut StateMachine,
) -> Option<MostRecentMonthlyNodeProviderRewards> {
    let result = state_machine
        .execute_ingress(
            GOVERNANCE_CANISTER_ID,
            "get_most_recent_monthly_node_provider_rewards",
            Encode!(&()).unwrap(),
        )
        .unwrap();

    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => {
            panic!(
                "Call to get_most_recent_monthly_node_provider_rewards failed: {:#?}",
                s
            )
        }
    };

    Decode!(&result, Option<MostRecentMonthlyNodeProviderRewards>).unwrap()
}

pub fn nns_get_network_economics_parameters(state_machine: &mut StateMachine) -> NetworkEconomics {
    let result = state_machine
        .execute_ingress(
            GOVERNANCE_CANISTER_ID,
            "get_network_economics_parameters",
            Encode!(&()).unwrap(),
        )
        .unwrap();

    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => {
            panic!("Call to get_network_economics_parameters failed: {:#?}", s)
        }
    };

    Decode!(&result, NetworkEconomics).unwrap()
}

pub fn list_deployed_snses(state_machine: &mut StateMachine) -> ListDeployedSnsesResponse {
    let result = state_machine
        .execute_ingress(
            SNS_WASM_CANISTER_ID,
            "list_deployed_snses",
            Encode!(&ListDeployedSnsesRequest::default()).unwrap(),
        )
        .unwrap();

    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to list_deployed_snses failed: {:#?}", s),
    };

    Decode!(&result, ListDeployedSnsesResponse).unwrap()
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

/// Returns when the proposal has been executed. A proposal is considered to be
/// executed when executed_timestamp_seconds > 0.
pub fn nns_wait_for_proposal_execution(machine: &mut StateMachine, proposal_id: u64) {
    // We create some blocks until the proposal has finished executing (machine.tick())
    let mut attempt_count = 0;
    let mut last_proposal = None;
    while attempt_count < 50 {
        attempt_count += 1;

        machine.tick();
        let proposal = nns_governance_get_proposal_info_as_anonymous(machine, proposal_id);
        if proposal.executed_timestamp_seconds > 0 {
            return;
        }
        assert_eq!(
            proposal.failure_reason, None,
            "Proposal execution failed: {:#?}",
            proposal
        );

        last_proposal = Some(proposal);
        machine.advance_time(Duration::from_millis(100));
    }

    panic!(
        "Looks like proposal {:?} is never going to be executed: {:#?}",
        proposal_id, last_proposal,
    );
}

/// Returns when the proposal has failed execution. A proposal is considered to be
/// executed when failed_timestamp_seconds > 0.
pub fn nns_wait_for_proposal_failure(machine: &mut StateMachine, proposal_id: u64) {
    // We create some blocks until the proposal has finished failing (machine.tick())
    let mut last_proposal = None;
    for _ in 0..50 {
        machine.tick();
        let proposal = nns_governance_get_proposal_info_as_anonymous(machine, proposal_id);
        if proposal.failed_timestamp_seconds > 0 {
            return;
        }
        assert_eq!(
            proposal.executed_timestamp_seconds, 0,
            "Proposal execution succeeded when it was not supposed to: {:#?}",
            proposal
        );

        last_proposal = Some(proposal);
        machine.advance_time(Duration::from_millis(100));
    }

    panic!(
        "Looks like proposal {:?} is never going to be executed: {:#?}",
        proposal_id, last_proposal,
    );
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
                owner: governance_canister_id.get().0,
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

pub fn ledger_account_balance(
    state_machine: &mut StateMachine,
    ledger_canister_id: CanisterId,
    request: &BinaryAccountBalanceArgs,
) -> Tokens {
    let result = state_machine
        .execute_ingress(
            ledger_canister_id,
            "account_balance",
            Encode!(&request).unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!("get_state was rejected by the swap canister: {:#?}", reject)
        }
    };
    Decode!(&result, Tokens).unwrap()
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

pub fn icrc1_fee(machine: &StateMachine, ledger_id: CanisterId) -> Nat {
    let result = query(machine, ledger_id, "icrc1_fee", Encode!().unwrap()).unwrap();
    Decode!(&result, Nat).unwrap()
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

pub fn icrc1_token_name(machine: &StateMachine, ledger_id: CanisterId) -> String {
    let result = query(machine, ledger_id, "icrc1_name", Encode!(&()).unwrap()).unwrap();
    Decode!(&result, String).unwrap()
}

pub fn icrc1_token_symbol(machine: &StateMachine, ledger_id: CanisterId) -> String {
    let result = query(machine, ledger_id, "icrc1_symbol", Encode!(&()).unwrap()).unwrap();
    Decode!(&result, String).unwrap()
}

pub fn icrc1_token_logo(machine: &StateMachine, ledger_id: CanisterId) -> Option<String> {
    let result = query(machine, ledger_id, "icrc1_metadata", Encode!(&()).unwrap()).unwrap();
    use icrc_ledger_types::icrc::generic_metadata_value::MetadataValue;
    Decode!(&result, Vec<(String, MetadataValue)>)
        .unwrap()
        .into_iter()
        .find(|(key, _)| key == "icrc1:logo")
        .map(|(_key, value)| match value {
            MetadataValue::Text(s) => s,
            m => panic!("Unexpected metadata value {m:?}"),
        })
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
        sns_pb::ManageNeuron {
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
    proposal: sns_pb::Proposal,
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

/// Call the get_mode method.
pub fn sns_governance_get_mode(
    state_machine: &mut StateMachine,
    sns_governance_canister_id: CanisterId,
) -> Result</* mode as i32 */ i32, String> {
    let get_mode_response = query(
        state_machine,
        sns_governance_canister_id,
        "get_mode",
        Encode!(&sns_pb::GetMode {}).unwrap(),
    )
    .map_err(|e| format!("Error calling get_mode: {}", e))?;

    let GetModeResponse { mode } = Decode!(&get_mode_response, sns_pb::GetModeResponse).unwrap();

    Ok(mode.unwrap())
}

pub fn sns_swap_get_auto_finalization_status(
    state_machine: &StateMachine,
    sns_swap_canister_id: CanisterId,
) -> GetAutoFinalizationStatusResponse {
    let get_auto_finalization_status_response = query(
        state_machine,
        sns_swap_canister_id,
        "get_auto_finalization_status",
        Encode!(&GetAutoFinalizationStatusRequest {}).unwrap(),
    )
    .unwrap();

    Decode!(
        &get_auto_finalization_status_response,
        GetAutoFinalizationStatusResponse
    )
    .unwrap()
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
            "proposal {:?} not executed after {} attempts: {:?}",
            proposal_id,
            attempt_count,
            proposal
        );

        if let Ok(p) = proposal {
            proposal_executed = p.executed_timestamp_seconds != 0;
        }
        machine.advance_time(Duration::from_millis(100));
    }
}

pub fn sns_wait_for_proposal_executed_or_failed(
    machine: &StateMachine,
    governance: CanisterId,
    proposal_id: sns_pb::ProposalId,
) {
    // We create some blocks until the proposal has finished executing (machine.tick())
    let mut attempt_count = 0;
    let mut proposal_executed = false;
    let mut proposal_failed = false;
    while !proposal_executed && !proposal_failed {
        attempt_count += 1;
        machine.tick();

        let proposal = sns_get_proposal(machine, governance, proposal_id);
        assert!(
            attempt_count < 50,
            "proposal {:?} not executed after {} attempts: {:?}",
            proposal_id,
            attempt_count,
            proposal
        );

        if let Ok(p) = proposal {
            proposal_executed = p.executed_timestamp_seconds != 0;
            proposal_failed = p.failed_timestamp_seconds != 0;
        }
        machine.advance_time(Duration::from_millis(100));
    }
}

pub fn sns_get_icp_treasury_account_balance(
    machine: &StateMachine,
    sns_governance_id: PrincipalId,
) -> Tokens {
    icrc1_balance(
        machine,
        LEDGER_CANISTER_ID,
        Account {
            owner: sns_governance_id.0,
            subaccount: None,
        },
    )
}

/// Get the ICP/XDR conversion rate from the cycles minting canister.
pub fn get_icp_xdr_conversion_rate(
    machine: &StateMachine,
) -> IcpXdrConversionRateCertifiedResponse {
    let bytes = query(
        machine,
        CYCLES_MINTING_CANISTER_ID,
        "get_icp_xdr_conversion_rate",
        Encode!().unwrap(),
    )
    .expect("Failed to retrieve the conversion rate");
    Decode!(&bytes, IcpXdrConversionRateCertifiedResponse).unwrap()
}

pub fn cmc_set_default_authorized_subnetworks(
    machine: &mut StateMachine,
    subnets: Vec<SubnetId>,
    sender: PrincipalId,
    neuron_id: NeuronId,
) {
    let args = SetAuthorizedSubnetworkListArgs { who: None, subnets };
    let proposal = Proposal {
        title: Some("set subnetworks".to_string()),
        summary: "setting subnetworks".to_string(),
        url: "".to_string(),
        action: Some(Action::ExecuteNnsFunction(ExecuteNnsFunction {
            nns_function: NnsFunction::SetAuthorizedSubnetworks as i32,
            payload: Encode!(&args).unwrap(),
        })),
    };

    let propose_response = nns_governance_make_proposal(machine, sender, neuron_id, &proposal);

    let proposal_id = match propose_response.command.unwrap() {
        manage_neuron_response::Command::MakeProposal(response) => response.proposal_id.unwrap(),
        _ => panic!("Propose didn't return MakeProposal"),
    };

    nns_wait_for_proposal_execution(machine, proposal_id.id);
}

pub fn setup_cycles_ledger(state_machine: &StateMachine) {
    #[derive(CandidType, Serialize, Clone, Debug, PartialEq, Eq)]
    enum LedgerArgs {
        Init(Config),
    }
    #[derive(CandidType, Serialize, Clone, Debug, PartialEq, Eq)]
    struct Config {
        pub max_transactions_per_request: u64,
        pub index_id: Option<candid::Principal>,
    }

    state_machine.reroute_canister_range(
        std::ops::RangeInclusive::<CanisterId>::new(
            CYCLES_LEDGER_CANISTER_ID.try_into().unwrap(),
            CYCLES_LEDGER_CANISTER_ID.try_into().unwrap(),
        ),
        state_machine.get_subnet_id(),
    );
    state_machine.create_canister_with_cycles(
        Some(CYCLES_LEDGER_CANISTER_ID),
        Cycles::zero(),
        None,
    );
    let cycles_ledger_wasm = std::fs::read(
        std::env::var("CYCLES_LEDGER_WASM_PATH").expect("CYCLES_LEDGER_WASM_PATH not set"),
    )
    .unwrap();
    let arg = Encode!(&LedgerArgs::Init(Config {
        max_transactions_per_request: 50,
        index_id: None,
    }))
    .unwrap();
    state_machine
        .install_existing_canister(
            CYCLES_LEDGER_CANISTER_ID.try_into().unwrap(),
            cycles_ledger_wasm,
            arg,
        )
        .expect("Installing cycles ledger failed");
}

pub fn setup_subnet_rental_canister_with_correct_canister_id(state_machine: &StateMachine) {
    let canister_id = create_canister_id_at_position(
        state_machine,
        SUBNET_RENTAL_CANISTER_INDEX_IN_NNS_SUBNET,
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_controllers(vec![ROOT_CANISTER_ID.get()])
                .with_memory_allocation(memory_allocation_of(SUBNET_RENTAL_CANISTER_ID))
                .build(),
        ),
    );
    assert_eq!(canister_id, SUBNET_RENTAL_CANISTER_ID);

    let subnet_rental_canister_wasm = std::fs::read(
        std::env::var("SUBNET_RENTAL_CANISTER_WASM_PATH")
            .expect("SUBNET_RENTAL_CANISTER_WASM_PATH not set"),
    )
    .unwrap();
    let arg = Encode!(&()).unwrap();
    state_machine
        .install_existing_canister(SUBNET_RENTAL_CANISTER_ID, subnet_rental_canister_wasm, arg)
        .expect("Installing subnet rental canister failed");

    // Subnet Rental Canister needs cycles to call XRC
    state_machine.add_cycles(canister_id, 100_000_000_000_000);
}
