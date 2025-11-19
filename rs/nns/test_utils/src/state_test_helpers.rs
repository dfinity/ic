use crate::common::{
    NnsInitPayloads, build_cmc_wasm, build_genesis_token_wasm, build_governance_wasm_with_features,
    build_ledger_wasm, build_lifeline_wasm, build_node_rewards_wasm,
    build_registry_wasm_with_features, build_root_wasm, build_sns_wasms_wasm,
};
use crate::state_test_helpers::nns_governance_pb::Visibility;
use candid::{CandidType, Decode, Encode, Nat};
use canister_test::Wasm;
use cycles_minting_canister::{
    CyclesCanisterInitPayload, IcpXdrConversionRateCertifiedResponse,
    SetAuthorizedSubnetworkListArgs,
};
use dfn_http::types::{HttpRequest, HttpResponse};
use dfn_protobuf::ToProto;
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_management_canister_types_private::{
    CanisterInstallMode, CanisterSettingsArgs, CanisterSettingsArgsBuilder, CanisterStatusResultV2,
    UpdateSettingsArgs,
};
use ic_nervous_system_clients::{
    canister_id_record::CanisterIdRecord,
    canister_status::{CanisterStatusResult, CanisterStatusType},
};
use ic_nervous_system_common::{
    DEFAULT_TRANSFER_FEE, ONE_DAY_SECONDS,
    ledger::{compute_neuron_staking_subaccount, compute_neuron_staking_subaccount_bytes},
};
use ic_nns_common::init::LifelineCanisterInitPayload;
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_nns_constants::{
    CYCLES_LEDGER_CANISTER_ID, CYCLES_MINTING_CANISTER_ID,
    CYCLES_MINTING_CANISTER_INDEX_IN_NNS_SUBNET, GENESIS_TOKEN_CANISTER_INDEX_IN_NNS_SUBNET,
    GOVERNANCE_CANISTER_ID, GOVERNANCE_CANISTER_INDEX_IN_NNS_SUBNET, LEDGER_CANISTER_ID,
    LEDGER_CANISTER_INDEX_IN_NNS_SUBNET, LIFELINE_CANISTER_ID,
    LIFELINE_CANISTER_INDEX_IN_NNS_SUBNET, NODE_REWARDS_CANISTER_INDEX_IN_NNS_SUBNET,
    REGISTRY_CANISTER_ID, REGISTRY_CANISTER_INDEX_IN_NNS_SUBNET, ROOT_CANISTER_ID,
    ROOT_CANISTER_INDEX_IN_NNS_SUBNET, SNS_WASM_CANISTER_ID, SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET,
    SUBNET_RENTAL_CANISTER_ID, SUBNET_RENTAL_CANISTER_INDEX_IN_NNS_SUBNET,
    canister_id_to_nns_canister_name, memory_allocation_of,
};
use ic_nns_governance_api::{
    self as nns_governance_pb, Empty, ExecuteNnsFunction, GetNeuronsFundAuditInfoRequest,
    GetNeuronsFundAuditInfoResponse, Governance, GovernanceError, InstallCodeRequest,
    ListNeuronVotesRequest, ListNeuronVotesResponse, ListNeurons, ListNeuronsResponse,
    ListNodeProviderRewardsRequest, ListNodeProviderRewardsResponse, ListProposalInfoRequest,
    ListProposalInfoResponse, MakeProposalRequest, ManageNeuronCommandRequest, ManageNeuronRequest,
    ManageNeuronResponse, MonthlyNodeProviderRewards, NetworkEconomics, NnsFunction,
    ProposalActionRequest, ProposalInfo, RewardNodeProviders, Vote,
    manage_neuron::{
        self, AddHotKey, ChangeAutoStakeMaturity, ClaimOrRefresh, Configure, Disburse,
        DisburseMaturity, Follow, IncreaseDissolveDelay, JoinCommunityFund, LeaveCommunityFund,
        RegisterVote, RemoveHotKey, Split, StakeMaturity,
        claim_or_refresh::{self, MemoAndController},
        configure::Operation,
    },
    manage_neuron_response::{self, ClaimOrRefreshResponse},
};
use ic_nns_gtc::pb::v1::Gtc;
use ic_nns_handler_root::init::RootCanisterInitPayload;
use ic_registry_canister_api::{GetChunkRequest, mutate_test_high_capacity_records};
use ic_registry_transport::{
    deserialize_get_latest_version_response,
    pb::v1::{
        HighCapacityRegistryGetChangesSinceResponse, HighCapacityRegistryGetValueResponse,
        RegistryGetChangesSinceRequest, RegistryGetValueRequest,
    },
};
use ic_sns_governance::pb::v1::{
    self as sns_pb, GetModeResponse, manage_neuron_response::Command as SnsCommandResponse,
};
use ic_sns_swap::pb::v1::{GetAutoFinalizationStatusRequest, GetAutoFinalizationStatusResponse};
use ic_sns_wasm::{
    init::SnsWasmCanisterInitPayload,
    pb::v1::{ListDeployedSnsesRequest, ListDeployedSnsesResponse},
};
use ic_state_machine_tests::{StateMachine, StateMachineBuilder};
use ic_test_utilities::universal_canister::{
    UNIVERSAL_CANISTER_WASM, call_args, wasm as universal_canister_argument_builder,
};
use ic_types::{Cycles, ingress::WasmResult};
use icp_ledger::{
    AccountIdentifier, BinaryAccountBalanceArgs, BlockIndex, LedgerCanisterInitPayload, Memo,
    SendArgs, Tokens,
};
use icrc_ledger_types::icrc1::{
    account::Account,
    transfer::{TransferArg, TransferError},
};
use num_traits::ToPrimitive;
use prost::Message;
use registry_canister::init::RegistryCanisterInitPayload;
use serde::Serialize;
use std::{convert::TryInto, time::Duration};
/// This canister ID can be used as `specified_id` in tests on `state_machine_builder_for_nns_tests`.
/// Canisters created in those tests without any `specified_id` are assigned to the default range
/// from `CanisterId::from_u64(0x0000000)` to `CanisterId::from_u64(0x00FFFFF)` and thus
/// canisters created with `specified_id` can only be assigned to the extra range
/// from `CanisterId::from_u64(0x2100000)` to `CanisterId::from_u64(0x21FFFFE)`.
pub const SPECIFIED_CANISTER_ID: CanisterId = CanisterId::from_u64(0x2100000);

/// A `StateMachine` builder setting the IC time to the current time
/// and using the canister ranges of both the NNS and II subnets.
/// Note. The last canister ID in the canister range of the II subnet
/// is omitted so that the canister range of the II subnet is not used
/// for automatic generation of new canister IDs.
pub fn state_machine_builder_for_nns_tests() -> StateMachineBuilder {
    StateMachineBuilder::new()
        .with_current_time()
        .with_extra_canister_range(std::ops::RangeInclusive::<CanisterId>::new(
            CanisterId::from_u64(0x2100000),
            CanisterId::from_u64(0x21FFFFE),
        ))
}

pub fn registry_mutate_test_high_capacity_records(
    state_machine: &StateMachine,
    request: mutate_test_high_capacity_records::Request,
) -> u64 {
    let sender = PrincipalId::from(GOVERNANCE_CANISTER_ID);
    let result = state_machine
        .execute_ingress_as(
            sender,
            REGISTRY_CANISTER_ID,
            "mutate_test_high_capacity_records",
            Encode!(&request).unwrap(),
        )
        .unwrap();

    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!("get_changes_since was rejected by the NNS registry canister: {reject:#?}")
        }
    };

    Decode!(&result, u64).unwrap()
}

pub fn registry_latest_version(state_machine: &StateMachine) -> Result<u64, String> {
    let response = update(
        state_machine,
        REGISTRY_CANISTER_ID,
        "get_latest_version",
        vec![],
    )?;
    deserialize_get_latest_version_response(response)
        .map_err(|e| format!("Could not decode response {e:?}"))
}

pub fn registry_high_capacity_get_changes_since(
    state_machine: &StateMachine,
    sender: PrincipalId,
    version: u64,
) -> HighCapacityRegistryGetChangesSinceResponse {
    let mut request = vec![];
    RegistryGetChangesSinceRequest { version }
        .encode(&mut request)
        .unwrap();

    let result = state_machine
        .execute_ingress_as(sender, REGISTRY_CANISTER_ID, "get_changes_since", request)
        .unwrap();

    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!("get_changes_since was rejected by the NNS registry canister: {reject:#?}")
        }
    };

    HighCapacityRegistryGetChangesSinceResponse::decode(&result[..]).unwrap()
}

pub fn registry_get_value(
    state_machine: &StateMachine,
    key: &[u8],
) -> HighCapacityRegistryGetValueResponse {
    let request = RegistryGetValueRequest {
        key: key.to_vec(),
        version: None,
    }
    .encode_to_vec();

    let result = state_machine
        .execute_ingress(REGISTRY_CANISTER_ID, "get_value", request)
        .unwrap();

    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!("get_changes_since was rejected by the NNS registry canister: {reject:#?}")
        }
    };

    HighCapacityRegistryGetValueResponse::decode(&result[..]).unwrap()
}

pub fn registry_get_chunk(
    state_machine: &StateMachine,
    chunk_content_sha256: &[u8],
) -> Result<ic_registry_canister_api::Chunk, String> {
    let content_sha256 = Some(chunk_content_sha256.to_vec());
    let request = GetChunkRequest { content_sha256 };

    let result = state_machine
        .execute_ingress(
            REGISTRY_CANISTER_ID,
            "get_chunk",
            Encode!(&request).unwrap(),
        )
        .unwrap();

    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!("get chunk was rejected by the NNS registry canister: {reject:#?}")
        }
    };

    Decode!(&result, Result<ic_registry_canister_api::Chunk, String>).unwrap()
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
    update_with_sender_bytes(
        machine,
        canister_target,
        method_name,
        payload,
        PrincipalId::new_anonymous(),
    )
}

pub fn update_with_sender_bytes(
    machine: &StateMachine,
    canister_target: CanisterId,
    method_name: &str,
    payload: Vec<u8>,
    sender: PrincipalId,
) -> Result<Vec<u8>, String> {
    let result = machine
        .execute_ingress_as(sender, canister_target, method_name, payload)
        .map_err(|e| e.to_string())?;
    match result {
        WasmResult::Reply(v) => Ok(v),
        WasmResult::Reject(s) => Err(format!("Canister rejected with message: {s}")),
    }
}

pub fn update_with_sender<Payload, ReturnType>(
    machine: &StateMachine,
    canister_target: CanisterId,
    method_name: &str,
    payload: Payload,
    sender: PrincipalId,
) -> Result<ReturnType, String>
where
    Payload: CandidType,
    ReturnType: CandidType + for<'de> serde::Deserialize<'de>,
{
    // move time forward
    machine.advance_time(Duration::from_secs(2));

    let response = update_with_sender_bytes(
        machine,
        canister_target,
        method_name,
        Encode!(&payload).unwrap(),
        sender,
    )?;

    Decode!(&response, ReturnType).map_err(|e| e.to_string())
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
        WasmResult::Reject(s) => Err(format!("Canister rejected with message: {s}")),
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

/// Once you have a Scrape, pass it to a function like get_gauge, get_counter,
/// et. al., which are provided by nervous_system/common/test_utils.
pub fn scrape_metrics(
    state_machine: &StateMachine,
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

    assert_eq!(http_response.status_code, 200, "{http_response:#?}");

    let body = String::from_utf8(http_response.body.to_vec())
        .unwrap()
        .lines()
        .map(|s| Ok(s.to_owned()))
        .collect::<Vec<_>>()
        .into_iter();

    prometheus_parse::Scrape::parse(body).unwrap()
}

pub fn make_http_request(
    state_machine: &StateMachine,
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
        CanisterIdRecord::from(target),
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
        CanisterIdRecord::from(target),
        sender,
    )
}

pub fn get_root_canister_status(machine: &StateMachine) -> Result<CanisterStatusResultV2, String> {
    machine
        .canister_status_as(PrincipalId::from(LIFELINE_CANISTER_ID), ROOT_CANISTER_ID)
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
        CanisterIdRecord::from(target),
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
            Wasm::from_bytes(UNIVERSAL_CANISTER_WASM.to_vec()).bytes(),
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

/// Check that a canister exists  at 0-indexed position (assuming canisters are created sequentially).
/// If it does not, then create it (and all canisters in between).
/// This approach is used because create_canister advances the canister ID counter in the underlying
/// execution environment, which otherwise creates problems with creating other canisters
/// with non-specified IDs.  If that bug is fixed, the behavior in this test helper can be changed.
pub fn ensure_canister_id_exists_at_position_with_settings(
    machine: &StateMachine,
    position: u64,
    canister_settings: Option<CanisterSettingsArgs>,
) -> CanisterId {
    let mut canister_id = CanisterId::from_u64(position);
    if !machine.canister_exists(canister_id) {
        canister_id = machine.create_canister(None);
        while canister_id_to_u64(canister_id) < position {
            canister_id = machine.create_canister(canister_settings.clone());
        }

        // In case we tried using this when we are already past the sequence
        assert_eq!(canister_id_to_u64(canister_id), position);
    }

    if let Some(settings) = canister_settings {
        machine
            .update_settings(&canister_id, settings)
            .expect("Canister settings could not be updated.");
    };

    canister_id
}

fn setup_nns_canister_at_position(
    machine: &StateMachine,
    index: u64,
    wasm: Wasm,
    payload: Vec<u8>,
) {
    let controllers = if index == ROOT_CANISTER_INDEX_IN_NNS_SUBNET {
        vec![LIFELINE_CANISTER_ID.get()]
    } else {
        vec![ROOT_CANISTER_ID.get()]
    };
    let args = CanisterSettingsArgsBuilder::new()
        .with_memory_allocation(memory_allocation_of(CanisterId::from_u64(index)))
        .with_controllers(controllers)
        .build();

    let canister_id =
        ensure_canister_id_exists_at_position_with_settings(machine, index, Some(args));

    machine
        .install_wasm_in_mode(
            canister_id,
            CanisterInstallMode::Install,
            wasm.bytes(),
            payload,
        )
        .unwrap();
}

pub fn setup_registry_with_correct_canister_id(
    machine: &StateMachine,
    init_payload: RegistryCanisterInitPayload,
    features: &[&str],
) {
    setup_nns_canister_at_position(
        machine,
        REGISTRY_CANISTER_INDEX_IN_NNS_SUBNET,
        build_registry_wasm_with_features(features),
        Encode!(&init_payload).unwrap(),
    );
}

pub fn setup_nns_governance_with_correct_canister_id(
    machine: &StateMachine,
    init_payload: Governance,
    features: &[&str],
) {
    setup_nns_canister_at_position(
        machine,
        GOVERNANCE_CANISTER_INDEX_IN_NNS_SUBNET,
        build_governance_wasm_with_features(features),
        Encode!(&init_payload).unwrap(),
    );
}

pub fn setup_nns_ledger_canister_with_correct_canister_id(
    machine: &StateMachine,
    init_payload: LedgerCanisterInitPayload,
) {
    setup_nns_canister_at_position(
        machine,
        LEDGER_CANISTER_INDEX_IN_NNS_SUBNET,
        build_ledger_wasm(),
        Encode!(&init_payload).unwrap(),
    );
}

pub fn setup_nns_root_with_correct_canister_id(
    machine: &StateMachine,
    init_payload: RootCanisterInitPayload,
) {
    setup_nns_canister_at_position(
        machine,
        ROOT_CANISTER_INDEX_IN_NNS_SUBNET,
        build_root_wasm(),
        Encode!(&init_payload).unwrap(),
    );
}

pub fn setup_cmc_with_correct_canister_id(
    machine: &StateMachine,
    init_payload: Option<CyclesCanisterInitPayload>,
) {
    setup_nns_canister_at_position(
        machine,
        CYCLES_MINTING_CANISTER_INDEX_IN_NNS_SUBNET,
        build_cmc_wasm(),
        Encode!(&init_payload).unwrap(),
    );
}

pub fn setup_lifeline_with_correct_canister_id(
    machine: &StateMachine,
    init_payload: LifelineCanisterInitPayload,
) {
    setup_nns_canister_at_position(
        machine,
        LIFELINE_CANISTER_INDEX_IN_NNS_SUBNET,
        build_lifeline_wasm(),
        Encode!(&init_payload).unwrap(),
    );
}

pub fn setup_gtc_with_correct_canister_id(machine: &StateMachine, init_payload: Gtc) {
    setup_nns_canister_at_position(
        machine,
        GENESIS_TOKEN_CANISTER_INDEX_IN_NNS_SUBNET,
        build_genesis_token_wasm(),
        init_payload.encode_to_vec(),
    );
}

/// Creates empty canisters up until the correct SNS-WASM id, then installs SNS-WASMs with payload
/// This allows creating a few canisters before calling this.
pub fn setup_nns_sns_wasms_with_correct_canister_id(
    machine: &StateMachine,
    init_payload: SnsWasmCanisterInitPayload,
) {
    setup_nns_canister_at_position(
        machine,
        SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET,
        build_sns_wasms_wasm(),
        Encode!(&init_payload).unwrap(),
    );
}

pub fn setup_nns_node_rewards_with_correct_canister_id(machine: &StateMachine) {
    setup_nns_canister_at_position(
        machine,
        NODE_REWARDS_CANISTER_INDEX_IN_NNS_SUBNET,
        build_node_rewards_wasm(),
        Encode!().unwrap(),
    );
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
    setup_registry_with_correct_canister_id(machine, init_payloads.registry, features);

    setup_nns_governance_with_correct_canister_id(machine, init_payloads.governance, features);

    setup_nns_ledger_canister_with_correct_canister_id(machine, init_payloads.ledger);

    setup_nns_root_with_correct_canister_id(machine, init_payloads.root);

    setup_cmc_with_correct_canister_id(machine, init_payloads.cycles_minting);

    setup_lifeline_with_correct_canister_id(machine, init_payloads.lifeline);

    setup_gtc_with_correct_canister_id(machine, init_payloads.genesis_token);

    // Canister IDs are automatically filled in by subsequent creation scripts (so they exist, but
    // nothing is installed).

    setup_nns_sns_wasms_with_correct_canister_id(machine, init_payloads.sns_wasms);

    setup_nns_node_rewards_with_correct_canister_id(machine);
}

pub fn mint_icp(state_machine: &StateMachine, destination: AccountIdentifier, amount: Tokens) {
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
        _ => panic!("{result:?}"),
    }
}

pub fn nns_governance_get_full_neuron(
    state_machine: &StateMachine,
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
            panic!("get_full_neuron was rejected by the NNS governance canister: {reject:#?}")
        }
    };
    Decode!(&result, Result<nns_governance_pb::Neuron, GovernanceError>).unwrap()
}

pub fn nns_governance_get_neuron_info(
    state_machine: &StateMachine,
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
            panic!("get_neuron_info was rejected by the NNS governance canister: {reject:#?}")
        }
    };
    Decode!(&result, Result<nns_governance_pb::NeuronInfo, GovernanceError>).unwrap()
}

pub fn nns_governance_get_proposal_info_as_anonymous(
    state_machine: &StateMachine,
    proposal_id: u64,
) -> ProposalInfo {
    nns_governance_get_proposal_info(state_machine, proposal_id, PrincipalId::new_anonymous())
}

pub fn nns_governance_get_proposal_info(
    state_machine: &StateMachine,
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
            panic!("get_proposal_info was rejected by the NNS governance canister: {reject:#?}")
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

fn manage_neuron(
    state_machine: &StateMachine,
    sender: PrincipalId,
    neuron_id: NeuronId,
    command: nns_governance_pb::ManageNeuronCommandRequest,
) -> Result<ManageNeuronResponse, String> {
    let result = state_machine
        .execute_ingress_as(
            sender,
            GOVERNANCE_CANISTER_ID,
            "manage_neuron",
            Encode!(&ManageNeuronRequest {
                id: Some(neuron_id),
                command: Some(command),
                neuron_id_or_subaccount: None
            })
            .unwrap(),
        )
        .map_err(|e| e.to_string())?;

    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => return Err(s),
    };
    let response = Decode!(&result, ManageNeuronResponse).unwrap();

    Ok(response)
}

#[must_use]
fn manage_neuron_or_panic(
    state_machine: &StateMachine,
    sender: PrincipalId,
    neuron_id: NeuronId,
    command: nns_governance_pb::ManageNeuronCommandRequest,
) -> ManageNeuronResponse {
    manage_neuron(state_machine, sender, neuron_id, command).expect("manage_neuron failed")
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
    fn into_command(self) -> nns_governance_pb::ManageNeuronCommandRequest;
}

impl NnsManageNeuronCommand for nns_governance_pb::manage_neuron::Configure {
    fn into_command(self) -> nns_governance_pb::ManageNeuronCommandRequest {
        nns_governance_pb::ManageNeuronCommandRequest::Configure(self)
    }
}

fn nns_configure_neuron(
    state_machine: &StateMachine,
    sender: PrincipalId,
    neuron_id: NeuronId,
    operation: nns_governance_pb::manage_neuron::configure::Operation,
) -> Result<
    // No useful information here (currently).
    nns_governance_pb::manage_neuron_response::ConfigureResponse,
    nns_governance_pb::GovernanceError,
> {
    let result = manage_neuron_or_panic(
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
        _ => panic!("{result:#?}"),
    }
}

#[must_use]
pub fn nns_create_super_powerful_neuron(
    state_machine: &StateMachine,
    controller: PrincipalId,
    tokens: Tokens,
) -> NeuronId {
    let memo = 0xCAFE_F00D;

    // Mint ICP for new Neuron.
    let destination = AccountIdentifier::new(
        PrincipalId::from(GOVERNANCE_CANISTER_ID),
        Some(compute_neuron_staking_subaccount(controller, memo)),
    );
    // "Overwhelmingly" large, but still small enough to avoid addition overflow.
    mint_icp(state_machine, destination, tokens);

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
        _ => panic!("{increase_dissolve_delay_result:#?}"),
    }

    neuron_id
}

#[must_use]
pub fn nns_claim_or_refresh_neuron(
    state_machine: &StateMachine,
    controller: PrincipalId,
    memo: u64,
) -> NeuronId {
    // Construct request.
    let command = Some(ManageNeuronCommandRequest::ClaimOrRefresh(ClaimOrRefresh {
        by: Some(claim_or_refresh::By::MemoAndController(MemoAndController {
            memo,
            controller: Some(controller),
        })),
    }));
    let manage_neuron = ManageNeuronRequest {
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
        _ => panic!("{result:?}"),
    };
    let neuron_id = match &result.command {
        Some(manage_neuron_response::Command::ClaimOrRefresh(ClaimOrRefreshResponse {
            refreshed_neuron_id: Some(neuron_id),
        })) => neuron_id,
        _ => panic!("{result:?}"),
    };
    *neuron_id
}

pub fn nns_disburse_neuron(
    state_machine: &StateMachine,
    sender: PrincipalId,
    neuron_id: NeuronId,
    amount_e8s: Option<u64>,
    to_account: Option<AccountIdentifier>,
) -> ManageNeuronResponse {
    manage_neuron_or_panic(
        state_machine,
        sender,
        neuron_id,
        ManageNeuronCommandRequest::Disburse(Disburse {
            amount: amount_e8s
                .map(|amount_e8s| manage_neuron::disburse::Amount { e8s: amount_e8s }),
            to_account: to_account.map(|account| account.into()),
        }),
    )
}

pub fn nns_increase_dissolve_delay(
    state_machine: &StateMachine,
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

pub fn nns_make_neuron_public(
    state_machine: &StateMachine,
    sender: PrincipalId,
    neuron_id: NeuronId,
) -> Result<
    nns_governance_pb::manage_neuron_response::ConfigureResponse,
    nns_governance_pb::GovernanceError,
> {
    nns_configure_neuron(
        state_machine,
        sender,
        neuron_id,
        Operation::SetVisibility(nns_governance_pb::manage_neuron::SetVisibility {
            visibility: Some(Visibility::Public as i32),
        }),
    )
}

pub fn nns_start_dissolving(
    state_machine: &StateMachine,
    sender: PrincipalId,
    neuron_id: NeuronId,
) -> Result<
    nns_governance_pb::manage_neuron_response::ConfigureResponse,
    nns_governance_pb::GovernanceError,
> {
    nns_configure_neuron(
        state_machine,
        sender,
        neuron_id,
        Operation::StartDissolving(nns_governance_pb::manage_neuron::StartDissolving {}),
    )
}

pub fn nns_disburse_maturity(
    state_machine: &StateMachine,
    sender: PrincipalId,
    neuron_id: NeuronId,
    disburse_maturity: DisburseMaturity,
) -> ManageNeuronResponse {
    manage_neuron_or_panic(
        state_machine,
        sender,
        neuron_id,
        ManageNeuronCommandRequest::DisburseMaturity(disburse_maturity),
    )
}

#[must_use]
pub fn nns_propose_upgrade_nns_canister(
    state_machine: &StateMachine,
    neuron_controller: PrincipalId,
    proposer_neuron_id: NeuronId,
    target_canister_id: CanisterId,
    wasm_module: Vec<u8>,
    module_arg: Vec<u8>,
) -> ProposalId {
    let target_canister_name = canister_id_to_nns_canister_name(target_canister_id);

    let proposal = MakeProposalRequest {
        title: Some(format!("Upgrade {target_canister_name}")),
        action: Some(ProposalActionRequest::InstallCode(InstallCodeRequest {
            canister_id: Some(target_canister_id.get()),
            install_mode: Some(3),
            wasm_module: Some(wasm_module),
            arg: Some(module_arg),
            skip_stopping_before_installing: None,
        })),
        ..Default::default()
    };

    // Make the proposal
    let manage_neuron_response = nns_governance_make_proposal(
        state_machine,
        neuron_controller, // sender
        proposer_neuron_id,
        &proposal,
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

        _ => panic!("{manage_neuron_response:#?}"),
    }
}

fn slice_to_hex(slice: &[u8]) -> String {
    slice
        .iter()
        .map(|b| format!("{:02X}", *b))
        .collect::<Vec<String>>()
        .join("")
}

pub fn wait_for_canister_upgrade_to_succeed(
    state_machine: &StateMachine,
    canister_id: CanisterId,
    new_wasm_hash: &[u8; 32],
    // For most NNS canisters, ROOT_CANISTER_ID would be passed here (modulo conversion).
    controller_principal_id: PrincipalId,
) {
    let mut last_status = None;
    for i in 0..25 {
        state_machine.tick();

        // Fetch status of the canister being upgraded.
        let status_result = get_canister_status(
            state_machine,
            controller_principal_id,
            canister_id,
            CanisterId::ic_00(), // callee: the management canister.
        );

        // Continue if call was an err. This isn't necessarily a problem,
        // because there is a brief period when the canister is being upgraded
        // during which, it is temporarily unavailable.
        let status = match status_result {
            Ok(ok) => ok,
            Err(err) => {
                println!(
                    "Unable to read the status of {canister_id} on iteration {i}. \
                     This is most likely a transient error:\n{err:?}",
                );
                continue;
            }
        };

        last_status = Some(status.clone());

        // Return if done.
        let done = status.status == CanisterStatusType::Running
            // Hash matches.
            && status.module_hash.as_ref().unwrap() == &new_wasm_hash.to_vec();
        if done {
            println!(
                "Yay! We were able to upgrade {} to {} on iteration {}.",
                canister_id_to_nns_canister_name(canister_id),
                slice_to_hex(new_wasm_hash),
                i,
            );
            return;
        }

        println!(
            "Upgrade is not done yet (as of iteration {}): {}.",
            i, status.status,
        );
    }

    panic!(
        "After waiting a long time, Canister {} never ended up with WASM {}. \
         last status: {:#?}",
        canister_id,
        slice_to_hex(new_wasm_hash),
        last_status,
    );
}

pub fn nns_cast_vote(
    state_machine: &StateMachine,
    sender: PrincipalId,
    neuron_id: NeuronId,
    proposal_id: u64,
    vote: Vote,
) -> Result<ManageNeuronResponse, String> {
    let command = ManageNeuronCommandRequest::RegisterVote(RegisterVote {
        proposal: Some(ic_nns_common::pb::v1::ProposalId { id: proposal_id }),
        vote: vote as i32,
    });

    manage_neuron(state_machine, sender, neuron_id, command)
}

pub fn nns_cast_vote_or_panic(
    state_machine: &StateMachine,
    sender: PrincipalId,
    neuron_id: NeuronId,
    proposal_id: u64,
    vote: Vote,
) -> ManageNeuronResponse {
    nns_cast_vote(state_machine, sender, neuron_id, proposal_id, vote).expect("Failed to cast vote")
}

pub fn nns_split_neuron(
    state_machine: &StateMachine,
    sender: PrincipalId,
    neuron_id: NeuronId,
    amount: u64,
) -> ManageNeuronResponse {
    let command = ManageNeuronCommandRequest::Split(Split {
        amount_e8s: amount,
        memo: None,
    });

    manage_neuron_or_panic(state_machine, sender, neuron_id, command)
}

pub fn get_neuron_ids(state_machine: &StateMachine, sender: PrincipalId) -> Vec<u64> {
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
        WasmResult::Reject(s) => panic!("Call to get_neuron_ids failed: {s:#?}"),
    };

    Decode!(&result, Vec<u64>).unwrap()
}

pub fn get_pending_proposals(state_machine: &StateMachine) -> Vec<ProposalInfo> {
    let result = state_machine
        .execute_ingress(
            GOVERNANCE_CANISTER_ID,
            "get_pending_proposals",
            Encode!(&Empty {}).unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to get_pending_proposals failed: {s:#?}"),
    };

    Decode!(&result, Vec<ProposalInfo>).unwrap()
}

pub fn nns_join_community_fund(
    state_machine: &StateMachine,
    sender: PrincipalId,
    neuron_id: NeuronId,
) -> ManageNeuronResponse {
    let command = ManageNeuronCommandRequest::Configure(Configure {
        operation: Some(Operation::JoinCommunityFund(JoinCommunityFund {})),
    });

    manage_neuron_or_panic(state_machine, sender, neuron_id, command)
}

pub fn nns_leave_community_fund(
    state_machine: &StateMachine,
    sender: PrincipalId,
    neuron_id: NeuronId,
) -> ManageNeuronResponse {
    let command = ManageNeuronCommandRequest::Configure(Configure {
        operation: Some(Operation::LeaveCommunityFund(LeaveCommunityFund {})),
    });

    manage_neuron_or_panic(state_machine, sender, neuron_id, command)
}

pub fn nns_governance_make_proposal(
    state_machine: &StateMachine,
    sender: PrincipalId,
    neuron_id: NeuronId,
    proposal: &MakeProposalRequest,
) -> ManageNeuronResponse {
    let command = ManageNeuronCommandRequest::MakeProposal(Box::new(proposal.clone()));

    manage_neuron_or_panic(state_machine, sender, neuron_id, command)
}

pub fn nns_add_hot_key(
    state_machine: &StateMachine,
    sender: PrincipalId,
    neuron_id: NeuronId,
    new_hot_key: PrincipalId,
) -> ManageNeuronResponse {
    let command = ManageNeuronCommandRequest::Configure(Configure {
        operation: Some(Operation::AddHotKey(AddHotKey {
            new_hot_key: Some(new_hot_key),
        })),
    });

    manage_neuron_or_panic(state_machine, sender, neuron_id, command)
}

pub fn nns_set_followees_for_neuron(
    state_machine: &StateMachine,
    sender: PrincipalId,
    neuron_id: NeuronId,
    followees: &[NeuronId],
    topic: i32,
) -> ManageNeuronResponse {
    let command = ManageNeuronCommandRequest::Follow(Follow {
        topic,
        followees: followees
            .iter()
            .map(|leader| NeuronId { id: leader.id })
            .collect(),
    });

    manage_neuron_or_panic(state_machine, sender, neuron_id, command)
}

pub fn nns_remove_hot_key(
    state_machine: &StateMachine,
    sender: PrincipalId,
    neuron_id: NeuronId,
    hot_key_to_remove: PrincipalId,
) -> ManageNeuronResponse {
    let command = ManageNeuronCommandRequest::Configure(Configure {
        operation: Some(Operation::RemoveHotKey(RemoveHotKey {
            hot_key_to_remove: Some(hot_key_to_remove),
        })),
    });

    manage_neuron_or_panic(state_machine, sender, neuron_id, command)
}

pub fn nns_stake_maturity(
    state_machine: &StateMachine,
    sender: PrincipalId,
    neuron_id: NeuronId,
    percentage_to_stake: Option<u32>,
) -> ManageNeuronResponse {
    let command = ManageNeuronCommandRequest::StakeMaturity(StakeMaturity {
        percentage_to_stake,
    });

    manage_neuron_or_panic(state_machine, sender, neuron_id, command)
}

pub fn nns_set_auto_stake_maturity(
    state_machine: &StateMachine,
    sender: PrincipalId,
    neuron_id: NeuronId,
    auto_stake: bool,
) -> ManageNeuronResponse {
    let command = ManageNeuronCommandRequest::Configure(Configure {
        operation: Some(Operation::ChangeAutoStakeMaturity(
            ChangeAutoStakeMaturity {
                requested_setting_for_auto_stake_maturity: auto_stake,
            },
        )),
    });

    manage_neuron_or_panic(state_machine, sender, neuron_id, command)
}

pub fn nns_list_proposals(
    state_machine: &StateMachine,
    request: ListProposalInfoRequest,
) -> ListProposalInfoResponse {
    let result = state_machine
        .execute_ingress(
            GOVERNANCE_CANISTER_ID,
            "list_proposals",
            Encode!(&request).unwrap(),
        )
        .unwrap();

    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to list_proposals failed: {s:#?}"),
    };

    Decode!(&result, ListProposalInfoResponse).unwrap()
}

/// Return the monthly Node Provider rewards
pub fn nns_get_monthly_node_provider_rewards(
    state_machine: &StateMachine,
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
            panic!("Call to get_monthly_node_provider_rewards failed: {s:#?}")
        }
    };

    Decode!(&result, Result<RewardNodeProviders, GovernanceError>).unwrap()
}

/// Return the most recent monthly Node Provider rewards
pub fn nns_get_most_recent_monthly_node_provider_rewards(
    state_machine: &StateMachine,
) -> Option<MonthlyNodeProviderRewards> {
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
            panic!("Call to get_most_recent_monthly_node_provider_rewards failed: {s:#?}")
        }
    };

    Decode!(&result, Option<MonthlyNodeProviderRewards>).unwrap()
}

pub fn nns_list_node_provider_rewards(
    state_machine: &StateMachine,
    list_node_provider_rewards_request: ListNodeProviderRewardsRequest,
) -> ListNodeProviderRewardsResponse {
    let result = state_machine
        .execute_ingress(
            GOVERNANCE_CANISTER_ID,
            "list_node_provider_rewards",
            Encode!(&list_node_provider_rewards_request).unwrap(),
        )
        .unwrap();

    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to list_node_provider_rewards failed: {s:#?}"),
    };

    Decode!(&result, ListNodeProviderRewardsResponse).unwrap()
}

pub fn nns_get_network_economics_parameters(state_machine: &StateMachine) -> NetworkEconomics {
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
            panic!("Call to get_network_economics_parameters failed: {s:#?}")
        }
    };

    Decode!(&result, NetworkEconomics).unwrap()
}

pub fn list_deployed_snses(state_machine: &StateMachine) -> ListDeployedSnsesResponse {
    let result = state_machine
        .execute_ingress(
            SNS_WASM_CANISTER_ID,
            "list_deployed_snses",
            Encode!(&ListDeployedSnsesRequest::default()).unwrap(),
        )
        .unwrap();

    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to list_deployed_snses failed: {s:#?}"),
    };

    Decode!(&result, ListDeployedSnsesResponse).unwrap()
}

pub fn get_neurons_fund_audit_info(
    state_machine: &StateMachine,
    proposal_id: ProposalId,
) -> GetNeuronsFundAuditInfoResponse {
    let result = state_machine
        .execute_ingress_as(
            PrincipalId::new_anonymous(),
            GOVERNANCE_CANISTER_ID,
            "get_neurons_fund_audit_info",
            Encode!(&GetNeuronsFundAuditInfoRequest {
                nns_proposal_id: Some(proposal_id)
            })
            .unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => {
            panic!("Call to get_neurons_fund_audit_info failed: {s:#?}")
        }
    };

    Decode!(&result, GetNeuronsFundAuditInfoResponse).unwrap()
}

pub fn list_neurons(
    state_machine: &StateMachine,
    sender: PrincipalId,
    request: ListNeurons,
) -> ListNeuronsResponse {
    let result = state_machine
        .execute_ingress_as(
            sender,
            GOVERNANCE_CANISTER_ID,
            "list_neurons",
            Encode!(&request).unwrap(),
        )
        .unwrap();

    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to list_neurons failed: {s:#?}"),
    };

    Decode!(&result, ListNeuronsResponse).unwrap()
}

/// This function is intended to ensure all neurons are paged through.  It
/// recursively calls `list_neurons`.  This method will panic if more than 20 requests are made
/// this method could be adjusted.
pub fn list_all_neurons_and_combine_responses(
    state_machine: &StateMachine,
    sender: PrincipalId,
    request: ListNeurons,
) -> ListNeuronsResponse {
    assert_eq!(
        request.page_number.unwrap_or_default(),
        0,
        "This method is intended to ensure all neurons \
                        are paged through.  `page_number` should be None or Some(0)"
    );

    let mut response = list_neurons(state_machine, sender, request.clone());

    let pages_needed = response.total_pages_available.unwrap();

    for page in 1..=pages_needed {
        let mut new_request = request.clone();
        new_request.page_number = Some(page);
        let mut new_response = list_neurons(state_machine, sender, new_request);
        response.full_neurons.append(&mut new_response.full_neurons);
        response
            .neuron_infos
            .extend(new_response.neuron_infos.into_iter());
    }

    response
}

pub fn list_neurons_by_principal(
    state_machine: &StateMachine,
    sender: PrincipalId,
) -> ListNeuronsResponse {
    list_neurons(
        state_machine,
        sender,
        ListNeurons {
            neuron_ids: vec![],
            include_neurons_readable_by_caller: true,
            include_empty_neurons_readable_by_caller: None,
            include_public_neurons_in_full_neurons: None,
            page_number: None,
            page_size: None,
            neuron_subaccounts: None,
        },
    )
}

/// Returns when the proposal has been executed. A proposal is considered to be
/// executed when executed_timestamp_seconds > 0.
pub fn nns_wait_for_proposal_execution(machine: &StateMachine, proposal_id: u64) {
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
            "Proposal execution failed: {proposal:#?}"
        );

        last_proposal = Some(proposal);
        machine.advance_time(Duration::from_millis(100));
    }

    panic!("Looks like proposal {proposal_id:?} is never going to be executed: {last_proposal:#?}",);
}

/// Returns when the proposal has failed execution. A proposal is considered to be
/// executed when failed_timestamp_seconds > 0.
pub fn nns_wait_for_proposal_failure(machine: &StateMachine, proposal_id: u64) {
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
            "Proposal execution succeeded when it was not supposed to: {proposal:#?}"
        );

        last_proposal = Some(proposal);
        machine.advance_time(Duration::from_millis(100));
    }

    panic!("Looks like proposal {proposal_id:?} is never going to be executed: {last_proposal:#?}",);
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
    state_machine: &StateMachine,
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
            panic!("get_state was rejected by the swap canister: {reject:#?}")
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
    let result: Result<Result<Nat, TransferError>, String> =
        update_with_sender(machine, ledger_id, "icrc1_transfer", args, sender);

    let result = result.unwrap();
    match result {
        Ok(n) => Ok(n.0.to_u64().unwrap()),
        Err(e) => Err(format!("{e:?}")),
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
            println!("User {sender} successfully claimed neuron");

            response.refreshed_neuron_id.unwrap()
        }
        SnsCommandResponse::Error(error) => {
            panic!("Unexpected error when claiming neuron for user {sender}: {error}")
        }
        _ => panic!("Unexpected command response when claiming neuron for user {sender}."),
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
        payload,
        sender,
    )
    .expect("Error calling the manage_neuron API.");

    match increase_response.command.unwrap() {
        SnsCommandResponse::Configure(_) => (),
        SnsCommandResponse::Error(error) => {
            panic!("Unexpected error when increasing dissolve delay for user {sender}: {error}")
        }
        _ => {
            panic!("Unexpected command response when increasing dissolve delay for user {sender}.")
        }
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
    state_machine: &StateMachine,
    sns_governance_canister_id: CanisterId,
) -> Result</* mode as i32 */ i32, String> {
    let get_mode_response = query(
        state_machine,
        sns_governance_canister_id,
        "get_mode",
        Encode!(&sns_pb::GetMode {}).unwrap(),
    )
    .map_err(|e| format!("Error calling get_mode: {e}"))?;

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
    .map_err(|e| format!("Error calling get_proposal: {e}"))?;

    let get_proposal_response =
        Decode!(&get_proposal_response, sns_pb::GetProposalResponse).unwrap();
    match get_proposal_response
        .result
        .expect("Empty get_proposal_response")
    {
        sns_pb::get_proposal_response::Result::Error(e) => {
            panic!("get_proposal error: {e}");
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
            "proposal {proposal_id:?} not executed after {attempt_count} attempts: {proposal:?}"
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
            "proposal {proposal_id:?} not executed after {attempt_count} attempts: {proposal:?}"
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

pub fn get_average_icp_xdr_conversion_rate(
    machine: &StateMachine,
) -> IcpXdrConversionRateCertifiedResponse {
    let bytes = query(
        machine,
        CYCLES_MINTING_CANISTER_ID,
        "get_average_icp_xdr_conversion_rate",
        Encode!().unwrap(),
    )
    .expect("Failed to retrieve the average conversion rate");
    Decode!(&bytes, IcpXdrConversionRateCertifiedResponse).unwrap()
}

pub fn cmc_set_default_authorized_subnetworks(
    machine: &StateMachine,
    subnets: Vec<SubnetId>,
    sender: PrincipalId,
    neuron_id: NeuronId,
) {
    cmc_set_authorized_subnetworks_for_principal(machine, None, subnets, sender, neuron_id);
}

pub fn cmc_set_authorized_subnetworks_for_principal(
    machine: &StateMachine,
    principal: Option<PrincipalId>,
    subnets: Vec<SubnetId>,
    sender: PrincipalId,
    neuron_id: NeuronId,
) {
    let args = SetAuthorizedSubnetworkListArgs {
        who: principal,
        subnets,
    };
    let proposal = MakeProposalRequest {
        title: Some("set subnetworks".to_string()),
        summary: "setting subnetworks".to_string(),
        url: "".to_string(),
        action: Some(ProposalActionRequest::ExecuteNnsFunction(
            ExecuteNnsFunction {
                nns_function: NnsFunction::SetAuthorizedSubnetworks as i32,
                payload: Encode!(&args).unwrap(),
            },
        )),
    };

    let propose_response = nns_governance_make_proposal(machine, sender, neuron_id, &proposal);

    let proposal_id = match propose_response.command.unwrap() {
        manage_neuron_response::Command::MakeProposal(response) => response.proposal_id.unwrap(),
        _ => panic!("Propose didn't return MakeProposal"),
    };

    nns_wait_for_proposal_execution(machine, proposal_id.id);
}

pub fn manage_network_economics(
    machine: &StateMachine,
    network_economics: NetworkEconomics,
    sender: PrincipalId,
    neuron_id: NeuronId,
) -> ProposalId {
    let proposal = MakeProposalRequest {
        title: Some("manage network economics".to_string()),
        summary: "manage network economics".to_string(),
        url: "".to_string(),
        action: Some(ProposalActionRequest::ManageNetworkEconomics(
            network_economics,
        )),
    };

    let propose_response = nns_governance_make_proposal(machine, sender, neuron_id, &proposal);

    match propose_response.command.unwrap() {
        manage_neuron_response::Command::MakeProposal(response) => response.proposal_id.unwrap(),
        _ => panic!("Propose didn't return MakeProposal"),
    }
}

pub fn setup_cycles_ledger(state_machine: &StateMachine) {
    #[derive(Clone, Eq, PartialEq, Debug, CandidType, Serialize)]
    enum LedgerArgs {
        Init(Config),
    }
    #[derive(Clone, Eq, PartialEq, Debug, CandidType, Serialize)]
    struct Config {
        pub max_blocks_per_request: u64,
        pub index_id: Option<candid::Principal>,
    }

    state_machine.reroute_canister_range(
        std::ops::RangeInclusive::<CanisterId>::new(
            CYCLES_LEDGER_CANISTER_ID,
            CYCLES_LEDGER_CANISTER_ID,
        ),
        state_machine.get_subnet_id(),
    );
    state_machine.create_canister_with_cycles(
        Some(CYCLES_LEDGER_CANISTER_ID.get()),
        Cycles::zero(),
        None,
    );
    let cycles_ledger_wasm = std::fs::read(
        std::env::var("CYCLES_LEDGER_WASM_PATH").expect("CYCLES_LEDGER_WASM_PATH not set"),
    )
    .unwrap();
    let arg = Encode!(&LedgerArgs::Init(Config {
        max_blocks_per_request: 50,
        index_id: None,
    }))
    .unwrap();
    state_machine
        .install_existing_canister(CYCLES_LEDGER_CANISTER_ID, cycles_ledger_wasm, arg)
        .expect("Installing cycles ledger failed");
}

pub fn setup_subnet_rental_canister_with_correct_canister_id(state_machine: &StateMachine) {
    let canister_id = ensure_canister_id_exists_at_position_with_settings(
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

/// Helper function to register a known neuron via governance proposal.
pub fn nns_register_known_neuron(
    state_machine: &StateMachine,
    proposer_principal: PrincipalId,
    proposer_neuron_id: NeuronId,
    known_neuron: ic_nns_governance_api::KnownNeuron,
) -> ProposalId {
    let proposal = ic_nns_governance_api::MakeProposalRequest {
        title: Some("Register Known Neuron".to_string()),
        summary: "Proposal to register a neuron as a known neuron".to_string(),
        url: "".to_string(),
        action: Some(
            ic_nns_governance_api::ProposalActionRequest::RegisterKnownNeuron(known_neuron),
        ),
    };

    let manage_neuron_response = nns_governance_make_proposal(
        state_machine,
        proposer_principal,
        proposer_neuron_id,
        &proposal,
    );

    match manage_neuron_response.command.unwrap() {
        ic_nns_governance_api::manage_neuron_response::Command::MakeProposal(response) => {
            let proposal_id = response.proposal_id.unwrap();
            nns_wait_for_proposal_execution(state_machine, proposal_id.id);
            proposal_id
        }
        other => panic!("Expected MakeProposal response but got: {other:?}"),
    }
}

/// Helper function to deregister a known neuron via governance proposal.
pub fn nns_deregister_known_neuron(
    state_machine: &StateMachine,
    proposer_principal: PrincipalId,
    proposer_neuron_id: NeuronId,
    deregister_request: ic_nns_governance_api::DeregisterKnownNeuron,
) {
    let proposal = ic_nns_governance_api::MakeProposalRequest {
        title: Some("Deregister Known Neuron".to_string()),
        summary: "Proposal to deregister a known neuron".to_string(),
        url: "".to_string(),
        action: Some(
            ic_nns_governance_api::ProposalActionRequest::DeregisterKnownNeuron(deregister_request),
        ),
    };

    let manage_neuron_response = nns_governance_make_proposal(
        state_machine,
        proposer_principal,
        proposer_neuron_id,
        &proposal,
    );

    match manage_neuron_response.command.unwrap() {
        ic_nns_governance_api::manage_neuron_response::Command::MakeProposal(response) => {
            let proposal_id = response.proposal_id.unwrap();
            nns_wait_for_proposal_execution(state_machine, proposal_id.id);
        }
        other => panic!("Expected MakeProposal response but got: {other:?}"),
    }
}

/// Helper function to list neuron votes.
pub fn nns_list_neuron_votes(
    state_machine: &StateMachine,
    neuron_id: NeuronId,
) -> ListNeuronVotesResponse {
    let request = ListNeuronVotesRequest {
        neuron_id: Some(neuron_id),
        before_proposal: None,
        limit: None,
    };
    let response = query(
        state_machine,
        GOVERNANCE_CANISTER_ID,
        "list_neuron_votes",
        Encode!(&request).unwrap(),
    )
    .expect("Error calling list_neuron_votes");
    Decode!(&response, ListNeuronVotesResponse).expect("Error decoding ListNeuronVotesResponse")
}

pub fn nns_list_neuron_votes_or_panic(
    state_machine: &StateMachine,
    neuron_id: NeuronId,
) -> Vec<(ProposalId, Vote)> {
    nns_list_neuron_votes(state_machine, neuron_id)
        .unwrap()
        .votes
        .unwrap()
        .into_iter()
        .map(|vote| (vote.proposal_id.unwrap(), vote.vote.unwrap()))
        .collect()
}

/// Helper function to list known neurons.
pub fn list_known_neurons(
    state_machine: &StateMachine,
) -> ic_nns_governance_api::ListKnownNeuronsResponse {
    let response_bytes = query(
        state_machine,
        GOVERNANCE_CANISTER_ID,
        "list_known_neurons",
        Encode!(&()).unwrap(),
    )
    .expect("Error calling list_known_neurons");

    Decode!(
        &response_bytes,
        ic_nns_governance_api::ListKnownNeuronsResponse
    )
    .expect("Error decoding ListKnownNeuronsResponse")
}
