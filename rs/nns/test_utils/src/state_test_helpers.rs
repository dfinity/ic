use crate::common::{
    build_cmc_wasm, build_genesis_token_wasm, build_governance_wasm, build_ledger_wasm,
    build_lifeline_wasm, build_registry_wasm, build_root_wasm, build_sns_wasms_wasm,
    NnsInitPayloads,
};
use candid::Encode;
use canister_test::Wasm;
use ic_base_types::{CanisterId, PrincipalId};
use ic_ic00_types::{CanisterInstallMode, CanisterSettingsArgs};
use ic_nns_constants::{
    memory_allocation_of, CYCLES_MINTING_CANISTER_ID, GENESIS_TOKEN_CANISTER_ID,
    GOVERNANCE_CANISTER_ID, IDENTITY_CANISTER_ID, LEDGER_CANISTER_ID, LIFELINE_CANISTER_ID,
    NNS_UI_CANISTER_ID, REGISTRY_CANISTER_ID, ROOT_CANISTER_ID, SNS_WASM_CANISTER_ID,
};
use ic_state_machine_tests::StateMachine;
use ic_test_utilities::universal_canister::{
    call_args, wasm as universal_canister_argument_builder, UNIVERSAL_CANISTER_WASM,
};
use ic_types::ingress::WasmResult;
use ic_types::Cycles;
use on_wire::{FromWire, IntoWire, NewType};
use prost::Message;
use std::default::Default;
use std::env;

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
    machine.set_time(std::time::SystemTime::now());
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
    machine.set_time(std::time::SystemTime::now());
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
    machine.set_time(std::time::SystemTime::now());
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

    let governance_canister_id = create_canister(
        machine,
        build_governance_wasm(),
        Some(init_payloads.governance.encode_to_vec()),
        Some(CanisterSettingsArgs {
            memory_allocation: Some(memory_allocation_of(GOVERNANCE_CANISTER_ID).into()),
            ..Default::default()
        }),
    );
    assert_eq!(governance_canister_id, GOVERNANCE_CANISTER_ID);

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

    let sns_wasms_canister_id = create_canister(
        machine,
        build_sns_wasms_wasm(),
        Some(Encode!(&init_payloads.sns_wasms).unwrap()),
        Some(CanisterSettingsArgs {
            memory_allocation: Some(memory_allocation_of(SNS_WASM_CANISTER_ID).into()),
            ..Default::default()
        }),
    );
    assert_eq!(sns_wasms_canister_id, SNS_WASM_CANISTER_ID);
}
