use candid::{Decode, Encode};
use ic_config::{
    embedders::Config as EmbeddersConfig,
    execution_environment::Config as HypervisorConfig,
    subnet_config::{CyclesAccountManagerConfig, SubnetConfig},
};
use ic_management_canister_types::{
    self as ic00, BoundedHttpHeaders, CanisterHttpRequestArgs, CanisterIdRecord,
    CanisterInstallMode, CanisterSettingsArgsBuilder, DerivationPath, EcdsaCurve, EcdsaKeyId,
    HttpMethod, MasterPublicKeyId, TransformContext, TransformFunc,
};
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder, StateMachineConfig};
use ic_test_utilities::universal_canister::{call_args, wasm, UNIVERSAL_CANISTER_WASM};
use ic_test_utilities_types::messages::SignedIngressBuilder;
use ic_types::canister_http::MAX_CANISTER_HTTP_RESPONSE_BYTES;
use ic_types::ingress::WasmResult;
use ic_types::messages::{SignedIngressContent, MAX_INTER_CANISTER_PAYLOAD_IN_BYTES};
use ic_types::{
    CanisterId, ComputeAllocation, Cycles, NumBytes, NumInstructions, PrincipalId, SubnetId,
};
use more_asserts::assert_lt;
use std::time::Duration;
use std::{convert::TryFrom, str::FromStr};

const B: u64 = 1_000_000_000;

const DEFAULT_REFERENCE_SUBNET_SIZE: usize = 13;
const TEST_SUBNET_SIZES: [usize; 3] = [4, 13, 34];

pub const ECDSA_SIGNATURE_FEE: Cycles = Cycles::new(10 * B as u128);
pub const SCHNORR_SIGNATURE_FEE: Cycles = Cycles::new(10 * B as u128);
const DEFAULT_CYCLES_PER_NODE: Cycles = Cycles::new(100 * B as u128);
const TEST_CANISTER_INSTALL_EXECUTION_INSTRUCTIONS: u64 = 0;

// instruction cost of executing inc method on the test canister
fn inc_instruction_cost(config: HypervisorConfig) -> u64 {
    use ic_config::embedders::MeteringType;
    use ic_embedders::wasm_utils::instrumentation::instruction_to_cost;
    use ic_embedders::wasm_utils::instrumentation::WasmMemoryType;

    let instruction_to_cost = match config.embedders_config.metering_type {
        MeteringType::New => instruction_to_cost,
        MeteringType::None => |_op: &wasmparser::Operator, _mem_type: WasmMemoryType| 0u64,
    };

    let cc = instruction_to_cost(
        &wasmparser::Operator::I32Const { value: 1 },
        WasmMemoryType::Wasm32,
    );
    let cs = instruction_to_cost(
        &wasmparser::Operator::I32Store {
            memarg: wasmparser::MemArg {
                align: 0,
                max_align: 0,
                offset: 0,
                memory: 0,
            },
        },
        WasmMemoryType::Wasm32,
    );
    let cl = instruction_to_cost(
        &wasmparser::Operator::I32Load {
            memarg: wasmparser::MemArg {
                align: 0,
                max_align: 0,
                offset: 0,
                memory: 0,
            },
        },
        WasmMemoryType::Wasm32,
    );
    let ca = instruction_to_cost(&wasmparser::Operator::I32Add, WasmMemoryType::Wasm32);
    let ccall = instruction_to_cost(
        &wasmparser::Operator::Call { function_index: 0 },
        WasmMemoryType::Wasm32,
    );
    let csys = match config.embedders_config.metering_type {
        MeteringType::New => {
            ic_embedders::wasmtime_embedder::system_api_complexity::overhead::MSG_REPLY_DATA_APPEND
                .get()
                + ic_embedders::wasmtime_embedder::system_api_complexity::overhead::MSG_REPLY.get()
        }
        MeteringType::None => 0,
    };

    let cd = if let MeteringType::New = config.embedders_config.metering_type {
        ic_config::subnet_config::SchedulerConfig::application_subnet()
            .dirty_page_overhead
            .get()
    } else {
        0
    };

    5 * cc + cs + cl + ca + 2 * ccall + csys + cd
}

/// This is a canister that keeps a counter on the heap and exposes various test
/// methods. Exposed methods:
///  * "inc"       increment the counter
///  * "read"      read the counter value
///  * "persist"   copy the counter value to stable memory
///  * "load"      restore the counter value from stable memory
///  * "copy_to"   copy the counter value to the specified address on the heap
///  * "read_at"   read a 32-bit integer at the specified address on the heap
///  * "grow_page" grow stable memory by 1 page
///  * "grow_mem"  grow memory by the current counter value
const TEST_CANISTER: &str = r#"
(module
    (import "ic0" "msg_arg_data_copy"
    (func $msg_arg_data_copy (param $dst i32) (param $offset i32) (param $size i32)))
    (import "ic0" "msg_reply" (func $msg_reply))
    (import "ic0" "msg_reply_data_append"
    (func $msg_reply_data_append (param i32 i32)))
    (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
    (import "ic0" "stable_read"
    (func $stable_read (param $dst i32) (param $offset i32) (param $size i32)))
    (import "ic0" "stable_write"
    (func $stable_write (param $offset i32) (param $src i32) (param $size i32)))

    (func $inc

    ;; load the old counter value, increment, and store it back
    (i32.store

        ;; store at the beginning of the heap
        (i32.const 0) ;; store at the beginning of the heap

        ;; increment heap[0]
        (i32.add

        ;; the old value at heap[0]
        (i32.load (i32.const 0))

        ;; "1"
        (i32.const 1)
        )
    )
    (call $msg_reply_data_append (i32.const 0) (i32.const 0))
    (call $msg_reply)
    )

    (func $read
    ;; now we copied the counter address into heap[0]
    (call $msg_reply_data_append
        (i32.const 0) ;; the counter address from heap[0]
        (i32.const 4) ;; length
    )
    (call $msg_reply)
    )

    (func $copy_to
    (call $msg_arg_data_copy (i32.const 4) (i32.const 0) (i32.const 4))
    (i32.store (i32.load (i32.const 4)) (i32.load (i32.const 0)))
    (call $msg_reply)
    )

    (func $read_at
    (call $msg_arg_data_copy (i32.const 4) (i32.const 0) (i32.const 4))
    (call $msg_reply_data_append (i32.load (i32.const 4)) (i32.const 4))
    (call $msg_reply)
    )

    (func $grow_page
    (drop (call $stable_grow (i32.const 1)))
    (call $msg_reply)
    )

    (func $grow_mem
    (call $msg_arg_data_copy (i32.const 4) (i32.const 0) (i32.const 4))
    (i32.store (i32.const 4)
        (memory.grow (i32.load (i32.const 4))))
    (call $msg_reply_data_append (i32.const 4) (i32.const 4))
    (call $msg_reply)
    )

    (func $persist
    (call $stable_write
        (i32.const 0) ;; offset
        (i32.const 0) ;; src
        (i32.const 4) ;; length
    )
    (call $msg_reply)
    )

    (func $load
    (call $stable_read
        (i32.const 0) ;; dst
        (i32.const 0) ;; offset
        (i32.const 4) ;; length
    )
    (call $msg_reply)
    )

    (memory $memory 1)
    (export "memory" (memory $memory))
    (export "canister_query read" (func $read))
    (export "canister_query read_at" (func $read_at))
    (export "canister_update inc" (func $inc))
    (export "canister_update persist" (func $persist))
    (export "canister_update load" (func $load))
    (export "canister_update copy_to" (func $copy_to))
    (export "canister_update grow_page" (func $grow_page))
    (export "canister_update grow_mem" (func $grow_mem))
)"#;

const TEST_HEARTBEAT_CANISTER_EXECUTE_HEARTBEAT_INSTRUCTIONS: u64 = 1;

/// This is an empty canister that only exposes canister_heartbeat method.
const TEST_HEARTBEAT_CANISTER: &str = r#"
(module
    (func $x)
    (export "canister_heartbeat" (func $x))
)"#;

/// Creates a canister with cycles and installs a wasm module on it.
fn create_canister_with_cycles_install_wasm(
    env: &StateMachine,
    cycles: Cycles,
    wasm: Vec<u8>,
) -> CanisterId {
    let canister_id = env.create_canister_with_cycles(None, cycles, None);
    env.install_wasm_in_mode(canister_id, CanisterInstallMode::Install, wasm, vec![])
        .unwrap();
    canister_id
}

/// Creates universal canister with cycles.
fn create_universal_canister_with_cycles(env: &StateMachine, cycles: Cycles) -> CanisterId {
    create_canister_with_cycles_install_wasm(env, cycles, UNIVERSAL_CANISTER_WASM.to_vec())
}

/// Simulates `execute_round` to get the storage cost of 1 GiB for 1 second
/// with a given compute allocation.
/// Since the duration between allocation charges may not be equal to 1 second
/// the final cost is scaled proportionally.
fn simulate_one_gib_per_second_cost(
    subnet_type: SubnetType,
    subnet_size: usize,
    compute_allocation: ComputeAllocation,
) -> Cycles {
    let one_gib: u64 = 1 << 30;
    let one_second = Duration::from_secs(1);

    let env = StateMachineBuilder::new()
        .with_subnet_type(subnet_type)
        .with_subnet_size(subnet_size)
        .build();
    let canister_id = env.create_canister_with_cycles(
        None,
        DEFAULT_CYCLES_PER_NODE * subnet_size,
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_freezing_threshold(1)
                .with_compute_allocation(compute_allocation.as_percent())
                .with_memory_allocation(one_gib)
                .build(),
        ),
    );

    // The time delta is long enough that allocation charging should be triggered.
    let duration_between_allocation_charges = Duration::from_secs(10);
    env.advance_time(duration_between_allocation_charges);

    let balance_before = env.cycle_balance(canister_id);
    env.tick();
    let balance_after = env.cycle_balance(canister_id);

    // Scale the cost from a defined in config value to a 1 second duration.
    let cost = balance_before - balance_after;
    let one_second_cost =
        (cost * one_second.as_millis()) / duration_between_allocation_charges.as_millis();

    Cycles::from(one_second_cost)
}

/// Specifies fees to keep in `CyclesAccountManagerConfig` for specific operations,
/// eg. `ingress induction cost`, `execution cost` etc.
enum KeepFeesFilter {
    Execution,
    IngressInduction,
    XnetCall,
}

/// Helps to distinguish different costs that are withdrawn within the same execution round.
/// All irrelevant fees in `CyclesAccountManagerConfig` are dropped to zero.
/// This hack allows to calculate operation cost by comparing canister's balance before and after
/// execution round.
fn apply_filter(
    initial_config: CyclesAccountManagerConfig,
    filter: KeepFeesFilter,
) -> CyclesAccountManagerConfig {
    let mut filtered_config = CyclesAccountManagerConfig::system_subnet();
    match filter {
        KeepFeesFilter::Execution => {
            filtered_config.update_message_execution_fee =
                initial_config.update_message_execution_fee;
            filtered_config.ten_update_instructions_execution_fee =
                initial_config.ten_update_instructions_execution_fee;
            filtered_config
        }
        KeepFeesFilter::IngressInduction => {
            filtered_config.ingress_message_reception_fee =
                initial_config.ingress_message_reception_fee;
            filtered_config.ingress_byte_reception_fee = initial_config.ingress_byte_reception_fee;
            filtered_config
        }
        KeepFeesFilter::XnetCall => {
            filtered_config.xnet_call_fee = initial_config.xnet_call_fee;
            filtered_config.xnet_byte_transmission_fee = initial_config.xnet_byte_transmission_fee;
            filtered_config
        }
    }
}

/// Create a `SubnetConfig` with a redacted `CyclesAccountManagerConfig` to have only the fees
/// for specific operation.
fn filtered_subnet_config(subnet_type: SubnetType, filter: KeepFeesFilter) -> SubnetConfig {
    let mut subnet_config = SubnetConfig::new(subnet_type);
    subnet_config.cycles_account_manager_config =
        apply_filter(subnet_config.cycles_account_manager_config, filter);

    subnet_config
}

/// Simulates `execute_round` to get the cost of installing code,
/// including charging and refunding execution cycles.
/// Filtered `CyclesAccountManagerConfig` is used to avoid irrelevant costs,
/// eg. ingress induction cost.
fn simulate_execute_install_code_cost(subnet_type: SubnetType, subnet_size: usize) -> Cycles {
    let env = StateMachineBuilder::new()
        .with_subnet_type(subnet_type)
        .with_subnet_size(subnet_size)
        .with_config(Some(StateMachineConfig::new(
            filtered_subnet_config(subnet_type, KeepFeesFilter::Execution),
            HypervisorConfig {
                embedders_config: EmbeddersConfig {
                    cost_to_compile_wasm_instruction: NumInstructions::from(0),
                    ..Default::default()
                },
                ..Default::default()
            },
        )))
        .build();
    let canister_id =
        env.create_canister_with_cycles(None, DEFAULT_CYCLES_PER_NODE * subnet_size, None);

    let balance_before = env.cycle_balance(canister_id);
    env.install_wasm_in_mode(
        canister_id,
        CanisterInstallMode::Install,
        wat::parse_str(TEST_CANISTER).expect("invalid WAT"),
        vec![],
    )
    .unwrap();
    let balance_after = env.cycle_balance(canister_id);

    Cycles::from(balance_before - balance_after)
}

/// Simulates `execute_round` to get the cost during executing ingress.
/// Filtered `CyclesAccountManagerConfig` is used to avoid irrelevant costs.
fn simulate_execute_ingress_cost(
    subnet_type: SubnetType,
    subnet_size: usize,
    filter: KeepFeesFilter,
) -> Cycles {
    let env = StateMachineBuilder::new()
        .with_subnet_type(subnet_type)
        .with_subnet_size(subnet_size)
        .with_config(Some(StateMachineConfig::new(
            filtered_subnet_config(subnet_type, filter),
            HypervisorConfig::default(),
        )))
        .build();
    let canister_id = create_canister_with_cycles_install_wasm(
        &env,
        DEFAULT_CYCLES_PER_NODE * subnet_size,
        wat::parse_str(TEST_CANISTER).expect("invalid WAT"),
    );

    let balance_before = env.cycle_balance(canister_id);
    env.execute_ingress(canister_id, "inc", vec![]).unwrap();
    let balance_after = env.cycle_balance(canister_id);

    Cycles::from(balance_before - balance_after)
}

fn simulate_ingress_induction_cost(subnet_type: SubnetType, subnet_size: usize) -> Cycles {
    simulate_execute_ingress_cost(subnet_type, subnet_size, KeepFeesFilter::IngressInduction)
}

fn simulate_execute_message_cost(subnet_type: SubnetType, subnet_size: usize) -> Cycles {
    simulate_execute_ingress_cost(subnet_type, subnet_size, KeepFeesFilter::Execution)
}

/// Simulates `execute_round` to get the cost of executing a heartbeat,
/// including charging and refunding execution cycles.
fn simulate_execute_canister_heartbeat_cost(subnet_type: SubnetType, subnet_size: usize) -> Cycles {
    let env = StateMachineBuilder::new()
        .with_subnet_type(subnet_type)
        .with_subnet_size(subnet_size)
        .build();
    let canister_id = create_canister_with_cycles_install_wasm(
        &env,
        DEFAULT_CYCLES_PER_NODE * subnet_size,
        wat::parse_str(TEST_HEARTBEAT_CANISTER).expect("invalid WAT"),
    );

    let balance_before = env.cycle_balance(canister_id);
    env.tick();
    let balance_after = env.cycle_balance(canister_id);

    Cycles::from(balance_before - balance_after)
}

/// Simulates `execute_round` to get the cost of executing signing with ECDSA.
/// Payment is done via attaching cycles to request and the cost is subtracted from it
/// after executing the message.
fn simulate_sign_with_ecdsa_cost(
    subnet_type: SubnetType,
    subnet_size: usize,
    nns_subnet_id: SubnetId,
    subnet_id: SubnetId,
) -> Cycles {
    let key_id = EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: "key_id_secp256k1".to_string(),
    };
    let env = StateMachineBuilder::new()
        .with_subnet_type(subnet_type)
        .with_subnet_size(subnet_size)
        .with_nns_subnet_id(nns_subnet_id)
        .with_subnet_id(subnet_id)
        .with_idkg_key(MasterPublicKeyId::Ecdsa(key_id.clone()))
        .build();
    // Create canister with initial cycles for some unrelated costs (eg. ingress induction, heartbeat).
    let canister_id =
        create_universal_canister_with_cycles(&env, DEFAULT_CYCLES_PER_NODE * subnet_size);

    // SignWithECDSA is paid with cycles attached to the request.
    let payment_before = Cycles::new((2 * B).into()) * subnet_size;
    let sign_with_ecdsa = wasm()
        .call_with_cycles(
            ic00::IC_00,
            ic00::Method::SignWithECDSA,
            call_args().other_side(
                Encode!(&ic00::SignWithECDSAArgs {
                    message_hash: [0; 32],
                    derivation_path: DerivationPath::new(Vec::new()),
                    key_id,
                })
                .unwrap(),
            ),
            payment_before,
        )
        .build();
    // Ignore ingress message response, since SignWithECDSA requires a response
    // from consensus, which is not simulated in staet_machine_tests.
    let _msg_id = env.send_ingress(
        PrincipalId::new_anonymous(),
        canister_id,
        "update",
        sign_with_ecdsa,
    );
    // Run `execute_subnet_message`.
    env.tick();

    // Expect `SignWithEcdsa` request to be added into subnet call context manager.
    // Signature fee is deduced from `request.payment`, the excess amount
    // will be reimbursed after the consensus response.
    let sign_with_ecdsa_contexts = env.sign_with_ecdsa_contexts();
    assert_eq!(sign_with_ecdsa_contexts.len(), 1);
    let (_, context) = sign_with_ecdsa_contexts.iter().next().unwrap();
    let payment_after = context.request.payment;

    payment_before - payment_after
}

/// Simulates `execute_round` to get the cost of executing HTTP request.
/// Payment is done via attaching cycles to request and the cost is subtracted from it
/// after executing the message.
fn simulate_http_request_cost(subnet_type: SubnetType, subnet_size: usize) -> Cycles {
    let env = StateMachineBuilder::new()
        .with_subnet_type(subnet_type)
        .with_subnet_size(subnet_size)
        .with_features(SubnetFeatures::from_str("http_requests").unwrap())
        .build();
    // Create canister with initial cycles for some unrelated costs (eg. ingress induction, heartbeat).
    let canister_id =
        create_universal_canister_with_cycles(&env, DEFAULT_CYCLES_PER_NODE * subnet_size);

    // HttpRequest is paid with cycles attached to the request.
    let payment_before = Cycles::new((20 * B).into()) * subnet_size;
    let http_request = wasm()
        .call_with_cycles(
            ic00::IC_00,
            ic00::Method::HttpRequest,
            call_args().other_side(
                Encode!(&CanisterHttpRequestArgs {
                    url: "https://".to_string(),
                    max_response_bytes: None,
                    headers: BoundedHttpHeaders::new(vec![]),
                    body: None,
                    method: HttpMethod::GET,
                    transform: Some(TransformContext {
                        function: TransformFunc(candid::Func {
                            principal: canister_id.get().0,
                            method: "transform".to_string(),
                        }),
                        context: vec![],
                    }),
                })
                .unwrap(),
            ),
            payment_before,
        )
        .build();
    // Ignore ingress message response, since HttpRequest requires a consensus response,
    // which is not simulated in staet_machine_tests.
    let _msg_id = env.send_ingress(
        PrincipalId::new_anonymous(),
        canister_id,
        "update",
        http_request,
    );

    // Run `execute_subnet_message`.
    env.tick();

    // Expect `HttpRequest` request to be added into subnet call context manager.
    // HttpRequest fee is deduced from `request.payment`, the excess amount
    // will be reimbursed after the consensus response.
    let canister_http_request_contexts = env.canister_http_request_contexts();
    assert_eq!(canister_http_request_contexts.len(), 1);
    let (_, context) = canister_http_request_contexts.iter().next().unwrap();
    let payment_after = context.request.payment;

    payment_before - payment_after
}

/// Simulates sending cycles from canister `Alice` to canister `Bob` to get the cost of xnet call.
/// Filtered subnet config is used to avoid dealing with irrelevant costs.
fn simulate_xnet_call_cost(subnet_type: SubnetType, subnet_size: usize) -> Cycles {
    let env = StateMachineBuilder::new()
        .with_subnet_type(subnet_type)
        .with_subnet_size(subnet_size)
        .with_config(Some(StateMachineConfig::new(
            filtered_subnet_config(subnet_type, KeepFeesFilter::XnetCall),
            HypervisorConfig::default(),
        )))
        .build();

    // Create two identical canisters Alice and Bob.
    let cycles = DEFAULT_CYCLES_PER_NODE * subnet_size;
    let alice = create_universal_canister_with_cycles(&env, cycles);
    let bob = create_universal_canister_with_cycles(&env, cycles);

    // Preserve canister's balances before the operation.
    let alice_balance_before = env.cycle_balance(alice);
    let bob_balance_before = env.cycle_balance(bob);

    // Canister Alice sends cycles to canister Bob, Bob accepts only a half of those cycles.
    let cycles_to_send = Cycles::new(2_000);
    let accept_cycles = Cycles::new(cycles_to_send.get() / 2);
    env.execute_ingress(
        alice,
        "update",
        wasm()
            .call_with_cycles(
                bob,
                "update",
                call_args().other_side(wasm().accept_cycles(accept_cycles)),
                cycles_to_send,
            )
            .build(),
    )
    .unwrap();

    // Calculate xnet call cost as a difference between canister balance changes.
    let alices_loss = alice_balance_before - env.cycle_balance(alice);
    let bobs_gain = env.cycle_balance(bob) - bob_balance_before;
    let xnet_call_cost = alices_loss - bobs_gain;

    Cycles::new(xnet_call_cost)
}

/// Simulates creating canister B from canister A to get a canister creation cost.
fn simulate_create_canister_cost(subnet_type: SubnetType, subnet_size: usize) -> Cycles {
    let env = StateMachineBuilder::new()
        .with_subnet_type(subnet_type)
        .with_subnet_size(subnet_size)
        .build();

    // Create a canister A with enough cycles to create another canister B.
    let canister_a_initial_balance = Cycles::new((200 * B).into()) * subnet_size;
    let canister_b_initial_balance = Cycles::new((100 * B).into()) * subnet_size;
    assert_lt!(canister_b_initial_balance, canister_a_initial_balance);

    let canister_a = create_universal_canister_with_cycles(&env, canister_a_initial_balance);

    // Canister B creation fee is deduced from its initial balance sent as a payment with the request.
    let create_canister = wasm()
        .call_with_cycles(
            ic00::IC_00,
            ic00::Method::CreateCanister,
            call_args().other_side(
                Encode!(&ic00::CreateCanisterArgs {
                    settings: None,
                    sender_canister_version: None
                })
                .unwrap(),
            ),
            canister_b_initial_balance,
        )
        .build();
    let result = env
        .execute_ingress(canister_a, "update", create_canister)
        .unwrap();
    let canister_b = match result {
        WasmResult::Reply(bytes) => Decode!(&bytes, CanisterIdRecord).unwrap().get_canister_id(),
        WasmResult::Reject(err) => panic!("Expected CreateCanister to succeed but got {}", err),
    };

    canister_b_initial_balance - Cycles::new(env.cycle_balance(canister_b))
}

fn calculate_create_canister_cost(
    config: &CyclesAccountManagerConfig,
    subnet_size: usize,
) -> Cycles {
    scale_cost(config, config.canister_creation_fee, subnet_size)
}

fn calculate_xnet_call_cost(
    config: &CyclesAccountManagerConfig,
    request_size: NumBytes,
    response_size: NumBytes,
    subnet_size: usize,
) -> Cycles {
    // Prepayed cost.
    let prepayment_for_response_transmission = scale_cost(
        config,
        config.xnet_byte_transmission_fee * MAX_INTER_CANISTER_PAYLOAD_IN_BYTES.get(),
        subnet_size,
    );
    let prepayment_for_response_execution = Cycles::new(0);
    let prepayed = scale_cost(
        config,
        config.xnet_call_fee + config.xnet_byte_transmission_fee * request_size.get(),
        subnet_size,
    ) + prepayment_for_response_transmission
        + prepayment_for_response_execution;

    // Actually transmitted cost and refund.
    let transmission_cost = scale_cost(
        config,
        config.xnet_byte_transmission_fee * response_size.get(),
        subnet_size,
    );
    let refund = prepayment_for_response_transmission
        - transmission_cost.min(prepayment_for_response_transmission);

    prepayed - refund
}

fn calculate_http_request_cost(
    config: &CyclesAccountManagerConfig,
    request_size: NumBytes,
    response_size_limit: Option<NumBytes>,
    subnet_size: usize,
) -> Cycles {
    let response_size = match response_size_limit {
        Some(response_size) => response_size.get(),
        // Defaults to maximum response size.
        None => MAX_CANISTER_HTTP_RESPONSE_BYTES,
    };
    (config.http_request_linear_baseline_fee
        + config.http_request_quadratic_baseline_fee * (subnet_size as u64)
        + config.http_request_per_byte_fee * request_size.get()
        + config.http_response_per_byte_fee * response_size)
        * (subnet_size as u64)
}

fn calculate_sign_with_ecdsa_cost(
    config: &CyclesAccountManagerConfig,
    subnet_size: usize,
) -> Cycles {
    scale_cost(config, config.ecdsa_signature_fee, subnet_size)
}

fn trillion_cycles(value: f64) -> Cycles {
    Cycles::new((value * 1e12) as u128)
}

fn get_cycles_account_manager_config(subnet_type: SubnetType) -> CyclesAccountManagerConfig {
    match subnet_type {
        SubnetType::System => CyclesAccountManagerConfig {
            reference_subnet_size: DEFAULT_REFERENCE_SUBNET_SIZE,
            canister_creation_fee: Cycles::new(0),
            compute_percent_allocated_per_second_fee: Cycles::new(0),
            update_message_execution_fee: Cycles::new(0),
            ten_update_instructions_execution_fee: Cycles::new(0),
            xnet_call_fee: Cycles::new(0),
            xnet_byte_transmission_fee: Cycles::new(0),
            ingress_message_reception_fee: Cycles::new(0),
            ingress_byte_reception_fee: Cycles::new(0),
            gib_storage_per_second_fee: Cycles::new(0),
            duration_between_allocation_charges: Duration::from_secs(10),
            // ECDSA and Schnorr signature fees are the fees charged when creating a
            // signature on this subnet. The request likely came from a
            // different subnet which is not a system subnet. There is an
            // explicit exception for requests originating from the NNS when the
            // charging occurs.
            ecdsa_signature_fee: ECDSA_SIGNATURE_FEE,
            schnorr_signature_fee: SCHNORR_SIGNATURE_FEE,
            http_request_linear_baseline_fee: Cycles::new(0),
            http_request_quadratic_baseline_fee: Cycles::new(0),
            http_request_per_byte_fee: Cycles::new(0),
            http_response_per_byte_fee: Cycles::new(0),
            max_storage_reservation_period: Duration::from_secs(0),
            default_reserved_balance_limit: CyclesAccountManagerConfig::system_subnet()
                .default_reserved_balance_limit,
        },
        SubnetType::Application | SubnetType::VerifiedApplication => CyclesAccountManagerConfig {
            reference_subnet_size: DEFAULT_REFERENCE_SUBNET_SIZE,
            canister_creation_fee: Cycles::new(100_000_000_000),
            compute_percent_allocated_per_second_fee: Cycles::new(10_000_000),

            // The following fields are set based on a thought experiment where
            // we estimated how many resources a representative benchmark on a
            // verified subnet is using.
            update_message_execution_fee: Cycles::new(590_000),
            ten_update_instructions_execution_fee: Cycles::new(4),
            xnet_call_fee: Cycles::new(260_000),
            xnet_byte_transmission_fee: Cycles::new(1_000),
            ingress_message_reception_fee: Cycles::new(1_200_000),
            ingress_byte_reception_fee: Cycles::new(2_000),
            // 4 SDR per GiB per year => 4e12 Cycles per year
            gib_storage_per_second_fee: Cycles::new(127_000),
            duration_between_allocation_charges: Duration::from_secs(10),
            ecdsa_signature_fee: ECDSA_SIGNATURE_FEE,
            schnorr_signature_fee: SCHNORR_SIGNATURE_FEE,
            http_request_linear_baseline_fee: Cycles::new(3_000_000),
            http_request_quadratic_baseline_fee: Cycles::new(60_000),
            http_request_per_byte_fee: Cycles::new(400),
            http_response_per_byte_fee: Cycles::new(800),
            max_storage_reservation_period: Duration::from_secs(0),
            default_reserved_balance_limit: CyclesAccountManagerConfig::application_subnet()
                .default_reserved_balance_limit,
        },
    }
}

fn scale_cost(config: &CyclesAccountManagerConfig, cycles: Cycles, subnet_size: usize) -> Cycles {
    (cycles * subnet_size) / config.reference_subnet_size
}

fn memory_cost(
    config: &CyclesAccountManagerConfig,
    bytes: NumBytes,
    duration: Duration,
    subnet_size: usize,
) -> Cycles {
    let one_gib = 1024 * 1024 * 1024;
    let cycles = Cycles::from(
        (bytes.get() as u128
            * config.gib_storage_per_second_fee.get()
            * duration.as_secs() as u128)
            / one_gib,
    );
    scale_cost(config, cycles, subnet_size)
}

fn compute_allocation_cost(
    config: &CyclesAccountManagerConfig,
    compute_allocation: ComputeAllocation,
    duration: Duration,
    subnet_size: usize,
) -> Cycles {
    let cycles = config.compute_percent_allocated_per_second_fee
        * duration.as_secs()
        * compute_allocation.as_percent();
    scale_cost(config, cycles, subnet_size)
}

fn calculate_one_gib_per_second_cost(
    config: &CyclesAccountManagerConfig,
    subnet_size: usize,
    compute_allocation: ComputeAllocation,
) -> Cycles {
    let one_gib = NumBytes::from(1 << 30);
    let duration = Duration::from_secs(1);
    memory_cost(config, one_gib, duration, subnet_size)
        + compute_allocation_cost(config, compute_allocation, duration, subnet_size)
}

// This function compares Cycles with absolute and relative tolerance.
//
// Simulated and calculated costs may carry calculation error, that has to be ignored in assertions.
// Eg. simulated cost may lose precision when is composed from several other integer costs (accumulated error).
//
// a = scale(x) + err_x + scale(y) + err_y + scale(z) + err_z
// b = scale(x + y + z) + err_xyz
// err_x + err_y + err_z != err_xyz
fn is_almost_eq(a: Cycles, b: Cycles) -> bool {
    let a = a.get();
    let b = b.get();
    let mx = std::cmp::max(a, b);
    let rel_tolerance = mx / 1_000;
    let abs_tolerance = 1;
    let diff = a.abs_diff(b);

    // Absolute tolerance works for big diff values (>0.1%), eg. is_almost_eq(50, 51) == true.
    // Relative tolerance works for small diff values (<0.1%), eg. is_almost_eq(1_000_000, 1_000_500) == true.
    diff <= std::cmp::max(abs_tolerance, rel_tolerance)
}

fn convert_instructions_to_cycles(
    config: &CyclesAccountManagerConfig,
    num_instructions: NumInstructions,
) -> Cycles {
    config.ten_update_instructions_execution_fee * num_instructions.get() / 10_u64
}

fn prepay_execution_cycles(
    config: &CyclesAccountManagerConfig,
    num_instructions: NumInstructions,
    subnet_size: usize,
) -> Cycles {
    scale_cost(
        config,
        config.update_message_execution_fee
            + convert_instructions_to_cycles(config, num_instructions),
        subnet_size,
    )
}

fn refund_unused_execution_cycles(
    config: &CyclesAccountManagerConfig,
    num_instructions: NumInstructions,
    num_instructions_initially_charged: NumInstructions,
    prepaid_execution_cycles: Cycles,
    subnet_size: usize,
) -> Cycles {
    let num_instructions_to_refund =
        std::cmp::min(num_instructions, num_instructions_initially_charged);
    let cycles = convert_instructions_to_cycles(config, num_instructions_to_refund);

    scale_cost(config, cycles, subnet_size).min(prepaid_execution_cycles)
}

fn calculate_execution_cost(
    config: &CyclesAccountManagerConfig,
    instructions: NumInstructions,
    subnet_size: usize,
) -> Cycles {
    let instructions_limit = NumInstructions::from(200 * B);
    let instructions_left = instructions_limit - instructions;

    let prepaid_execution_cycles = prepay_execution_cycles(config, instructions_limit, subnet_size);
    let refund = refund_unused_execution_cycles(
        config,
        instructions_left,
        instructions_limit,
        prepaid_execution_cycles,
        subnet_size,
    );

    prepaid_execution_cycles - refund
}

fn ingress_induction_cost_from_bytes(
    config: &CyclesAccountManagerConfig,
    bytes: NumBytes,
    subnet_size: usize,
) -> Cycles {
    scale_cost(
        config,
        config.ingress_message_reception_fee + config.ingress_byte_reception_fee * bytes.get(),
        subnet_size,
    )
}

fn calculate_induction_cost(
    config: &CyclesAccountManagerConfig,
    ingress: &SignedIngressContent,
    subnet_size: usize,
) -> Cycles {
    let bytes_to_charge = ingress.arg().len()
        + ingress.method_name().len()
        + ingress.nonce().map(|n| n.len()).unwrap_or(0);

    ingress_induction_cost_from_bytes(config, NumBytes::from(bytes_to_charge as u64), subnet_size)
}

#[test]
fn test_subnet_size_one_gib_storage_default_cost() {
    let subnet_size_lo = 13;
    let subnet_size_hi = 34;
    let subnet_type = SubnetType::Application;
    let compute_allocation = ComputeAllocation::zero();
    let per_year: u64 = 60 * 60 * 24 * 365;

    // Assert small subnet size cost per year.
    let cost = simulate_one_gib_per_second_cost(subnet_type, subnet_size_lo, compute_allocation);
    assert_eq!(cost * per_year, trillion_cycles(4.005_072));

    // Assert big subnet size cost per year.
    let cost = simulate_one_gib_per_second_cost(subnet_type, subnet_size_hi, compute_allocation);
    assert_eq!(cost * per_year, trillion_cycles(10.474_777_008));

    // Assert big subnet size cost per year scaled to a small size.
    let adjusted_cost = (cost * subnet_size_lo) / subnet_size_hi;
    assert_eq!(adjusted_cost * per_year, trillion_cycles(4.005_040_464));
}

// Storage cost tests split into 2: zero and non-zero compute allocation.
// Reasons:
// - storage cost includes both memory cost and compute allocation cost
// - memory cost differs depending on subnet size
//   -  <20 nodes: memory cost is subsidised and does not scale
//   - >=20 nodes: memory cost is not-subsidised and scales according to subnet size
// - allocation cost always scales according to subnet size

#[test]
fn test_subnet_size_one_gib_storage_zero_compute_allocation_cost() {
    let compute_allocation = ComputeAllocation::zero();
    let subnet_type = SubnetType::Application;
    let config = get_cycles_account_manager_config(subnet_type);
    let reference_subnet_size = config.reference_subnet_size;

    // Check default cost.
    assert_eq!(
        simulate_one_gib_per_second_cost(subnet_type, reference_subnet_size, compute_allocation),
        calculate_one_gib_per_second_cost(&config, reference_subnet_size, compute_allocation)
    );

    // Check if cost is increasing with subnet size.
    assert_lt!(
        simulate_one_gib_per_second_cost(subnet_type, 1, compute_allocation),
        simulate_one_gib_per_second_cost(subnet_type, 2, compute_allocation)
    );
    assert_lt!(
        simulate_one_gib_per_second_cost(subnet_type, 11, compute_allocation),
        simulate_one_gib_per_second_cost(subnet_type, 12, compute_allocation)
    );
    assert_lt!(
        simulate_one_gib_per_second_cost(subnet_type, 101, compute_allocation),
        simulate_one_gib_per_second_cost(subnet_type, 102, compute_allocation)
    );
    assert_lt!(
        simulate_one_gib_per_second_cost(subnet_type, 1_001, compute_allocation),
        simulate_one_gib_per_second_cost(subnet_type, 1_002, compute_allocation)
    );

    // Check linear scaling.
    let reference_subnet_size = config.reference_subnet_size;
    let reference_cost =
        calculate_one_gib_per_second_cost(&config, reference_subnet_size, compute_allocation);
    for subnet_size in TEST_SUBNET_SIZES {
        let simulated_cost =
            calculate_one_gib_per_second_cost(&config, subnet_size, compute_allocation);
        let calculated_cost = (reference_cost * subnet_size) / reference_subnet_size;
        assert!(
            is_almost_eq(simulated_cost, calculated_cost),
            "compute_allocation={compute_allocation:?}, subnet_size={subnet_size}",
        );
    }
}

#[test]
fn test_subnet_size_one_gib_storage_non_zero_compute_allocation_cost() {
    for compute_allocation in [
        ComputeAllocation::try_from(1).unwrap(),
        ComputeAllocation::try_from(50).unwrap(),
        ComputeAllocation::try_from(100).unwrap(),
    ] {
        let subnet_type = SubnetType::Application;
        let config = get_cycles_account_manager_config(subnet_type);
        let reference_subnet_size = config.reference_subnet_size;

        // Check default cost.
        assert_eq!(
            simulate_one_gib_per_second_cost(
                subnet_type,
                reference_subnet_size,
                compute_allocation
            ),
            calculate_one_gib_per_second_cost(&config, reference_subnet_size, compute_allocation)
        );

        // Check if cost is increasing with subnet size.
        assert_lt!(
            simulate_one_gib_per_second_cost(subnet_type, 1, compute_allocation),
            simulate_one_gib_per_second_cost(subnet_type, 2, compute_allocation)
        );
        assert_lt!(
            simulate_one_gib_per_second_cost(subnet_type, 11, compute_allocation),
            simulate_one_gib_per_second_cost(subnet_type, 12, compute_allocation)
        );
        assert_lt!(
            simulate_one_gib_per_second_cost(subnet_type, 101, compute_allocation),
            simulate_one_gib_per_second_cost(subnet_type, 102, compute_allocation)
        );
        assert_lt!(
            simulate_one_gib_per_second_cost(subnet_type, 1_001, compute_allocation),
            simulate_one_gib_per_second_cost(subnet_type, 1_002, compute_allocation)
        );

        // Check linear scaling.
        let reference_subnet_size = config.reference_subnet_size;
        let reference_cost =
            calculate_one_gib_per_second_cost(&config, reference_subnet_size, compute_allocation);
        for subnet_size in TEST_SUBNET_SIZES {
            let simulated_cost =
                calculate_one_gib_per_second_cost(&config, subnet_size, compute_allocation);
            let calculated_cost = (reference_cost * subnet_size) / reference_subnet_size;
            assert!(
                is_almost_eq(simulated_cost, calculated_cost),
                "compute_allocation={compute_allocation:?}, subnet_size={subnet_size}",
            );
        }
    }
}

#[test]
fn test_subnet_size_execute_install_code_cost() {
    let subnet_type = SubnetType::Application;
    let config = get_cycles_account_manager_config(subnet_type);
    let reference_subnet_size = config.reference_subnet_size;
    let reference_cost = calculate_execution_cost(
        &config,
        NumInstructions::from(TEST_CANISTER_INSTALL_EXECUTION_INSTRUCTIONS),
        reference_subnet_size,
    );

    // Check default cost.
    assert_eq!(
        simulate_execute_install_code_cost(subnet_type, reference_subnet_size),
        reference_cost
    );

    // Check if cost is increasing with subnet size.
    assert_lt!(
        simulate_execute_install_code_cost(subnet_type, 1),
        simulate_execute_install_code_cost(subnet_type, 2)
    );
    assert_lt!(
        simulate_execute_install_code_cost(subnet_type, 11),
        simulate_execute_install_code_cost(subnet_type, 12)
    );
    assert_lt!(
        simulate_execute_install_code_cost(subnet_type, 101),
        simulate_execute_install_code_cost(subnet_type, 102)
    );
    assert_lt!(
        simulate_execute_install_code_cost(subnet_type, 1_001),
        simulate_execute_install_code_cost(subnet_type, 1_002)
    );

    // Check linear scaling.
    let reference_subnet_size = config.reference_subnet_size;
    let reference_cost = simulate_execute_install_code_cost(subnet_type, reference_subnet_size);
    for subnet_size in TEST_SUBNET_SIZES {
        let simulated_cost = simulate_execute_install_code_cost(subnet_type, subnet_size);
        let calculated_cost = (reference_cost * subnet_size) / reference_subnet_size;
        assert!(
            is_almost_eq(simulated_cost, calculated_cost),
            "subnet_size={subnet_size}, simulated_cost={simulated_cost}, calculated_cost={calculated_cost}"
        );
    }
}

#[test]
fn test_subnet_size_ingress_induction_cost() {
    let subnet_type = SubnetType::Application;
    let config = get_cycles_account_manager_config(subnet_type);
    let reference_subnet_size = config.reference_subnet_size;
    let signed_ingress = SignedIngressBuilder::new()
        .method_name("inc")
        .nonce(3)
        .build();
    let reference_cost =
        calculate_induction_cost(&config, signed_ingress.content(), reference_subnet_size);

    // Check default cost.
    assert_eq!(
        simulate_ingress_induction_cost(subnet_type, reference_subnet_size),
        reference_cost
    );

    // Check if cost is increasing with subnet size.
    assert_lt!(
        simulate_execute_install_code_cost(subnet_type, 1),
        simulate_execute_install_code_cost(subnet_type, 2)
    );
    assert_lt!(
        simulate_execute_install_code_cost(subnet_type, 11),
        simulate_execute_install_code_cost(subnet_type, 12)
    );
    assert_lt!(
        simulate_execute_install_code_cost(subnet_type, 101),
        simulate_execute_install_code_cost(subnet_type, 102)
    );
    assert_lt!(
        simulate_execute_install_code_cost(subnet_type, 1_001),
        simulate_execute_install_code_cost(subnet_type, 1_002)
    );

    // Check linear scaling.
    let reference_subnet_size = config.reference_subnet_size;
    let reference_cost = simulate_execute_install_code_cost(subnet_type, reference_subnet_size);
    for subnet_size in TEST_SUBNET_SIZES {
        let simulated_cost = simulate_execute_install_code_cost(subnet_type, subnet_size);
        let calculated_cost = (reference_cost * subnet_size) / reference_subnet_size;
        assert!(
            is_almost_eq(simulated_cost, calculated_cost),
            "subnet_size={subnet_size}, simulated_cost={simulated_cost}, calculated_cost={calculated_cost}"
        );
    }
}

#[test]
fn test_subnet_size_execute_message_cost() {
    let subnet_type = SubnetType::Application;
    let config = get_cycles_account_manager_config(subnet_type);
    let reference_subnet_size = config.reference_subnet_size;
    let reference_cost = calculate_execution_cost(
        &config,
        NumInstructions::from(inc_instruction_cost(HypervisorConfig::default())),
        reference_subnet_size,
    );

    // Check default cost.
    assert_eq!(
        simulate_execute_message_cost(subnet_type, reference_subnet_size),
        reference_cost
    );

    // Check if cost is increasing with subnet size.
    assert_lt!(
        simulate_execute_message_cost(subnet_type, 1),
        simulate_execute_message_cost(subnet_type, 2)
    );
    assert_lt!(
        simulate_execute_message_cost(subnet_type, 11),
        simulate_execute_message_cost(subnet_type, 12)
    );
    assert_lt!(
        simulate_execute_message_cost(subnet_type, 101),
        simulate_execute_message_cost(subnet_type, 102)
    );
    assert_lt!(
        simulate_execute_message_cost(subnet_type, 1_001),
        simulate_execute_message_cost(subnet_type, 1_002)
    );

    // Check linear scaling.
    let reference_subnet_size = config.reference_subnet_size;
    let reference_cost = simulate_execute_message_cost(subnet_type, reference_subnet_size);
    for subnet_size in TEST_SUBNET_SIZES {
        let simulated_cost = simulate_execute_message_cost(subnet_type, subnet_size);
        let calculated_cost = (reference_cost * subnet_size) / reference_subnet_size;
        assert!(
            is_almost_eq(simulated_cost, calculated_cost),
            "subnet_size={subnet_size}, simulated_cost={simulated_cost}, calculated_cost={calculated_cost}"
        );
    }
}

#[test]
fn test_subnet_size_execute_heartbeat_cost() {
    let subnet_type = SubnetType::Application;
    let config = get_cycles_account_manager_config(subnet_type);
    let reference_subnet_size = config.reference_subnet_size;
    let reference_cost = calculate_execution_cost(
        &config,
        NumInstructions::from(TEST_HEARTBEAT_CANISTER_EXECUTE_HEARTBEAT_INSTRUCTIONS),
        reference_subnet_size,
    );

    // Check default cost.
    assert_eq!(
        simulate_execute_canister_heartbeat_cost(subnet_type, reference_subnet_size),
        reference_cost
    );

    // Check if cost is increasing with subnet size.
    assert_lt!(
        simulate_execute_canister_heartbeat_cost(subnet_type, 1),
        simulate_execute_canister_heartbeat_cost(subnet_type, 2)
    );
    assert_lt!(
        simulate_execute_canister_heartbeat_cost(subnet_type, 11),
        simulate_execute_canister_heartbeat_cost(subnet_type, 12)
    );
    assert_lt!(
        simulate_execute_canister_heartbeat_cost(subnet_type, 101),
        simulate_execute_canister_heartbeat_cost(subnet_type, 102)
    );
    assert_lt!(
        simulate_execute_canister_heartbeat_cost(subnet_type, 1_001),
        simulate_execute_canister_heartbeat_cost(subnet_type, 1_002)
    );

    // Check linear scaling.
    let reference_subnet_size = config.reference_subnet_size;
    let reference_cost =
        simulate_execute_canister_heartbeat_cost(subnet_type, reference_subnet_size);
    for subnet_size in TEST_SUBNET_SIZES {
        let simulated_cost = simulate_execute_canister_heartbeat_cost(subnet_type, subnet_size);
        let calculated_cost = (reference_cost * subnet_size) / reference_subnet_size;
        assert!(
            is_almost_eq(simulated_cost, calculated_cost),
            "subnet_size={subnet_size}, simulated_cost={simulated_cost}, calculated_cost={calculated_cost}"
        );
    }
}

#[test]
fn test_subnet_size_execute_heartbeat_default_cost() {
    let subnet_size_lo = 13;
    let subnet_size_hi = 34;
    let subnet_type = SubnetType::Application;
    let heart_beat_rate_ms = 917; // Based on production statistics for the past 2 days.
    let per_year: u64 = 60 * 60 * 24 * 365 * 1_000 / heart_beat_rate_ms;

    // Assert small subnet size costs per single heartbeat and per year.
    let cost = simulate_execute_canister_heartbeat_cost(subnet_type, subnet_size_lo);
    assert_eq!(cost, Cycles::new(590001));
    assert_eq!(cost * per_year, Cycles::new(20290372160403));

    // Assert big subnet size cost per single heartbeat and per year.
    let cost = simulate_execute_canister_heartbeat_cost(subnet_type, subnet_size_hi);
    // Scaled instrumentation + update message cost.
    assert_eq!(cost, Cycles::new(1543080));
    assert_eq!(cost * per_year, Cycles::new(53067143061240));

    // Assert big subnet size cost scaled to a small size.
    let adjusted_cost = (cost * subnet_size_lo) / subnet_size_hi;
    assert_eq!(adjusted_cost, Cycles::new(590001));
    assert_eq!(adjusted_cost * per_year, Cycles::new(20290372160403));
}

#[test]
fn test_subnet_size_sign_with_ecdsa_non_zero_cost() {
    // This test is testing non-zero cost of ECDSA signature, which happens in 2 cases:
    // - when called from application subnet
    // - when called from system subnet that is not NNS subnet
    let nns_subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(1));
    let subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(2));
    // Own subnet and NNS subnet IDs must be different.
    assert_ne!(nns_subnet_id, subnet_id);

    for subnet_type in [SubnetType::Application, SubnetType::System] {
        let config = get_cycles_account_manager_config(subnet_type);
        let reference_subnet_size = config.reference_subnet_size;
        let reference_cost = calculate_sign_with_ecdsa_cost(&config, reference_subnet_size);

        // Check default cost.
        assert_eq!(
            simulate_sign_with_ecdsa_cost(
                subnet_type,
                reference_subnet_size,
                nns_subnet_id,
                subnet_id
            ),
            reference_cost
        );

        // Check if cost is increasing with subnet size.
        assert_lt!(
            simulate_sign_with_ecdsa_cost(subnet_type, 1, nns_subnet_id, subnet_id),
            simulate_sign_with_ecdsa_cost(subnet_type, 2, nns_subnet_id, subnet_id)
        );
        assert_lt!(
            simulate_sign_with_ecdsa_cost(subnet_type, 11, nns_subnet_id, subnet_id),
            simulate_sign_with_ecdsa_cost(subnet_type, 12, nns_subnet_id, subnet_id)
        );
        assert_lt!(
            simulate_sign_with_ecdsa_cost(subnet_type, 101, nns_subnet_id, subnet_id),
            simulate_sign_with_ecdsa_cost(subnet_type, 102, nns_subnet_id, subnet_id)
        );
        assert_lt!(
            simulate_sign_with_ecdsa_cost(subnet_type, 1_001, nns_subnet_id, subnet_id),
            simulate_sign_with_ecdsa_cost(subnet_type, 1_002, nns_subnet_id, subnet_id)
        );

        // Check linear scaling.
        let reference_subnet_size = config.reference_subnet_size;
        let reference_cost = simulate_sign_with_ecdsa_cost(
            subnet_type,
            reference_subnet_size,
            nns_subnet_id,
            subnet_id,
        );
        for subnet_size in TEST_SUBNET_SIZES {
            let simulated_cost =
                simulate_sign_with_ecdsa_cost(subnet_type, subnet_size, nns_subnet_id, subnet_id);
            let calculated_cost = (reference_cost * subnet_size) / reference_subnet_size;
            assert!(
                is_almost_eq(simulated_cost, calculated_cost),
                "subnet_type={subnet_type:?}, subnet_size={subnet_size}, subnet_id={subnet_id}, nns_subnet_id={nns_subnet_id}",
            );
        }
    }
}

#[test]
fn test_subnet_size_sign_with_ecdsa_zero_cost() {
    // This test is testing zero cost of ECDSA signature, which happens only when called from NNS subnet.
    let subnet_type = SubnetType::System;
    let nns_subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(1));
    let subnet_id = nns_subnet_id;
    // Own subnet and NNS subnet IDs must be the same.
    assert_eq!(nns_subnet_id, subnet_id);

    // Check that the cost is zero independently of the subnet size.
    for subnet_size in TEST_SUBNET_SIZES {
        assert_eq!(
            simulate_sign_with_ecdsa_cost(subnet_type, subnet_size, nns_subnet_id, subnet_id),
            Cycles::zero(),
            "subnet_type={subnet_type:?}, subnet_size={subnet_size}, subnet_id={subnet_id}, nns_subnet_id={nns_subnet_id}"
        );
    }
}

#[test]
fn test_subnet_size_http_request_cost() {
    let subnet_type = SubnetType::Application;
    let config = get_cycles_account_manager_config(subnet_type);
    let reference_subnet_size = config.reference_subnet_size;
    let reference_cost =
        calculate_http_request_cost(&config, NumBytes::new(17), None, reference_subnet_size);

    // Check default cost.
    assert_eq!(
        simulate_http_request_cost(subnet_type, reference_subnet_size),
        reference_cost
    );

    // Check if cost is increasing with subnet size.
    assert_lt!(
        simulate_http_request_cost(subnet_type, 1),
        simulate_http_request_cost(subnet_type, 2)
    );
    assert_lt!(
        simulate_http_request_cost(subnet_type, 11),
        simulate_http_request_cost(subnet_type, 12)
    );
    assert_lt!(
        simulate_http_request_cost(subnet_type, 101),
        simulate_http_request_cost(subnet_type, 102)
    );
    assert_lt!(
        simulate_http_request_cost(subnet_type, 1_001),
        simulate_http_request_cost(subnet_type, 1_002)
    );

    // Check linear scaling.
    let reference_subnet_size = config.reference_subnet_size;
    let reference_cost = simulate_http_request_cost(subnet_type, reference_subnet_size);
    for subnet_size in TEST_SUBNET_SIZES {
        let simulated_cost = simulate_http_request_cost(subnet_type, subnet_size);
        let calculated_cost = (reference_cost * subnet_size) / reference_subnet_size;
        assert!(
            is_almost_eq(simulated_cost, calculated_cost),
            "subnet_size={subnet_size}, simulated_cost={simulated_cost}, calculated_cost={calculated_cost}"
        );
    }
}

#[test]
fn test_subnet_size_xnet_call_cost() {
    let subnet_type = SubnetType::Application;
    let config = get_cycles_account_manager_config(subnet_type);
    let reference_subnet_size = config.reference_subnet_size;
    let reference_cost = calculate_xnet_call_cost(
        &config,
        NumBytes::new(25),
        NumBytes::new(12),
        reference_subnet_size,
    );

    // Check default cost.
    assert_eq!(
        simulate_xnet_call_cost(subnet_type, reference_subnet_size),
        reference_cost
    );

    // Check if cost is increasing with subnet size.
    assert_lt!(
        simulate_xnet_call_cost(subnet_type, 1),
        simulate_xnet_call_cost(subnet_type, 2)
    );
    assert_lt!(
        simulate_xnet_call_cost(subnet_type, 11),
        simulate_xnet_call_cost(subnet_type, 12)
    );
    assert_lt!(
        simulate_xnet_call_cost(subnet_type, 101),
        simulate_xnet_call_cost(subnet_type, 102)
    );
    assert_lt!(
        simulate_xnet_call_cost(subnet_type, 1_001),
        simulate_xnet_call_cost(subnet_type, 1_002)
    );

    // Check linear scaling.
    let reference_subnet_size = config.reference_subnet_size;
    let reference_cost = simulate_xnet_call_cost(subnet_type, reference_subnet_size);
    for subnet_size in TEST_SUBNET_SIZES {
        let simulated_cost = simulate_xnet_call_cost(subnet_type, subnet_size);
        let calculated_cost = (reference_cost * subnet_size) / reference_subnet_size;
        assert!(
            is_almost_eq(simulated_cost, calculated_cost),
            "subnet_size={subnet_size}, simulated_cost={simulated_cost}, calculated_cost={calculated_cost}"
        );
    }
}

#[test]
fn test_subnet_size_create_canister_cost() {
    let subnet_type = SubnetType::Application;
    let config = get_cycles_account_manager_config(subnet_type);
    let reference_subnet_size = config.reference_subnet_size;
    let reference_cost = calculate_create_canister_cost(&config, reference_subnet_size);

    // Check default cost.
    assert_eq!(
        simulate_create_canister_cost(subnet_type, reference_subnet_size),
        reference_cost
    );

    // Check if cost is increasing with subnet size.
    assert_lt!(
        simulate_create_canister_cost(subnet_type, 1),
        simulate_create_canister_cost(subnet_type, 2)
    );
    assert_lt!(
        simulate_create_canister_cost(subnet_type, 11),
        simulate_create_canister_cost(subnet_type, 12)
    );
    assert_lt!(
        simulate_create_canister_cost(subnet_type, 101),
        simulate_create_canister_cost(subnet_type, 102)
    );
    assert_lt!(
        simulate_create_canister_cost(subnet_type, 1_001),
        simulate_create_canister_cost(subnet_type, 1_002)
    );

    // Check linear scaling.
    let reference_subnet_size = config.reference_subnet_size;
    let reference_cost = simulate_create_canister_cost(subnet_type, reference_subnet_size);
    for subnet_size in TEST_SUBNET_SIZES {
        let simulated_cost = simulate_create_canister_cost(subnet_type, subnet_size);
        let calculated_cost = (reference_cost * subnet_size) / reference_subnet_size;
        assert!(
            is_almost_eq(simulated_cost, calculated_cost),
            "subnet_size={subnet_size}, simulated_cost={simulated_cost}, calculated_cost={calculated_cost}"
        );
    }
}

#[test]
fn test_subnet_size_system_subnet_has_zero_cost() {
    let subnet_type = SubnetType::System;

    for subnet_size in TEST_SUBNET_SIZES {
        let compute_allocation = ComputeAllocation::zero();
        assert_eq!(
            simulate_one_gib_per_second_cost(subnet_type, subnet_size, compute_allocation),
            Cycles::zero(),
            "subnet_size={subnet_size}"
        );

        let compute_allocation = ComputeAllocation::try_from(50).unwrap();
        assert_eq!(
            simulate_one_gib_per_second_cost(subnet_type, subnet_size, compute_allocation),
            Cycles::zero(),
            "subnet_size={subnet_size}"
        );

        let compute_allocation = ComputeAllocation::try_from(100).unwrap();
        assert_eq!(
            simulate_one_gib_per_second_cost(subnet_type, subnet_size, compute_allocation),
            Cycles::zero(),
            "subnet_size={subnet_size}"
        );

        assert_eq!(
            simulate_execute_message_cost(subnet_type, subnet_size),
            Cycles::zero(),
            "subnet_size={subnet_size}"
        );

        assert_eq!(
            simulate_execute_install_code_cost(subnet_type, subnet_size),
            Cycles::zero(),
            "subnet_size={subnet_size}"
        );

        assert_eq!(
            simulate_execute_canister_heartbeat_cost(subnet_type, subnet_size),
            Cycles::zero(),
            "subnet_size={subnet_size}"
        );

        assert_eq!(
            simulate_http_request_cost(subnet_type, subnet_size),
            Cycles::zero(),
            "subnet_size={subnet_size}"
        );

        assert_eq!(
            simulate_xnet_call_cost(subnet_type, subnet_size),
            Cycles::zero(),
            "subnet_size={subnet_size}"
        );

        assert_eq!(
            simulate_create_canister_cost(subnet_type, subnet_size),
            Cycles::zero(),
            "subnet_size={subnet_size}"
        );
    }
}
