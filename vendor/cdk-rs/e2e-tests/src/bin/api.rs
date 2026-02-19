//! # NOTE
//! The [`inspect_message`] function defined below mandates that all the update/query entrypoints must start with "call_".

use candid::Principal;
use ic_cdk::api::*;

#[export_name = "canister_update call_msg_arg_data"]
fn call_msg_arg_data() {
    assert_eq!(msg_arg_data(), vec![42]);
    msg_reply(vec![]);
}

#[export_name = "canister_update call_msg_caller"]
fn call_msg_caller() {
    assert_eq!(msg_caller(), Principal::anonymous());
    msg_reply(vec![]);
}

/// This entrypoint will call [`call_msg_deadline`] with both `bounded_wait` and `unbounded_wait`.
#[ic_cdk::update]
async fn call_msg_deadline_caller() {
    use ic_cdk::call::Call;
    let reply1 = Call::bounded_wait(canister_self(), "call_msg_deadline")
        .await
        .unwrap()
        .into_bytes();
    assert_eq!(reply1, vec![1]);
    let reply1 = Call::unbounded_wait(canister_self(), "call_msg_deadline")
        .await
        .unwrap()
        .into_bytes();
    assert_eq!(reply1, vec![0]);
}

/// This entrypoint is to be called by [`call_msg_deadline_caller`].
/// If the call was made with `bounded_wait`, `msg_deadline` should be `Some`, then return 1.
/// If the call was made with `unbounded_wait`, `msg_deadline` should be `None`, then return 0.
#[export_name = "canister_update call_msg_deadline"]
fn call_msg_deadline() {
    let reply = match msg_deadline() {
        Some(v) => {
            // `NonZeroU64::get()` converts the value to `u64`.
            assert!(v.get() > 1);
            1
        }
        None => 0,
    };
    msg_reply(vec![reply]);
}

#[export_name = "canister_update call_msg_reply"]
fn call_msg_reply() {
    msg_reply(vec![42]);
}

#[export_name = "canister_update call_msg_reject"]
fn call_msg_reject() {
    msg_reject("e2e test reject");
}

#[export_name = "canister_update call_msg_cycles_available"]
fn call_msg_cycles_available() {
    assert_eq!(msg_cycles_available(), 0);
    msg_reply(vec![]);
}

#[export_name = "canister_update call_msg_cycles_accept"]
fn call_msg_cycles_accept() {
    // The available cycles are 0, so the actual cycles accepted are 0.
    assert_eq!(msg_cycles_accept(1000), 0);
    msg_reply(vec![]);
}

#[export_name = "canister_update call_cycles_burn"]
fn call_cycles_burn() {
    assert_eq!(cycles_burn(1000), 1000);
    msg_reply(vec![]);
}

#[export_name = "canister_update call_canister_self"]
fn call_canister_self() {
    let self_id = canister_self();
    // The sender sended canister ID
    let data = msg_arg_data();
    assert_eq!(self_id.as_slice(), data);
    msg_reply(vec![]);
}

#[export_name = "canister_update call_canister_cycle_balance"]
fn call_canister_cycle_balance() {
    assert!(canister_cycle_balance() > 0);
    msg_reply(vec![]);
}

#[export_name = "canister_update call_canister_liquid_cycle_balance"]
fn call_canister_liquid_cycle_balance() {
    assert!(canister_liquid_cycle_balance() > 0);
    msg_reply(vec![]);
}

#[export_name = "canister_update call_canister_status"]
fn call_canister_status() {
    assert_eq!(canister_status(), CanisterStatusCode::Running);
    assert_eq!(canister_status(), 1);
    msg_reply(vec![]);
}

#[export_name = "canister_update call_canister_version"]
fn call_canister_version() {
    assert!(canister_version() > 0);
    msg_reply(vec![]);
}

#[export_name = "canister_update call_subnet_self"]
fn call_subnet_self() {
    let id = subnet_self();
    debug_print(format!("Subnet ID: {:?}", id.to_text()));
    // The subnet ID is a Principal which uses all 29 bytes.
    assert_eq!(id.as_slice().len(), 29);
    msg_reply(vec![]);
}

#[export_name = "canister_inspect_message"]
fn inspect_message() {
    assert!(msg_method_name().starts_with("call_"));
    accept_message();
}

#[export_name = "canister_update call_stable"]
fn call_stable() {
    assert_eq!(stable_size(), 0);
    assert_eq!(stable_grow(1), 0);
    let data = vec![42];
    stable_write(0, &data);
    let mut read_buf = vec![0];
    stable_read(0, &mut read_buf);
    assert_eq!(read_buf, data);
    msg_reply(vec![]);
}

#[export_name = "canister_update call_root_key"]
fn call_root_key() {
    let root_key = root_key();
    assert!(!root_key.is_empty());
    msg_reply(vec![]);
}

#[export_name = "canister_update call_certified_data_set"]
fn call_certified_data_set() {
    certified_data_set(vec![42]);
    msg_reply(vec![]);
}

#[export_name = "canister_query call_data_certificate"]
fn call_data_certificate() {
    assert!(data_certificate().is_some());
    msg_reply(vec![]);
}

#[export_name = "canister_update call_time"]
fn call_time() {
    assert!(time() > 0);
    msg_reply(vec![]);
}

#[export_name = "canister_update call_performance_counter"]
fn call_performance_counter() {
    let t0 = PerformanceCounterType::InstructionCounter;
    assert_eq!(t0, 0);
    let ic0 = performance_counter(0);
    let ic1 = performance_counter(t0);
    let ic2 = instruction_counter();
    assert!(ic0 < ic1);
    assert!(ic1 < ic2);

    let t1 = PerformanceCounterType::CallContextInstructionCounter;
    assert_eq!(t1, 1);
    let ccic0 = performance_counter(1);
    let ccic1 = performance_counter(t1);
    let ccic2 = call_context_instruction_counter();
    assert!(ccic0 < ccic1);
    assert!(ccic1 < ccic2);
    msg_reply(vec![]);
}

#[export_name = "canister_update call_is_controller"]
fn call_is_controller() {
    // The canister was created by the anonymous principal.
    assert!(is_controller(&Principal::anonymous()));
    msg_reply(vec![]);
}

/// This entry point will be called by both update and query calls.
/// The query call will return 0, and the update call will return 1.
#[export_name = "canister_query call_in_replicated_execution"]
fn call_in_replicated_execution() {
    let res = match in_replicated_execution() {
        true => 1,
        false => 0,
    };
    msg_reply(vec![res]);
}

#[export_name = "canister_update call_cost_call"]
fn call_cost_call() {
    let res = cost_call(1, 2);
    assert!(res > 0);
    msg_reply(vec![]);
}

#[export_name = "canister_query call_cost_create_canister"]
fn call_cost_create_canister() {
    let res = cost_create_canister();
    assert!(res > 0);
    msg_reply(vec![]);
}

#[export_name = "canister_query call_cost_http_request"]
fn call_cost_http_request() {
    let res = cost_http_request(100, 1000);
    assert!(res > 0);
    msg_reply(vec![]);
}

const INVALID_KEY_NAME: &str = "invalid_key_name";
const INVALID_CURVE_OR_ALGORITHM: u32 = 42; // Just a big number which is impossible to be valid.
const VALID_KEY_NAME: &str = "test_key_1";

#[export_name = "canister_query call_cost_sign_with_ecdsa"]
fn call_cost_sign_with_ecdsa() {
    let err = cost_sign_with_ecdsa(VALID_KEY_NAME, INVALID_CURVE_OR_ALGORITHM).unwrap_err();
    assert!(matches!(err, SignCostError::InvalidCurveOrAlgorithm));
    let err = cost_sign_with_ecdsa(INVALID_KEY_NAME, 0).unwrap_err();
    assert!(matches!(err, SignCostError::InvalidKeyName));
    // The current implementation doesn't follow the `bitflags` approach.
    // When both key name and curve/algorithm are invalid, the error is `InvalidCurveOrAlgorithm`.
    let err = cost_sign_with_ecdsa(INVALID_KEY_NAME, INVALID_CURVE_OR_ALGORITHM).unwrap_err();
    assert!(matches!(err, SignCostError::InvalidCurveOrAlgorithm));
    let res = cost_sign_with_ecdsa(VALID_KEY_NAME, 0).unwrap();
    assert!(res > 0);
    msg_reply(vec![]);
}

#[export_name = "canister_query call_cost_sign_with_schnorr"]
fn call_cost_sign_with_schnorr() {
    let err = cost_sign_with_schnorr(VALID_KEY_NAME, INVALID_CURVE_OR_ALGORITHM).unwrap_err();
    assert!(matches!(err, SignCostError::InvalidCurveOrAlgorithm));
    let err = cost_sign_with_schnorr(INVALID_KEY_NAME, 0).unwrap_err();
    assert!(matches!(err, SignCostError::InvalidKeyName));
    // The current implementation doesn't follow the `bitflags` approach.
    // When both key name and curve/algorithm are invalid, the error is `InvalidCurveOrAlgorithm`.
    let err = cost_sign_with_schnorr(INVALID_KEY_NAME, INVALID_CURVE_OR_ALGORITHM).unwrap_err();
    assert!(matches!(err, SignCostError::InvalidCurveOrAlgorithm));
    let res = cost_sign_with_schnorr(VALID_KEY_NAME, 0).unwrap();
    assert!(res > 0);
    let res = cost_sign_with_schnorr(VALID_KEY_NAME, 1).unwrap();
    assert!(res > 0);
    msg_reply(vec![]);
}

#[export_name = "canister_query call_env_var_count"]
fn call_env_var_count() {
    let count = env_var_count();
    assert_eq!(count, 2);
    msg_reply(vec![]);
}

#[export_name = "canister_query call_env_var_name"]
fn call_env_var_name() {
    // This is expected to panic as no environment variables are set.
    assert_eq!(env_var_name(0), "key1");
    assert_eq!(env_var_name(1), "key2");
    msg_reply(vec![]);
}

#[export_name = "canister_query call_env_var_name_exists"]
fn call_env_var_name_exists() {
    assert!(env_var_name_exists("key1"));
    assert!(env_var_name_exists("key2"));
    assert!(!env_var_name_exists("non_existent_var"));
    msg_reply(vec![]);
}

#[export_name = "canister_query call_env_var_value"]
fn call_env_var_value() {
    assert_eq!(env_var_value("key1"), "value1");
    assert_eq!(env_var_value("key2"), "value2");
    msg_reply(vec![]);
}

#[export_name = "canister_update call_debug_print"]
fn call_debug_print() {
    debug_print("Hello, world!");
    msg_reply(vec![]);
}

#[export_name = "canister_update call_trap"]
fn call_trap() {
    trap("It's a trap!");
}

fn main() {}
