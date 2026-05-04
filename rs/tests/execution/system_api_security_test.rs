/*
   These tests tries to provide malicious input to induce mistake in the application, disclose unauthorized
   data, write into unauthorized memory etc.
*/

use anyhow::Result;
use core::fmt::Write;
use ic_agent::{AgentError, RequestId, agent::RejectResponse, export::Principal};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_system_test_driver::{
    driver::{
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer},
    },
    util::*,
};
use ic_utils::interfaces::ManagementCanister;
use slog::{Logger, debug};
use std::{time::Duration, time::Instant};
use tokio::time::sleep_until;

// Enables additional debug logs
const ENABLE_DEBUG_LOG: bool = false;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(malicious_inputs))
        .add_test(systest!(malicious_intercanister_calls))
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .add_subnet(Subnet::new(SubnetType::Application).add_nodes(1))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

pub fn malicious_inputs(env: TestEnv) {
    let wasm = wat::parse_str(
        r#"(module
              (import "ic0" "msg_reply" (func $msg_reply))
              (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32) (param i32)))
              (import "ic0" "msg_arg_data_size"
                (func $msg_arg_data_size (result i32)))
              (import "ic0" "msg_arg_data_copy"
                (func $msg_arg_data_copy (param i32) (param i32) (param i32)))
              (import "ic0" "msg_caller_size"
                (func $msg_caller_size (result i32)))
              (import "ic0" "msg_caller_copy"
                (func $msg_caller_copy (param i32) (param i32) (param i32)))

              (func $proxy_msg_arg_data_copy_last_10_bytes
                (call $msg_arg_data_copy (i32.const 0) (i32.sub (call $msg_arg_data_size) (i32.const 10)) (i32.const 10))
                (call $msg_reply_data_append (i32.const 0) (i32.const 10))
                (call $msg_reply))

              (func $proxy_msg_arg_data_copy_return_last_4_bytes
                (call $msg_arg_data_copy (i32.const 0) (i32.const 0) (i32.const 65536))
                (call $msg_reply_data_append (i32.const 65532) (i32.const 4))
                (call $msg_reply))

              (func $proxy_msg_caller
                ;; Message caller size in normal case is 29
                ;; This can be verified by uncommenting the below line
                ;; (i32.store (i32.const 0) (call $msg_caller_size))
                (call $msg_arg_data_copy (i32.const 65532) (i32.const 0) (i32.const 4))
                (i32.store (i32.const 0) (i32.load (i32.const 65532)))
                (call $msg_caller_copy (i32.const 1) (i32.const 0) (i32.load (i32.const 65532)))
                (call $msg_reply_data_append (i32.const 0) (i32.const 1))
                (call $msg_reply_data_append (i32.const 1) (i32.load (i32.const 65532)))
                (call $msg_reply))

              (memory $memory 1)
              (export "memory" (memory $memory))
              (export "canister_query proxy_msg_arg_data_copy_last_10_bytes" (func $proxy_msg_arg_data_copy_last_10_bytes))
              (export "canister_query proxy_msg_caller" (func $proxy_msg_caller))
              )"#,
    ).unwrap();

    let topology_snapshot = env.topology_snapshot();
    let subnet = topology_snapshot
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap();
    let node = subnet.nodes().next().unwrap();

    node.await_status_is_healthy().unwrap_or_else(|e| {
        panic!(
            "Node {:?} didn't become healthy in time because {e:?}",
            node.node_id
        )
    });

    let agent = node.build_default_agent();

    block_on(async move {
        let mgr = ManagementCanister::create(&agent);
        let canister_id = mgr
            .create_canister()
            .as_provisional_create_with_amount(None)
            .with_effective_canister_id(node.effective_canister_id())
            .call_and_wait()
            .await
            .expect("Error creating canister")
            .0;

        mgr.install_code(&canister_id, &wasm)
            .call_and_wait()
            .await
            .unwrap();

        tests_for_illegal_data_buffer_access(&agent, &canister_id).await;
    });
}

async fn tests_for_illegal_data_buffer_access(agent: &ic_agent::Agent, canister_id: &Principal) {
    // Provide 1 GB of data
    let ret_val = agent
        .query(canister_id, "proxy_msg_arg_data_copy_last_10_bytes")
        .with_arg(vec![1; 1024 * 1024 * 1024])
        .call()
        .await;
    let _containing_str = "Request is too big. Max allowed size in bytes is: 5242880";
    assert!(
        ret_val.is_err(),
        "Should return error if 1GB of data sent as input"
    );

    // Calls msg caller with correct size = 29 bytes
    let ret_val = agent
        .query(canister_id, "proxy_msg_caller")
        .with_arg(vec![29, 0, 0, 0])
        .call()
        .await;
    assert!(ret_val.is_ok(), "msg_caller with caller length 29 failed");

    // Calls msg caller with larger size
    let ret_val = agent
        .query(canister_id, "proxy_msg_caller")
        .with_arg(vec![128, 0, 0, 0])
        .call()
        .await;
    let containing_str =
        "violated contract: ic0.msg_caller_copy id: src=0 + length=128 exceeds the slice size=29";
    assert!(
        matches!(
            ret_val,
            Err(AgentError::UncertifiedReject { reject: RejectResponse {reject_message, .. }, .. }) if reject_message.contains(containing_str)
        ),
        "msg_caller with caller large length 128 was accepted"
    );
}

/*
   This test has two canister's A and B. Canister A is the one that will interfaced
   by the client and canister B is called by Canister A. The intent is to test malicious
   inter-canister calls
*/
pub fn malicious_intercanister_calls(env: TestEnv) {
    let logger = &env.logger();
    let canister_b_wasm = wat::parse_str(
        r#"(module
            (import "ic0" "msg_arg_data_copy" (func $ic0_msg_arg_data_copy (param i32) (param i32) (param i32)))
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_reply_data_append" (func $msg_reply_data_append (param i32 i32)))
            (func $echo
              (call $ic0_msg_arg_data_copy (i32.const 0) (i32.const 0) (i32.const 4))
              (call $msg_reply_data_append (i32.const 0) (i32.const 4))
              (call $msg_reply))
            (memory $memory 1)
            (export "memory" (memory $memory))
            (export "canister_query echo" (func $echo)))"#,
    ).unwrap();

    let topology_snapshot = env.topology_snapshot();
    let subnet = topology_snapshot
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap();
    let node = subnet.nodes().next().unwrap();

    node.await_status_is_healthy().unwrap_or_else(|e| {
        panic!(
            "Node {:?} didn't become healthy in time because {e:?}",
            node.node_id
        )
    });

    let agent = node.build_default_agent();

    block_on(async move {
        let canister_b =
            create_and_install(&agent, node.effective_canister_id(), &canister_b_wasm).await;

        let canister_a_wasm = wat::parse_str(format!(
            r#"(module
            (import "ic0" "msg_arg_data_copy" (func $ic0_msg_arg_data_copy (param i32) (param i32) (param i32)))
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_reply_data_append" (func $msg_reply_data_append (param i32 i32)))
            (import "ic0" "debug_print" (func $debug_print (param i32) (param i32)))
            (import "ic0" "call_new"
                (func $ic0_call_new
                (param i32 i32)
                (param $method_name_src i32)    (param $method_name_len i32)
                (param $reply_fun i32)          (param $reply_env i32)
                (param $reject_fun i32)         (param $reject_env i32)
            ))
            (import "ic0" "call_data_append" (func $ic0_call_data_append (param $src i32) (param $size i32)))
            (import "ic0" "call_cycles_add" (func $ic0_call_cycles_add (param $amount i64)))
            (import "ic0" "call_perform" (func $ic0_call_perform (result i32)))
            (import "ic0" "canister_cycle_balance" (func $canister_cycle_balance (result i64)))
            (import "ic0" "msg_method_name_size" (func $msg_method_name_size (result i32)))

            ;; This call doesn't trap and models a successful API call
            (func $proxy
              (call $ic0_msg_arg_data_copy (i32.const 10) (i32.const 0) (i32.const 4))
              ;; Call B
              (call $ic0_call_new
                (i32.const 100) (i32.const {})  ;; 100 represents heap address, the size is populated by format func
                (i32.const 0) (i32.const 4)     ;; refers to "echo" on the heap
                (i32.const 0) (i32.const 0)     ;; on_reply closure
                (i32.const 1) (i32.const 0)     ;; on_reject closure
              )
              (call $ic0_call_data_append
                (i32.const 10) (i32.const 4)    ;; refers to byte copied from the payload
              )
              (call $ic0_call_perform)
              drop
              ;; Some additional work is done
              (i32.store (i32.const 80) (i32.const 0))
              (i32.store (i32.const 90) (i32.const 10000))
              (block
                    (loop
                          (i32.store (i32.const 80) (i32.add (i32.load (i32.const 80)) (i32.const 1)))
                          (br_if 1 (i32.eq (i32.load (i32.const 80)) (i32.load (i32.const 90))))
                          (br 0)
                    )
              )
            )

            ;; This function as opposite to the previous funct traps by calling some system API
            ;; that shouldn't work in this context
            (func $proxy_err
              (call $ic0_msg_arg_data_copy (i32.const 10) (i32.const 0) (i32.const 4))
              ;; Call B
              (call $ic0_call_new
                (i32.const 100) (i32.const {})  ;; 100 represents heap address, the size is populated by format func
                (i32.const 0) (i32.const 4)     ;; refers to "echo" on the heap
                (i32.const 0) (i32.const 0)     ;; on_reply closure
                (i32.const 1) (i32.const 0)     ;; on_reject closure
              )
              (call $ic0_call_data_append
                (i32.const 10) (i32.const 4)    ;; refers to byte copied from the payload
              )
              (call $ic0_call_perform)
              drop
              ;; Triggers trap
              (call $msg_method_name_size)
              drop
              ;; Some additional work is done
              (i32.store (i32.const 80) (i32.const 0))
              (i32.store (i32.const 90) (i32.const 10000))
              (block
                    (loop
                          (i32.store (i32.const 80) (i32.add (i32.load (i32.const 80)) (i32.const 1)))
                          (br_if 1 (i32.eq (i32.load (i32.const 80)) (i32.load (i32.const 90))))
                          (br 0)
                    )
              )
            )

            ;; The reply callback is executed upon successful completion of the inter-canister
            ;; method call
            (func $on_reply (param $env i32)
              (call $ic0_msg_arg_data_copy (i32.const 60) (i32.const 0) (i32.const 4))
              (i32.store (i32.const 64) (i32.const 1))
              (call $msg_reply_data_append (i32.const 60) (i32.const 5))
              (call $msg_reply)
            )

            ;; The reject callback is executed if the method call fails asynchronously or
            ;; the other canister explicitly rejects the call
            (func $on_reject (param $env i32)
              (call $msg_reply_data_append (i32.const 10) (i32.const 5))
              (call $msg_reply)
            )

            ;; Reads the wasm buffer and returns the content
            (func $read
              (call $msg_reply_data_append (i32.const 60) (i32.const 5))
              (call $msg_reply)
            )

            (func $num_cycles
              (i64.store (i32.const 40) (call $canister_cycle_balance))
            )

            (func $read_cycles
              (i64.store (i32.const 40) (call $canister_cycle_balance))
              (call $msg_reply_data_append (i32.const 40) (i32.const 8))
              (call $msg_reply)
            )

            (table funcref (elem $on_reply $on_reject))
            ;; wasm heap 1 page = 64 KB
            (memory $memory 1)
            (data (i32.const 0) "echo")
            (data (i32.const 100) "{}")
            (export "canister_update proxy" (func $proxy))
            (export "canister_update proxy_err" (func $proxy_err))
            (export "canister_query read" (func $read))
            (export "canister_query read_cycles" (func $read_cycles))
            (export "memory" (memory $memory)))"#,
            canister_b.as_slice().len(),
            canister_b.as_slice().len(),
            escape_for_wat(&canister_b))).unwrap();
        let canister_a =
            create_and_install(&agent, node.effective_canister_id(), &canister_a_wasm).await;

        let ret_val = agent.query(&canister_a, "read_cycles").call().await;
        let num_cycles_before =
            print_validate_num_cycles(logger, &ret_val, "Before calling proxy()");

        let ret_val = agent
            .update(&canister_a, "proxy")
            .with_arg(vec![1; 4])
            .call()
            .await;
        assert!(ret_val.is_ok());

        const NR_SLEEPS: usize = 3;
        for _ in 0..NR_SLEEPS {
            // Wait for few seconds before reading the data.
            sleep_until(tokio::time::Instant::from_std(
                Instant::now() + Duration::from_secs(5),
            ))
            .await;
            let ret_val = agent.query(&canister_a, "read").call().await;
            assert!(ret_val.is_ok());
            let result = ret_val.unwrap();
            // Initial value at mem location 60 is [0,0,0,0,0]
            if result.as_slice() != [0, 0, 0, 0, 0] {
                // The last (5th) byte having a value of 1 means that the inter-canister response was processed by on_reply
                assert_eq!(
                    [1, 1, 1, 1, 1],
                    result.as_slice(),
                    "Expected result is [1,1,1,1,1]"
                );
                break;
            }
        }

        let ret_val = agent.query(&canister_a, "read_cycles").call().await;
        let num_cycles_after = print_validate_num_cycles(logger, &ret_val, "After calling proxy()");
        assert!(
            (num_cycles_after < num_cycles_before),
            "num_cycles_after is not less than num_cycles_before"
        );
        let cycles_used_proxy = num_cycles_before - num_cycles_after;
        if ENABLE_DEBUG_LOG {
            debug!(logger, "total cycles used = {}", cycles_used_proxy);
        }

        /* Now make intercanister call proxy_err that throws error and check the cycles used */
        let ret_val = agent.query(&canister_a, "read_cycles").call().await;
        let num_cycles_before =
            print_validate_num_cycles(logger, &ret_val, "Before calling proxy_err()");

        let ret_val = agent
            .update(&canister_a, "proxy_err")
            .with_arg(vec![2; 4])
            .call_and_wait()
            .await;

        assert!(matches!(ret_val, Err(AgentError::CertifiedReject { .. })));

        // Wait for few seconds before reading the data.
        for _ in 0..NR_SLEEPS {
            sleep_until(tokio::time::Instant::from_std(
                Instant::now() + Duration::from_secs(5),
            ))
            .await;
            let ret_val = agent.query(&canister_a, "read").call().await;
            assert!(ret_val.is_ok());
            let result = ret_val.unwrap();
            // The initial value is [1,1,1,1,1] because of the previous call that succeeded and copies [1,1,1,1,1] to mem location 60
            if result.as_slice() != [1, 1, 1, 1, 1] {
                // The last (5th) byte having a value of 1 means that the inter-canister response was processed by on_reply
                assert_eq!(
                    [2, 2, 2, 2, 1],
                    result.as_slice(),
                    "Expected result is [2,2,2,2,1]"
                );
                break;
            }
        }

        let ret_val = agent.query(&canister_a, "read_cycles").call().await;
        let num_cycles_after =
            print_validate_num_cycles(logger, &ret_val, "After calling proxy_err()");
        assert!(
            (num_cycles_after < num_cycles_before),
            "num_cycles_after is not less than num_cycles_before"
        );
        let cycles_used_proxy_err = num_cycles_before - num_cycles_after;
        if ENABLE_DEBUG_LOG {
            debug!(logger, "total cycles used = {}", cycles_used_proxy_err);
        }
        assert!(cycles_used_proxy > cycles_used_proxy_err);
    });
}

#[allow(dead_code)]
fn get_request_id_hex(request_id: &RequestId) -> String {
    let request_id_bytes = request_id.as_slice();
    let mut request_id_hex = String::with_capacity(request_id_bytes.len() * 2);
    for b in request_id_bytes {
        let result = write!(request_id_hex, "{b:02x}");
        if result.is_err() {
            return String::new();
        }
    }
    println!("Request Id {request_id_hex}");
    request_id_hex
}

fn convert_bytes_to_number(input: &[u8]) -> Option<u64> {
    if input.len() > 8 {
        return None;
    }

    let mut result: Option<u64> = Some(0);
    for i in input.iter().enumerate() {
        let partial_result = u64::pow(256, (i.0) as u32).checked_mul(*(i.1) as u64);
        if partial_result.is_none() {
            return partial_result;
        }

        result = result.unwrap().checked_add(partial_result.unwrap());
        if result.is_none() {
            return result;
        }
    }
    result
}

fn print_validate_num_cycles(
    logger: &Logger,
    ret_val: &Result<Vec<u8>, AgentError>,
    message: &str,
) -> u64 {
    assert!(ret_val.is_ok(), "{:?}", ret_val.as_ref().unwrap_err());
    // Prints the raw data returned from the canister
    if ENABLE_DEBUG_LOG {
        print_result(logger, ret_val, "Number of cycles raw");
    }
    let result = ret_val.as_ref().unwrap_or(&vec![]).clone();

    if let Some(num_cycles) = convert_bytes_to_number(result.as_slice()) {
        // Prints the number of cycles
        if ENABLE_DEBUG_LOG {
            print_cycles(logger, num_cycles, message);
        }
        num_cycles
    } else {
        debug!(
            logger,
            "{} - Error while converting query result for read_cycles", message
        );
        0
    }
}

fn print_result(logger: &Logger, ret_val: &Result<Vec<u8>, AgentError>, msg: &str) {
    if let Ok(result) = ret_val {
        debug!(logger, "{} {:?}", msg, result);
    }
}

fn print_cycles(logger: &Logger, num_cycles: u64, message: &str) {
    debug!(logger, "Number of cycles {} - {}", num_cycles, message);
}
