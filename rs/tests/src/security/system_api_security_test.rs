/*
   These tests tries to provide malicious input to induce mistake in the application, disclose unauthorized
   data, write into unauthorized memory etc.
*/
use crate::util::*;
use core::fmt::Write;
use fondue::log::debug;
use ic_agent::export::Principal;
use ic_agent::AgentError;
use ic_agent::RequestId;
use ic_fondue::{
    ic_manager::IcHandle,                          // we run the test on the IC
    internet_computer::{InternetComputer, Subnet}, // which is declared through these types
};
use ic_registry_subnet_type::SubnetType;
use ic_utils::interfaces::ManagementCanister;
use std::{time::Duration, time::Instant};
use tokio::time::sleep_until;

pub fn config() -> InternetComputer {
    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .add_subnet(Subnet::new(SubnetType::Application).add_nodes(1))
}

// Enables additional debug logs
const ENABLE_DEBUG_LOG: bool = false;

pub fn malicious_inputs(handle: IcHandle, ctx: &fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    let wasm = wabt::wat2wasm(
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
              (import "ic0" "data_certificate_copy"
                (func $data_certificate_copy (param i32) (param i32) (param i32)))
              (import "ic0" "data_certificate_size"
                (func $data_certificate_size (result i32)))
              (import "ic0" "data_certificate_present"
                (func $data_certificate_present (result i32)))
              (import "ic0" "certified_data_set"
                (func $certified_data_set (param i32) (param i32)))
              (import "ic0" "call_new"
                (func $ic0_call_new
                (param i32 i32)
                (param $method_name_src i32)    (param $method_name_len i32)
                (param $reply_fun i32)          (param $reply_env i32)
                (param $reject_fun i32)         (param $reject_env i32)
              ))
              (import "ic0" "call_perform" (func $ic0_call_perform (result i32)))

              (func $proxy_msg_reply_data_append
                (call $msg_arg_data_copy (i32.const 0) (i32.const 0) (call $msg_arg_data_size))
                (call $msg_reply_data_append (i32.load (i32.const 0)) (i32.load (i32.const 4)))
                (call $msg_reply))

              (func $proxy_msg_arg_data_copy_from_buffer_without_input
                (call $msg_arg_data_copy (i32.const 0) (i32.const 0) (i32.const 10)))

              (func $proxy_msg_arg_data_copy_last_10_bytes
                (call $msg_arg_data_copy (i32.const 0) (i32.sub (call $msg_arg_data_size) (i32.const 10)) (i32.const 10))
                (call $msg_reply_data_append (i32.const 0) (i32.const 10))
                (call $msg_reply))

              (func $proxy_msg_arg_data_copy_to_oob_buffer
                (call $msg_arg_data_copy (i32.const 65536) (i32.const 0) (i32.const 10))
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

              ;; All the function below are not used 
              (func $proxy_data_certificate_present
                (i32.const 0)
                (call $data_certificate_present)
                (i32.store)
                (call $msg_reply_data_append (i32.const 0) (i32.const 1))
                (call $msg_reply))

              (func $proxy_certified_data_set
                (call $msg_arg_data_copy (i32.const 0) (i32.const 0) (call $msg_arg_data_size))
                (call $certified_data_set (i32.const 0) (call $msg_arg_data_size))
                (call $msg_reply_data_append (i32.const 0) (call $msg_arg_data_size))
                (call $msg_reply))

              (func $proxy_data_certificate_copy
                (call $data_certificate_copy (i32.const 0) (i32.const 0) (i32.const 32))
                (call $msg_reply_data_append (i32.const 0) (i32.const 32))
                (call $msg_reply))

              (func $f_100 (result i32)
                i32.const 100)
              (func $f_200 (result i32)
                i32.const 200)

              (type $return_i32 (func (result i32))) ;; if this was f32, type checking would fail
              (func $callByIndex
                (i32.const 0)
                (call_indirect (type $return_i32) (i32.const 0))
                (i32.store)
                (call $msg_reply_data_append (i32.const 0) (i32.const 4))
                (call $msg_reply))

              (table funcref (elem $f_100 $f_200))
              (memory $memory 1)
              (export "memory" (memory $memory))
              (export "canister_query callByIndex" (func $callByIndex))
              (export "canister_query proxy_msg_reply_data_append" (func $proxy_msg_reply_data_append))
              (export "canister_query proxy_msg_arg_data_copy_from_buffer_without_input" (func $proxy_msg_arg_data_copy_from_buffer_without_input))
              (export "canister_query proxy_msg_arg_data_copy_last_10_bytes" (func $proxy_msg_arg_data_copy_last_10_bytes))
              (export "canister_query proxy_msg_arg_data_copy_to_oob_buffer" (func $proxy_msg_arg_data_copy_to_oob_buffer))
              (export "canister_query proxy_msg_caller" (func $proxy_msg_caller))
              (export "canister_query proxy_data_certificate_present" (func $proxy_data_certificate_present))
              (export "canister_update proxy_certified_data_set" (func $proxy_certified_data_set))
              (export "canister_query proxy_data_certificate_copy" (func $proxy_data_certificate_copy))
              )"#,
    ).unwrap();

    rt.block_on(async move {
        let endpoint = get_random_application_node_endpoint(&handle, &mut rng);
        endpoint.assert_ready(ctx).await;
        let agent = assert_create_agent(endpoint.url.as_str()).await;
        let mgr = ManagementCanister::create(&agent);
        let canister_id = mgr
            .create_canister()
            .as_provisional_create_with_amount(None)
            .call_and_wait(delay())
            .await
            .expect("Error creating canister")
            .0;

        mgr.install_code(&canister_id, &wasm)
            .call_and_wait(delay())
            .await
            .unwrap();

        tests_for_illegal_wasm_memory_access(ctx, &agent, &canister_id).await;

        tests_for_stale_data_in_buffer_between_calls(&agent, &canister_id).await;

        tests_for_illegal_data_buffer_access(&agent, &canister_id).await;
    })
}

async fn tests_for_illegal_data_buffer_access(agent: &ic_agent::Agent, canister_id: &Principal) {
    // No input given but still read the input buffer
    let ret_val = agent
        .query(
            canister_id,
            "proxy_msg_arg_data_copy_from_buffer_without_input",
        )
        .call()
        .await;
    let containing_str = "violated contract: ic0.msg_arg_data_copy payload: src=0 + length=10 exceeds the slice size=0";
    assert!(
        matches!(
            ret_val,
            Err(AgentError::ReplicaError {reject_message, .. }) if reject_message.contains(containing_str)
        ),
        "Should return error if try to read input buffer on no input",
    );

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

    // copy data from argument buffer to out of bound internal buffer
    let ret_val = agent
        .query(canister_id, "proxy_msg_arg_data_copy_to_oob_buffer")
        .with_arg(vec![1; 10])
        .call()
        .await;
    let containing_str = "violated contract: ic0.msg_arg_data_copy heap: src=65536 + length=10 exceeds the slice size=65536";
    assert!(
        matches!(
            ret_val,
            Err(AgentError::ReplicaError {reject_message, .. }) if reject_message.contains(containing_str)
        ),
        "Should return error if input data is copied to out of bound internal buffer"
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
            Err(AgentError::ReplicaError {reject_message, .. }) if reject_message.contains(containing_str)
        ),
        "msg_caller with caller large length 128 was accepted"
    );
}

async fn tests_for_stale_data_in_buffer_between_calls(
    agent: &ic_agent::Agent,
    canister_id: &Principal,
) {
    // Between every query the input data buffer is expected to be reset
    // and no stale data from previous query can be found. The following
    // test check this case
    let input = &mut vec![10; (32 * 1024) + 8];
    for i in input.iter_mut().take(8) {
        *i = 0;
    }
    input[0] = 8; //bytes 0x00 0x00 0x00 0x08 start index = 8 - Little Endian
    input[5] = 128; //bytes 0x00 0x00 0x80 0x00 size = 32768 - Little Endian
    let ret_val = agent
        .query(canister_id, "proxy_msg_reply_data_append")
        .with_arg(input)
        .call()
        .await;
    assert!(
        ret_val.is_ok(),
        "Check for stale data step 1 failed. Error: {}",
        ret_val.unwrap_err()
    );
    let data = ret_val.unwrap();
    assert_eq!(
        [10, 10, 10, 10],
        &data[0..4],
        "first read - expected [10, 10, 10, 10] at data index 0 to 4 {:?}",
        &data[0..4]
    );
    assert_eq!(
        [10, 10, 10, 10],
        &data[32764..32768],
        "first read - expected [10, 10, 10, 10] at data index 32765 to 32768 {:?}",
        &data[32764..32768]
    );
    let ret_val = agent
        .query(canister_id, "proxy_msg_reply_data_append")
        .with_arg(vec![8, 0, 0, 0, 0, 128, 0, 0])
        .call()
        .await;
    assert!(
        ret_val.is_ok(),
        "Check for stale data step 2 failed. Error: {}",
        ret_val.unwrap_err()
    );
    let data = ret_val.unwrap();
    assert_eq!(
        [0, 0, 0, 0],
        &data[0..4],
        "second read - stale data present, expected [0, 0, 0, 0] at data index 0 to 4 {:?}",
        &data[0..4]
    );
    assert_eq!(
        [0, 0, 0, 0],
        &data[32764..32768],
        "second read - stale data present, expected [0, 0, 0, 0] at data index 32765 to 32768 {:?}",
        &data[32764..32768]
    );
}

async fn tests_for_illegal_wasm_memory_access(
    ctx: &fondue::pot::Context,
    agent: &ic_agent::Agent,
    canister_id: &Principal,
) {
    // msg_reply_data_append(0, 65536) => expect no error
    let ret_val = agent
        .query(canister_id, "proxy_msg_reply_data_append")
        .with_arg(vec![0, 0, 0, 0, 0, 0, 1, 0])
        .call()
        .await;
    if ENABLE_DEBUG_LOG {
        print_result_or_error(
            ctx,
            &ret_val,
            format!(
                "proxy_msg_reply_data_appendInput => {} {} Ouput =>",
                0, 65536
            )
            .as_str(),
        );
    }
    assert!(
        ret_val.is_ok(),
        "msg_reply_data_append(0, 65536) failed. Error: {}",
        ret_val.unwrap_err()
    );

    // msg_reply_data_append(0, 65537) => expect no error
    let ret_val = agent
        .query(canister_id, "proxy_msg_reply_data_append")
        .with_arg(vec![0, 0, 0, 0, 1, 0, 1, 0])
        .call()
        .await;
    let containing_str =
        "violated contract: msg.reply: src=0 + length=65537 exceeds the slice size=65536";
    assert!(
        matches!(
            ret_val,
            Err(AgentError::ReplicaError {reject_message, .. }) if reject_message.contains(containing_str)
        ),
        "expected msg_reply_data_append(0, 65537) to fail"
    );

    // msg_reply_data_append(65536, 10) => expect error
    let ret_val = agent
        .query(canister_id, "proxy_msg_reply_data_append")
        .with_arg(vec![0, 0, 1, 0, 10, 0, 0, 0])
        .call()
        .await;
    let containing_str =
        "violated contract: msg.reply: src=65536 + length=10 exceeds the slice size=65536";
    assert!(
        matches!(
            ret_val,
            Err(AgentError::ReplicaError {reject_message, .. }) if reject_message.contains(containing_str)
        ),
        "expected msg_reply_data_append(65536, 10) to fail"
    );
}

/*
   This test has two canister's A and B. Canister A is the one that will interfaced
   by the client and canister B is called by Canister A. The intent is to test malicious
   inter-canister calls
*/
pub fn malicious_intercanister_calls(handle: IcHandle, ctx: &fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    let canister_b_wasm = wabt::wat2wasm(
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

    rt.block_on(async move {
        let endpoint = get_random_application_node_endpoint(&handle, &mut rng);
        endpoint.assert_ready(ctx).await;
        let agent = assert_create_agent(endpoint.url.as_str()).await;
        let canister_b = create_and_install(&agent, &canister_b_wasm).await;

        let canister_a_wasm = wabt::wat2wasm(format!(
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
        let canister_a = create_and_install(&agent, &canister_a_wasm).await;

        let ret_val = agent.query(&canister_a, "read_cycles").call().await;
        let num_cycles_before = print_validate_num_cycles(ctx, &ret_val, "Before calling proxy()");

        let ret_val = agent.update(&canister_a, "proxy").with_arg(vec![1; 4]).call().await;
        assert!(ret_val.is_ok());

        const NR_SLEEPS: usize = 3;
        for _ in 0..NR_SLEEPS {
            // Wait for few seconds before reading the data.
            sleep_until(tokio::time::Instant::from_std(Instant::now() + Duration::from_secs(5))).await;
            let ret_val = agent.query(&canister_a, "read").call().await;
            assert!(ret_val.is_ok());
            let result = ret_val.unwrap();
            // Initial value at mem location 60 is [0,0,0,0,0]
            if result.as_slice() != [0,0,0,0,0] {
                // The last (5th) byte having a value of 1 means that the inter-canister response was processed by on_reply
                assert_eq!([1,1,1,1,1], result.as_slice(), "Expected result is [1,1,1,1,1]");
                break;
            }
        }

        let ret_val = agent.query(&canister_a, "read_cycles").call().await;
        let num_cycles_after = print_validate_num_cycles(ctx,&ret_val, "After calling proxy()");
        assert!((num_cycles_after < num_cycles_before), "num_cycles_after is not less than num_cycles_before");
        let cycles_used_proxy = num_cycles_before - num_cycles_after;
        if ENABLE_DEBUG_LOG {
            debug!(ctx.logger, "total cycles used = {}", cycles_used_proxy);
        }

        /* Now make intercanister call proxy_err that throws error  and check the cycles used */
        let ret_val = agent.query(&canister_a, "read_cycles").call().await;
        let num_cycles_before = print_validate_num_cycles(ctx, &ret_val, "Before calling proxy_err()");

        let ret_val = agent.update(&canister_a, "proxy_err").with_arg(vec![2; 4]).call().await;
        assert!(ret_val.is_ok());

        // Wait for few seconds before reading the data.
        for _ in 0..NR_SLEEPS {
            sleep_until(tokio::time::Instant::from_std(Instant::now() + Duration::from_secs(5))).await;
            let ret_val = agent.query(&canister_a, "read").call().await;
            assert!(ret_val.is_ok());
            let result = ret_val.unwrap();
            // The initial value is [1,1,1,1,1] because of the previous call that succeeded and copies [1,1,1,1,1] to mem location 60
            if result.as_slice() != [1,1,1,1,1] {
                // The last (5th) byte having a value of 1 means that the inter-canister response was processed by on_reply
                assert_eq!([2,2,2,2,1], result.as_slice(), "Expected result is [2,2,2,2,1]");
                break;
            }
        }

        let ret_val = agent.query(&canister_a, "read_cycles").call().await;
        let num_cycles_after = print_validate_num_cycles(ctx,&ret_val, "After calling proxy_err()");
        assert!((num_cycles_after < num_cycles_before), "num_cycles_after is not less than num_cycles_before");
        let cycles_used_proxy_err = num_cycles_before - num_cycles_after;
        if ENABLE_DEBUG_LOG {
            debug!(ctx.logger, "total cycles used = {}", cycles_used_proxy_err);
        }
        assert!(cycles_used_proxy > cycles_used_proxy_err);

    });
}

fn escape_for_wat(id: &Principal) -> String {
    // Quoting from
    // https://webassembly.github.io/spec/core/text/values.html#text-string:
    //
    // "Strings [...] can represent both textual and binary data" and
    //
    // "hexadecimal escape sequences ‘∖ℎℎ’, [...] represent raw bytes of the
    // respective value".
    id.as_slice().iter().fold(String::new(), |mut res, b| {
        res.push_str(&format!("\\{:02x}", b));
        res
    })
}

#[allow(dead_code)]
fn get_request_id_hex(request_id: &RequestId) -> String {
    let request_id_bytes = request_id.as_slice();
    let mut request_id_hex = String::with_capacity(request_id_bytes.len() * 2);
    for b in request_id_bytes {
        let result = write!(request_id_hex, "{:02x}", b);
        if result.is_err() {
            return String::new();
        }
    }
    println!("Request Id {}", request_id_hex);
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
    ctx: &fondue::pot::Context,
    ret_val: &Result<Vec<u8>, AgentError>,
    message: &str,
) -> u64 {
    assert!(ret_val.is_ok(), "{:?}", ret_val.as_ref().unwrap_err());
    // Prints the raw data returned from the canister
    if ENABLE_DEBUG_LOG {
        print_result(ctx, ret_val, "Number of cycles raw");
    }
    let result = ret_val.as_ref().unwrap_or(&vec![]).clone();

    let num_cycles = if let Some(num_cycles) = convert_bytes_to_number(result.as_slice()) {
        // Prints the number of cycles
        if ENABLE_DEBUG_LOG {
            print_cycles(ctx, num_cycles, message);
        }
        num_cycles
    } else {
        debug!(
            ctx.logger,
            "{} - Error while converting query result for read_cycles", message
        );
        0
    };
    num_cycles
}

fn print_result_or_error(
    ctx: &fondue::pot::Context,
    ret_val: &Result<Vec<u8>, AgentError>,
    msg: &str,
) {
    match ret_val {
        Ok(result) => {
            debug!(ctx.logger, "{} - Message Length:{:?}", msg, result.len());
            print_result_range(ctx, &Ok(result.clone()), msg);
        }
        Err(err) => debug!(ctx.logger, "{} {:?}", msg, err),
    }
}

fn print_result_range(
    ctx: &fondue::pot::Context,
    ret_val: &Result<Vec<u8>, AgentError>,
    msg: &str,
) {
    match ret_val {
        Ok(result) => {
            if result.len() > 32 {
                let mut v1: [u8; 16] = [0; 16];
                let mut v2: [u8; 16] = [0; 16];
                for i in 0..16 {
                    v1[i] = result[i];
                    v2[i] = result[result.len() - 16 + i];
                }
                debug!(ctx.logger, "{} {:?}..{:?}", msg, v1, v2)
            } else {
                debug!(ctx.logger, "{} {:?}", msg, result);
            }
        }
        Err(_) => (),
    }
}

fn print_result(ctx: &fondue::pot::Context, ret_val: &Result<Vec<u8>, AgentError>, msg: &str) {
    match ret_val {
        Ok(result) => {
            debug!(ctx.logger, "{} {:?}", msg, result);
        }
        Err(_) => (),
    }
}

fn print_cycles(ctx: &fondue::pot::Context, num_cycles: u64, message: &str) {
    debug!(ctx.logger, "Number of cycles {} - {}", num_cycles, message);
}
