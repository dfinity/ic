use canister_test::*;
use ic_state_machine_tests::StateMachine;
use ic00::CanisterSettingsArgsBuilder;

#[test]
fn test_memory_test_canisters() {
    let env = StateMachine::new();

    let features = [];
    let wasm = Project::cargo_bin_maybe_from_env("memory_test_canister", &features);

    let canister_id = env
        .install_canister_with_cycles(
            wasm.bytes(),
            vec![],
            Some(
                CanisterSettingsArgsBuilder::new()
                    .with_memory_allocation(8 * 1024 * 1024 * 1024) // 8GiB
                    .build(),
            ),
            Cycles::from(u128::MAX),
        )
        .unwrap();

    // Test reads after writes
    {
        let payload = r#"{"address": 0, "size": 4096, "value": 1}"#.as_bytes().to_vec();
        env.execute_ingress(canister_id, "update_write", payload.clone())
            .unwrap();
        assert_reply_eq(
            env.query(canister_id, "query_read", payload).unwrap(),
            // By default we write and read every 8 bytes
            4096 / 8,
        );
    }

    // Test reads after writes with step
    {
        let payload = r#"{"address": 0, "size": 100000000, "value": 2, "step": 1000}"#
            .as_bytes()
            .to_vec();
        env.execute_ingress(canister_id, "update_write", payload.clone())
            .unwrap();
        assert_reply_eq(
            env.query(canister_id, "query_read", payload).unwrap(),
            100_000_000 / 1_000 * 2,
        );
    }

    // Test read_write()
    {
        let payload = r#"{"address": 0, "size": 100000000, "value": 3, "step": 1000}"#
            .as_bytes()
            .to_vec();
        env.execute_ingress(canister_id, "update_read_write", payload.clone())
            .unwrap();
        assert_reply_eq(
            env.execute_ingress(canister_id, "update_read_write", payload)
                .unwrap(),
            100_000_000 / 1_000 * 3,
        );
        let payload = r#"{"address": 0, "size": 2000, "value": 3, "step": 1000}"#
            .as_bytes()
            .to_vec();
        assert_reply_eq(
            env.query(canister_id, "query_read", payload).unwrap(),
            2 * 3,
        );
    }

    // Test stable read after stable write
    {
        let payload = r#"{"address": 0, "size": 500000000, "value": 10, "step": 5000}"#
            .as_bytes()
            .to_vec();
        env.execute_ingress(canister_id, "update_stable_write", payload.clone())
            .unwrap();
        assert_reply_eq(
            env.query(canister_id, "query_stable_read", payload)
                .unwrap(),
            500_000_000_u64 / 5_000 * 10,
        );
    }

    // Test stable_read_write()
    {
        let payload = r#"{"address": 0, "size": 500000000, "value": 11, "step": 5000}"#
            .as_bytes()
            .to_vec();
        env.execute_ingress(canister_id, "update_stable_read_write", payload.clone())
            .unwrap();
        assert_reply_eq(
            env.execute_ingress(canister_id, "update_stable_read_write", payload)
                .unwrap(),
            500_000_000_u64 / 5_000 * 11,
        );
        let payload = r#"{"address": 0, "size": 10000, "value": 11, "step": 5000}"#
            .as_bytes()
            .to_vec();
        assert_reply_eq(
            env.query(canister_id, "query_stable_read", payload)
                .unwrap(),
            2 * 11,
        );
    }
}

/// Asserts that the `WasmResult` provided is a `Reply` that matches the
/// given expected value.
fn assert_reply_eq(res: WasmResult, expected: u64) {
    match res {
        WasmResult::Reply(reply) => {
            assert_eq!(String::from_utf8(reply).unwrap(), expected.to_string());
        }
        WasmResult::Reject(err) => panic!("Expected a reply but got {err}"),
    }
}
