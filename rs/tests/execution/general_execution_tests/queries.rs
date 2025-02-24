/* tag::catalog[]
end::catalog[] */

use ic_agent::agent::RejectCode;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::GetFirstHealthyNodeSnapshot;
use ic_system_test_driver::driver::test_env_api::HasPublicApiUrl;
use ic_system_test_driver::util::*;
use ic_utils::interfaces::ManagementCanister;

/// Tests that query replies can be larger than update replies.
pub fn query_reply_sizes(env: TestEnv) {
    // A wasm that exports a query function that has a 3MiB reply.
    let wasm = wat::parse_str(
        r#"(module
              (import "ic0" "msg_reply" (func $msg_reply))
              (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32) (param i32)))

              (func $hi
                (call $msg_reply_data_append (i32.const 0) (i32.const 3145728))
                (call $msg_reply))

              (memory $memory 48)
              (export "memory" (memory $memory))
              (export "canister_query hi" (func $hi)))"#,
    )
    .unwrap();
    let app_node = env.get_first_healthy_application_node_snapshot();
    let agent = app_node.build_default_agent();
    block_on({
        async move {
            let mgr = ManagementCanister::create(&agent);

            let canister_id = mgr
                .create_canister()
                .as_provisional_create_with_amount(None)
                .with_effective_canister_id(app_node.effective_canister_id())
                .call_and_wait()
                .await
                .expect("Couldn't create canister with provisional API.")
                .0;
            mgr.install_code(&canister_id, &wasm)
                .call_and_wait()
                .await
                .unwrap();

            // Calling the query function as a query succeeds.
            agent.query(&canister_id, "hi").call().await.unwrap();
            // Calling the query function as an update fails because the reply
            // is too big.
            let res = agent.update(&canister_id, "hi").call_and_wait().await;
            assert_reject(res, RejectCode::CanisterError);
        }
    })
}
