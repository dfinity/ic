/* tag::catalog[]
end::catalog[] */

use crate::types::*;
use crate::util::*;
use ic_fondue::{ic_instance::InternetComputer, ic_manager::IcHandle};
use ic_registry_subnet_type::SubnetType;
use ic_utils::interfaces::ManagementCanister;

pub fn config() -> InternetComputer {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .add_fast_single_node_subnet(SubnetType::Application)
}

/// Tests that query replies can be larger than update replies.
pub fn query_reply_sizes(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    // A wasm that exports a query function that has a 3MiB reply.
    let wasm = wabt::wat2wasm(
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
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let endpoint = get_random_application_node_endpoint(&handle, &mut rng);
            endpoint.assert_ready(ctx).await;
            let agent = assert_create_agent(endpoint.url.as_str()).await;
            let mgr = ManagementCanister::create(&agent);

            let canister_id = mgr
                .create_canister()
                .as_provisional_create_with_amount(None)
                .call_and_wait(delay())
                .await
                .expect("Couldn't create canister with provisional API.")
                .0;
            mgr.install_code(&canister_id, &wasm)
                .call_and_wait(delay())
                .await
                .unwrap();

            // Calling the query function as a query succeeds.
            agent.query(&canister_id, "hi").call().await.unwrap();
            // Calling the query function as an update fails because the reply
            // is too big.
            let res = agent
                .update(&canister_id, "hi")
                .call_and_wait(delay())
                .await;
            assert_reject(res, RejectCode::CanisterError);
        }
    })
}
