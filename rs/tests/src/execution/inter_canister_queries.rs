/* tag::catalog[]
end::catalog[] */
use crate::{
    types::RejectCode,
    util::{
        assert_create_agent, assert_reject, create_and_install, escape_for_wat,
        get_random_nns_node_endpoint, get_random_node_endpoint,
        get_random_verified_app_node_endpoint, UniversalCanister,
    },
};
use ic_fondue::{ic_instance::InternetComputer, ic_manager::IcHandle};
use ic_registry_subnet_type::SubnetType;
use ic_types::CanisterId;
use ic_universal_canister::{call_args, wasm};

pub fn config() -> InternetComputer {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .add_fast_single_node_subnet(SubnetType::VerifiedApplication)
}

/// User queries A on first subnet. A queries B on another subnet which fails.
pub fn cannot_query_xnet_canister(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let endpoint_nns = get_random_nns_node_endpoint(&handle, &mut rng);
            endpoint_nns.assert_ready(ctx).await;
            let agent_nns = assert_create_agent(endpoint_nns.url.as_str()).await;
            let endpoint_application = get_random_verified_app_node_endpoint(&handle, &mut rng);
            endpoint_application.assert_ready(ctx).await;
            let agent_application = assert_create_agent(endpoint_application.url.as_str()).await;

            let canister_a = UniversalCanister::new(&agent_nns).await;
            let canister_b = UniversalCanister::new(&agent_application).await;

            let res = canister_a
                .query(wasm().inter_query(canister_b.canister_id(), call_args()))
                .await;
            assert_reject(res, RejectCode::CanisterReject);
        }
    });
}

/// User queries canister A; A replies to user.
pub fn simple_query(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let endpoint = get_random_node_endpoint(&handle, &mut rng);
            endpoint.assert_ready(ctx).await;
            let agent = assert_create_agent(endpoint.url.as_str()).await;
            let canister = UniversalCanister::new(&agent).await;
            let arbitrary_bytes = b"l49sdk";
            assert_eq!(
                canister
                    .query(wasm().reply_data(arbitrary_bytes))
                    .await
                    .unwrap(),
                arbitrary_bytes
            );
        }
    });
}

/// User queries canister A; A queries self which fails.
pub fn self_loop_fails(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let endpoint = get_random_node_endpoint(&handle, &mut rng);
            endpoint.assert_ready(ctx).await;
            let agent = assert_create_agent(endpoint.url.as_str()).await;
            let canister = UniversalCanister::new(&agent).await;
            let res = canister
                .query(wasm().inter_query(canister.canister_id(), call_args()))
                .await;
            assert_reject(res, RejectCode::CanisterError);
        }
    });
}

/// User queries canister A; A queries B; B queries A which fails.
pub fn canisters_loop_fails(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let endpoint = get_random_node_endpoint(&handle, &mut rng);
            endpoint.assert_ready(ctx).await;
            let agent = assert_create_agent(endpoint.url.as_str()).await;
            let canister_a = UniversalCanister::new(&agent).await;
            let canister_b = UniversalCanister::new(&agent).await;
            let res = canister_a
                .query(
                    wasm().inter_query(
                        canister_b.canister_id(),
                        call_args()
                            .other_side(wasm().inter_query(canister_a.canister_id(), call_args())),
                    ),
                )
                .await;
            assert_reject(res, RejectCode::CanisterError);
        }
    });
}

/// User queries canister A; A queries B; B replies to A; A does not reply to
/// the user.
pub fn intermediate_canister_does_not_reply(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let endpoint = get_random_node_endpoint(&handle, &mut rng);
            endpoint.assert_ready(ctx).await;
            let agent = assert_create_agent(endpoint.url.as_str()).await;
            let canister_a = UniversalCanister::new(&agent).await;
            let canister_b = UniversalCanister::new(&agent).await;
            let res = canister_a
                .query(
                    wasm().inter_query(
                        canister_b.canister_id(),
                        call_args()
                            .other_side(wasm().reply())
                            .on_reply(wasm().noop()),
                    ),
                )
                .await;
            assert_reject(res, RejectCode::CanisterError);
        }
    });
}

/// User queries canister A; canister A queries canister B; B replies to A; A
/// replies to user.
pub fn query_two_canisters(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let endpoint = get_random_node_endpoint(&handle, &mut rng);
            endpoint.assert_ready(ctx).await;
            let agent = assert_create_agent(endpoint.url.as_str()).await;
            let canister_a = UniversalCanister::new(&agent).await;
            let canister_b = UniversalCanister::new(&agent).await;
            let arbitrary_bytes = b";ioapusdvzn,x";
            assert_eq!(
                canister_a
                    .query(wasm().inter_query(
                        canister_b.canister_id(),
                        call_args().other_side(wasm().reply_data(arbitrary_bytes)),
                    ))
                    .await
                    .unwrap(),
                arbitrary_bytes
            );
        }
    });
}

/// User queries A; A queries B; B queries C; C replies to B; B replies to A; A
/// replies to user
pub fn query_three_canisters(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let endpoint = get_random_node_endpoint(&handle, &mut rng);
            endpoint.assert_ready(ctx).await;
            let agent = assert_create_agent(endpoint.url.as_str()).await;
            let canister_a = UniversalCanister::new(&agent).await;
            let canister_b = UniversalCanister::new(&agent).await;
            let canister_c = UniversalCanister::new(&agent).await;
            let arbitrary_bytes = b";ioapusdvzn,x";
            assert_eq!(
                canister_a
                    .query(wasm().inter_query(
                        canister_b.canister_id(),
                        call_args().other_side(wasm().inter_query(
                            canister_c.canister_id(),
                            call_args().other_side(wasm().reply_data(arbitrary_bytes))
                        ))
                    ))
                    .await
                    .unwrap(),
                arbitrary_bytes
            );
        }
    });
}

/// User queries A; A queries non-existent canister; A sends error to user;
pub fn canister_queries_non_existent(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let endpoint = get_random_node_endpoint(&handle, &mut rng);
            endpoint.assert_ready(ctx).await;
            let agent = assert_create_agent(endpoint.url.as_str()).await;
            let canister_a = UniversalCanister::new(&agent).await;
            let non_existent = CanisterId::from(12345);
            let res = canister_a
                .query(wasm().inter_query(non_existent, call_args()))
                .await;
            assert_reject(res, RejectCode::CanisterReject);
        }
    });
}

/// User queries A; A queries B; B does not respond; A handles no-reply and
/// replies to user;
pub fn canister_queries_does_not_reply(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let endpoint = get_random_node_endpoint(&handle, &mut rng);
            endpoint.assert_ready(ctx).await;
            let agent = assert_create_agent(endpoint.url.as_str()).await;
            let canister_a = UniversalCanister::new(&agent).await;
            let canister_b = UniversalCanister::new(&agent).await;
            let res = canister_a
                .query(wasm().inter_query(
                    canister_b.canister_id(),
                    call_args().other_side(wasm().noop()),
                ))
                .await;
            assert_reject(res, RejectCode::CanisterReject);
        }
    });
}

/// End user sends a query msg to canisterA; canisterA sends two queries to
/// canisterB; canisterB replies to both; canisterA replies when it sees the
/// second reply from canisterB.
pub fn inter_canister_query_first_canister_multiple_request(
    handle: IcHandle,
    ctx: &ic_fondue::pot::Context,
) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let endpoint = get_random_node_endpoint(&handle, &mut rng);
endpoint.assert_ready(ctx).await;
            let agent = assert_create_agent(endpoint.url.as_str()).await;

            let canister_b_wasm = wabt::wat2wasm(
                r#"(module
              (import "ic0" "msg_arg_data_copy" (func $ic0_msg_arg_data_copy (param i32) (param i32) (param i32)))
              (import "ic0" "msg_reply" (func $msg_reply))
              (import "ic0" "msg_reply_data_append" (func $msg_reply_data_append (param i32 i32)))
              (func $hi
                (call $ic0_msg_arg_data_copy (i32.const 0) (i32.const 0) (i32.const 1))
                (call $msg_reply_data_append (i32.const 0) (i32.const 1))
                (call $msg_reply))
              (data (i32.const 0) "0")
              (memory $memory 1)
              (export "memory" (memory $memory))
              (export "canister_query hi" (func $hi)))"#,
            )
                .unwrap();
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
                    (import "ic0" "call_perform" (func $ic0_call_perform (result i32)))
                    (func $hi
                      ;; heap[10] = payload[0]
                      (call $ic0_msg_arg_data_copy (i32.const 10) (i32.const 0) (i32.const 1))
                      ;; Call B
                      (i32.store
                        (i32.const 30)
                        (call $ic0_call_new
                          (i32.const 100) (i32.const {})  ;; reflector canister id
                          (i32.const 0) (i32.const 2)     ;; refers to "hi" on the heap
                          (i32.const 0) (i32.const 0)     ;; on_reply closure
                          (i32.const 0) (i32.const 0)     ;; on_reject closure
                        )
                        (call $ic0_call_data_append
                          (i32.const 10) (i32.const 1)    ;; refers to byte copied from the payload
                        )
                        (call $ic0_call_perform)
                      )
                      ;; Call B again
                      (i32.store
                        (i32.const 30)
                        (call $ic0_call_new
                          (i32.const 100) (i32.const {})  ;; reflector canister id
                          (i32.const 0) (i32.const 2)     ;; refers to "hi" on the heap
                          (i32.const 0) (i32.const 0)     ;; on_reply closure
                          (i32.const 0) (i32.const 0)     ;; on_reject closure
                        )
                        (call $ic0_call_data_append
                          (i32.const 10) (i32.const 1)    ;; refers to byte copied from the payload
                        )
                        (call $ic0_call_perform)
                      )
                    )
                    (func $on_reply (param $env i32)
                      ;; Increment that we saw a reply
                      (i32.store (i32.const 20) (i32.add (i32.const 1) (i32.load (i32.const 20))))
                      ;; if two replies seen, then reply
                      (if (i32.eq (i32.load (i32.const 20)) (i32.const 2))
                        (then
                          (call $msg_reply_data_append (i32.const 10) (i32.const 1))
                          (call $msg_reply)
                        )
                      )
                    )
                    (func $on_reject (param $env i32)
                      unreachable
                    )
                    (table funcref (elem $on_reply $on_reject))
                    (memory $memory 1)
                    (data (i32.const 0) "hi")
                    (data (i32.const 100) "{}")
                    (export "canister_query hi" (func $hi))
                    (export "memory" (memory $memory)))"#,
                canister_b.as_slice().len(),
                canister_b.as_slice().len(),
                escape_for_wat(&canister_b))).unwrap();
            let canister_a = create_and_install(&agent, &canister_a_wasm).await;
            let result = agent.query(&canister_a, "hi").with_arg(vec![5]).call().await.unwrap();
            assert_eq!(result, vec![5]);
        }
    });
}
