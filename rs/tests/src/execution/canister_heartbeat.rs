/* tag::catalog[]
end::catalog[] */

use std::time::{Duration, Instant};

use crate::util;
use ic_fondue::ic_manager::IcHandle;
use ic_universal_canister::UNIVERSAL_CANISTER_WASM;
use ic_universal_canister::{call_args, wasm};
use ic_utils::call::AsyncCall;
use ic_utils::interfaces::ManagementCanister;

const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(40);

pub fn canister_heartbeat_is_called_at_regular_intervals(
    handle: IcHandle,
    ctx: &fondue::pot::Context,
) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let nns_endpoint = util::get_random_nns_node_endpoint(&handle, &mut rng);
            nns_endpoint.assert_ready(ctx).await;
            let agent_nns = util::assert_create_agent(nns_endpoint.url.as_str()).await;
            let canister_on_nns = util::UniversalCanister::new(&agent_nns).await;

            let app_endpoint = util::get_random_application_node_endpoint(&handle, &mut rng);
            app_endpoint.assert_ready(ctx).await;
            let agent_app = util::assert_create_agent(app_endpoint.url.as_str()).await;
            let canister_on_app = util::UniversalCanister::new(&agent_app).await;

            // Set the heartbeat of the canister to store a character in memory.
            canister_on_nns
                .update(wasm().set_heartbeat(wasm().stable_write(0, b"x")).reply())
                .await
                .unwrap();
            canister_on_app
                .update(wasm().set_heartbeat(wasm().stable_write(0, b"x")).reply())
                .await
                .unwrap();

            // Wait a few seconds. In that time, the heartbeat should've been invoked
            // and the memory should've been updated.
            // TODO(EXC-155): Expose a way to tell if canister_heartbeat has executed.
            let start = Instant::now();
            while start.elapsed() < HEARTBEAT_TIMEOUT {
                if canister_on_nns.try_read_stable(0, 1).await[0] != 0
                    && canister_on_app.try_read_stable(0, 1).await[0] != 0
                {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs(1));
            }

            assert_eq!(canister_on_nns.try_read_stable(0, 1).await, b"x");
            assert_eq!(canister_on_app.try_read_stable(0, 1).await, b"x");
        }
    });
}

pub fn stopping_a_canister_with_a_heartbeat_succeeds(handle: IcHandle, ctx: &fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let endpoint = util::get_random_node_endpoint(&handle, &mut rng);
            endpoint.assert_ready(ctx).await;
            let agent = util::assert_create_agent(endpoint.url.as_str()).await;

            // Create and then stop the canister.
            // NOTE: The universal canister exposes a heartbeat.
            let canister = util::UniversalCanister::new(&agent).await;
            let mgr = ManagementCanister::create(&agent);
            mgr.stop_canister(&canister.canister_id())
                .call_and_wait(util::delay())
                .await
                .expect("Couldn't stop canister");
        }
    });
}

pub fn canister_heartbeat_can_call_another_canister(handle: IcHandle, ctx: &fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let endpoint = util::get_random_node_endpoint(&handle, &mut rng);
            endpoint.assert_ready(ctx).await;
            let agent = util::assert_create_agent(endpoint.url.as_str()).await;

            let canister_a = util::UniversalCanister::new(&agent).await;
            let canister_b = util::UniversalCanister::new(&agent).await;

            // Set the heartbeat of canister A to call canister B and store a character in
            // canister B's memory.
            canister_a
                .update(
                    wasm()
                        .set_heartbeat(
                            wasm().inter_update(
                                canister_b.canister_id(),
                                call_args()
                                    .other_side(wasm().stable_write(0, b"x").reply())
                                    // Do nothing after response from B is received.
                                    .on_reply(wasm().noop()),
                            ),
                        )
                        .reply(),
                )
                .await
                .unwrap();

            // Wait a few seconds. In that time, the heartbeat should've been invoked
            // and the memory should've been updated.
            // TODO(EXC-155): Expose a way to tell if canister_heartbeat has executed.
            let start = Instant::now();
            while start.elapsed() < HEARTBEAT_TIMEOUT {
                if canister_b.try_read_stable(0, 1).await[0] != 0 {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
            assert_eq!(canister_b.try_read_stable(0, 1).await, b"x");
        }
    });
}

pub fn canister_heartbeat_can_call_multiple_canisters_xnet(
    handle: IcHandle,
    ctx: &fondue::pot::Context,
) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let endpoint_nns = util::get_random_node_endpoint(&handle, &mut rng);
            endpoint_nns.assert_ready(ctx).await;
            let agent_nns = util::assert_create_agent(endpoint_nns.url.as_str()).await;

            let endpoint_application =
                util::get_random_application_node_endpoint(&handle, &mut rng);
            endpoint_application.assert_ready(ctx).await;
            let agent_application =
                util::assert_create_agent(endpoint_application.url.as_str()).await;

            // Canisters are installed across different subnets to test xnet.
            let canister_a = util::UniversalCanister::new(&agent_nns).await;
            let canister_b = util::UniversalCanister::new(&agent_application).await;
            let canister_c = util::UniversalCanister::new(&agent_application).await;

            canister_a
                .update(
                    wasm()
                        .set_heartbeat(
                            wasm().inter_update(
                                // Send a request to update the memory of canister B
                                canister_b.canister_id(),
                                call_args()
                                    .other_side(wasm().stable_write(0, b"x").reply())
                                    .on_reply(
                                        // Once B responds, send a request to update the memory of
                                        // canister C
                                        wasm().inter_update(
                                            canister_c.canister_id(),
                                            call_args()
                                                .other_side(wasm().stable_write(0, b"y").reply())
                                                // A does nothing after the response from C is
                                                // received.
                                                .on_reply(wasm().noop()),
                                        ),
                                    ),
                            ),
                        )
                        .reply(),
                )
                .await
                .unwrap();

            // Wait a few seconds. In that time, the heartbeat should've been invoked
            // and the memory should've been updated.
            // TODO(EXC-155): Expose a way to tell if canister_heartbeat has executed.
            // We double the timeout because we have two chained calls:
            // Canister A calls canister B which calls canister C.
            let start = Instant::now();
            while start.elapsed() < HEARTBEAT_TIMEOUT * 2 {
                if canister_b.try_read_stable(0, 1).await[0] != 0
                    && canister_c.try_read_stable(0, 1).await[0] != 0
                {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs(1));
            }

            assert_eq!(canister_a.try_read_stable(0, 1).await[0], 0);
            assert_eq!(canister_b.try_read_stable(0, 1).await, b"x");
            assert_eq!(canister_c.try_read_stable(0, 1).await, b"y");
        }
    });
}

pub fn canister_heartbeat_cannot_reply(handle: IcHandle, ctx: &fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let endpoint = util::get_random_node_endpoint(&handle, &mut rng);
            endpoint.assert_ready(ctx).await;
            let agent = util::assert_create_agent(endpoint.url.as_str()).await;
            let canister = util::UniversalCanister::new(&agent).await;

            // Set the heartbeat of the canister to store something in its memory then
            // reply.
            canister
                .update(
                    wasm()
                        .set_heartbeat(wasm().stable_write(0, b"x").reply())
                        .reply(),
                )
                .await
                .unwrap();

            // Wait a few seconds for the heartbeat to be invoked.
            // The heartbeat should've trapped and the memory is not written to.
            std::thread::sleep(HEARTBEAT_TIMEOUT);

            assert_eq!(canister.try_read_stable(0, 1).await[0], 0);
        }
    });
}

/// Creates canister C without a wasm module. Canister A keeps sending requests
/// to canister C from its heartbeat execution. While A is sending C messages, a
/// wasm module is installed on C.  We try to stop A and it should stop.
pub fn canister_heartbeat_can_stop(handle: IcHandle, ctx: &fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let endpoint = util::get_random_node_endpoint(&handle, &mut rng);
            endpoint.assert_ready(ctx).await;
            let agent = util::assert_create_agent(endpoint.url.as_str()).await;

            let mgr = ManagementCanister::create(&agent);

            let canister_a = util::UniversalCanister::new(&agent).await;
            let canister_c = mgr
                .create_canister()
                .as_provisional_create_with_amount(None)
                .call_and_wait(util::delay())
                .await
                .unwrap()
                .0;

            // Send a request to C, C doesn't exist.
            canister_a
                .update(
                    wasm()
                        .set_heartbeat(
                            wasm().debug_print(b"calling heartbeat").inter_update(
                                canister_c,
                                call_args()
                                    .other_side(wasm().trap())
                                    .on_reply(wasm().noop()),
                            ),
                        )
                        .reply(),
                )
                .await
                .unwrap();

            // Wait a few seconds for the heartbeat to be invoked.
            std::thread::sleep(std::time::Duration::from_secs(10));
            eprintln!("installing canister");
            // Install the universal canister.
            mgr.install_code(&canister_c, UNIVERSAL_CANISTER_WASM)
                .with_raw_arg(vec![])
                .call_and_wait(util::delay())
                .await
                .unwrap();

            std::thread::sleep(std::time::Duration::from_secs(10));
            // Try stopping canister A
            eprintln!("Trying to stop the canister");
            mgr.stop_canister(&canister_a.canister_id())
                .call_and_wait(util::delay())
                .await
                .expect("Couldn't stop canister");
        }
    });
}
