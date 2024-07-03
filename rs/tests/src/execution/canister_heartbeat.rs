/* tag::catalog[]
end::catalog[] */

use std::time::{Duration, Instant};

use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{GetFirstHealthyNodeSnapshot, HasPublicApiUrl};
use ic_system_test_driver::util::{self, block_on};
use ic_universal_canister::UNIVERSAL_CANISTER_WASM;
use ic_universal_canister::{call_args, wasm};
use ic_utils::call::AsyncCall;
use ic_utils::interfaces::ManagementCanister;

const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(40);

pub fn canister_heartbeat_is_called_at_regular_intervals(env: TestEnv) {
    let logger = env.logger();
    let nns_node = env.get_first_healthy_nns_node_snapshot();
    let app_node = env.get_first_healthy_application_node_snapshot();
    let agent_nns = nns_node.build_default_agent();
    let agent_app = app_node.build_default_agent();
    block_on({
        async move {
            let canister_on_nns = util::UniversalCanister::new_with_retries(
                &agent_nns,
                nns_node.effective_canister_id(),
                &logger,
            )
            .await;

            let canister_on_app = util::UniversalCanister::new_with_retries(
                &agent_app,
                app_node.effective_canister_id(),
                &logger,
            )
            .await;

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

pub fn stopping_a_canister_with_a_heartbeat_succeeds(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();
    let agent = node.build_default_agent();
    block_on({
        async move {
            // Create and then stop the canister.
            // NOTE: The universal canister exposes a heartbeat.
            let canister = util::UniversalCanister::new_with_retries(
                &agent,
                node.effective_canister_id(),
                &logger,
            )
            .await;
            let mgr = ManagementCanister::create(&agent);
            mgr.stop_canister(&canister.canister_id())
                .call_and_wait()
                .await
                .expect("Couldn't stop canister");
        }
    });
}

pub fn canister_heartbeat_can_call_another_canister(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();
    let agent = node.build_default_agent();
    block_on({
        async move {
            let canister_a = util::UniversalCanister::new_with_retries(
                &agent,
                node.effective_canister_id(),
                &logger,
            )
            .await;
            let canister_b = util::UniversalCanister::new_with_retries(
                &agent,
                node.effective_canister_id(),
                &logger,
            )
            .await;

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

pub fn canister_heartbeat_can_call_multiple_canisters_xnet(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();
    let app_node = env.get_first_healthy_application_node_snapshot();
    let agent = node.build_default_agent();
    let agent_app = app_node.build_default_agent();
    block_on({
        async move {
            // Canisters are installed across different subnets to test xnet.
            let canister_a = util::UniversalCanister::new_with_retries(
                &agent,
                node.effective_canister_id(),
                &logger,
            )
            .await;
            let canister_b = util::UniversalCanister::new_with_retries(
                &agent_app,
                app_node.effective_canister_id(),
                &logger,
            )
            .await;
            let canister_c = util::UniversalCanister::new_with_retries(
                &agent_app,
                app_node.effective_canister_id(),
                &logger,
            )
            .await;

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

pub fn canister_heartbeat_cannot_reply(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();
    let agent = node.build_default_agent();
    block_on({
        async move {
            let canister = util::UniversalCanister::new_with_retries(
                &agent,
                node.effective_canister_id(),
                &logger,
            )
            .await;

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
pub fn canister_heartbeat_can_stop(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();
    let agent = node.build_default_agent();
    block_on({
        async move {
            let mgr = ManagementCanister::create(&agent);

            let canister_a = util::UniversalCanister::new_with_retries(
                &agent,
                node.effective_canister_id(),
                &logger,
            )
            .await;
            let canister_c = mgr
                .create_canister()
                .as_provisional_create_with_amount(None)
                .with_effective_canister_id(node.effective_canister_id())
                .call_and_wait()
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
                .call_and_wait()
                .await
                .unwrap();

            std::thread::sleep(std::time::Duration::from_secs(10));
            // Try stopping canister A
            eprintln!("Trying to stop the canister");
            mgr.stop_canister(&canister_a.canister_id())
                .call_and_wait()
                .await
                .expect("Couldn't stop canister");
        }
    });
}
