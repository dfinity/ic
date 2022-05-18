/* tag::catalog[]
end::catalog[] */

use crate::{types::RejectCode, util::*};
use ic_agent::AgentError;
use ic_fondue::ic_manager::IcHandle;
use ic_types::Cycles;
use ic_universal_canister::{call_args, wasm};

pub fn can_transfer_cycles_from_a_canister_to_another(
    handle: IcHandle,
    ctx: &ic_fondue::pot::Context,
) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let endpoint = get_random_nns_node_endpoint(&handle, &mut rng);
            endpoint.assert_ready(ctx).await;
            let agent = assert_create_agent(endpoint.url.as_str()).await;

            // Create a canister, called "Alice", using the provisional API. Alice will
            // receive some cycles.
            let alice = UniversalCanister::new_with_cycles(&agent, 100_000_000u64).await;

            // Create a canister, called "Bob", using the provisional API. Bob will send
            // some cycles to Alice.
            let bob = UniversalCanister::new(&agent).await;

            let initial_alice_balance = get_balance(&alice.canister_id(), &agent).await;
            let initial_bob_balance = get_balance(&bob.canister_id(), &agent).await;

            let cycles_to_send = 500_000_000;
            let accept_cycles = Cycles::from(cycles_to_send / 2);

            // Bob sends Alice some cycles and Alice accepts half of them.
            bob.update(
                wasm()
                    .call_with_cycles(
                        alice.canister_id(),
                        "update",
                        call_args().other_side(wasm().accept_cycles128(accept_cycles.into_parts())),
                        Cycles::from(cycles_to_send).into_parts(),
                    )
                    .reply(),
            )
            .await
            .unwrap();

            // Final cycles balance should reflect the transfer.
            let final_alice_balance = get_balance(&alice.canister_id(), &agent).await;
            let final_bob_balance = get_balance(&bob.canister_id(), &agent).await;

            assert_eq!(
                final_alice_balance,
                initial_alice_balance + cycles_to_send / 2
            );
            assert_eq!(final_bob_balance, initial_bob_balance - cycles_to_send / 2);
        }
    })
}

pub fn cannot_send_cycles_from_application_to_verified_subnets(
    handle: IcHandle,
    ctx: &ic_fondue::pot::Context,
) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let verified_endpoint = get_random_verified_app_node_endpoint(&handle, &mut rng);
            verified_endpoint.assert_ready(ctx).await;
            let verified_agent = assert_create_agent(verified_endpoint.url.as_str()).await;
            let application_endpoint = get_random_application_node_endpoint(&handle, &mut rng);
            application_endpoint.assert_ready(ctx).await;
            let application_agent = assert_create_agent(application_endpoint.url.as_str()).await;

            // Create a canister, called "Bob", using the provisional API. Bob will send
            // some cycles to Alice.
            let bob = UniversalCanister::new(&application_agent).await;

            // Create a canister, called "Alice", using the provisional API. Alice will
            // receive some cycles.
            let alice = UniversalCanister::new(&verified_agent).await;

            let cycles_to_send = 500_000_000;
            let accept_cycles = Cycles::from(cycles_to_send / 2);
            // Bob sends Alice some cycles and Alice accepts half of them.
            let result = bob
                .update(
                    wasm().call_with_cycles(
                        alice.canister_id(),
                        "update",
                        call_args()
                            .other_side(wasm().accept_cycles128(accept_cycles.into_parts()))
                            .on_reject(wasm().reject_message().reject()),
                        Cycles::from(cycles_to_send).into_parts(),
                    ),
                )
                .await;
            assert_eq!(result.unwrap_err(), AgentError::ReplicaError {
                reject_code: RejectCode::CanisterReject as u64,
                reject_message: format!("Canister {} violated contract: Canisters on Application subnets cannot send cycles to canister {} on a Verified Application subnet", bob.canister_id(), alice.canister_id())
            });
        }
    })
}

pub fn trapping_with_large_blob_does_not_cause_cycles_underflow(
    handle: IcHandle,
    ctx: &ic_fondue::pot::Context,
) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    let initial_balance = 123_000_000_000_000u64;
    rt.block_on({
        async move {
            let endpoint = get_random_verified_app_node_endpoint(&handle, &mut rng);
            endpoint.assert_ready(ctx).await;

            let agent = assert_create_agent(endpoint.url.as_str()).await;
            let canister = UniversalCanister::new_with_cycles(&agent, initial_balance).await;

            assert_reject(
                canister
                    .update(wasm().inter_update(
                        canister.canister_id(),
                        // Trap with a large blob.
                        call_args().other_side(wasm().trap_with_blob(&[0; 1024 * 1024 * 3])),
                    ))
                    .await,
                RejectCode::CanisterReject,
            );

            // Assert that the balance did not underflow.
            assert!(get_balance(&canister.canister_id(), &agent).await <= initial_balance as u128);
        }
    });
}

pub fn rejecting_with_large_blob_does_not_cause_cycles_underflow(
    handle: IcHandle,
    ctx: &ic_fondue::pot::Context,
) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    let initial_balance = 123_000_000_000_000u64;
    rt.block_on({
        async move {
            let endpoint = get_random_verified_app_node_endpoint(&handle, &mut rng);
            endpoint.assert_ready(ctx).await;

            let agent = assert_create_agent(endpoint.url.as_str()).await;
            let canister = UniversalCanister::new_with_cycles(&agent, initial_balance).await;

            assert_reject(
                canister
                    .update(wasm().inter_update(
                        canister.canister_id(),
                        call_args().other_side(wasm().push_bytes(&[0; 1024 * 1024 * 2]).reject()),
                    ))
                    .await,
                RejectCode::CanisterReject,
            );

            // Assert that the balance did not underflow.
            assert!(get_balance(&canister.canister_id(), &agent).await <= initial_balance as u128);
        }
    });
}
