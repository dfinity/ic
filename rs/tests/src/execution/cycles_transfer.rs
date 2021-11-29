/* tag::catalog[]
end::catalog[] */

use crate::{types::RejectCode, util::*};
use ic_fondue::ic_manager::IcHandle;
use ic_universal_canister::{call_args, wasm};

pub fn can_transfer_cycles_from_a_canister_to_another(
    handle: IcHandle,
    ctx: &fondue::pot::Context,
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

            // Bob sends Alice some cycles and Alice accepts half of them.
            bob.update(
                wasm()
                    .call_with_cycles(
                        alice.canister_id(),
                        "update",
                        call_args().other_side(wasm().accept_cycles(cycles_to_send / 2)),
                        cycles_to_send,
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
    ctx: &fondue::pot::Context,
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
            // Bob sends Alice some cycles and Alice accepts half of them.
            let result = bob
                .update(
                    wasm()
                        .call_with_cycles(
                            alice.canister_id(),
                            "update",
                            call_args().other_side(wasm().accept_cycles(cycles_to_send / 2)),
                            cycles_to_send,
                        )
                        .reply(),
                )
                .await;
            assert_reject(result, RejectCode::CanisterError);
        }
    })
}
