/* tag::catalog[]
end::catalog[] */

use ic_agent::agent::RejectCode;
use ic_system_test_driver::{
    driver::{
        test_env::TestEnv,
        test_env_api::{GetFirstHealthyNodeSnapshot, HasPublicApiUrl},
    },
    util::*,
};
use ic_types::Cycles;
use ic_universal_canister::{call_args, wasm};

pub fn can_transfer_cycles_from_a_canister_to_another(env: TestEnv) {
    let logger = env.logger();
    let nns_node = env.get_first_healthy_nns_node_snapshot();
    let agent = nns_node.build_default_agent();
    block_on({
        async move {
            // Create a canister, called "Alice", using the provisional API. Alice will
            // receive some cycles.
            let alice = UniversalCanister::new_with_cycles_with_retries(
                &agent,
                nns_node.effective_canister_id(),
                100_000_000u64,
                &logger,
            )
            .await;

            // Create a canister, called "Bob", using the provisional API. Bob will send
            // some cycles to Alice.
            let bob = UniversalCanister::new_with_retries(
                &agent,
                nns_node.effective_canister_id(),
                &logger,
            )
            .await;

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
                        call_args().other_side(wasm().accept_cycles(accept_cycles)),
                        Cycles::from(cycles_to_send),
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

pub fn trapping_with_large_blob_does_not_cause_cycles_underflow(env: TestEnv) {
    let logger = env.logger();
    let ver_app_node = env.get_first_healthy_verified_application_node_snapshot();
    let agent = ver_app_node.build_default_agent();
    let initial_balance = 123_000_000_000_000u64;
    block_on({
        async move {
            let canister = UniversalCanister::new_with_cycles_with_retries(
                &agent,
                ver_app_node.effective_canister_id(),
                initial_balance,
                &logger,
            )
            .await;

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

pub fn rejecting_with_large_blob_does_not_cause_cycles_underflow(env: TestEnv) {
    let logger = env.logger();
    let ver_app_node = env.get_first_healthy_verified_application_node_snapshot();
    let agent = ver_app_node.build_default_agent();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    let initial_balance = 123_000_000_000_000u64;
    rt.block_on({
        async move {
            let canister = UniversalCanister::new_with_cycles_with_retries(
                &agent,
                ver_app_node.effective_canister_id(),
                initial_balance,
                &logger,
            )
            .await;

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
