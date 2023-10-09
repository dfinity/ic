/* tag::catalog[]
end::catalog[] */

use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::GetFirstHealthyNodeSnapshot;
use crate::driver::test_env_api::HasPublicApiUrl;
use crate::util::*;
use canister_test::PrincipalId;
use ic_agent::agent::RejectCode;
use ic_ic00_types::{self as ic00, EmptyBlob, Method, Payload};
use ic_types::Cycles;
use ic_universal_canister::{call_args, wasm};

pub fn test_raw_rand_api(env: TestEnv) {
    let logger = env.logger();
    let app_node = env.get_first_healthy_application_node_snapshot();
    let agent = app_node.build_default_agent();
    block_on({
        async move {
            let canister = UniversalCanister::new_with_retries(
                &agent,
                app_node.effective_canister_id(),
                &logger,
            )
            .await;

            // Calling raw_rand as a query fails.
            let result_query = canister
                .query(wasm().call_simple(
                    ic00::IC_00,
                    Method::RawRand,
                    call_args().other_side(EmptyBlob.encode()),
                ))
                .await;

            assert_reject(result_query, RejectCode::CanisterError);

            // Calling raw_rand as an update succeeds.
            canister
                .update(wasm().call_simple(
                    ic00::IC_00,
                    Method::RawRand,
                    call_args().other_side(EmptyBlob.encode()),
                ))
                .await
                .unwrap();
        }
    })
}

pub fn test_controller(env: TestEnv) {
    let nns_node = env.get_first_healthy_nns_node_snapshot();
    let agent = nns_node.build_default_agent();
    let logger = env.logger();
    block_on({
        async move {
            let canister_a = UniversalCanister::new_with_retries(
                &agent,
                nns_node.effective_canister_id(),
                &logger,
            )
            .await;
            let canister_b = UniversalCanister::new_with_retries(
                &agent,
                nns_node.effective_canister_id(),
                &logger,
            )
            .await;

            set_controller(&canister_a.canister_id(), &canister_b.canister_id(), &agent).await;

            // canister_b is the controller of the canister_a, hence we
            // expect 1 to be returned.
            assert_eq!(
                canister_a
                    .update(
                        wasm()
                            .is_controller(canister_b.canister_id().as_ref())
                            .reply_int(),
                    )
                    .await
                    .unwrap(),
                vec![1u8, 0u8, 0u8, 0u8]
            );

            // Passed Principal ID is not the controller canister_a, hence we
            // expect 0 to be returned.
            assert_eq!(
                canister_a
                    .update(
                        wasm()
                            .is_controller(PrincipalId::new_user_test_id(15).0.as_ref())
                            .reply_int(),
                    )
                    .await
                    .unwrap(),
                vec![0u8; 4]
            );

            // The passed argument is not Principal ID, hence we
            // expect is_controller to be rejected.
            assert_reject(
                canister_a
                    .update(wasm().is_controller(&[0u8; 128]).reply_int())
                    .await,
                RejectCode::CanisterError,
            );
        }
    })
}

pub fn test_cycles_burn(env: TestEnv) {
    let nns_node = env.get_first_healthy_nns_node_snapshot();
    let agent = nns_node.build_default_agent();
    let logger = env.logger();
    block_on({
        async move {
            let balance_initial = 1_000_000_000;
            let canister_a = UniversalCanister::new_with_cycles_with_retries(
                &agent,
                nns_node.effective_canister_id(),
                Cycles::new(balance_initial),
                &logger,
            )
            .await;
            let amount_to_burn = 1_000_000;
            assert_eq!(
                canister_a
                    .update(
                        wasm()
                            .cycles_burn128(Cycles::new(amount_to_burn))
                            .reply_data_append()
                            .reply()
                            .build()
                    )
                    .await
                    .unwrap(),
                amount_to_burn.to_le_bytes()
            );

            assert_eq!(
                balance_initial - amount_to_burn,
                get_balance(&canister_a.canister_id(), &agent).await
            );
        }
    })
}
