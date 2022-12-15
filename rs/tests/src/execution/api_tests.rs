/* tag::catalog[]
end::catalog[] */

use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::GetFirstHealthyNodeSnapshot;
use crate::driver::test_env_api::HasPublicApiUrl;
use crate::types::*;
use crate::util::*;
use ic_ic00_types::{self as ic00, EmptyBlob, Method, Payload};
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
