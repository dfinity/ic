/* tag::catalog[]
end::catalog[] */

use crate::driver::pot_dsl::get_ic_handle_and_ctx;
use crate::driver::test_env::TestEnv;
use crate::types::*;
use crate::util::*;
use ic_ic00_types::{self as ic00, EmptyBlob, Method, Payload};
use ic_universal_canister::{call_args, wasm};

pub fn test_raw_rand_api(env: TestEnv) {
    let logger = env.logger();
    let (handle, ref ctx) = get_ic_handle_and_ctx(env);
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let endpoint = get_random_application_node_endpoint(&handle, &mut rng);
            endpoint.assert_ready(ctx).await;
            let agent = assert_create_agent(endpoint.url.as_str()).await;
            let canister = UniversalCanister::new_with_retries(
                &agent,
                endpoint.effective_canister_id(),
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
