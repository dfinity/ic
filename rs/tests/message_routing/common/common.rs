use candid::Principal;
use canister_test::{Canister, Runtime, Wasm};
use dfn_candid::candid;
use futures::{Future, future::join_all};
use ic_management_canister_types::CanisterId;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::get_dependency_path;
use slog::info;
use std::{convert::TryFrom, env};
use xnet_test::StartArgs;

/// Concurrently calls `start` on all canisters in `canisters` with the
/// given parameters.
pub async fn start_all_canisters(
    canisters: &[Vec<Canister<'_>>],
    request_payload_size_bytes: u64,
    call_timeouts_seconds: &[Option<u32>],
    response_payload_size_bytes: u64,
    canister_to_subnet_rate: u64,
) {
    let topology: Vec<Vec<CanisterId>> = canisters
        .iter()
        .map(|x| {
            x.iter()
                .map(|y| Principal::try_from(y.canister_id_vec8()).unwrap())
                .collect()
        })
        .collect();
    let mut futures = vec![];
    for (subnet_idx, canister_idx, canister) in canisters
        .iter()
        .enumerate()
        .flat_map(|(x, v)| v.iter().enumerate().map(move |(y, v)| (x, y, v)))
    {
        let input = StartArgs {
            network_topology: topology.clone(),
            canister_to_subnet_rate,
            request_payload_size_bytes,
            call_timeouts_seconds: call_timeouts_seconds.to_vec(),
            response_payload_size_bytes,
        };
        futures.push(async move {
            let _: String = canister
                .update_("start", candid, (input,))
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "Starting canister_idx={canister_idx} on subnet_idx={subnet_idx} failed because of: {e}"
                    )
                });
        });
    }
    futures::future::join_all(futures).await;
}

/// Concurrently installs `canisters_per_subnet` instances of the XNet test canister
/// onto the subnets corresponding to the runtimes `0..subnets` in `endpoint_runtime`.
pub async fn install_canisters(
    env: TestEnv,
    endpoints_runtime: &[Runtime],
    subnets: usize,
    canisters_per_subnet: usize,
) -> Vec<Vec<Canister<'_>>> {
    let logger = env.logger();
    let wasm = Wasm::from_file(get_dependency_path(
        env::var("XNET_TEST_CANISTER_WASM_PATH").expect("XNET_TEST_CANISTER_WASM_PATH not set"),
    ));

    // Install canisters in batches to avoid running into HTTP endpoint rate limits.
    const BATCH_SIZE: usize = 40;
    let mut result = (0..subnets).map(|_| Vec::new()).collect::<Vec<_>>();
    for batch in 0.. {
        if batch * BATCH_SIZE >= canisters_per_subnet {
            break;
        }
        let mut futures: Vec<Vec<_>> = Vec::new();
        for subnet_idx in 0..subnets {
            futures.push(vec![]);
            for canister_idx in (0..canisters_per_subnet)
                .skip(batch * BATCH_SIZE)
                .take(BATCH_SIZE)
            {
                let new_wasm = wasm.clone();
                let new_logger = logger.clone();
                futures[subnet_idx].push(async move {
                    let canister = new_wasm
                        .clone()
                        .install_(&endpoints_runtime[subnet_idx], vec![])
                        .await
                        .unwrap_or_else(|e| {
                            panic!(
                                "Installation of the canister_idx={canister_idx} on subnet_idx={subnet_idx} failed with error: {e}"
                            )
                        });
                    info!(
                        new_logger,
                        "Installed canister (#{:?}) {} on subnet #{:?}",
                        canister_idx,
                        canister.canister_id(),
                        subnet_idx
                    );
                    canister
                });
            }
        }
        let batch_canisters =
            join_all(futures.into_iter().map(|x| async { join_all(x).await })).await;
        for (subnet, canisters) in batch_canisters.into_iter().enumerate() {
            result[subnet].extend(canisters);
        }
    }
    result
}

/// Concurrently executes the `call` async closure for every item in `targets`,
/// postprocessing each result with `post` and collecting them.
pub async fn parallel_async<I, F, Pre, Post, P, O>(targets: I, call: Pre, post: Post) -> O
where
    I: IntoIterator,
    F: Future,
    Pre: Fn(I::Item) -> F,
    Post: Fn(usize, F::Output) -> P,
    O: FromIterator<P>,
{
    let futures = targets.into_iter().map(call);
    join_all(futures)
        .await
        .into_iter()
        .enumerate()
        .map(|(i, res)| post(i, res))
        .collect()
}
