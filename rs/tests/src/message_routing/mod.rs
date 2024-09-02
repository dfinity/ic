pub mod compatibility;
pub mod global_reboot_test;
pub mod malicious_slices;
pub mod memory_safety_test;
pub mod rejoin_test;
pub mod rejoin_test_large_state;
pub mod state_sync_malicious_chunk;
pub mod xnet_slo_test;

mod common {
    use canister_test::{Canister, Runtime, Wasm};
    use chrono::Utc;
    use dfn_candid::candid;
    use futures::{future::join_all, Future};
    use slog::info;
    use std::env;
    use xnet_test::CanisterId;

    use ic_system_test_driver::driver::test_env::TestEnv;
    use ic_system_test_driver::driver::test_env_api::get_dependency_path;

    /// Concurrently calls `start` on all canisters in `canisters` with the
    /// given parameters.
    pub async fn start_all_canisters(
        canisters: &[Vec<Canister<'_>>],
        payload_size_bytes: u64,
        canister_to_subnet_rate: u64,
    ) {
        let topology: Vec<Vec<CanisterId>> = canisters
            .iter()
            .map(|x| x.iter().map(|y| y.canister_id_vec8()).collect())
            .collect();
        let mut futures = vec![];
        for (subnet_idx, canister_idx, canister) in canisters
            .iter()
            .enumerate()
            .flat_map(|(x, v)| v.iter().enumerate().map(move |(y, v)| (x, y, v)))
        {
            let input = (&topology, canister_to_subnet_rate, payload_size_bytes);
            futures.push(async move {
                let _: String = canister
                    .update_("start", candid, input)
                    .await
                    .unwrap_or_else(|_| {
                        panic!(
                            "Starting canister_idx={} on subnet_idx={}",
                            canister_idx, subnet_idx
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
    ) -> Vec<Vec<Canister>> {
        let logger = env.logger();
        let wasm = Wasm::from_file(get_dependency_path(
            env::var("XNET_TEST_CANISTER_WASM_PATH").expect("XNET_TEST_CANISTER_WASM_PATH not set"),
        ));
        let mut futures: Vec<Vec<_>> = Vec::new();
        for subnet_idx in 0..subnets {
            futures.push(vec![]);
            for canister_idx in 0..canisters_per_subnet {
                let new_wasm = wasm.clone();
                let new_logger = logger.clone();
                futures[subnet_idx].push(async move {
                    let canister = new_wasm
                        .clone()
                        .install_(&endpoints_runtime[subnet_idx], vec![])
                        .await
                        .unwrap_or_else(|_| {
                            panic!(
                                "Installation of the canister_idx={} on subnet_idx={} failed.",
                                canister_idx, subnet_idx
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
        join_all(futures.into_iter().map(|x| async { join_all(x).await })).await
    }

    pub async fn install_statesync_test_canisters(
        env: TestEnv,
        endpoint_runtime: &Runtime,
        num_canisters: usize,
    ) -> Vec<Canister> {
        let logger = env.logger();
        let wasm = Wasm::from_file(get_dependency_path(
            env::var("STATESYNC_TEST_CANISTER_WASM_PATH")
                .expect("STATESYNC_TEST_CANISTER_WASM_PATH not set"),
        ));
        let mut futures: Vec<_> = Vec::new();
        for canister_idx in 0..num_canisters {
            let new_wasm = wasm.clone();
            let new_logger = logger.clone();
            futures.push(async move {
                // Each canister is allocated with slightly more than 1GB of memory
                // and the memory will later grow by the `expand_state` calls.
                let canister = new_wasm
                    .clone()
                    .install(endpoint_runtime)
                    .with_memory_allocation(1056 * 1024 * 1024)
                    .bytes(Vec::new())
                    .await
                    .unwrap_or_else(|_| {
                        panic!("Installation of the canister_idx={} failed.", canister_idx)
                    });
                info!(
                    new_logger,
                    "Installed canister (#{:?}) {}",
                    canister_idx,
                    canister.canister_id(),
                );
                canister
            });
        }
        join_all(futures).await
    }

    pub async fn modify_canister_heap(
        logger: slog::Logger,
        canisters: Vec<Canister<'_>>,
        size_level: usize,
        num_canisters: usize,
        skip_odd_indexed_canister: bool,
        seed: usize,
    ) {
        for x in 1..=size_level {
            info!(
                logger,
                "Start modifying canisters {} times, it is now {}",
                x,
                Utc::now()
            );
            for (i, canister) in canisters.iter().enumerate() {
                if skip_odd_indexed_canister && i % 2 == 1 {
                    continue;
                }
                let seed_for_canister = i + (x - 1) * num_canisters + seed;
                // Each call will expand the memory by writing a chunk of 128 MiB.
                // There are 8 chunks in the canister, so the memory will grow by 1 GiB after 8 calls.
                let _res: Result<u8, String> = canister
                    .update_(
                        "expand_state",
                        dfn_json::json,
                        (x as u32, seed_for_canister as u32),
                    )
                    .await
                    .unwrap_or_else(|e| {
                        panic!(
                            "Calling expand_state() on canister {} failed: {}",
                            canister.canister_id_vec8()[0],
                            e
                        )
                    });
            }
            info!(
                logger,
                "Expanded canisters {} times, it is now {}",
                x,
                Utc::now()
            );
        }
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
}
