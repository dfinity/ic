/* tag::catalog[]
Title:: Stress test for the http_requests feature

Goal:: Measure the qps of http_requests originating from one canister. The test should be run with the following command:
```
ict test //rs/tests/networking:canister_http_stress_test -- --test_tmpdir=./canister_http_stress_test
```

Runbook::
0. Instantiate a universal VM with a webserver
1. Instantiate a Prometheus VM to track the evolving qps in grafana
2. Instantiate an IC with two application subnets (containing 13, 28 and 40 nodes respectively), both with the HTTP feature enabled.
3. Apply prod network settings to the 13 and 28 node subnets (packet drop rate, rount trip time, etc)
4. Install NNS canisters
5. Install the proxy canister on all 3 application subnets
6. Make a few update calls to the proxy canisters, one update call for each concurrency level.
7. For each update call, the canister tries to send multiple (up to 500) concurrent http requests to the webserver, and measures the observed time the requests took.

Success::
1. All http responses with status 200.
2. The results are written to a json file (in benchmark/benchmark.json).

end::catalog[] */
#![allow(deprecated)]

use std::time::Duration;

use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use canister_http::*;
use canister_test::Canister;
use dfn_candid::candid_one;
use ic_cdk::api::call::RejectionCode;
use ic_management_canister_types_private::{HttpMethod, TransformContext, TransformFunc};
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::test_env_api::IcNodeContainer;
use ic_system_test_driver::driver::{
    test_env::TestEnv,
    test_env_api::{READY_WAIT_TIMEOUT, RETRY_BACKOFF},
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::block_on;
use ic_types::Cycles;
use proxy_canister::UnvalidatedCanisterHttpRequestArgs;
use proxy_canister::{RemoteHttpRequest, RemoteHttpStressRequest, RemoteHttpStressResponse};
use serde::{Deserialize, Serialize};
use slog::{Logger, info};

const BENCHMARK_REPORT_FILE: &str = "benchmark/benchmark.json";
const WITH_WARM_UP: bool = true;

#[derive(Serialize, Deserialize, Debug)]
struct BenchmarkResult {
    subnet_size: usize,
    concurrent_requests: u64,
    qps: f64,
    average_latency_s: f64,
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(stress_setup)
        .add_test(systest!(test))
        // This test takes consistently around 20 mintues, so setting 30 minutes to be safe.
        .with_timeout_per_test(Duration::from_secs(30 * 60))
        .execute_from_args()?;

    Ok(())
}

pub fn test(env: TestEnv) {
    let logger = env.logger();
    let mut all_results: Vec<BenchmarkResult> = vec![];

    let app_subnets = get_all_application_subnets(&env);

    for (i, subnet_snapshot) in app_subnets.into_iter().enumerate() {
        // For each application subnet, we run the stress test.
        let subnet_size = subnet_snapshot.nodes().count();
        info!(
            logger,
            "=== Running stress test on Application subnet #{} which has {} nodes ===",
            i,
            subnet_size
        );

        let node = subnet_snapshot
            .nodes()
            .next()
            .expect("there is no node in this application subnet");

        let runtime = get_runtime_from_node(&node);
        // Each requests costs ~6-7 billion cycles, and we make many thousands of requests.
        // The default 100T cycles may not be enough.
        let proxy_canister =
            create_proxy_canister_with_cycles(&env, &runtime, &node, Cycles::new(u128::MAX));

        let webserver_ipv6 = get_universal_vm_address(&env);

        block_on(async {
            let url = format!("https://[{webserver_ipv6}]");

            if WITH_WARM_UP {
                // Make an http_outcall once, to establish the session between the adapter and the target server.
                // This is necessary in order to avoid the server potentially being overloaded by 40 * 500 TCP/TLS handshake requests.
                test_proxy_canister(&proxy_canister, url.clone(), logger.clone(), 1).await;
            }

            for concurrent_requests in CONCURRENCY_LEVELS {
                println!(
                    "debuggg testing {} nodes, with concurrency {} at time {}",
                    subnet_size,
                    concurrent_requests,
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                );
                // For each concurrency level in this subnet, we run the stress test.
                let (qps, duration) = test_proxy_canister(
                    &proxy_canister,
                    url.clone(),
                    logger.clone(),
                    concurrent_requests,
                )
                .await;
                all_results.push(BenchmarkResult {
                    subnet_size,
                    concurrent_requests,
                    qps,
                    average_latency_s: duration.as_secs_f64(),
                });
            }
        });
    }
    let base_dir = env.base_path();
    let json_file = base_dir.join(BENCHMARK_REPORT_FILE);
    std::fs::create_dir_all(json_file.parent().unwrap()).unwrap();

    let json_str = serde_json::to_string_pretty(&all_results).unwrap();
    std::fs::write(&json_file, json_str).unwrap();

    info!(
        logger,
        "All benchmark results have been written to {:?}", json_file
    );
}

async fn do_request(
    proxy_canister: &Canister<'_>,
    url: String,
    logger: &Logger,
    concurrent_requests: u64,
) -> Result<Duration, anyhow::Error> {
    let context = "There is context to be appended in body";
    let res = proxy_canister
        .update_(
            "send_requests_in_parallel",
            candid_one::<
                Result<RemoteHttpStressResponse, (RejectionCode, String)>,
                RemoteHttpStressRequest,
            >,
            RemoteHttpStressRequest {
                request: RemoteHttpRequest {
                    request: UnvalidatedCanisterHttpRequestArgs {
                        url,
                        headers: vec![],
                        body: None,
                        transform: Some(TransformContext {
                            function: TransformFunc(candid::Func {
                                principal: proxy_canister.canister_id().get().0,
                                method: "transform_with_context".to_string(),
                            }),
                            context: context.as_bytes().to_vec(),
                        }),
                        method: HttpMethod::GET,
                        max_response_bytes: None,
                        is_replicated: None,
                        pricing_version: None,
                    },
                    cycles: 500_000_000_000,
                },
                count: concurrent_requests,
            },
        )
        .await
        .map_err(|e| anyhow!("Update call to proxy canister failed with {:?}", e))?;

    match res {
        Ok(ref x) if x.response.status == 200 && x.response.body.contains(context) => {
            info!(
                logger,
                "All {} concurrent requests succeeded!", concurrent_requests
            );
            Ok(x.duration)
        }
        _ => {
            bail!("Http request failed response: {:?}", res);
        }
    }
}

// Returns the average qps and average latency of a single request.
pub async fn test_proxy_canister(
    proxy_canister: &Canister<'_>,
    url: String,
    logger: Logger,
    concurrent_requests: u64,
) -> (f64, Duration) {
    let mut experiments = 0;
    let mut total_duration = Duration::from_secs(0);

    // We don't leave the experiment running for much longer than 60 seconds.
    while total_duration < Duration::from_secs(60) {
        experiments += 1;

        let single_call_duration = ic_system_test_driver::retry_with_msg_async!(
            format!(
                "calling send_requests_in_parallel of proxy canister {} with URL {}",
                proxy_canister.canister_id(),
                url
            ),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                do_request(proxy_canister, url.clone(), &logger, concurrent_requests).await
            }
        )
        .await
        .expect("Timeout or repeated failure on canister HTTP calls");

        total_duration += single_call_duration;
    }

    let elapsed_seconds = total_duration.as_secs_f64();
    let qps = (concurrent_requests * experiments) as f64 / elapsed_seconds;
    info!(
        logger,
        "Average qps for {} concurrent request(s) and {} experiment(s) is {}",
        concurrent_requests,
        experiments,
        qps
    );
    (qps, total_duration / experiments as u32)
}
