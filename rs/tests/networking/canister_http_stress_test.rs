/* tag::catalog[]
Title:: Stress test for the http_requests feature

Goal:: Measure the qps of http_requests originating from one canister. The test shuold be run with the following command:
```
ict ict testnet create canister_http_stress_test --lifetime-mins=180 --output-dir=./canister_http_stress_test -- --test_tmpdir=./canister_http_stress_test
```

Runbook::
0. Instantiate a universal VM with a webserver
1. Instantiate a Prometheus VM to track the evolving qps in grafana
2. Instantiate an IC with two application subnets (containing 13 and 40 ndoes respectively), both with the HTTP feature enabled.
3. Install NNS canisters
4. Install the proxy canister on both application subnets
5. Make a few update calls to the proxy canisters, on update call for each concurrency level.
6. For each update call, the canister tries to send multiple (up to 500) concurrent http requests to the webserver, and measures the observed time the requests took.

Success::
1. All http responses with status 200.
2. The proxy canister is left sending requests in batches of 500 to track the qps in grafana.
3. The results are written to a json file (in benchmark/benchmark.json).

end::catalog[] */

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Result;
use canister_http::*;
use canister_test::Canister;
use dfn_candid::candid_one;
use ic_cdk::api::call::RejectionCode;
use ic_management_canister_types_private::{HttpMethod, TransformContext, TransformFunc};
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::boundary_node::BoundaryNode;
use ic_system_test_driver::driver::boundary_node::BoundaryNodeVm;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::prometheus_vm::HasPrometheus;
use ic_system_test_driver::driver::prometheus_vm::PrometheusVm;
use ic_system_test_driver::driver::test_env_api::{
    get_dependency_path, HasPublicApiUrl, IcNodeContainer,
};
use ic_system_test_driver::driver::universal_vm::UniversalVm;
use ic_system_test_driver::driver::{
    test_env::TestEnv,
    test_env_api::{READY_WAIT_TIMEOUT, RETRY_BACKOFF},
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::block_on;
use ic_types::Cycles;
use proxy_canister::RemoteHttpResponse;
use proxy_canister::UnvalidatedCanisterHttpRequestArgs;
use proxy_canister::{RemoteHttpRequest, RemoteHttpStressRequest, RemoteHttpStressResponse};
use serde::{Deserialize, Serialize};
use slog::{info, Logger};

const NS_IN_1_MS: u64 = 1_000_000;
const MS_IN_1_SEC: u64 = 1_000;
const NS_IN_1_SEC: u64 = NS_IN_1_MS * MS_IN_1_SEC;
const BN_NAME: &str = "bn-1";
const BENCHMARK_REPORT_FILE: &str = "benchmark/benchmark.json";
const APP_SUBNET_SIZES: [usize; 2] = [13, 40];
const CONCURRENCY_LEVELS: [u64; 3] = [200, 500, 1000];

#[derive(Serialize, Deserialize, Debug)]
struct BenchmarkResult {
    subnet_size: usize,
    concurrent_requests: u64,
    qps: f64,
    average_latency_s: f64,
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;

    Ok(())
}

pub fn setup(env: TestEnv) {
    let logger = env.logger();
    PrometheusVm::default()
        .start(&env)
        .expect("Failed to start prometheus VM");

    UniversalVm::new(String::from(UNIVERSAL_VM_NAME))
        .with_config_img(get_dependency_path(
            "rs/tests/networking/canister_http/http_uvm_config_image.zst",
        ))
        .start(&env)
        .expect("failed to set up universal VM");

    start_httpbin_on_uvm(&env);
    info!(&logger, "Started Universal VM!");

    let bn_vm = BoundaryNode::new(BN_NAME.to_string())
        .allocate_vm(&env)
        .unwrap();
    let bn_ipv6 = bn_vm.ipv6();

    info!(&logger, "Created raw BN with IP {}!", bn_ipv6);

    let mut ic = InternetComputer::new()
        .with_socks_proxy(format!("socks5://[{bn_ipv6}]:1080"))
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_features(SubnetFeatures {
                    http_requests: true,
                    ..SubnetFeatures::default()
                })
                .add_nodes(1),
        );
    for subnet_size in APP_SUBNET_SIZES.iter() {
        ic = ic.add_subnet(
            Subnet::new(SubnetType::Application)
                .with_features(SubnetFeatures {
                    http_requests: true,
                    ..SubnetFeatures::default()
                })
                .add_nodes(*subnet_size),
        );
    }
    ic.with_api_boundary_nodes(1)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    await_nodes_healthy(&env);
    install_nns_canisters(&env);

    bn_vm
        .for_ic(&env, "")
        .start(&env)
        .expect("failed to setup BoundaryNode VM");

    env.sync_with_prometheus_by_name("", env.get_playnet_url(BN_NAME));

    let boundary_node_vm = env
        .get_deployed_boundary_node(BN_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();

    boundary_node_vm
        .await_status_is_healthy()
        .expect("Boundary node did not come up healthy.");
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
            let url = format!("https://[{webserver_ipv6}]:20443");

            // Make an http_outcall once, to establish the session between the adapter and the target server.
            // This is necessary in order to avoid the server potentially being overloaded by 40 * 500 TCP/TLS handshake requests.
            test_proxy_canister(&proxy_canister, url.clone(), logger.clone(), 1).await;
            for concurrent_requests in CONCURRENCY_LEVELS.iter() {
                // For each concurrency level in this subnet, we run the stress test.
                let (qps, duration_s) = test_proxy_canister(
                    &proxy_canister,
                    url.clone(),
                    logger.clone(),
                    *concurrent_requests,
                )
                .await;
                all_results.push(BenchmarkResult {
                    subnet_size,
                    concurrent_requests: *concurrent_requests,
                    qps,
                    average_latency_s: duration_s,
                });
            }
            leave_proxy_canister_running(&proxy_canister, url.clone(), logger.clone()).await;
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

async fn leave_proxy_canister_running(proxy_canister: &Canister<'_>, url: String, logger: Logger) {
    ic_system_test_driver::retry_with_msg_async!(
        format!(
            "calling start_continuous_requests of proxy canister {} with URL {}",
            proxy_canister.canister_id(),
            url
        ),
        &logger,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            let context = "There is context to be appended in body";
            let res = proxy_canister
                .update_(
                    "start_continuous_requests",
                    candid_one::<
                        Result<RemoteHttpResponse, (RejectionCode, String)>,
                        RemoteHttpRequest,
                    >,
                    RemoteHttpRequest {
                        request: UnvalidatedCanisterHttpRequestArgs {
                            url: url.to_string(),
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
                        },
                        cycles: 500_000_000_000,
                    },
                )
                .await
                .expect("Update call to proxy canister failed");
            if !matches!(res, Ok(ref x) if x.status == 200) {
                bail!("Http request failed response: {:?}", res);
            }
            info!(&logger, "Update call succeeded! {:?}", res);
            Ok(())
        }
    )
    .await
    .expect("Timeout on doing a canister http call to the webserver");
}

async fn do_request(
    proxy_canister: &Canister<'_>,
    url: String,
    logger: &Logger,
    concurrent_requests: u64,
) -> Result<u64, anyhow::Error> {
    let proxy_canister = proxy_canister.clone();
    let url = url.clone();

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
                        url: url.clone(),
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
                    },
                    cycles: 500_000_000_000,
                },
                count: concurrent_requests,
            },
        )
        .await
        .map_err(|e| anyhow!("Update call to proxy canister failed with {:?}", e))?;

    if !matches!(res, Ok(ref x) if x.response.status == 200 && x.response.body.contains(context)) {
        bail!("Http request failed response: {:?}", res);
    }
    let res = res.unwrap();
    info!(
        logger,
        "All {} concurrent requests succeeded!", concurrent_requests
    );

    let duration_ns = res.duration_ns;
    Ok(duration_ns)
}

// Returns the average qps and average latency of a single request.
pub async fn test_proxy_canister(
    proxy_canister: &Canister<'_>,
    url: String,
    logger: Logger,
    concurrent_requests: u64,
) -> (f64, f64) {
    let mut experiments = 0;
    let max_experiments = 3;
    let mut total_duration_ns = 0;

    // We don't leave the experiment running for much longer than 60 seconds.
    while total_duration_ns < 60 * NS_IN_1_SEC && experiments < max_experiments {
        experiments += 1;

        let single_call_duration_ns = ic_system_test_driver::retry_with_msg_async!(
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

        total_duration_ns += single_call_duration_ns;
    }

    let elapsed_seconds = total_duration_ns as f64 / NS_IN_1_SEC as f64;
    let qps = (concurrent_requests * experiments) as f64 / elapsed_seconds;
    info!(
        logger,
        "Average qps for {} concurrent request(s) and {} experiment(s) is {}",
        concurrent_requests,
        experiments,
        qps
    );
    (qps, elapsed_seconds / experiments as f64)
}
