/* tag::catalog[]
Title:: Soak test for the http_requests feature

Goal:: Measure the evolving qps of http_requests originating from one canister. The test should be run with the following command:
```
ict testnet create //rs/tests/networking:canister_http_soak_test --lifetime-mins=180 --output-dir=./canister_http_soak_test -- --test_tmpdir=./canister_http_soak_test
```

Runbook::
0. Same setup as canister_http_stress_test.rs. In short, 3 subnets (13, 28, 40 nodes each) setup, the proxy canister installed on each
1. The proxy canister has a special update_ method which leaves it sending requests in batches of 500.
2. The evolving qps can be seen in the adapter's metrics in grafana.

Success::
1. The proxy canister is left sending requests in batches of 500 to track the qps in grafana.

end::catalog[] */
#![allow(deprecated)]

use std::time::Duration;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Result;
use canister_http::*;
use canister_test::Canister;
use dfn_candid::candid_one;
use futures::future::join_all;
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
use proxy_canister::RemoteHttpRequest;
use proxy_canister::RemoteHttpResponse;
use proxy_canister::RemoteHttpStressResponse;
use proxy_canister::RemoteHttpStressRequest;
use proxy_canister::UnvalidatedCanisterHttpRequestArgs; 
use serde::{Deserialize, Serialize};
use slog::{info, Logger};

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
        .execute_from_args()?;

    Ok(())
}

pub fn test(env: TestEnv) {
    let logger = env.logger();

    let app_subnets = get_all_application_subnets(&env);

    for subnet_snapshot in app_subnets {
        // For each application subnet, we run the soak test.

        let node = subnet_snapshot
            .nodes()
            .next()
            .expect("there is no node in this application subnet");

        let runtime = get_runtime_from_node(&node);

        let canisters: Vec<_> = (0..0)  
            .map(|i| {
                let canister_name = format!("canister-{}", i);
                create_proxy_canister_with_name_and_cycles(
                    &env,
                    &runtime,
                    &node,
                    &canister_name,
                    Cycles::new(u128::MAX),
                )
            })
            .collect();

        let honest_canister = create_proxy_canister_with_name_and_cycles(&env, &runtime, &node, "honest-canister", Cycles::new(u128::MAX));

        let webserver_ipv6 = get_universal_vm_address(&env);

        block_on(async {
            let url = format!("https://[{webserver_ipv6}]:20443");

            for proxy_canister in &canisters {
                leave_proxy_canister_running(proxy_canister, url.clone(), logger.clone(), "start_continuous_requests").await;
            }
            return;
            for i in 0..10 {
                println!("Request {} of 10", i + 1);
                let response = do_request(&honest_canister, url.clone(), &logger, 1)
                    .await
                    .unwrap_or(Duration::from_secs(60));
                println!(
                    "Average latency for 1 concurrent request: {:?}",
                    response
                );
            }
        });
    }
}

async fn leave_proxy_canister_running(proxy_canister: &Canister<'_>, url: String, logger: Logger, method: &str) {
    ic_system_test_driver::retry_with_msg_async!(
        format!(
            "calling {} of proxy canister {} with URL {}",
            method,
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
                    method,
                    candid_one::<
                        Result<RemoteHttpResponse, (RejectionCode, String)>,
                        RemoteHttpRequest,
                    >,
                    RemoteHttpRequest {
                        request: UnvalidatedCanisterHttpRequestArgs {
                            url: url.to_string(),
                            headers: vec![],
                            body: None,
                            // transform: Some(TransformContext {
                            //     function: TransformFunc(candid::Func {
                            //         principal: proxy_canister.canister_id().get().0,
                            //         method: "deterministic".to_string(),
                            //     }),
                            //     context: context.as_bytes().to_vec(),
                            // }),
                            transform: None,
                            method: HttpMethod::GET,
                            max_response_bytes: Some(1000),
                            is_replicated: Some(true),
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