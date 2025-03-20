/* tag::catalog[]
Title:: Basic HTTP requests from canisters

Goal:: Ensure simple HTTP requests can be made from canisters.

Runbook::
0. Instantiate a universal VM with a webserver
1. Instantiate an IC with one application subnet with the HTTP feature enabled.
2. Install NNS canisters
3. Install the proxy canister
4. Make an update call to the proxy canister.

Success::
1. Received http response with status 200.

end::catalog[] */

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
use ic_system_test_driver::driver::resource;
use ic_system_test_driver::driver::{
    test_env::TestEnv,
    test_env_api::{READY_WAIT_TIMEOUT, RETRY_BACKOFF},
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::block_on;
use ic_system_test_driver::util::deposit_cycles;
use ic_types::Cycles;
use proxy_canister::UnvalidatedCanisterHttpRequestArgs;
use proxy_canister::{RemoteHttpRequest, RemoteHttpStressRequest, RemoteHttpStressResponse, RemoteHttpResponse};
use slog::{info, Logger};

const NS_IN_1_SEC: u64 = 1_000_000_000;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(canister_http::setup)
        .add_test(systest!(test))
        .execute_from_args()?;

    Ok(())
}

pub fn test(env: TestEnv) {
    let logger = env.logger();
    let mut nodes = get_node_snapshots(&env);
    let node = nodes.next().expect("there is no application node");
    let runtime = get_runtime_from_node(&node);
    // Because we are stressing the outcalls feature with ~100K requests, and each requests costs ~6-7 billion cycles,
    // the default 100T starting cycles would not be enough cover the cost of all the requests.
    let proxy_canister = create_proxy_canister_with_cycles(&env, &runtime, &node, Cycles::new(1 << 127));
    let webserver_ipv6 = get_universal_vm_address(&env);

    block_on(async {
        stress_test_proxy_canister(
            &proxy_canister,
            format!("https://[{webserver_ipv6}]:20443"),
            logger,
        )
        .await;
    });
}

async fn stress_test_proxy_canister(proxy_canister: &Canister<'_>, url: String, logger: Logger) {
    test_proxy_canister(proxy_canister, url.clone(), logger.clone(), 500).await;
    test_proxy_canister(proxy_canister, url.clone(), logger.clone(), 1000).await;
    test_proxy_canister(proxy_canister, url.clone(), logger.clone(), 2000).await;
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

pub async fn test_proxy_canister(
    proxy_canister: &Canister<'_>,
    url: String,
    logger: Logger,
    concurrent_requests: u64,
) {
    let mut experiments = 0;
    let mut total_duration_ns = 0;

    // We leave the experiment running for at least one minute.
    while total_duration_ns < 60 * NS_IN_1_SEC {
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

    // One second has 1_000_000_000 nanoseconds.
    let elapsed_secs = total_duration_ns as f64 / NS_IN_1_SEC as f64;
    let qps = (concurrent_requests * experiments) as f64 / elapsed_secs;
    println!(
        "average qps for {} concurrent request(s) and {} experiment(s) is {}",
        concurrent_requests, experiments, qps
    );
    assert!(qps > 100);
}

