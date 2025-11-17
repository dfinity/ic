/* tag::catalog[]
Title:: Basic HTTP requests from canisters

Goal:: Ensure simple HTTP requests can be made from canisters.

Run with:
ict test //rs/tests/networking:canister_http_non_replicated_test -- --test_tmpdir=./canister_http_non_replicated_test

Runbook::
0. Instantiate a universal VM with a webserver
1. Instantiate an IC with one application subnet with the HTTP feature enabled.
2. Install NNS canisters
3. Install the proxy canister
4. Make an update call to the proxy canister.

Success::
1. Received http response with status 200.

end::catalog[] */
#![allow(deprecated)]

use anyhow::Result;
use anyhow::bail;
use canister_http::*;
use canister_test::Canister;
use dfn_candid::candid_one;
use ic_cdk::api::call::RejectionCode;
use ic_management_canister_types_private::{HttpMethod, TransformContext, TransformFunc};
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::{
    test_env::TestEnv,
    test_env_api::{READY_WAIT_TIMEOUT, RETRY_BACKOFF},
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::block_on;
use proxy_canister::UnvalidatedCanisterHttpRequestArgs;
use proxy_canister::{RemoteHttpRequest, RemoteHttpResponse};
use slog::{Logger, info};

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
    let proxy_canister = create_proxy_canister(&env, &runtime, &node);
    let webserver_ipv6 = get_universal_vm_address(&env);

    block_on(async {
        let url = format!("https://[{webserver_ipv6}]/random");
        test_non_replicated_random_endpoint_works(&proxy_canister, url.clone(), &logger).await;

        test_fully_replicated_random_endpoint_fails(&proxy_canister, url, &logger).await;
    });
}

async fn make_non_replicated_request(
    proxy_canister: &Canister<'_>,
    url: String,
    context: &str,
) -> Result<RemoteHttpResponse, (RejectionCode, String)> {
    make_request(proxy_canister, url, context, false).await
}

async fn make_fully_replicated_request(
    proxy_canister: &Canister<'_>,
    url: String,
    context: &str,
) -> Result<RemoteHttpResponse, (RejectionCode, String)> {
    make_request(proxy_canister, url, context, true).await
}

async fn make_request(
    proxy_canister: &Canister<'_>,
    url: String,
    context: &str,
    is_replicated: bool,
) -> Result<RemoteHttpResponse, (RejectionCode, String)> {
    proxy_canister
        .update_(
            "send_request",
            candid_one::<Result<RemoteHttpResponse, (RejectionCode, String)>, RemoteHttpRequest>,
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
                    is_replicated: Some(is_replicated),
                    pricing_version: None,
                },
                cycles: 500_000_000_000,
            },
        )
        .await
        .expect("Update call to proxy canister failed")
}

async fn test_non_replicated_random_endpoint_works(
    proxy_canister: &Canister<'_>,
    url: String,
    logger: &Logger,
) {
    ic_system_test_driver::retry_with_msg_async!(
        format!(
            "calling send_request of proxy canister {} with URL {}",
            proxy_canister.canister_id(),
            url
        ),
        logger,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            let context = "There is context to be appended in body";
            let res = make_non_replicated_request(proxy_canister, url.to_string(), context).await;
            if !matches!(res, Ok(ref x) if x.status == 200 && x.body.contains(context)) {
                bail!("Http request failed response: {:?}", res);
            }
            info!(logger, "Update call succeeded! {:?}", res);
            Ok(())
        }
    )
    .await
    .expect("Timeout on doing a canister http call to the webserver");
}

async fn test_fully_replicated_random_endpoint_fails(
    proxy_canister: &Canister<'_>,
    url: String,
    logger: &Logger,
) {
    ic_system_test_driver::retry_with_msg_async!(
        format!(
            "calling send_request of proxy canister {} with URL {}",
            proxy_canister.canister_id(),
            url
        ),
        logger,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            let context = "There is context to be appended in body";
            let res = make_fully_replicated_request(proxy_canister, url.to_string(), context).await;
            if !matches!(res, Err((RejectionCode::SysTransient, _))) {
                // The probability of at least 3 nodes agreeing on the random value is ~1 in 10^18,
                // which is astronomically low. Furthermore, even if that happens, we retry.
                bail!(
                    "Http request succeeded or did not return the expected error: {:?}",
                    res
                );
            }
            info!(&logger, "Update call failed as expected! {:?}", res);
            Ok(())
        }
    )
    .await
    .expect("Timeout on doing a canister http call to the webserver");
}
