/* tag::catalog[]
Title:: HTTP outcalls from composite queries

Goal:: Ensure a composite query's attempt to make an HTTP outcall is handled as
the subnet's configuration says it should be.

Run with:
bazel test //rs/tests/networking:canister_http_query_test --test_tmpdir=./canister_http_query_test

Runbook::
0. Instantiate a universal VM with a webserver
1. Instantiate an IC with one application subnet with the HTTP feature enabled.
2. Install NNS canisters
3. Install the proxy canister
4. Make a composite query call to the proxy canister.

Success::
1. Received http response with status 200, without a consensus round trip.
2. A request that asks to be replicated is rejected: a query is served by one
   node, so there is nothing to replicate it across.

end::catalog[] */
#![allow(deprecated)]

use anyhow::Result;
use anyhow::bail;
use canister_http::*;
use canister_test::Canister;
use dfn_candid::candid_one;
use ic_management_canister_types_private::HttpMethod;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::{
    test_env::TestEnv,
    test_env_api::{READY_WAIT_TIMEOUT, RETRY_BACKOFF},
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::block_on;
use proxy_canister::UnvalidatedCanisterHttpRequestArgs;
use proxy_canister::{RejectionCode, RemoteHttpRequest, RemoteHttpResponse};
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
        test_outcall_from_query_works(&proxy_canister, url, &logger).await;
    });
}

/// Makes a composite query call that asks for a non-replicated HTTP outcall.
async fn make_query_outcall(
    proxy_canister: &Canister<'_>,
    url: String,
    is_replicated: Option<bool>,
) -> Result<RemoteHttpResponse, (RejectionCode, String)> {
    proxy_canister
        .query_(
            "send_request_from_query",
            candid_one::<Result<RemoteHttpResponse, (RejectionCode, String)>, RemoteHttpRequest>,
            RemoteHttpRequest {
                request: UnvalidatedCanisterHttpRequestArgs {
                    url,
                    headers: vec![],
                    body: None,
                    transform: None,
                    method: HttpMethod::GET,
                    max_response_bytes: Some(1024),
                    is_replicated,
                    pricing_version: None,
                },
                // Ignored: an outcall from a query is not charged for, and cycles
                // cannot be attached from a composite query in any case.
                cycles: 0,
            },
        )
        .await
        .expect("Query call to proxy canister failed")
}

/// A composite query's outcall reaches the webserver and its response reaches
/// the canister -- without going through consensus.
async fn test_outcall_from_query_works(
    proxy_canister: &Canister<'_>,
    url: String,
    logger: &Logger,
) {
    ic_system_test_driver::retry_with_msg_async!(
        format!(
            "calling send_request_from_query of proxy canister {} with URL {}",
            proxy_canister.canister_id(),
            url
        ),
        logger,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            let res = make_query_outcall(proxy_canister, url.clone(), Some(false)).await;
            if !matches!(res, Ok(ref x) if x.status == 200) {
                bail!("Http outcall from a query failed: {:?}", res);
            }
            info!(logger, "Outcall from a query succeeded! {:?}", res);
            Ok(())
        }
    )
    .await
    .expect("Timeout on doing an HTTP outcall from a composite query");

    // Replication is not a choice a query has: one node serves it, so there is
    // nothing to replicate the request across.
    for is_replicated in [None, Some(true)] {
        let res = make_query_outcall(proxy_canister, url.clone(), is_replicated).await;
        assert!(
            matches!(res, Err((_, ref m)) if m.contains("non-replicated")),
            "is_replicated {is_replicated:?} should have been rejected, got: {res:?}"
        );
    }
}
