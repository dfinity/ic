/* tag::catalog[]
Title:: HTTP requests timeout behaviour

Goal:: Ensure HTTP requests to invalid endpoint occur a timeout, and bounded-wait HTTP requests
are cancelled at their deadline.

Runbook::
1. Instantiate an IC with one applications subnet with the HTTP feature enabled.
2. Install NNS canisters
3. Install the proxy canister
4. Make a update call to the proxy canister to a valid http endpoint.
5. Make a update call to the proxy canister to a invalid http endpoint.
6. Make a update call to the proxy canister that makes a bounded-wait http request with a 5s
   timeout to an endpoint that answers after 40s.

Success::
1. Http request to valid http endpoint returns status 200.
2. Http request to invalid http endpoint returns a transient timeout error.
3. Bounded-wait http request times out, and consensus times it out at its deadline instead of
   waiting for the adapter to give up.

end::catalog[] */

use anyhow::Result;
use anyhow::bail;
use canister_http::*;
use dfn_candid::candid_one;
use ic_management_canister_types_private::{HttpMethod, TransformContext, TransformFunc};
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{READY_WAIT_TIMEOUT, RETRY_BACKOFF};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::*;
use proxy_canister::UnvalidatedCanisterHttpRequestArgs;
use proxy_canister::{RejectionCode, RemoteHttpRequest, RemoteHttpResponse};
use slog::info;

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
        let url_to_succeed = format!("https://[{webserver_ipv6}]");
        let mut request = RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url: url_to_succeed.clone(),
                headers: vec![],
                method: HttpMethod::GET,
                body: Some("".as_bytes().to_vec()),
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: proxy_canister.canister_id().get().0,
                        method: "transform".to_string(),
                    }),
                    context: vec![0, 1, 2],
                }),
                max_response_bytes: None,
                is_replicated: None,
                pricing_version: None,
            },
            cycles: 500_000_000_000,
        };

        info!(&logger, "Send an update call...");

        let p = proxy_canister.clone();
        let r = request.clone();
        // Retry till we get success response
        ic_system_test_driver::retry_with_msg_async!(
            format!("calling send_request of proxy canister {}", p.canister_id()),
            &env.logger(),
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let succeeded = p
                    .update_(
                        "send_request",
                        candid_one::<
                            Result<RemoteHttpResponse, (RejectionCode, String)>,
                            RemoteHttpRequest,
                        >,
                        r.clone(),
                    )
                    .await
                    .expect("Update call to proxy canister failed");
                if !matches!(succeeded, Ok(ref x) if x.status == 200) {
                    bail!("Http request failed response: {:?}", succeeded);
                }
                Ok(())
            }
        )
        .await
        .expect("Timeout on doing a canister http call to the webserver");

        // Test remote timeout case
        let url_to_fail = "https://[40d:40d:40d:40d:40d:40d:40d:40d]:28992".to_string();
        request.request.url.clone_from(&url_to_fail);
        let r = request.clone();
        let p = proxy_canister.clone();
        ic_system_test_driver::retry_with_msg_async!(
            format!("calling send_request of proxy canister {}", p.canister_id()),
            &env.logger(),
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let failure_update = p
                    .update_(
                        "send_request",
                        candid_one::<
                            Result<RemoteHttpResponse, (RejectionCode, String)>,
                            RemoteHttpRequest,
                        >,
                        r.clone(),
                    )
                    .await
                    .expect("Update call to proxy canister failed");
                // TODO: Better way to verify timeout
                if !matches!(failure_update, Err((RejectionCode::SysTransient, _))) {
                    bail!(
                        "Http request did not timeout response: {:?}",
                        failure_update
                    );
                }
                Ok(())
            }
        )
        .await
        .expect("Timeout on doing a canister http call to the webserver");

        // Test that consensus times out a bounded-wait request at its deadline. Otherwise
        // the adapter's 30s request timeout would end it with a response first.
        const TIMEOUT_SECONDS: u32 = 5;
        let timeouts_before = timeouts_delivered_once_idle(&env).await;
        request.request.url = format!("https://[{webserver_ipv6}]/delay/40");
        let response = proxy_canister
            .update_(
                "send_bounded_wait_request",
                dfn_candid::candid::<
                    Result<RemoteHttpResponse, (RejectionCode, String)>,
                    (RemoteHttpRequest, u32),
                >,
                (request, TIMEOUT_SECONDS),
            )
            .await
            .expect("Update call to proxy canister failed");
        assert!(
            matches!(
                response,
                Err((RejectionCode::SysUnknown | RejectionCode::SysTransient, _))
            ),
            "Bounded-wait http request did not time out, response: {response:?}"
        );

        let timeouts_after = timeouts_delivered_once_idle(&env).await;
        assert!(
            timeouts_after > timeouts_before,
            "Bounded-wait http request was not timed out at its deadline"
        );
    });
}

/// Waits until no http requests are in flight, then returns the number of http request
/// timeouts consensus has delivered, summed over all nodes.
async fn timeouts_delivered_once_idle(env: &TestEnv) -> u64 {
    const IN_FLIGHT: &str = "canister_http_in_flight_requests";
    const TIMEOUTS: &str = "canister_http_timeouts_delivered";
    let metrics = MetricsFetcher::new(
        get_node_snapshots(env),
        vec![IN_FLIGHT.to_string(), TIMEOUTS.to_string()],
    );
    ic_system_test_driver::retry_with_msg_async!(
        "waiting for no http requests to be in flight",
        &env.logger(),
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            let values = metrics.fetch::<u64>().await?;
            match (values.get(IN_FLIGHT), values.get(TIMEOUTS)) {
                (Some(in_flight), Some(timeouts)) if in_flight.iter().all(|&count| count == 0) => {
                    Ok(timeouts.iter().sum())
                }
                _ => bail!("Http requests still in flight: {values:?}"),
            }
        }
    )
    .await
    .expect("Http requests stayed in flight")
}
