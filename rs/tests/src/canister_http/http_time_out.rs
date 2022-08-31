/* tag::catalog[]
Title:: HTTP requests timeout behaviour

Goal:: Ensure HTTP requests to invalid endpoint occur a timeout.

Runbook::
1. Instantiate an IC with one applications subnet with the HTTP feature enabled.
2. Install NNS canisters
3. Install the proxy canister
4. Make a update call to the proxy canister to a valid http endpoint.
5. Make a update call to the proxy canister to a invalid http endpoint.

Success::
1. Http request to valid http endpoint returns status 200.
2. Http request to invalid http endpoint returns a transient timeout error.

end::catalog[] */

use crate::canister_http::lib::*;
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::{retry_async, RETRY_BACKOFF, RETRY_TIMEOUT};
use crate::util::*;
use anyhow::bail;
use dfn_candid::candid_one;
use ic_cdk::api::call::RejectionCode;
use ic_ic00_types::{CanisterHttpRequestArgs, HttpMethod, TransformType};
use proxy_canister::{RemoteHttpRequest, RemoteHttpResponse};
use slog::info;

pub fn test(env: TestEnv) {
    let logger = env.logger();
    let mut nodes = get_node_snapshots(&env);
    let node = nodes.next().expect("there is no application node");
    let runtime = get_runtime_from_node(&node);
    let proxy_canister = create_proxy_canister(&env, &runtime, &node);
    let webserver_ipv6 = get_universal_vm_address(&env);

    block_on(async {
        let url_to_succeed = format!("https://[{webserver_ipv6}]:20443");
        let mut request = RemoteHttpRequest {
            request: CanisterHttpRequestArgs {
                url: url_to_succeed.clone(),
                headers: vec![],
                method: HttpMethod::GET,
                body: Some("".as_bytes().to_vec()),
                transform: Some(TransformType::Function(candid::Func {
                    principal: proxy_canister.canister_id().get().0,
                    method: "transform".to_string(),
                })),
                max_response_bytes: None,
            },
            cycles: 500_000_000_000,
        };

        info!(&logger, "Send an update call...");

        let p = proxy_canister.clone();
        let r = request.clone();
        // Retry till we get success response
        retry_async(&env.logger(), RETRY_TIMEOUT, RETRY_BACKOFF, || async {
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
        })
        .await
        .expect("Timeout on doing a canister http call to the webserver");

        // Test remote timeout case
        let url_to_fail = "https://[40d:40d:40d:40d:40d:40d:40d:40d]:28992".to_string();
        request.request.url = url_to_fail.clone();
        let r = request.clone();
        let p = proxy_canister.clone();
        retry_async(&env.logger(), RETRY_TIMEOUT, RETRY_BACKOFF, || async {
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
        })
        .await
        .expect("Timeout on doing a canister http call to the webserver");
    });
}
