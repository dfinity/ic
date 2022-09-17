/* tag::catalog[]
Title:: Basic HTTP requests from canisters to remote service.

Goal:: Ensure simple HTTP requests can be made from canisters to service in internet.

Runbook::
1. Instantiate an IC with one applications subnet with the HTTP feature enabled.
2. Install NNS canisters
3. Install the proxy canister
4. Make an update call to the proxy canister

Success::
1. Received http response with status 200.

end::catalog[] */

use crate::canister_http::lib::*;
use crate::driver::{
    test_env::TestEnv,
    test_env_api::{retry_async, READY_WAIT_TIMEOUT, RETRY_BACKOFF},
};
use crate::util::block_on;
use anyhow::bail;
use dfn_candid::candid_one;
use ic_cdk::api::call::RejectionCode;
use ic_ic00_types::{CanisterHttpRequestArgs, HttpMethod, TransformFunc, TransformType};
use proxy_canister::{RemoteHttpRequest, RemoteHttpResponse};
use slog::info;

pub fn test(env: TestEnv) {
    let mut nodes = get_node_snapshots(&env);
    let node = nodes.next().expect("there is no application node");
    let runtime = get_runtime_from_node(&node);
    let proxy_canister = create_proxy_canister(&env, &runtime, &node);

    block_on(async {
        let url = "https://example.com/";
        info!(&env.logger(), "Send an update call...");
        retry_async(&env.logger(), READY_WAIT_TIMEOUT, RETRY_BACKOFF, || async {
            let updated = proxy_canister
                .update_(
                    "send_request",
                    candid_one::<
                        Result<RemoteHttpResponse, (RejectionCode, String)>,
                        RemoteHttpRequest,
                    >,
                    RemoteHttpRequest {
                        request: CanisterHttpRequestArgs {
                            url: url.to_string(),
                            headers: vec![],
                            method: HttpMethod::GET,
                            body: Some("".as_bytes().to_vec()),
                            transform: Some(TransformType::Function(TransformFunc(candid::Func {
                                principal: proxy_canister.canister_id().get().0,
                                method: "transform".to_string(),
                            }))),
                            max_response_bytes: None,
                        },
                        cycles: 500_000_000_000,
                    },
                )
                .await
                .expect("Failed to send update call");
            if !matches!(updated, Ok(ref x) if x.status == 200) {
                bail!("Http request failed response: {:?}", updated);
            }
            info!(
                &env.logger(),
                "Canister Http update call response: {:?}", updated
            );
            Ok(())
        })
        .await
        .expect("Timeout on doing a canister http call to the webserver");
    });
}
