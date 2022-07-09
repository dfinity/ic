/* tag::catalog[]
Title:: Basic HTTP requests from canisters

Goal:: Ensure simple HTTP requests can be made from canisters.

Runbook::
1. Instantiate an IC with one applications subnet with the HTTP feature enabled.
2. Install NNS canisters
3. Install the proxy canister
4. Make a query to the proxy canister
5. Make an update call to the proxy canister
6. Make a query to the proxy canister

Success::
1. Result of last query returns what the update call put in the canister.

end::catalog[] */

use crate::canister_http::lib::*;
use crate::driver::test_env::TestEnv;
use crate::util::block_on;
use dfn_candid::candid_one;
use ic_ic00_types::HttpMethod;
use proxy_canister::{RemoteHttpRequest, RemoteHttpResponse};
use slog::{error, info};

pub fn test(env: TestEnv) {
    let mut nodes = get_node_snapshots(&env);
    let node = nodes.next().expect("there is no application node");
    let runtime = get_runtime_from_node(&node);
    let proxy_canister = create_proxy_canister(&env, &runtime, &node);

    block_on(async {
        let url = "https://example.com/";
        let empty_result = proxy_canister
            .query_(
                "check_response",
                candid_one::<Result<RemoteHttpResponse, String>, _>,
                url.to_string(),
            )
            .await
            .expect("Error");
        assert!(empty_result.is_err());
        assert_eq!(
            empty_result.unwrap_err(),
            format!("Request to URL {} has not been made.", url)
        );

        info!(&env.logger(), "Send an update call...");

        let updated = proxy_canister
            .update_(
                "send_request",
                candid_one::<Result<(), String>, RemoteHttpRequest>,
                RemoteHttpRequest {
                    url: url.to_string(),
                    headers: vec![],
                    method: HttpMethod::GET,
                    body: "".to_string(),
                    transform: Some("transform".to_string()),
                    max_response_size: None,
                    cycles: 500_000_000_000,
                },
            )
            .await
            .expect("Failed to send update call")
            .expect("Update call failed");
        info!(
            &env.logger(),
            "Canister Http update call response: {:?}", updated
        );

        let _ = proxy_canister
            .query_(
                "check_response",
                candid_one::<Result<RemoteHttpResponse, String>, String>,
                url.to_string(),
            )
            .await
            .map_err(|err| {
                error!(&env.logger(), "Failed to pull response: {}", err);
            })
            .map(|result| {
                let success = result.unwrap();
                info!(
                    &env.logger(),
                    "Successfully pulled response! status: {}, body: {}",
                    success.status,
                    success.body
                );
                assert_ne!("", success.body);
            });
    });
}
