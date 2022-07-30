/* tag::catalog[]
Title:: Basic HTTP requests from canisters

Goal:: Ensure simple HTTP requests can be made from canisters.

Runbook::
1. Instantiate an IC with one applications subnet with the HTTP feature enabled.
2. Install NNS canisters
3. Install the proxy canister
4. Make a query to the proxy canister to a non-existent endpoint
5. Verify response timed out

Success::
1. Result of last query returns what the update call put in the canister.

end::catalog[] */

use crate::canister_http::lib::*;
use crate::driver::test_env::TestEnv;
use crate::util::*;
use dfn_candid::candid_one;
use ic_ic00_types::HttpMethod;
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
        let url_to_succeed = format!("https://[{webserver_ipv6}]:443");
        let request_to_succeed = RemoteHttpRequest {
            url: url_to_succeed.clone(),
            headers: vec![],
            method: HttpMethod::GET,
            body: "".to_string(),
            transform: Some("transform".to_string()),
            max_response_size: None,
            cycles: 500_000_000_000,
        };

        info!(&logger, "Send an update call...");
        let succeeded = proxy_canister
            .update_(
                "send_request",
                candid_one::<Result<(), String>, RemoteHttpRequest>,
                request_to_succeed.clone(),
            )
            .await
            .expect("update call failed");
        let _ = succeeded.expect("send_request failed");

        let httpbin_success = proxy_canister
            .query_(
                "check_response",
                candid_one::<Result<RemoteHttpResponse, String>, String>,
                url_to_succeed,
            )
            .await
            .unwrap();
        assert!(httpbin_success.is_ok());
        assert_eq!(httpbin_success.unwrap().status, 200);

        // Test remote timeout case
        let url_to_fail = "https://[40d:40d:40d:40d:40d:40d:40d:40d]:28992".to_string();
        let mut request_to_fail = request_to_succeed;
        request_to_fail.url = url_to_fail.clone();
        let failure_update = proxy_canister
            .update_(
                "send_request",
                candid_one::<Result<(), String>, RemoteHttpRequest>,
                request_to_fail,
            )
            .await
            .expect("Error");
        assert!(
            failure_update.is_err(),
            "Failure expected when URL is unreachable, but request succeeded!"
        );
        let unwrapped_error = failure_update.unwrap_err();
        info!(&logger, "{unwrapped_error}");
        assert!(
            unwrapped_error.contains("RejectionCode: SysTransient"),
            "Expected SysTransient"
        );
        assert!(unwrapped_error.contains("Failed to connect"));

        let httpbin_timeout = proxy_canister
            .query_(
                "check_response",
                candid_one::<Result<RemoteHttpResponse, String>, _>,
                url_to_fail.clone(),
            )
            .await
            .expect("Error");
        assert!(httpbin_timeout.is_err());
        assert_eq!(
            httpbin_timeout.unwrap_err(),
            format!("Request to URL {} has not been made.", url_to_fail)
        );
    });
}
