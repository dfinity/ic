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
#![allow(deprecated)]

use anyhow::Result;
use anyhow::bail;
use canister_http::*;
use canister_test::Canister;
use dfn_candid::candid_one;
use ic_cdk::api::call::RejectionCode;
use ic_management_canister_types_private::{
    BoundedHttpHeaders, FlexibleCanisterHttpRequestArgs, HttpMethod, TransformContext,
    TransformFunc,
};
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::{
    test_env::TestEnv,
    test_env_api::{READY_WAIT_TIMEOUT, RETRY_BACKOFF},
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::block_on;
use proxy_canister::FlexibleRemoteHttpRequest;
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
        test_proxy_canister(
            &proxy_canister,
            format!("https://[{webserver_ipv6}]"),
            logger,
        )
        .await;
    });
}

async fn test_proxy_canister(proxy_canister: &Canister<'_>, url: String, logger: Logger) {
    ic_system_test_driver::retry_with_msg_async!(
        format!(
            "calling send_request of proxy canister {} with URL {}",
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
                    "send_flexible_request",
                    candid_one::<
                        Result<Vec<u8>, (RejectionCode, String)>,
                        FlexibleRemoteHttpRequest,
                    >,
                    FlexibleRemoteHttpRequest {
                        request: FlexibleCanisterHttpRequestArgs {
                            url: url.clone(),
                            headers: BoundedHttpHeaders::new(vec![]),
                            body: None,
                            transform: Some(TransformContext {
                                function: TransformFunc(candid::Func {
                                    principal: proxy_canister.canister_id().get().0,
                                    method: "transform_with_context".to_string(),
                                }),
                                context: context.as_bytes().to_vec(),
                            }),
                            method: HttpMethod::GET,
                            replication: None,
                        },
                        cycles: 500_000_000_000,
                    },
                )
                .await
                .expect("Update call to proxy canister failed");

            let expected_error_msg = "FlexibleHttpRequest is not yet implemented";

            match res {
                Ok(_) => {
                    bail!("Update call succeeded unexpectedly.");
                }
                Err((code, message)) => {
                    if message == expected_error_msg {
                        info!(
                            &logger,
                            "Http request failed with expected error. Code: {:?}, Message: {}",
                            code, message
                        );
                        Ok(())
                    } else {
                        bail!(
                            "Http request failed with unexpected error. Code: {:?}, Message: '{}'. Expected: '{}'",
                            code, message, expected_error_msg
                        );
                    }
                }
            }
        }
    )
    .await
    .expect("Timeout waiting for http call to fail with the correct error");
}
