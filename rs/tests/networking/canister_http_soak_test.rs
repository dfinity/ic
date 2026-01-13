/* tag::catalog[]
Title:: Soak test for the http_requests feature

Goal:: Measure the evolving qps of http_requests originating from one canister. The test should be run with the following command:
```
ict testnet create //rs/tests/networking:canister_http_soak_test --output-dir=./canister_http_soak_test -- --test_tmpdir=./canister_http_soak_test
```

Runbook::
0. Same setup as canister_http_stress_test.rs. In short, 3 subnets (13, 28, 40 nodes each) setup, the proxy canister installed on each
1. The proxy canister has a special update_ method which leaves it sending requests in batches of 500.
2. The evolving qps can be seen in the adapter's metrics in grafana.

Success::
1. The proxy canister is left sending requests in batches of 500 to track the qps in grafana.

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
use proxy_canister::UnvalidatedCanisterHttpRequestArgs;
use slog::{Logger, info};

const INSTALLED_CANISTERS: usize = 6;

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
        let webserver_ipv6 = get_universal_vm_address(&env);
        let mut proxy_canisters = Vec::new();
        // Each requests costs ~6-7 billion cycles, and we make many thousands of requests.
        // The default 100T cycles may not be enough.

        // Install 6 proxy canisters and make them all send requests in paralel.
        for i in 0..INSTALLED_CANISTERS {
            let canister_name = format!("canister_name_{}", i);
            let proxy_canister = create_proxy_canister_with_name_and_cycles(
                &env,
                &runtime,
                &node,
                &canister_name,
                Cycles::new(u128::MAX),
            );
            proxy_canisters.push(proxy_canister);
        }

        block_on(async {
            let url = format!("https://[{webserver_ipv6}]");
            for canister in &proxy_canisters {
                leave_proxy_canister_running(canister, url.clone(), logger.clone()).await;
            }
        });
    }
}

async fn leave_proxy_canister_running(proxy_canister: &Canister<'_>, url: String, logger: Logger) {
    ic_system_test_driver::retry_with_msg_async!(
        format!(
            "calling start_continuous_requests of proxy canister {} with URL {}",
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
                    "start_continuous_requests",
                    candid_one::<
                        Result<RemoteHttpResponse, (RejectionCode, String)>,
                        RemoteHttpRequest,
                    >,
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
                            is_replicated: Some(true),
                            pricing_version: None,
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
