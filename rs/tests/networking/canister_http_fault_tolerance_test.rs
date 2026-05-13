/* tag::catalog[]
Title:: Fault tolerance test for HTTP requests

Goal:: Ensure HTTP requests can be made from canisters while 1 of 3 nodes fails.

Runbook::
1. Instantiate an IC with one application subnet with the HTTP feature enabled.
2. Install NNS canisters
3. Install the proxy canister
4. Spawn a task to continuously send HTTP requests.
5. Kill one of the nodes.
6. Query proxy canister and verify state is restored.

Success::
1. HTTP requests succeed in an environment where nodes fail.

end::catalog[] */
#![allow(deprecated)]

use anyhow::Result;
use anyhow::bail;
use candid::Principal;
use canister_http::*;
use canister_test::Canister;
use dfn_candid::candid_one;
use ic_cdk::api::call::RejectionCode;
use ic_management_canister_types_private::{HttpMethod, TransformContext, TransformFunc};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, HasVm, IcNodeContainer, READY_WAIT_TIMEOUT,
    RETRY_BACKOFF, load_wasm,
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util;
use ic_types::{CanisterId, PrincipalId};
use ic_utils::interfaces::ManagementCanister;
use proxy_canister::UnvalidatedCanisterHttpRequestArgs;
use proxy_canister::{RemoteHttpRequest, RemoteHttpResponse};
use slog::info;
use std::env;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(canister_http::setup)
        .add_test(systest!(test))
        .execute_from_args()?;

    Ok(())
}

pub fn test(env: TestEnv) {
    let logger = env.logger();

    let topology = env.topology_snapshot();

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    // This test needs at least 4 nodes.
    assert!(
        topology
            .subnets()
            .find(|s| s.subnet_type() == SubnetType::Application)
            .unwrap()
            .nodes()
            .count()
            > 3
    );

    let mut app_nodes = topology
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap()
        .nodes();

    // Select the node that should be killed during the test.
    let killed_app_endpoint = app_nodes.next().expect("no Application nodes.");
    // Select the endpoint that will stay healthy throughout the test.
    let healthy_app_endpoint = app_nodes.next().expect("no Application nodes.");

    let app_runtime = util::runtime_from_url(
        healthy_app_endpoint.get_public_url(),
        healthy_app_endpoint.effective_canister_id(),
    );

    // Wait for all endpoints to be ready.
    for endpoint in topology
        .subnets()
        .flat_map(|subnet| subnet.nodes())
        .collect::<Vec<_>>()
    {
        endpoint.await_status_is_healthy().unwrap();
    }

    info!(&logger, "All IC endpoints are reachable over HTTP.");

    let agent = rt.block_on(util::assert_create_agent(
        healthy_app_endpoint.get_public_url().as_str(),
    ));

    info!(&logger, "Installing proxy_canister.");
    let cid: Principal = rt.block_on(async {
        let mgr = ManagementCanister::create(&agent);
        let cid = mgr
            .create_canister()
            .as_provisional_create_with_amount(None)
            .with_effective_canister_id(healthy_app_endpoint.effective_canister_id())
            .call_and_wait()
            .await
            .expect("failed to create a canister")
            .0;
        mgr.install_code(
            &cid,
            &load_wasm(env::var("PROXY_WASM_PATH").expect("PROXY_WASM_PATH not set")),
        )
        .call_and_wait()
        .await
        .expect("failed to install canister");
        cid
    });

    info!(&logger, "proxy_canister {cid} installed");
    let webserver_ipv6 = get_universal_vm_address(&env);

    let log = logger.clone();

    let requests = Arc::new(AtomicUsize::new(0));

    let requests_c = requests.clone();
    let continuous_http_calls = rt.spawn(async move {
        info!(&log, "Starting workload of continued remote HTTP calls.");
        let proxy_canister = Canister::new(
            &app_runtime,
            CanisterId::unchecked_from_principal(PrincipalId::from(cid)),
        );

        // Proxy requests store responses in a HashMap indexed by URL.
        // We generate HTTP requests to httpbin/anything/{n},
        // which just returns n. All of these requests will be stored in the proxy
        // canister and we will later check that all of these were successful.
        let mut n = 0;
        loop {
            let reply = proxy_canister
                .update_(
                    "send_request",
                    candid_one::<
                        Result<RemoteHttpResponse, (RejectionCode, String)>,
                        RemoteHttpRequest,
                    >,
                    RemoteHttpRequest {
                        request: UnvalidatedCanisterHttpRequestArgs {
                            url: format!("https://[{webserver_ipv6}]/anything/{n}"),
                            headers: vec![],
                            method: HttpMethod::GET,
                            body: Some("".as_bytes().to_vec()),
                            transform: Some(TransformContext {
                                function: TransformFunc(candid::Func {
                                    principal: proxy_canister.canister_id().get().0,
                                    method: "deterministic_transform".to_string(),
                                }),
                                context: vec![0, 1, 2],
                            }),
                            max_response_bytes: None,
                            is_replicated: None,
                            pricing_version: None,
                        },
                        cycles: 500_000_000_000,
                    },
                )
                .await
                .expect("Failed to call proxy canister");
            info!(&log, "Continuous HTTP request {}: {:?}", n, reply);
            n += 1;
            requests_c.store(n, Ordering::SeqCst);
        }
    });

    info!(&logger, "Killing one of the nodes now.");
    killed_app_endpoint.vm().kill();

    // Wait until the node is actually killed.
    let http_client = reqwest::blocking::ClientBuilder::new()
        .build()
        .expect("Could not build reqwest client.");

    let killed_app_endpoint_url = killed_app_endpoint.get_public_url();
    ic_system_test_driver::retry_with_msg!(
        format!(
            "check if node {} is killed",
            killed_app_endpoint_url.to_string()
        ),
        env.logger(),
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || match http_client.get(killed_app_endpoint_url.clone()).send() {
            Ok(_) => bail!("Node not yet killed"),
            Err(_) => Ok(()),
        }
    )
    .expect("Failed to kill node.");
    info!(&logger, "Node successfully killed");

    // Recover the killed node and observe that it catches up on state.
    info!(&logger, "Restarting the killed node.");
    killed_app_endpoint.vm().start();
    let healthy_runtime = &util::runtime_from_url(
        healthy_app_endpoint.get_public_url(),
        healthy_app_endpoint.effective_canister_id(),
    );
    let canister_endpoint = Canister::new(
        healthy_runtime,
        CanisterId::unchecked_from_principal(PrincipalId::from(cid)),
    );

    // Wait until the killed node has recovered.
    info!(&logger, "Waiting for the killed node to recover.");
    let http_client = reqwest::blocking::ClientBuilder::new()
        .build()
        .expect("Could not build reqwest client.");
    let killed_app_endpoint_url = killed_app_endpoint.get_public_url();
    ic_system_test_driver::retry_with_msg!(
        format!(
            "check if node {} is killed",
            killed_app_endpoint_url.to_string()
        ),
        env.logger(),
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || match http_client.get(killed_app_endpoint_url.clone()).send() {
            Ok(_) => Ok(()),
            Err(e) => bail!("Killed node is not healthy yet: {e}"),
        }
    )
    .expect("Failed to restart killed node.");
    info!(&logger, "Killed node successfully recovered.");

    // Make sure we make at least one additional background request.
    // This ensures a potential consensus timeout issue is collected in the proxy canister.
    let current_requests_num = requests.load(Ordering::SeqCst);
    ic_system_test_driver::retry_with_msg!(
        "Checking whether one additional background HTTP request has been made",
        env.logger(),
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || {
            if requests.load(Ordering::SeqCst) > current_requests_num {
                Ok(())
            } else {
                bail!("Waiting for one additional background HTTP request.")
            }
        }
    )
    .expect("Failed to make an additional HTTP request after node restart.");

    // Verify that all stored HTTP responses are successful.
    rt.block_on(async {
        info!(
            &logger,
            "Checking {} requests sent by background task.",
            requests.load(Ordering::SeqCst)
        );
        for n in 0..requests.load(Ordering::SeqCst) {
            let waited_query =
                canister_endpoint
                    .query_(
                        "check_response",
                        candid_one::<
                            Option<Result<RemoteHttpResponse, (RejectionCode, String)>>,
                            String,
                        >,
                        format!("https://[{webserver_ipv6}]/anything/{n}"),
                    )
                    .await
                    .expect("Failed to call proxy canister.");
            match waited_query {
                Some(Ok(queried)) if queried.status == 200 && !queried.body.is_empty() => continue,
                Some(Ok(queried)) => {
                    panic!("Unexpected HTTP response {queried:?}.")
                }
                Some(Err(e)) => {
                    panic!("HTTP request failed {e:?}.")
                }
                None => {
                    panic!("Request was not made by proxy canister.")
                }
            }
        }
    });

    info!(&logger, "All requests returned 200. Success.",);
    // Now that the restarted node is verified to return previous HTTP requests correctly,
    // we can abort the continued HTTP calls.
    continuous_http_calls.abort();
}
