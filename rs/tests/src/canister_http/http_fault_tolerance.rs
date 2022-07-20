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
use crate::driver::pot_dsl::get_ic_handle_and_ctx;
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::HasArtifacts;
use crate::driver::vm_control::IcControl;
use crate::util;
use candid::Principal;
use canister_test::Canister;
use dfn_candid::candid_one;
use ic_ic00_types::HttpMethod;
use ic_registry_subnet_type::SubnetType;
use ic_types::{CanisterId, PrincipalId};
use ic_utils::interfaces::ManagementCanister;
use proxy_canister::{RemoteHttpRequest, RemoteHttpResponse};
use slog::{info, warn};
use std::time::{Duration, Instant};

const EXPIRATION: Duration = Duration::from_secs(180);
const BACKOFF_DELAY: Duration = Duration::from_secs(5);

pub fn test(env: TestEnv) {
    let logger = env.logger();

    // TODO: adapt the test below to use the env directly
    // instead of using the deprecated IcHandle and Context.
    let (handle, ctx) = get_ic_handle_and_ctx(env.clone());

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    let mut rng = ctx.rng.clone();

    // TODO: change this back to app_node_endpoint
    let app_endpoints: Vec<_> = handle
        .as_permutation(&mut rng)
        .filter(|e| e.subnet.as_ref().map(|s| s.type_of) == Some(SubnetType::Application))
        .collect();
    let app_endpoint = app_endpoints.first().expect("no Application nodes.");
    //let app_endpoint = util::get_random_application_node_endpoint(&handle, &mut rng);
    let app_runtime = util::runtime_from_url(app_endpoint.url.clone());
    rt.block_on(app_endpoint.assert_ready(&ctx));
    info!(&logger, "NNS endpoint reachable over http.");

    let agent = rt.block_on(util::assert_create_agent(app_endpoint.url.as_str()));

    info!(&logger, "Installing proxy_canister.");
    let cid: Principal = rt.block_on(async {
        let mgr = ManagementCanister::create(&agent);
        let cid = mgr
            .create_canister()
            .as_provisional_create_with_amount(None)
            .call_and_wait(util::delay())
            .await
            .expect("failed to create a canister")
            .0;
        mgr.install_code(&cid, &env.load_wasm("proxy_canister.wasm"))
            .call_and_wait(util::delay())
            .await
            .expect("failed to install canister");
        cid
    });

    info!(&logger, "proxy_canister {cid} installed");
    let webserver_ipv6 = get_universal_vm_address(&env);

    let continuous_http_calls = rt.spawn(async move {
        println!("Starting workload of continued remote HTTP calls.");
        let proxy_canister = Canister::new(
            &app_runtime,
            CanisterId::new(PrincipalId::from(cid)).unwrap(),
        );

        // keeping sending http calls as an application node is being killed.
        // all http requests should still succeed throughout.
        loop {
            let success_update = proxy_canister
                .update_(
                    "send_request",
                    candid_one::<Result<(), String>, RemoteHttpRequest>,
                    RemoteHttpRequest {
                        url: format!("https://[{webserver_ipv6}]:443"),
                        headers: vec![],
                        method: HttpMethod::GET,
                        body: "".to_string(),
                        transform: Some("transform".to_string()),
                        max_response_size: None,
                        cycles: 500_000_000_000,
                    },
                )
                .await
                .expect("HTTP request failed");
            match success_update {
                Ok(_) => {
                    println!("Update call successful!")
                }
                Err(failure) => {
                    let message = format!("Failed to make the update call. {}", failure);
                    panic!("{}", message);
                }
            }
        }
    });

    info!(&logger, "Killing one of the node now.");
    app_endpoints[1].kill_node(ctx.logger.clone());

    // wait the node is actually killed
    let http_client = reqwest::blocking::ClientBuilder::new()
        .build()
        .expect("Could not build reqwest client.");

    let start = Instant::now();
    while http_client.get(app_endpoints[1].url.clone()).send().is_ok() {
        if Instant::now() - start > EXPIRATION {
            panic!(
                "Failed to kill node. Endpoint {} remained available after timeout is hit.",
                app_endpoints[1].url
            );
        }
        std::thread::sleep(BACKOFF_DELAY);
    }
    info!(&logger, "Node successfully killed");

    // recover the killed node and observe it caught up on state
    info!(&logger, "Restarting the killed node now.");
    app_endpoints[1].start_node(ctx.logger.clone());
    let restarted_endpoint = &util::runtime_from_url(app_endpoints[1].url.clone());
    let restarted_canister_endpoint = Canister::new(
        restarted_endpoint,
        CanisterId::new(PrincipalId::from(cid)).unwrap(),
    );
    let start = Instant::now();
    rt.block_on(async {
        loop {
            if Instant::now() - start > EXPIRATION {
                panic!("Restarted node not able to catch up cached query content before timeout.");
            }
            let waited_query = restarted_canister_endpoint
                .query_(
                    "check_response",
                    candid_one::<Result<RemoteHttpResponse, String>, _>,
                    format!("https://[{webserver_ipv6}]:443"),
                )
                .await;

            if let Err(error) = waited_query {
                std::thread::sleep(BACKOFF_DELAY);
                warn!(
                    &logger,
                    "Restarted node hasn't caught up. Got error: {error}. Retrying.."
                );
                continue;
            }

            match waited_query.unwrap() {
                Err(error) => {
                    std::thread::sleep(BACKOFF_DELAY);
                    warn!(
                        &logger,
                        "Restarted node hasn't caught up. Got inner error: {error}. Retrying.."
                    );
                }
                Ok(queried) => {
                    info!(&logger, "Restarted node is caught up!");
                    assert!(queried.status == 200);
                    assert!(!queried.body.is_empty());
                    break;
                }
            }
        }
    });
    info!(
        &logger,
        "Restarted node caught up with cached query content. Success!"
    );

    // now that restarted node is verified returning previous HTTP request correctly,
    // we can abort the continued HTTP calls.
    continuous_http_calls.abort();
}
