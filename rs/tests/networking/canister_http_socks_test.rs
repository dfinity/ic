/* tag::catalog[]
Title:: HTTP requests from canisters to remote IPv4 service through socks proxy on boundary node.

Goal:: Ensure that only system subnets with the feature enabled can access IPv4 endpoints.

Runbook::
1. Instantiate an IC with one applications and one system subnet with the HTTP feature enabled.
2. Install NNS canisters
3. Install the proxy canister on both subnets.
4. Make a http outcall request to the IPv4 interface of the http server from the system subnet.
5. Make a http outcall request to the IPv4 interface of the http server from the application subnet.

Success::
1. Received http response with status 200 for system subnet.
2. Received failed to connect error from application subnet.

end::catalog[] */

use anyhow::bail;
use anyhow::Result;
use canister_http::*;
use dfn_candid::candid_one;
use ic_cdk::api::call::RejectionCode;
use ic_management_canister_types::{
    BoundedHttpHeaders, CanisterHttpRequestArgs, HttpMethod, TransformContext, TransformFunc,
};
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::test_env_api::{HasPublicApiUrl, RetrieveIpv4Addr};
use ic_system_test_driver::driver::{
    boundary_node::{BoundaryNode, BoundaryNodeVm},
    ic::{InternetComputer, Subnet},
    test_env::TestEnv,
    test_env_api::{get_dependency_path, READY_WAIT_TIMEOUT, RETRY_BACKOFF},
    universal_vm::UniversalVm,
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::block_on;
use proxy_canister::{RemoteHttpRequest, RemoteHttpResponse};
use slog::info;

const BN_NAME: &str = "socks-bn";

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;

    Ok(())
}

pub fn setup(env: TestEnv) {
    let logger = env.logger();

    // Set up Universal VM with HTTP Bin testing service

    UniversalVm::new(String::from(UNIVERSAL_VM_NAME))
        .with_config_img(get_dependency_path(
            "rs/tests/networking/canister_http/http_uvm_config_image.zst",
        ))
        .enable_ipv4()
        .start(&env)
        .expect("failed to set up universal VM");

    canister_http::start_httpbin_on_uvm(&env);
    info!(&logger, "Started Universal VM!");

    // Create raw BN vm to get ipv6 address with which we configure IC.
    let bn_vm = BoundaryNode::new(BN_NAME.to_string())
        .allocate_vm(&env)
        .unwrap();
    let bn_ipv6 = bn_vm.ipv6();

    info!(&logger, "Created raw BN with IP {}!", bn_ipv6);

    // Create IC with injected socks proxy.
    InternetComputer::new()
        .with_socks_proxy(format!("socks5://[{bn_ipv6}]:1080"))
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_features(SubnetFeatures {
                    http_requests: true,
                    ..SubnetFeatures::default()
                })
                .add_nodes(4),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_features(SubnetFeatures {
                    http_requests: true,
                    ..SubnetFeatures::default()
                })
                .add_nodes(4),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    await_nodes_healthy(&env);
    install_nns_canisters(&env);

    // Start BN.
    bn_vm
        .for_ic(&env, "")
        .start(&env)
        .expect("failed to setup BoundaryNode VM");

    let boundary_node_vm = env
        .get_deployed_boundary_node(BN_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();

    info!(
        &logger,
        "Boundary node {BN_NAME} has IPv4 {:?} and IPv6 {:?}",
        boundary_node_vm.block_on_ipv4().unwrap(),
        boundary_node_vm.ipv6()
    );

    info!(&logger, "Checking BN health");
    boundary_node_vm
        .await_status_is_healthy()
        .expect("Boundary node did not come up healthy.");
}

pub fn test(env: TestEnv) {
    let logger = env.logger();
    let webserver_ipv4 = get_universal_vm_ipv4_address(&env);
    let webserver_url = format!("https://{webserver_ipv4}:20443");

    // Request from system subnet.
    let mut system_nodes = get_system_subnet_node_snapshots(&env);
    let system_node = system_nodes.next().expect("there is no system subnet node");
    let runtime_system = get_runtime_from_node(&system_node);
    let proxy_canister_system = create_proxy_canister(&env, &runtime_system, &system_node);

    block_on(ic_system_test_driver::retry_with_msg_async!(
        format!(
            "calling send_request of proxy canister {} with URL {}",
            proxy_canister_system.canister_id(),
            webserver_url.to_string()
        ),
        &logger,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            let context = "There is context to be appended in body";
            let res = proxy_canister_system
                .update_(
                    "send_request",
                    candid_one::<
                        Result<RemoteHttpResponse, (RejectionCode, String)>,
                        RemoteHttpRequest,
                    >,
                    RemoteHttpRequest {
                        request: CanisterHttpRequestArgs {
                            url: webserver_url.to_string(),
                            headers: BoundedHttpHeaders::new(vec![]),
                            body: None,
                            transform: Some(TransformContext {
                                function: TransformFunc(candid::Func {
                                    principal: proxy_canister_system.canister_id().get().0,
                                    method: "transform_with_context".to_string(),
                                }),
                                context: context.as_bytes().to_vec(),
                            }),
                            method: HttpMethod::GET,
                            max_response_bytes: None,
                        },
                        cycles: 500_000_000_000,
                    },
                )
                .await
                .expect("Update call to proxy canister failed");
            if !matches!(res, Ok(ref x) if x.status == 200 && x.body.contains(context)) {
                bail!("Http request failed response: {:?}", res);
            }
            info!(&logger, "Update call succeeded! {:?}", res);
            Ok(())
        }
    ))
    .expect("Failed to call proxy canister");

    // Request from application subnet.
    let mut app_nodes = get_node_snapshots(&env);
    let app_node = app_nodes.next().expect("there is no application node");
    let runtime_app = get_runtime_from_node(&app_node);
    let proxy_canister_app = create_proxy_canister(&env, &runtime_app, &app_node);

    block_on(ic_system_test_driver::retry_with_msg_async!(
        format!(
            "calling send_request of proxy canister {} with URL {}",
            proxy_canister_app.canister_id(),
            webserver_url.to_string()
        ),
        &logger,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            let context = "There is context to be appended in body";
            let res = proxy_canister_app
                .update_(
                    "send_request",
                    candid_one::<
                        Result<RemoteHttpResponse, (RejectionCode, String)>,
                        RemoteHttpRequest,
                    >,
                    RemoteHttpRequest {
                        request: CanisterHttpRequestArgs {
                            url: webserver_url.to_string(),
                            headers: BoundedHttpHeaders::new(vec![]),
                            body: None,
                            transform: Some(TransformContext {
                                function: TransformFunc(candid::Func {
                                    principal: proxy_canister_app.canister_id().get().0,
                                    method: "transform_with_context".to_string(),
                                }),
                                context: context.as_bytes().to_vec(),
                            }),
                            method: HttpMethod::GET,
                            max_response_bytes: None,
                        },
                        cycles: 500_000_000_000,
                    },
                )
                .await
                .expect("Update call to proxy canister failed");
            if !matches!(res, Err((RejectionCode::SysTransient, _))) {
                bail!(
                    "Http request succeeded or did not return the expected error: {:?}",
                    res
                );
            }
            info!(&logger, "Update call failed as expected! {:?}", res);
            Ok(())
        }
    ))
    .expect("Failed to call proxy canister");
}
