/* tag::catalog[]
Title:: HTTP requests from canisters to remote IPv4 service through socks proxy on API boundary node.

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
#![allow(deprecated)]

use anyhow::Result;
use anyhow::bail;
use canister_http::*;
use canister_test::Canister;
use dfn_candid::candid_one;
use ic_cdk::api::call::RejectionCode;
use ic_management_canister_types_private::HttpMethod;
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::test_env_api::{HasTopologySnapshot, IcNodeSnapshot};
use ic_system_test_driver::driver::{
    ic::{InternetComputer, Subnet},
    test_env::TestEnv,
    test_env_api::{READY_WAIT_TIMEOUT, RETRY_BACKOFF, get_dependency_path},
    universal_vm::UniversalVm,
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::block_on;
use proxy_canister::UnvalidatedCanisterHttpRequestArgs;
use proxy_canister::{RemoteHttpRequest, RemoteHttpResponse};
use slog::Logger;
use slog::info;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test_system_subnet))
        .add_test(systest!(test_application_subnet))
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

    info!(&logger, "Started Universal VM!");

    // Create IC with injected socks proxy.
    InternetComputer::new()
        // .with_socks_proxy(format!("socks5://[{ipv6}]:1080"))
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_features(SubnetFeatures {
                    http_requests: true,
                    ..SubnetFeatures::default()
                })
                .add_nodes(1),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_features(SubnetFeatures {
                    http_requests: true,
                    ..SubnetFeatures::default()
                })
                .add_nodes(4),
        )
        // 2 api boundary nodes, one for system subnets, one for application subnets
        .with_api_boundary_nodes(2)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    await_nodes_healthy(&env);
    install_nns_canisters(&env);
    canister_http::start_httpbin_on_uvm(&env);
    canister_http::whitelist_nodes_access_to_apibns(&env);
}

pub fn test_system_subnet(env: TestEnv) {
    let subnet_nodes: Vec<IcNodeSnapshot> = get_system_subnet_node_snapshots(&env).collect();
    let api_bn_ips: Vec<String> = env
        .topology_snapshot()
        .system_api_boundary_nodes()
        .map(|bn| bn.get_ip_addr().to_string())
        .collect();

    setup_and_run_subnet_test(env, "system", subnet_nodes, api_bn_ips);
}

/// Tests that an outcall from the APPLICATION subnet is routed via an APPLICATION API BN.
pub fn test_application_subnet(env: TestEnv) {
    let subnet_nodes: Vec<IcNodeSnapshot> = get_node_snapshots(&env).collect();
    let api_bn_ips: Vec<String> = env
        .topology_snapshot()
        .app_api_boundary_nodes()
        .map(|bn| bn.get_ip_addr().to_string())
        .collect();

    setup_and_run_subnet_test(env, "application", subnet_nodes, api_bn_ips);
}

fn setup_and_run_subnet_test(
    env: TestEnv,
    subnet_type_str: &str,
    subnet_nodes: Vec<IcNodeSnapshot>,
    api_bn_ips: Vec<String>,
) {
    let logger = env.logger();
    info!(&logger, "Running test for {} subnet...", subnet_type_str);

    let webserver_ipv6 = get_universal_vm_address(&env).to_string();

    // The dante server running on the API boundary node expects a domain name.
    // Construct nip.io hostname for the IPv6 address.
    let nip_io_hostname = webserver_ipv6.replace(':', "-") + ".ipv6.nip.io";
    let webserver_url = format!("https://{}/ip", nip_io_hostname);

    let httpbin_ip_addr =
        IpAddr::from_str(&webserver_ipv6).expect("Invalid webserver IPv6 address string");
    let httpbin_socket_addr = SocketAddr::new(httpbin_ip_addr, 443);

    assert!(
        !subnet_nodes.is_empty(),
        "No {} subnet nodes found",
        subnet_type_str
    );

    let canister_node = &subnet_nodes[0];
    let runtime = get_runtime_from_node(canister_node);
    let proxy_canister = create_proxy_canister(&env, &runtime, canister_node);

    info!(
        &logger,
        "Expecting {} API BN IPs: {:?}", subnet_type_str, api_bn_ips
    );
    assert!(
        !api_bn_ips.is_empty(),
        "No {} API boundary nodes found!",
        subnet_type_str
    );

    run_http_outcall_test(
        &logger,
        &subnet_nodes,
        &proxy_canister,
        &webserver_url,
        httpbin_socket_addr,
        api_bn_ips,
    );
}

/// Helper function to run the core test logic:
/// 1. Block direct access from all nodes in the subnet.
/// 2. Assert the outcall goes through one of the expected API BNs.
/// 3. Unblock direct access from all nodes.
/// 4. Assert the outcall goes directly from one of the nodes itself.
fn run_http_outcall_test(
    logger: &Logger,
    subnet_nodes: &[IcNodeSnapshot],
    proxy_canister: &Canister<'_>,
    webserver_url: &str,
    httpbin_socket_addr: SocketAddr,
    expected_api_bn_ips: Vec<String>,
) {
    // Block the direct connection to the UVM for all nodes in the subnet.
    for node in subnet_nodes {
        node.insert_egress_reject_rule_for_outcalls_adapter(httpbin_socket_addr)
            .expect("Failed to add reject firewall rule on node");
    }

    // Direct connection is blocked. Hence the request should go through the API boundary node.
    // Verify that the outcall works and returns an expected IP address.
    info!(
        logger,
        "Testing with direct connection blocked. Expecting one of {:?}.", expected_api_bn_ips
    );
    assert_outcall_result_in_list(logger, proxy_canister, webserver_url, &expected_api_bn_ips);

    // Now allow direct connection again for all nodes.
    for node in subnet_nodes {
        node.insert_egress_accept_rule_for_outcalls_adapter(httpbin_socket_addr)
            .expect("Failed to add accept firewall rule on node");
    }

    // Derive the expected node IPs from the slice.
    let expected_subnet_node_ips: Vec<String> = subnet_nodes
        .iter()
        .map(|n| n.get_ip_addr().to_string())
        .collect();

    // Direct connection is allowed again. Hence the request should go directly to the webserver.
    // Verify that the outcall works and returns one of the subnet node's IP addresses.
    info!(
        logger,
        "Testing with direct connection allowed. Expecting one of node IPs {:?}.",
        expected_subnet_node_ips
    );
    assert_outcall_result_in_list(
        logger,
        proxy_canister,
        webserver_url,
        &expected_subnet_node_ips,
    );
}

/// Makes a non replicated outcall from the given proxy canister to the given webserver URL
/// Asserts that the response code is 200 and that the body is one of the expected IPs.
fn assert_outcall_result_in_list(
    logger: &Logger,
    proxy_canister: &Canister<'_>,
    webserver_url: &str,
    expected_ips: &[String],
) {
    block_on(ic_system_test_driver::retry_with_msg_async!(
        format!(
            "calling send_request of proxy canister {} with URL {}",
            proxy_canister.canister_id(),
            webserver_url.to_string()
        ),
        &logger,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            let res = proxy_canister
                .update_(
                    "send_request",
                    candid_one::<
                        Result<RemoteHttpResponse, (RejectionCode, String)>,
                        RemoteHttpRequest,
                    >,
                    RemoteHttpRequest {
                        request: UnvalidatedCanisterHttpRequestArgs {
                            url: webserver_url.to_string(),
                            headers: vec![],
                            body: None,
                            transform: None,
                            method: HttpMethod::GET,
                            max_response_bytes: None,
                            // Not replicated, as the /ip endpoint returns different results on each call.
                            is_replicated: Some(false),
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
            match res {
                Ok(response) => {
                    assert!(
                        expected_ips.contains(&response.body),
                        "Returned IP '{}' was not in the expected list of IPs: {:?}",
                        response.body,
                        expected_ips
                    );
                }
                Err((code, message)) => {
                    info!(logger, "Error code: {:?}, message: {}", code, message)
                }
            }
            Ok(())
        }
    ))
    .expect("Failed to call proxy canister");
}
