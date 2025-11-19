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
use ic_system_test_driver::driver::test_env_api::HasTopologySnapshot;
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

// NOTE: This test is currently non-functional because API boundary nodes running GuestOS on Farm VMs do not support IPv4.
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
        .with_api_boundary_nodes(1)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    await_nodes_healthy(&env);
    install_nns_canisters(&env);
    canister_http::start_httpbin_on_uvm(&env);
    canister_http::whitelist_nodes_access_to_apibns(&env);
}

pub fn test(env: TestEnv) {
    // This test verifies that outcalls are routed through the correct API Boundary nodes when necessary.
    //
    // Test steps:
    //  1. block direct access to the webserver from the system subnet node using nftables rules.
    //  2. make an outcall from a canister on the system subnet to the webserver at the /ip endpoint
    //  3. verify that the returned IP address is that of the API boundary node (indicating the outcall was routed correctly)
    //  4. undo the nftables rule to allow direct access again.
    //  5. make the outcall again
    //  6. verify that the returned IP address is that of the node itself (indicating direct access).
    //
    // The order of the assertiongs can't easily be flipped (ie first allow direct access, then block it) because
    // the TCP connection persists after the first request, and hyper will just try to reuse it for the second request.
    // This will result in the second request timing out instead of failing early and using the fallback.
    //
    // The reason we are not testing IPv4 outcalls here is that currently IC nodes can't easily get IPv4 connectivity.

    let logger = env.logger();

    let webserver_ipv6 = get_universal_vm_address(&env).to_string();

    // The dante server running on the API boundary node expects a domain name.
    // Construct nip.io hostname for the IPv6 address.
    let nip_io_hostname = webserver_ipv6.replace(':', "-") + ".ipv6.nip.io";
    let webserver_url = format!("https://{}/ip", nip_io_hostname);

    let httpbin_ip_addr =
        IpAddr::from_str(&webserver_ipv6).expect("Invalid webserver IPv6 address string");
    let httpbin_socket_addr = SocketAddr::new(httpbin_ip_addr, 443);

    let mut system_nodes = get_system_subnet_node_snapshots(&env);
    let system_node = system_nodes.next().expect("there is no system subnet node");

    let runtime_system = get_runtime_from_node(&system_node);
    let proxy_canister_system = create_proxy_canister(&env, &runtime_system, &system_node);

    // Block the direct connection to the UVM
    system_node
        .insert_egress_reject_rule_for_outcalls_adapter(httpbin_socket_addr)
        .expect("Failed to add reject firewall rule on system node");

    // Direct connection is blocked. Hence the request should go through the API boundary node.
    // Verify that the outcall works and returns the expected IP address (that of the API boundary node).
    let apibn_ip = env
        .topology_snapshot()
        .api_boundary_nodes()
        .next()
        .unwrap()
        .get_ip_addr()
        .to_string();
    assert_outcall_result(&logger, &proxy_canister_system, &webserver_url, apibn_ip);

    // Now allow direct connection again.
    system_node
        .insert_egress_accept_rule_for_outcalls_adapter(httpbin_socket_addr)
        .expect("Failed to add accept firewall rule on system node");

    // Direct connection is allowed again. Hence the request should go directly to the webserver.
    // Verify that the outcall works and returns the expected IP address (that of the system node itself).
    assert_outcall_result(
        &logger,
        &proxy_canister_system,
        &webserver_url,
        system_node.get_ip_addr().to_string(),
    );
}

// Makes a non replicated outcall from the given proxy canister to the given webserver URL
// Asserts that the response code is 200 and that the body matches the expected body.
fn assert_outcall_result(
    logger: &Logger,
    proxy_canister_system: &Canister<'_>,
    webserver_url: &str,
    expected_body: String,
) {
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
            let res = proxy_canister_system
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
                    assert_eq!(response.body, expected_body);
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
