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
use anyhow::anyhow;
use canister_http::*;
use dfn_candid::candid_one;
use ic_cdk::api::call::RejectionCode;
use ic_management_canister_types_private::{HttpMethod, TransformContext, TransformFunc};
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::test_env_api::HasTopologySnapshot;
use ic_system_test_driver::driver::test_env_api::IcNodeSnapshot;
use ic_system_test_driver::driver::test_env_api::SshSession;
use ic_system_test_driver::driver::universal_vm::*;
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
use slog::info;
use slog::Logger;
use std::net::{IpAddr, ToSocketAddrs};

// NOTE: This test is currently non-functional because API boundary nodes running GuestOS on Farm VMs do not support IPv4.
fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;

    Ok(())
}

fn upgrade_fw(logger: &Logger, nodes: &[IcNodeSnapshot], target_hostname: &str) -> Result<()> {
    let target_ipv6 = (target_hostname, 443) 
        .to_socket_addrs()?
        .filter_map(|addr| if addr.is_ipv6() { Some(addr.ip()) } else { None })
        .next()
        .ok_or_else(|| anyhow!("Could not resolve IPv6 for {}", target_hostname))?;
    info!(logger, "Resolved '{}' to IPv6: {}", target_hostname, target_ipv6);

    for node in nodes {
        info!(logger, "--- Configuring Node {} for Fallback Test ---", node.node_id);

        let read_script = r#"
            echo "--- Current OUTPUT Chain Rules: ---"
            sudo ip6tables -L OUTPUT -v -n --line-numbers
            echo "-------------------------------------"
        "#;
        match node.block_on_bash_script(read_script) {
            Ok(initial_rules) => info!(logger, "Initial firewall state for node {}:\n{}", node.node_id, initial_rules),
            Err(e) => info!(logger, "Warning: Could not read initial firewall rules for node {}: {:?}", node.node_id, e),
        }

        // === Step 2: Add the new blocking rule ===
        let add_rule_script = format!(
            r#"
            set -e
            # Get the UID of the user running the adapter
            ADAPTER_UID=$(id -u ic-http-adapter)
            echo "Found UID for ic-http-adapter: $ADAPTER_UID"
            
            echo "Inserting DROP rule for destination {} at the top of the OUTPUT chain..."
            # Insert a rule at the top of the OUTPUT chain to drop packets from our specific user
            # to the target IP. Using -I ensures it's evaluated before existing rules.
            sudo ip6tables -I OUTPUT 1 -m owner --uid-owner $ADAPTER_UID -p tcp -d "{}" -j DROP
            echo "Rule added successfully."
            "#,
            target_ipv6, target_ipv6
        );

        node.block_on_bash_script(&add_rule_script)?;
        info!(logger, "✅ Firewall rule ADDED to node {}", node.node_id);
    }
    Ok(())
}

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
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
    // Get application subnet node to deploy canister to.
    let mut nodes = get_node_snapshots(&env);
    let node = nodes.next().expect("there is no application node");
    let runtime = get_runtime_from_node(&node);
    let _ = create_proxy_canister(&env, &runtime, &node);
    // Set up Universal VM with HTTP Bin testing service
    UniversalVm::new(String::from(UNIVERSAL_VM_NAME))
        .with_config_img(get_dependency_path(
            "rs/tests/networking/canister_http/http_uvm_config_image.zst",
        ))
        .enable_ipv4()
        .start(&env)
        .expect("failed to set up universal VM");

    start_httpbin_on_uvm(&env);
}

pub fn setup_(env: TestEnv) {
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

    // Create IC with injected socks proxy.
    InternetComputer::new()
        // .with_socks_proxy(format!("socks5://[{ipv6}]:1080"))
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
        .with_api_boundary_nodes(1)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    await_nodes_healthy(&env);
    install_nns_canisters(&env);
}

pub fn test(env: TestEnv) {

    let apibn_ip = env.topology_snapshot().api_boundary_nodes().next().unwrap().get_ip_addr();
    
    let logger = env.logger();
    info!(logger, "API boundary node IP address: {}", apibn_ip.to_string());
    let webserver_ipv6 = get_universal_vm_address(&env);
    //let webserver_url = format!("https://[{webserver_ipv6}]:20443");
    let webserver_url = "https://ifconfig.me/ip";

    let universal_vm = env.get_deployed_universal_vm(UNIVERSAL_VM_NAME).unwrap();
    // match universal_vm.activate_fw(&x.to_string()) {
    //     Ok(v) => info!(logger, "Activated firewall rule on universal VM: {}", v),
    //     Err(e) => info!(logger, "Failed to activate firewall rule on universal VM: {}", e),
    // }

    let mut system_nodes = get_system_subnet_node_snapshots(&env);
    let system_node = system_nodes.next().expect("there is no system subnet node");

    //TODO(urgent): don't clone
    match upgrade_fw(&logger, &[system_node.clone()], "ifconfig.me") {
        Ok(_) => info!(logger, "Upgraded firewall rules on system node"),
        Err(e) => info!(logger, "Failed to upgrade firewall rules on system node: {}", e),
    }

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
                            is_replicated: None,
                        },
                        cycles: 500_000_000_000,
                    },
                )
                .await
                .expect("Update call to proxy canister failed");
            if !matches!(res, Ok(ref x) if x.status == 200) {
                bail!("Http request failed response: {:?}", res);
                //info!(&logger, "Http request failed response: {:?}", res);
            }
            info!(&logger, "Update call succeeded! {:?}", res);
            match res {
                Ok(response) => {
                    info!(logger, "Response body: {}", response.body);
                    info!(logger, "Expected API boundary node IP: {}", apibn_ip.to_string());
                    //assert!(response.body == apibn_ip.to_string())
                },
                Err((code, message)) => info!(logger, "Error code: {:?}, message: {}", code, message),
            }
            Ok(())
        }
    ))
    .expect("Failed to call proxy canister");
}

pub fn test_(env: TestEnv) {
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
                        request: UnvalidatedCanisterHttpRequestArgs {
                            url: webserver_url.to_string(),
                            headers: vec![],
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
                            is_replicated: None,
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
                        request: UnvalidatedCanisterHttpRequestArgs {
                            url: webserver_url.to_string(),
                            headers: vec![],
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
                            is_replicated: None,
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
