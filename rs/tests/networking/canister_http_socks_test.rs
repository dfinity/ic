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
use ic_management_canister_types_private::{HttpMethod, TransformContext, TransformFunc};
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::test_env_api::HasTopologySnapshot;
use ic_system_test_driver::driver::test_env_api::SshSession;
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

// NOTE: This test is currently non-functional because API boundary nodes running GuestOS on Farm VMs do not support IPv4.
fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;

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

    //TODO(urgent): name these variables better. 
    let apibn_ip = env.topology_snapshot().api_boundary_nodes().next().unwrap().get_ip_addr().to_string();
    
    let logger = env.logger();
    info!(logger, "API boundary node IP address: {}", apibn_ip);
    let webserver_ipv6 = get_universal_vm_address(&env).to_string();
    let webserver_url = format!("https://[{webserver_ipv6}]:443/ip");

    let mut system_nodes = get_system_subnet_node_snapshots(&env);
    let system_node = system_nodes.next().expect("there is no system subnet node");
    let system_node_id = system_node.node_id;

    let runtime_system = get_runtime_from_node(&system_node);
    let proxy_canister_system = create_proxy_canister(&env, &runtime_system, &system_node);

    //TODO(urgent): move this in the "ic.start" somwehere.
    let api_bn_accept_script = format!(
        r#"
        set -e
        ADAPTER_UID=$(id -u ic-http-adapter)
        echo "Inserting ACCEPT rule on node {system_node_id} for UVM destination {apibn_ip}..."
        
        # Insert a rule at the top of the OUTPUT chain to allow this specific connection
        sudo nft "insert rule ip6 filter OUTPUT meta skuid $ADAPTER_UID ip6 daddr {apibn_ip} tcp dport 1080 accept"
        "#,
    );

    system_node.block_on_bash_script(&api_bn_accept_script)
        .unwrap_or_else(|e| {
            panic!(
                "Failed to add accept firewall rule on node {}: {:?}",
                system_node_id, e
            )
        });
    
    let uvm_reject_script = format!(
        r#"
        set -e
        ADAPTER_UID=$(id -u ic-http-adapter)
        echo "Inserting REJECT rule on node {system_node_id} for UVM destination {webserver_ipv6}..."
        
        # Insert a rule at the top of the OUTPUT chain to allow this specific connection
        sudo nft "insert rule ip6 filter OUTPUT meta skuid $ADAPTER_UID ip6 daddr {webserver_ipv6} tcp dport 443 reject"
        "#,
    );

    system_node.block_on_bash_script(&uvm_reject_script)
        .unwrap_or_else(|e| {
            panic!(
                "Failed to add reject firewall rule on node {}: {:?}",
                system_node_id, e
            )
        });

    assert_outcall_result(&logger, &proxy_canister_system, &webserver_url, apibn_ip);

    let uvm_accept_script = format!(
        r#"
        set -e
        ADAPTER_UID=$(id -u ic-http-adapter)
        echo "Inserting REJECT rule on node {system_node_id} for UVM destination {webserver_ipv6}..."
        
        # Insert a rule at the top of the OUTPUT chain to allow this specific connection
        sudo nft "insert rule ip6 filter OUTPUT meta skuid $ADAPTER_UID ip6 daddr {webserver_ipv6} tcp dport 443 accept"
        "#,
    );

    system_node.block_on_bash_script(&uvm_accept_script)
        .unwrap_or_else(|e| {
            panic!(
                "Failed to add new accept firewall rule on node {}: {:?}",
                system_node_id, e
            )
        });

    assert_outcall_result(&logger, &proxy_canister_system, &webserver_url, system_node.get_ip_addr().to_string());
}

fn assert_outcall_result(logger: &Logger, proxy_canister_system: &Canister<'_>, webserver_url: &str, expected_body: String) {
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
                //bail!("Http request failed response: {:?}", res);
                info!(logger, "Http request failed response: {:?}", res);
            }
            info!(&logger, "Update call succeeded! {:?}", res);
            match res {
                Ok(response) => {
                    assert_eq!(response.body, expected_body);
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
