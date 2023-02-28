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

use crate::canister_http::lib::*;
use crate::driver::boundary_node::{BoundaryNode, BoundaryNodeVm};
use crate::driver::{
    ic::{InternetComputer, Subnet},
    test_env::TestEnv,
    test_env_api::{retry_async, HasGroupSetup, READY_WAIT_TIMEOUT, RETRY_BACKOFF},
    universal_vm::{insert_file_to_config, UniversalVm, UniversalVms},
};
use crate::util::block_on;
use anyhow::bail;
use dfn_candid::candid_one;
use ic_cdk::api::call::RejectionCode;
use ic_ic00_types::{CanisterHttpRequestArgs, HttpMethod, TransformContext, TransformFunc};
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use proxy_canister::{RemoteHttpRequest, RemoteHttpResponse};
use slog::info;
use std::io::Write;
use tempfile::NamedTempFile;

const BN_NAME: &str = "socks-bn";

// A valid NNS public key (mainnet). Could also be any other valid public key, it does not matter for the test.
// It is only needed because BN configuration requires a correctly formated key.
const PUB_KEY: &str = "
-----BEGIN PUBLIC KEY-----
MIGCMB0GDSsGAQQBgtx8BQMBAgEGDCsGAQQBgtx8BQMCAQNhAKyelsUDvp1A6h1+
RpPIq75fEGzjGnSTZWq/aWyftJXmLBv1HIT+TEeCX6Aj3SLPrgLPXPqhvSLQesaJ
5JKpuGUZkX/RWnYWa1Eklh8gXUtdeGUIJUS+F36Du7OCOHUsIQ==
-----END PUBLIC KEY-----
";

pub fn config(env: TestEnv) {
    let logger = env.logger();
    env.ensure_group_setup_created();

    // Set up Universal VM with HTTP Bin testing service
    let activate_script = &get_universal_vm_activation_script(&env)[..];
    let config_dir = env
        .single_activate_script_config_dir(UNIVERSAL_VM_NAME, activate_script)
        .unwrap();
    let _ = insert_file_to_config(
        config_dir.clone(),
        "cert.pem",
        get_pem_content(&env, &PemType::PemCert).as_bytes(),
    );
    let _ = insert_file_to_config(
        config_dir.clone(),
        "key.pem",
        get_pem_content(&env, &PemType::PemKey).as_bytes(),
    );

    UniversalVm::new(String::from(UNIVERSAL_VM_NAME))
        .with_config_dir(config_dir)
        .start(&env)
        .expect("failed to set up universal VM");

    info!(&logger, "Started Universal VM!");

    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "{}", PUB_KEY).unwrap();
    BoundaryNode::new(String::from(BN_NAME))
        //  Panics if not specified. Don't care about these value
        .with_replica_ipv6_rule("::/0".to_string())
        .with_nns_urls(vec!["http://doesnotexist.com".parse().unwrap()])
        .with_nns_public_key(file.path().to_path_buf())
        .start(&env)
        .expect("failed to setup BoundaryNode VM");

    let deployed_boundary_node = env.get_deployed_boundary_node(BN_NAME).unwrap();
    let bn_ipv6 = deployed_boundary_node.get_snapshot().unwrap().ipv6();
    info!(&logger, "Started BN!");

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

    block_on(retry_async(
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
        },
    ))
    .expect("Failed to call proxy canister");

    // Request from application subnet.
    let mut app_nodes = get_node_snapshots(&env);
    let app_node = app_nodes.next().expect("there is no application node");
    let runtime_app = get_runtime_from_node(&app_node);
    let proxy_canister_app = create_proxy_canister(&env, &runtime_app, &app_node);

    block_on(retry_async(
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
        },
    ))
    .expect("Failed to call proxy canister");
}
