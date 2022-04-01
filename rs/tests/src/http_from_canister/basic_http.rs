/* tag::catalog[]
Title:: Basic HTTP requests from canisters

Goal:: Ensure simple HTTP requests can be made from canisters.

Runbook::
0. Instantiate a universal VM with a webserver
1. Instantiate an IC with one applications subnet with the HTTP feature enabled.
2. Install NNS canisters
3. Install the universal canister
4. Make a query to the universal canister
5. Make an update call to the universal canister
6. Make a query to the universal canister

Success::
1. Result of last query returns what the update call put in the canister.

 (TODO replace steps 3-6 and succes criteria with meaningful content)

end::catalog[] */

use std::fs::{self, File};
use std::io::Write;
use std::net::Ipv6Addr;

use crate::nns::NnsExt;
use crate::util::{self /* runtime_from_url */};
// use canister_test::Project;
// use dfn_candid::candid;
use crate::driver::pot_dsl::get_ic_handle_and_ctx;
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::{DefaultIC, HasPublicApiUrl, IcNodeContainer};
use crate::driver::universal_vm::UniversalVms;
use crate::util::UniversalCanister;
use crate::{
    driver::ic::{InternetComputer, Subnet},
    driver::universal_vm::UniversalVm,
};
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use slog::{info, Logger};

const UNIVERSAL_VM_NAME: &str = "webserver";

pub fn config(env: TestEnv) {
    let activate_script = r#"#!/bin/sh
        docker run \
        -it --rm -d \
        -p 80:80 \
        --name web \
        -v /config/web-root:/usr/share/nginx/html \
        nginx"#;
    let config_dir = env
        .single_activate_script_config_dir(UNIVERSAL_VM_NAME, activate_script)
        .unwrap();

    let web_root_path = config_dir.join("web-root");
    fs::create_dir_all(web_root_path.clone()).unwrap();
    let index_path = web_root_path.join("index.html");
    let mut index_file = File::create(&index_path).unwrap();
    let index_html = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Docker Nginx running in Universal Farm VM</title>
</head>
<body>
  <h2>Hello from Nginx container running in a Universal Farm VM</h2>
</body>
</html>"#;
    index_file.write_all(index_html.as_bytes()).unwrap();
    index_file.sync_all().unwrap();

    UniversalVm::new(String::from(UNIVERSAL_VM_NAME))
        .with_config_dir(config_dir)
        .start(&env)
        .expect("failed to setup universal VM");

    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(4))
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
}

pub fn test(env: TestEnv, logger: Logger) {
    info!(&logger, "Checking readiness of all nodes...");
    for subnet in env.topology_snapshot().subnets() {
        for node in subnet.nodes() {
            node.await_status_is_healthy().unwrap();
        }
    }
    let webserver_ipv6: Ipv6Addr = env
        .universal_vm(UNIVERSAL_VM_NAME)
        .expect("No webserver found")
        .ipv6;
    info!(&logger, "Webserver has IPv6 {:?}", webserver_ipv6);

    let webserver_ipv4 = env.await_universal_vm_ipv4(UNIVERSAL_VM_NAME).unwrap();
    info!(&logger, "Webserver has IPv4 {:?}", webserver_ipv4);

    // TODO: adapt the test below to use the env directly
    // instead of using the deprecated IcHandle and Context.
    let (handle, ctx) = get_ic_handle_and_ctx(env, logger.clone());

    // Install NNS canisters
    ctx.install_nns_canisters(&handle, true);
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    let mut rng = ctx.rng.clone();

    let app_endpoint = util::get_random_application_node_endpoint(&handle, &mut rng);
    rt.block_on(app_endpoint.assert_ready(&ctx));
    info!(&logger, "App endpoint reachable over http.");

    let agent = rt.block_on(util::assert_create_agent(app_endpoint.url.as_str()));

    rt.block_on(async {
        info!(&logger, "Install canister...");
        let ucan = UniversalCanister::new(&agent).await;
        // If you don't want to work with universal canister you can deploy
        // your custom canister, see xnet_slo_test.rs or cow_safety_test.rs for
        // examples demonstrating how to interact with custom Rust and Motoko canisters

        info!(&logger, "Submitting a first query...");
        assert_eq!(ucan.try_read_stable(0, 0).await, Vec::<u8>::new());

        info!(&logger, "Send an update call...");
        const MSG: &[u8] = b"this beautiful prose should be persisted for future generations";
        ucan.store_to_stable(0, MSG).await;
        // In this test, you probably want to replace this with an update call which passes
        // the IP address of the webserver abd issues a HTTP request

        info!(
            &logger,
            "Make another query to check if the call was successful..."
        );
        assert_eq!(
            ucan.try_read_stable(0, MSG.len() as u32).await,
            MSG.to_vec()
        );
        // You can either check the result of the update call directly or with a query
        // submitted later
    });
}
