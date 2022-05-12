/* tag::catalog[]
Title:: Bitcoin integration test
end::catalog[] */

use std::io::Read;
use std::net::IpAddr;

use crate::nns::NnsExt;
use crate::util::{self /* runtime_from_url */};
// use canister_test::Project;
// use dfn_candid::candid;
use crate::driver::pot_dsl::get_ic_handle_and_ctx;
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, SshSession, ADMIN,
};
use crate::driver::universal_vm::UniversalVms;
use crate::{
    driver::ic::{InternetComputer, Subnet},
    driver::universal_vm::UniversalVm,
};
use ic_registry_subnet_features::{BitcoinFeature, SubnetFeatures};
use ic_registry_subnet_type::SubnetType;
use slog::info;

const UNIVERSAL_VM_NAME: &str = "btc-node";

pub fn config(env: TestEnv) {
    let activate_script = r#"#!/bin/sh
docker volume create --name=bitcoind-data
docker run -v bitcoind-data:/bitcoin/.bitcoin --name=bitcoind-node -d \
  -p 8333:8333 \
  -p 127.0.0.1:8332:8332 \
  kylemanna/bitcoind
"#;
    let config_dir = env
        .single_activate_script_config_dir(UNIVERSAL_VM_NAME, activate_script)
        .unwrap();

    UniversalVm::new(String::from(UNIVERSAL_VM_NAME))
        .with_config_dir(config_dir)
        .start(&env)
        .expect("failed to setup universal VM");

    let deployed_universal_vm = env.get_deployed_universal_vm(UNIVERSAL_VM_NAME).unwrap();
    let universal_vm = deployed_universal_vm.get_vm().unwrap();
    let btc_node_ipv6 = universal_vm.ipv6;

    InternetComputer::new()
        .with_bitcoind_addr(IpAddr::V6(btc_node_ipv6))
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_features(SubnetFeatures {
                    bitcoin_testnet_feature: Some(BitcoinFeature::Enabled),
                    ..SubnetFeatures::default()
                })
                .add_nodes(1),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

pub fn test(env: TestEnv) {
    let logger = env.logger();
    info!(&logger, "Checking readiness of all nodes...");
    for subnet in env.topology_snapshot().subnets() {
        for node in subnet.nodes() {
            node.await_status_is_healthy().unwrap();
        }
    }

    // SSH to universal-VM example:
    info!(
        logger,
        "Executing the uname -a command on the universal VM via SSH..."
    );
    let deployed_universal_vm = env.get_deployed_universal_vm(UNIVERSAL_VM_NAME).unwrap();
    let sess = deployed_universal_vm.block_on_ssh_session(ADMIN).unwrap();
    let mut channel = sess.channel_session().unwrap();
    channel.exec("uname -a").unwrap();
    let mut s = String::new();
    channel.read_to_string(&mut s).unwrap();
    info!(logger, "{}", s);
    channel.wait_close().unwrap();
    info!(logger, "{}", channel.exit_status().unwrap());

    // TODO: adapt the test below to use the env directly
    // instead of using the deprecated IcHandle and Context.
    let (handle, ctx) = get_ic_handle_and_ctx(env);

    // Install NNS canisters
    ctx.install_nns_canisters(&handle, true);
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    let mut rng = ctx.rng.clone();

    let app_endpoint = util::get_random_application_node_endpoint(&handle, &mut rng);
    rt.block_on(app_endpoint.assert_ready(&ctx));
    info!(&logger, "App endpoint reachable over http.");

    /*
    info!(&logger, "Building btc test canister wasm...");
    let wasm = Project::cargo_bin_maybe_use_path_relative_to_rs(
        "rust_canisters/btc",
        "btc-test-canister",
        &[],
    );

    info!(&logger, "Installing btc test canister...");
    rt.block_on(async {
        let crt = runtime_from_url(app_endpoint.clone().url);
        let canister = wasm
            .clone()
            .install_(&crt, vec![])
            .await
            .unwrap_or_else(|_| panic!("Installation of the btc test canister failed.",));

        let query_input = (); // ("BTC_address", ..);
        let query_result1: i32 = canister
            .query_("balance_query_call", candid, query_input)
            .await
            .unwrap_or_else(|_| panic!("Btc test canister query failed."));

        let amount = 3;
        let update_input = ("BTC_address", amount);
        let _update_result = canister
            .query_("transfer_update_call", candid, update_input)
            .await
            .unwrap_or_else(|_| panic!("Btc test canister update failed."));

        tokio::time::sleep(std::time::Duration::from_secs(100)).await;
        let query_result2: i32 = canister
            .query_("balance_query_call", candid, query_input)
            .await
            .unwrap_or_else(|_| panic!("Btc test canister query failed."));

        assert_eq!(query_result2 - query_result1, amount);
    });
    */
}
