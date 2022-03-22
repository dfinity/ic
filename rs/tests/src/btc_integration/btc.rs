/* tag::catalog[]
Title:: Bitcoin integration test
end::catalog[] */

use anyhow::Result;
use ic_fondue::prod_tests::test_env::TestEnv;
use ic_fondue::prod_tests::test_setup::{DefaultIC, HasPublicApiUrl, IcNodeContainer};
use ic_fondue::prod_tests::universal_vm::UniversalVms;
use ic_fondue::{
    prod_tests::ic::{InternetComputer, Subnet},
    prod_tests::universal_vm::UniversalVm,
};
use ic_registry_subnet_features::{BitcoinFeature, SubnetFeatures};
use ic_registry_subnet_type::SubnetType;
use slog::{info, Logger};
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::prelude::PermissionsExt;
use std::path::PathBuf;

// use std::thread::sleep;
// use std::time::Duration;

const UNIVERSAL_VM_NAME: &str = "btc-node";

pub fn config(env: TestEnv) {
    let activate_script = r#"#!/bin/sh
docker volume create --name=bitcoind-data
docker run -v bitcoind-data:/bitcoin/.bitcoin --name=bitcoind-node -d \
  -p 8333:8333 \
  -p 127.0.0.1:8332:8332 \
  kylemanna/bitcoind
"#;
    let config_dir =
        single_activate_script_config_dir(&env, UNIVERSAL_VM_NAME, activate_script).unwrap();

    UniversalVm::new(String::from(UNIVERSAL_VM_NAME))
        .with_config_dir(config_dir)
        .start(&env)
        .expect("failed to setup universal VM");

    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(4))
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_features(SubnetFeatures {
                    bitcoin_testnet_feature: Some(BitcoinFeature::Enabled),
                    ..SubnetFeatures::default()
                })
                .add_nodes(4),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

const CONFIG_DIR_NAME: &str = "config_dir";

fn single_activate_script_config_dir(
    env: &TestEnv,
    universal_vm_name: &str,
    activate_script: &str,
) -> Result<PathBuf> {
    let p: PathBuf = ["universal_vms", universal_vm_name, CONFIG_DIR_NAME]
        .iter()
        .collect();
    let config_dir = env.get_path(p);
    fs::create_dir_all(config_dir.clone())?;

    let activate_path = config_dir.join("activate");

    let mut activate_file = File::create(&activate_path)?;
    activate_file.write_all(activate_script.as_bytes())?;
    let metadata = activate_file.metadata()?;
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(activate_path, permissions)?;
    activate_file.sync_all()?;
    Ok(config_dir)
}

pub fn test(env: TestEnv, logger: Logger) {
    let btc_node_ipv6 = env.universal_vm(UNIVERSAL_VM_NAME).expect("foo").ipv6;

    info!(&logger, "BTC Node has IPv6 {:?}", btc_node_ipv6);

    info!(&logger, "Checking readiness of all nodes...");
    for subnet in env.topology_snapshot().subnets() {
        for node in subnet.nodes() {
            node.await_status_is_healthy().unwrap();
        }
    }

    // sleep(Duration::from_secs(15 * 60));

    /*
     // Install NNS canisters
     ctx.install_nns_canisters(&handle, true);
     let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
     let mut rng = ctx.rng.clone();

     let app_endpoint = util::get_random_application_node_endpoint(&handle, &mut rng);
     rt.block_on(app_endpoint.assert_ready(ctx));
     info!(ctx.logger, "App endpoint reachable over http.");

     info!(ctx.logger, "Building btc test canister wasm...");
     let wasm = Project::cargo_bin_maybe_use_path_relative_to_rs(
         "rust_canisters/btc",
         "btc-test-canister",
         &[],
     );

     info!(ctx.logger, "Installing btc test canister...");
     let canister = wasm
                     .clone()
                     .install_(&runtime_from_url(app_endpoint.url), vec![])
                     .await
                     .unwrap_or_else(|_| {
                         panic!(
                             "Installation of the btc test canister failed.",
                         )
                     });

     let query_input = ("BTC_address", ..);
     let query_result1 = canister
         .query_("balance_query_call", candid, query_input)
         .await
         .unwrap_or_else(|_| {panic!("Btc test canister query failed.")});

     let amount = 3;
     let udpate_input = ("BTC_address", amount);
     let _update_result = canister
         .query_("transfer_update_call", candid, ())
         .await
         .unwrap_or_else(|_| {panic!("Btc test canister update failed.")});

     tokio::time::sleep(std::time::Duration::from_secs(100)).await;

     let query_result2 = canister
             .query_("balance_query_call", candid, query_input)
             .await
             .unwrap_or_else(|_| {panic!("Btc test canister query failed.")});

     assert(query_result2-query_result1, amount);
    */
}
