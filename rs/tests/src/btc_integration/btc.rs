/* tag::catalog[]
Title:: Bitcoin integration test

Goal:: Test whether we can successfully retrieve the BTC balance of an address on the IC.

Runbook::
. Setup:
    . Bitcoind running in a docker container inside the Universal VM.
    . App subnet with bitcoin feature enabled and setup to talk to bitcoind.
. Create a BTC address
. Mint some blocks giving BTC to the address created
. Assert that a bitcoin_get_balance management call returns the expected value.

Success::
. The balance of the address matches the expected value.

end::catalog[] */

use std::net::{IpAddr, SocketAddr};

use crate::driver::pot_dsl::get_ic_handle_and_ctx;
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::{
    retry, retry_async, HasGroupSetup, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
    NnsInstallationExt, SshSession, ADMIN, READY_WAIT_TIMEOUT, RETRY_BACKOFF,
};
use crate::driver::universal_vm::UniversalVms;
use crate::util::{self, *};
use crate::{
    driver::ic::{InternetComputer, Subnet},
    driver::universal_vm::UniversalVm,
};
use anyhow::bail;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use candid::Decode;
use ic_btc_types::Network;
use ic_registry_subnet_features::{BitcoinFeature, BitcoinFeatureStatus, SubnetFeatures};
use ic_registry_subnet_type::SubnetType;
use ic_types::Height;
use ic_universal_canister::{management, wasm};
use slog::info;
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

const UNIVERSAL_VM_NAME: &str = "btc-node";

pub fn config(env: TestEnv) {
    env.ensure_group_setup_created();

    // Regtest bitcoin node listens on 18444
    // docker bitcoind image uses 8332 for the rpc server
    // https://en.bitcoinwiki.org/wiki/Running_Bitcoind
    let activate_script = r#"#!/bin/sh
cp /config/bitcoin.conf /tmp/bitcoin.conf
docker run  --name=bitcoind-node -d \
  -p 8332:8332 \
  -p 18444:18444 \
  -v /tmp:/bitcoin/.bitcoin \
  registry.gitlab.com/dfinity-lab/open/public-docker-registry/kylemanna/bitcoind
"#;
    let config_dir = env
        .single_activate_script_config_dir(UNIVERSAL_VM_NAME, activate_script)
        .unwrap();

    let bitcoin_conf_path = config_dir.join("bitcoin.conf");
    let mut bitcoin_conf = File::create(&bitcoin_conf_path).unwrap();
    bitcoin_conf.write_all(r#"
    # Enable regtest mode. This is required to setup a private bitcoin network.
    regtest=1
    debug=1
    whitelist=[::]/0
    fallbackfee=0.0002

    # Dummy credentials that are required by `bitcoin-cli`.
    rpcuser=btc-dev-preview
    rpcpassword=Wjh4u6SAjT4UMJKxPmoZ0AN2r9qbE-ksXQ5I2_-Hm4w=
    rpcauth=btc-dev-preview:8555f1162d473af8e1f744aa056fd728$afaf9cb17b8cf0e8e65994d1195e4b3a4348963b08897b4084d210e5ee588bcb
    "#
    .as_bytes()).unwrap();
    bitcoin_conf.sync_all().unwrap();

    UniversalVm::new(String::from(UNIVERSAL_VM_NAME))
        .with_config_dir(config_dir)
        .start(&env)
        .expect("failed to setup universal VM");

    let deployed_universal_vm = env.get_deployed_universal_vm(UNIVERSAL_VM_NAME).unwrap();
    let universal_vm = deployed_universal_vm.get_vm().unwrap();
    let btc_node_ipv6 = universal_vm.ipv6;

    InternetComputer::new()
        .with_bitcoind_addr(SocketAddr::new(IpAddr::V6(btc_node_ipv6), 18444))
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(10))
                .with_features(SubnetFeatures {
                    bitcoin: Some(BitcoinFeature {
                        network: Network::Regtest,
                        status: BitcoinFeatureStatus::Enabled,
                    }),
                    ..SubnetFeatures::default()
                })
                .add_nodes(1),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

fn get_bitcoind_log(env: &TestEnv) {
    let f = || -> Result<(), anyhow::Error> {
        let r = {
            let universal_vm = env.get_deployed_universal_vm(UNIVERSAL_VM_NAME).unwrap();
            let session = universal_vm.block_on_ssh_session(ADMIN).unwrap();

            // Give log file user permission to copy it from the host.
            universal_vm.block_on_bash_script_from_session(
                &session,
                "sudo chown -R $(id -u):$(id -g) /tmp/regtest/debug.log",
            )?;

            // Log file is mapped from docker container to tmp directory.
            let (mut remote_file, _) = session.scp_recv(Path::new("/tmp/regtest/debug.log"))?;

            let mut buf = String::new();
            remote_file.read_to_string(&mut buf)?;
            std::fs::write(env.base_path().join("bitcoind.log"), buf)
        };
        r.map_err(|e| e.into())
    };

    retry(env.logger(), READY_WAIT_TIMEOUT, RETRY_BACKOFF, f).expect("Failed to get bitcoind logs");
}

pub fn get_balance(env: TestEnv) {
    let logger = env.logger();
    info!(&logger, "Checking readiness of all nodes...");
    for subnet in env.topology_snapshot().subnets() {
        for node in subnet.nodes() {
            node.await_status_is_healthy().unwrap();
        }
    }

    let deployed_universal_vm = env.get_deployed_universal_vm(UNIVERSAL_VM_NAME).unwrap();

    let btc_rpc = Client::new(
        &format!(
            "http://[{}]:8332",
            deployed_universal_vm.get_vm().unwrap().ipv6
        ),
        Auth::UserPass(
            "btc-dev-preview".to_string(),
            "Wjh4u6SAjT4UMJKxPmoZ0AN2r9qbE-ksXQ5I2_-Hm4w=".to_string(),
        ),
    )
    .unwrap();

    // Create a wallet.
    let _ = btc_rpc
        .create_wallet("mywallet", None, None, None, None)
        .unwrap();

    // Generate an address.
    let btc_address = btc_rpc.get_new_address(None, None).unwrap();
    info!(&logger, "Created temporary btc address: {}", btc_address);

    // Mint some blocks for the address we generated.
    let block = btc_rpc.generate_to_address(101, &btc_address).unwrap();
    info!(&logger, "Generated {} btc blocks.", block.len());

    // We have minted 101 blocks and each one gives 50 bitcoin to the target address,
    // so in total the balance of the address without setting `any min_confirmations`
    // should be 50 * 101 = 5050 bitcoin or 505000000000 satoshis.
    let expected_balance_in_satoshis = 5050_0000_0000_u64;

    // Install NNS canisters
    info!(logger, "Installing NNS canisters...");
    env.topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap()
        .install_nns_canisters()
        .expect("Could not install NNS canisters");

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    // TODO: adapt the test below to use the env directly
    // instead of using the deprecated IcHandle and Context.
    let (handle, ctx) = get_ic_handle_and_ctx(env.clone());
    let mut rng = ctx.rng.clone();

    let app_endpoint = util::get_random_application_node_endpoint(&handle, &mut rng);
    rt.block_on(app_endpoint.assert_ready(&ctx));

    info!(&logger, "App endpoint reachable over http.");

    let res = rt.block_on(async {
        let agent = assert_create_agent(app_endpoint.url.as_str()).await;
        let canister = UniversalCanister::new(&agent, app_endpoint.effective_canister_id()).await;
        retry_async(&logger, READY_WAIT_TIMEOUT, RETRY_BACKOFF, || async {
            let res = canister
                .update(wasm().call(management::bitcoin_get_balance(
                    btc_address.to_string(),
                    None,
                )))
                .await
                .map(|res| Decode!(res.as_slice(), u64))
                .unwrap()
                .unwrap();

            if res != expected_balance_in_satoshis {
                bail!(
                    "IC balance {:?} does not match bitcoind balance {}",
                    res,
                    expected_balance_in_satoshis
                );
            }

            Ok(res)
        })
        .await
    });
    // blocks
    get_bitcoind_log(&env);
    // We only exit retry loop successfully if we got the expected satoshi balance
    res.expect("Failed to get btc balance");
}
