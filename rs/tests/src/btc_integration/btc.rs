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

use std::io::Read;
use std::net::{IpAddr, SocketAddr};

use crate::driver::pot_dsl::get_ic_handle_and_ctx;
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, SshSession, ADMIN,
};
use crate::driver::universal_vm::UniversalVms;
use crate::nns::NnsExt;
use crate::util::{self, *};
use crate::{
    driver::ic::{InternetComputer, Subnet},
    driver::universal_vm::UniversalVm,
};
use candid::Decode;
use ic_btc_types::Network;
use ic_registry_subnet_features::{BitcoinFeature, BitcoinFeatureStatus, SubnetFeatures};
use ic_registry_subnet_type::SubnetType;
use ic_universal_canister::{management, wasm};
use slog::info;
use ssh2::Session;
use std::{fs::File, io::Write};

const UNIVERSAL_VM_NAME: &str = "btc-node";
const MAX_RETRIES: usize = 10;

pub fn config(env: TestEnv) {
    // Regtest bitcoin node listens on 18444
    // docker bitcoind image uses 8332 for the rpc server
    // https://en.bitcoinwiki.org/wiki/Running_Bitcoind
    let activate_script = r#"#!/bin/sh
docker volume create --name=bitcoind-data
cp /config/bitcoin.conf /tmp/bitcoin.conf
docker run -v bitcoind-data:/bitcoin/.bitcoin --name=bitcoind-node -d \
  --privileged \
  -p 8332:8332 \
  -p 18444:18444 \
  -v /tmp/bitcoin.conf:/bitcoin/.bitcoin/bitcoin.conf \
  kylemanna/bitcoind
"#;
    let config_dir = env
        .single_activate_script_config_dir(UNIVERSAL_VM_NAME, activate_script)
        .unwrap();

    let bitcoin_conf_path = config_dir.join("bitcoin.conf");
    let mut bitcoin_conf = File::create(&bitcoin_conf_path).unwrap();
    bitcoin_conf.write_all(r#"
    # Enable regtest mode. This is required to setup a private bitcoin network.
    regtest=1

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

fn exec_command_in_docker_container(session: &Session, command: &str) -> String {
    let docker_command = String::from("docker exec bitcoind-node ") + command;
    let mut channel = session.channel_session().unwrap();
    channel.exec(&docker_command).unwrap();
    let mut stdout = String::new();
    channel.read_to_string(&mut stdout).unwrap();
    let mut stderr = String::new();
    match channel.exit_status() {
        // Exit code == 0, command should have worked.
        Ok(0) => (),
        // Exit code != 0, some error has happened. Stop the test execution and
        // get the error from stderr to log it.
        Ok(_) => {
            channel.stderr().read_to_string(&mut stderr).unwrap();
            panic!("Could not execute ssh command: {}", stderr);
        }
        Err(err) => {
            panic!("Could not get the exit code of ssh command: {}", err);
        }
    }
    channel.wait_close().unwrap();
    // Ensure no leading/trailing whitespaces that might affect parsing of output
    // or can create errors if the output is used as input to api calls.
    String::from(stdout.trim())
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
    let sess = deployed_universal_vm.block_on_ssh_session(ADMIN).unwrap();

    // Create a wallet.
    exec_command_in_docker_container(
        &sess,
        "bitcoin-cli -conf=/bitcoin/.bitcoin/bitcoin.conf --rpcport=8332 createwallet mywallet",
    );

    // Generate an address.
    let btc_address = exec_command_in_docker_container(
        &sess,
        "bitcoin-cli -conf=/bitcoin/.bitcoin/bitcoin.conf --rpcport=8332 getnewaddress",
    );

    // Mint some blocks for the address we generated.
    exec_command_in_docker_container(
        &sess,
        &format!(
            "bitcoin-cli -conf=/bitcoin/.bitcoin/bitcoin.conf --rpcport=8332 generatetoaddress 101 {}",
            btc_address
        ),
    );

    // We have minted 101 blocks and each one gives 50 bitcoin to the target address,
    // so in total the balance of the address without setting `any min_confirmations`
    // should be 50 * 101 = 5050 bitcoin or 505000000000 satoshis.
    let expected_balance_in_satoshis = 5050_0000_0000_u64;

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

    rt.block_on({
        async move {
            let agent = assert_create_agent(app_endpoint.url.as_str()).await;

            let canister = UniversalCanister::new(&agent).await;

            let mut iterations = 0;
            loop {
                let res = canister
                    .update(wasm().call(management::bitcoin_get_balance(btc_address.clone(), None)))
                    .await
                    .map(|res| Decode!(res.as_slice(), u64))
                    .unwrap()
                    .unwrap();

                if res == expected_balance_in_satoshis {
                    break;
                }

                if iterations > MAX_RETRIES {
                    panic!(
                        "IC balance {:?} does not match bitcoind balance {}",
                        res, expected_balance_in_satoshis
                    );
                }

                std::thread::sleep(std::time::Duration::from_secs(1));
                iterations += 1;
            }
        }
    })
}
