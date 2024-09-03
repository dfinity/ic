use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::HasPublicApiUrl;
use ic_system_test_driver::driver::test_env_api::HasTopologySnapshot;
use ic_system_test_driver::driver::test_env_api::IcNodeContainer;
use ic_system_test_driver::driver::universal_vm::UniversalVms;
use ic_system_test_driver::{
    driver::ic::{InternetComputer, Subnet},
    driver::universal_vm::UniversalVm,
};
use ic_types::Height;
use std::net::{IpAddr, SocketAddr};
use std::{fs::File, io::Write};

const UNIVERSAL_VM_NAME: &str = "btc-node";

pub fn config(env: TestEnv) {
    // Regtest bitcoin node listens on 18444
    // docker bitcoind image uses 8332 for the rpc server
    // https://en.bitcoinwiki.org/wiki/Running_Bitcoind
    let activate_script = r"#!/bin/sh
cp /config/bitcoin.conf /tmp/bitcoin.conf
docker run  --name=bitcoind-node -d \
  --net=host \
  -v /tmp:/bitcoin/.bitcoin \
  kylemanna/bitcoind@sha256:17c7dd21690f3be34630db7389d2f0bff14649e27a964afef03806a6d631e0f1 \
  -rpcbind=[::]:8332 -rpcallowip=::/0
";
    let config_dir = env
        .single_activate_script_config_dir(UNIVERSAL_VM_NAME, activate_script)
        .unwrap();

    let bitcoin_conf_path = config_dir.join("bitcoin.conf");
    let mut bitcoin_conf = File::create(bitcoin_conf_path).unwrap();
    bitcoin_conf.write_all(r#"
    # Enable regtest mode. This is required to setup a private bitcoin network.
    regtest=1
    debug=1
    whitelist=::/0
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
        .enable_ipv4()
        .start(&env)
        .expect("failed to setup universal VM");

    let deployed_universal_vm = env.get_deployed_universal_vm(UNIVERSAL_VM_NAME).unwrap();
    let universal_vm = deployed_universal_vm.get_vm().unwrap();
    let btc_node_ipv6 = universal_vm.ipv6;

    InternetComputer::new()
        .with_bitcoind_addr(SocketAddr::new(IpAddr::V6(btc_node_ipv6), 18444))
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(10))
                .add_nodes(1),
        )
        .use_specified_ids_allocation_range()
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}
