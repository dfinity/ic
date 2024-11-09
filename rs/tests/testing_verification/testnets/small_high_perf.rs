// Set up a testnet containing:
//   one 1-node System and one 1-node Application subnets, single boundary node, and a p8s (with grafana) VM.
// All replica nodes use the following resources: 64 vCPUs, 480 GiB of RAM, and 2'000 GiB disk.
//
// You can setup this testnet with a lifetime of 180 mins by executing the following commands:
//
//   $ ./ci/tools/docker-run
//   $ ict testnet create small_high_perf --lifetime-mins=180 --output-dir=./small_high_perf -- --test_tmpdir=./small_high_perf
//
// The --output-dir=./small_high_perf will store the debug output of the test driver in the specified directory.
// The --test_tmpdir=./small_high_perf will store the remaining test output in the specified directory.
// This is useful to have access to in case you need to SSH into an IC node for example like:
//
//   $ ssh -i small_high_perf/_tmp/*/setup/ssh/authorized_priv_keys/admin admin@
//
// Note that you can get the  address of the IC node from the ict console output:
//
//   {
//     nodes: [
//       {
//         id: y4g5e-dpl4n-swwhv-la7ec-32ngk-w7f3f-pr5bt-kqw67-2lmfy-agipc-zae,
//         ipv6: 2a0b:21c0:4003:2:5034:46ff:fe3c:e76f
//       }
//     ],
//     subnet_id: 5hv4k-srndq-xgw53-r6ldt-wtv4x-6xvbj-6lvpf-sbu5n-sqied-63bgv-eqe,
//     subnet_type: application
//   },
//
// To get access to P8s and Grafana look for the following lines in the ict console output:
//
//     prometheus: Prometheus Web UI at http://prometheus.small_high_perf--1692597750709.testnet.farm.dfinity.systems,
//     grafana: Grafana at http://grafana.small_high_perf--1692597750709.testnet.farm.dfinity.systems,
//     progress_clock: IC Progress Clock at http://grafana.small_high_perf--1692597750709.testnet.farm.dfinity.systems/d/ic-progress-clock/ic-progress-clock?refresh=10su0026from=now-5mu0026to=now,
//
// Happy testing!

use anyhow::Result;

use ic_consensus_system_test_utils::rw_message::install_nns_with_customizations_and_check_progress;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::{
    boundary_node::BoundaryNode,
    group::SystemTestGroup,
    ic::{AmountOfMemoryKiB, ImageSizeGiB, InternetComputer, NrOfVCPUs, Subnet, VmResources},
    prometheus_vm::{HasPrometheus, PrometheusVm},
    test_env::TestEnv,
    test_env_api::{
        await_boundary_node_healthy, get_dependency_path, HasPublicApiUrl, HasTopologySnapshot,
        IcNodeContainer, IcNodeSnapshot, NnsCustomizations, NnsInstallationBuilder, SubnetSnapshot,
    },
    universal_vm::{UniversalVm, UniversalVms},
};

use slog::{debug, info, Logger};
use std::{
    fs::File,
    io::Write,
    net::{IpAddr, SocketAddr},
};

const BOUNDARY_NODE_NAME: &str = "boundary-node-1";

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .execute_from_args()?;
    Ok(())
}

const UNIVERSAL_VM_NAME: &str = "btc-node";

pub fn setup(env: TestEnv) {
    PrometheusVm::default()
        .start(&env)
        .expect("Failed to start prometheus VM");

    //     // Regtest (switched to testnet) bitcoin node listens on 18444
    //     // docker bitcoind image uses 8332 for the rpc server
    //     // https://en.bitcoinwiki.org/wiki/Running_Bitcoind
    //     let activate_script = r"#!/bin/sh
    // cp /config/bitcoin.conf /tmp/bitcoin.conf
    // docker run  --name=bitcoind-node -d \
    //   --net=host \
    //   -v /tmp:/bitcoin/.bitcoin \
    //   ghcr.io/dfinity/bitcoind@sha256:17c7dd21690f3be34630db7389d2f0bff14649e27a964afef03806a6d631e0f1 -rpcbind=[::]:8332 -rpcallowip=::/0
    // ";
    //     let config_dir = env
    //         .single_activate_script_config_dir(UNIVERSAL_VM_NAME, activate_script)
    //         .unwrap();

    //     let bitcoin_conf_path = config_dir.join("bitcoin.conf");
    //     let mut bitcoin_conf = File::create(bitcoin_conf_path).unwrap();
    //     bitcoin_conf.write_all(r#"
    //     # Enable testnet mode. This is required to setup a private bitcoin network.
    //     chain=test
    //     # debug=1
    //     # whitelist=::/0
    //     # fallbackfee=0.0002

    //     # Dummy credentials that are required by `bitcoin-cli`.
    //     rpcuser=ic-btc-integration
    //     rpcpassword=QPQiNaph19FqUsCrBRN0FII7lyM26B51fAMeBQzCb-E=
    //     rpcauth=ic-btc-integration:cdf2741387f3a12438f69092f0fdad8e\$62081498c98bee09a0dce2b30671123fa561932992ce377585e8e08bb0c11dfa
    //     "#
    //     .as_bytes()).unwrap();
    //     bitcoin_conf.sync_all().unwrap();

    //     UniversalVm::new(String::from(UNIVERSAL_VM_NAME))
    //         .with_config_dir(config_dir)
    //         .enable_ipv4()
    //         .start(&env)
    //         .expect("failed to setup universal VM");

    //     let deployed_universal_vm = env.get_deployed_universal_vm(UNIVERSAL_VM_NAME).unwrap();
    //     let universal_vm = deployed_universal_vm.get_vm().unwrap();
    //     let btc_node_ipv6 = universal_vm.ipv6;

    InternetComputer::new()
        //.with_bitcoind_addr(SocketAddr::new(IpAddr::V6(btc_node_ipv6), 18444))
        .with_default_vm_resources(VmResources {
            vcpus: Some(NrOfVCPUs::new(64)),
            memory_kibibytes: Some(AmountOfMemoryKiB::new(480 << 20)),
            boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(2_000)),
        })
        .use_specified_ids_allocation_range()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .add_subnet(Subnet::new(SubnetType::Application).add_nodes(1))
        .setup_and_start(&env)
        .expect("Failed to setup IC under test");

    check_nodes_health(&env);
    install_nns_canisters_at_ids(&env);

    // install_nns_with_customizations_and_check_progress(
    //     env.topology_snapshot(),
    //     NnsCustomizations::default(),
    // );

    BoundaryNode::new(String::from(BOUNDARY_NODE_NAME))
        .allocate_vm(&env)
        .expect("Allocation of BoundaryNode failed.")
        .for_ic(&env, "")
        .use_real_certs_and_dns()
        .start(&env)
        .expect("failed to setup BoundaryNode VM");
    env.sync_with_prometheus();

    info!(&env.logger(), "Checking boundary node readines ...");
    await_boundary_node_healthy(&env, BOUNDARY_NODE_NAME);
    info!(&env.logger(), "Boundary node is ready.");
}

fn check_nodes_health(env: &TestEnv) {
    info!(
        &env.logger(),
        "Checking readiness of all nodes after the IC setup ..."
    );
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
    info!(&env.logger(), "All nodes are ready, IC setup succeeded.");
}

pub fn install_nns_canisters_at_ids(env: &TestEnv) {
    info!(
        &env.logger(),
        "Installing NNS canisters on the root subnet ..."
    );
    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .expect("there is no NNS node");
    NnsInstallationBuilder::new()
        .with_customizations(NnsCustomizations::default())
        .at_ids()
        .install(&nns_node, env)
        .expect("NNS canisters not installed");
    info!(&env.logger(), "NNS canisters installed");
}
