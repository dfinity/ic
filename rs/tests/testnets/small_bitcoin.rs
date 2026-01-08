// Set up a Bitcoin testnet containing:
//   one 1-node System subnet, single API boundary node, single ic-gateway and a p8s (with grafana) VM.
// The single system subnet node uses: 64 vCPUs, 480 GiB of RAM, and 2 TiB disk.
//
// Note, all canisters will be installed on a system subnet by default.
//
// You can setup this testnet by executing the following commands:
//
//   $ ./ci/tools/docker-run
//   $ ict testnet create small_bitcoin --output-dir=./small_bitcoin -- --test_tmpdir=./small_bitcoin
//
// The --output-dir=./small_bitcoin will store the debug output of the test driver in the specified directory.
// The --test_tmpdir=./small_bitcoin will store the remaining test output in the specified directory.
// This is useful to have access to in case you need to SSH into an IC node for example like:
//
//   $ ssh -i small_bitcoin/_tmp/*/setup/ssh/authorized_priv_keys/admin admin@
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
//     prometheus: Prometheus Web UI at http://prometheus.small_bitcoin--1692597750709.testnet.farm.dfinity.systems,
//     grafana: Grafana at http://grafana.small_bitcoin--1692597750709.testnet.farm.dfinity.systems,
//     progress_clock: IC Progress Clock at http://grafana.small_bitcoin--1692597750709.testnet.farm.dfinity.systems/d/ic-progress-clock/ic-progress-clock?refresh=10su0026from=now-5mu0026to=now,
//
// Happy testing!

use anyhow::Result;

use ic_consensus_system_test_utils::rw_message::cert_state_makes_progress_with_retries;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::{
    group::SystemTestGroup,
    ic::{AmountOfMemoryKiB, ImageSizeGiB, InternetComputer, NrOfVCPUs, Subnet, VmResources},
    ic_gateway_vm::{IC_GATEWAY_VM_NAME, IcGatewayVm},
    test_env::TestEnv,
    test_env_api::{HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsInstallationBuilder},
};
use slog::info;
use std::time::Duration;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .use_specified_ids_allocation_range()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_default_vm_resources(VmResources {
                    vcpus: Some(NrOfVCPUs::new(64)),
                    memory_kibibytes: Some(AmountOfMemoryKiB::new(480 << 20)),
                    boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(2_000)),
                })
                .add_nodes(1),
        )
        .with_api_boundary_nodes(1)
        .setup_and_start(&env)
        .expect("Failed to setup IC under test");
    await_nodes_healthy(&env);
    install_nns_canisters_at_ids(&env);
    IcGatewayVm::new(IC_GATEWAY_VM_NAME)
        .start(&env)
        .expect("failed to setup ic-gateway");
}

fn await_nodes_healthy(env: &TestEnv) {
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
    let topology = env.topology_snapshot();
    let nns_node = topology
        .root_subnet()
        .nodes()
        .next()
        .expect("there is no NNS node");
    NnsInstallationBuilder::new()
        .at_ids()
        .install(&nns_node, env)
        .expect("NNS canisters not installed");
    info!(&env.logger(), "NNS canisters installed");

    for subnet in topology
        .subnets()
        .filter(|subnet| subnet.subnet_id != topology.root_subnet_id())
    {
        if !subnet.raw_subnet_record().is_halted {
            info!(
                env.logger(),
                "Checking if all the nodes are participating in the subnet {}", subnet.subnet_id
            );
            for node in subnet.nodes() {
                cert_state_makes_progress_with_retries(
                    &node.get_public_url(),
                    node.effective_canister_id(),
                    &env.logger(),
                    /*timeout=*/ Duration::from_secs(600),
                    /*backoff=*/ Duration::from_secs(2),
                );
            }
        } else {
            info!(
                env.logger(),
                "Subnet {} is halted. Not checking if all the nodes are participating in the subnet",
                subnet.subnet_id,
            );
        }
    }
}
