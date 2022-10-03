/* tag::catalog[]
Title:: Boundary nodes SNP system tests
end::catalog[] */

use crate::driver::{
    boundary_node::{BoundaryNode, BoundaryNodeVm},
    // TODO: Uncomment this once spm41 is fixed for virsh
    //farm::HostFeature,
    ic::{AmountOfMemoryKiB, InternetComputer, Subnet, VmResources},
    test_env::TestEnv,
    test_env_api::{
        retry_async, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsInstallationExt,
        RetrieveIpv4Addr, SshSession, ADMIN, READY_WAIT_TIMEOUT, RETRY_BACKOFF,
    },
};

use std::io::Read;

use anyhow::{Context, Error};
use ic_interfaces_registry::RegistryValue;
use ic_protobuf::registry::routing_table::v1::RoutingTable as PbRoutingTable;
use ic_registry_keys::make_routing_table_record_key;
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_routing_table::RoutingTable;
use ic_registry_subnet_type::SubnetType;
use slog::info;

const BOUNDARY_NODE_SNP_NAME: &str = "boundary-node-snp-1";

fn exec_ssh_command(vm: &dyn SshSession, command: &str) -> Result<(String, i32), Error> {
    let mut channel = vm.block_on_ssh_session(ADMIN)?.channel_session()?;

    channel.exec(command)?;

    let mut output = String::new();
    channel.read_to_string(&mut output)?;
    channel.wait_close()?;

    Ok((output, channel.exit_status()?))
}

pub fn config(env: TestEnv) {
    let logger = env.logger();

    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    env.topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap()
        .install_nns_canisters()
        .expect("Could not install NNS canisters");

    let bn = BoundaryNode::new(String::from(BOUNDARY_NODE_SNP_NAME))
        .for_ic(&env, "")
        .with_vm_resources(VmResources {
            vcpus: None,
            memory_kibibytes: Some(AmountOfMemoryKiB::new(4194304)),
            boot_image_minimal_size_gibibytes: None,
        })
        .enable_sev()
        .with_snp_boot_img(&env);
    bn.start(&env).expect("failed to setup BoundaryNode VM");

    // Await Replicas
    info!(&logger, "Checking readiness of all replica nodes...");
    for subnet in env.topology_snapshot().subnets() {
        for node in subnet.nodes() {
            node.await_status_is_healthy()
                .expect("Replica did not come up healthy.");
        }
    }

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    info!(&logger, "Polling registry");
    let registry = RegistryCanister::new(bn.nns_node_urls);
    let (latest, routes) = rt.block_on(retry_async(&logger, READY_WAIT_TIMEOUT, RETRY_BACKOFF, || async {
        let (bytes, latest) = registry.get_value(make_routing_table_record_key().into(), None).await
            .context("Failed to `get_value` from registry")?;
        let routes = PbRoutingTable::decode(bytes.as_slice())
            .context("Failed to decode registry routes")?;
        let routes = RoutingTable::try_from(routes)
            .context("Failed to convert registry routes")?;
        Ok((latest, routes))
    }))
    .expect("Failed to poll registry. This is not a Boundary Node error. It is a test environment issue.");
    info!(&logger, "Latest registry {latest}: {routes:?}");

    // Await Boundary Node
    let boundary_node_vm = env
        .get_deployed_boundary_node(BOUNDARY_NODE_SNP_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();

    info!(
        &logger,
        "Boundary node {BOUNDARY_NODE_SNP_NAME} has IPv4 {:?} and IPv6 {:?}",
        boundary_node_vm.block_on_ipv4().unwrap(),
        boundary_node_vm.ipv6()
    );

    info!(&logger, "Waiting for routes file");
    let sleep_command = "until [ -f /var/cache/ic_routes/* ]; do sleep 5; done";
    let (cmd_output, exit_status) = exec_ssh_command(&boundary_node_vm, sleep_command).unwrap();
    info!(
        logger,
        "{BOUNDARY_NODE_SNP_NAME} ran `{sleep_command}`: '{}'. Exit status = {exit_status}",
        cmd_output.trim(),
    );

    info!(&logger, "Checking BN health");
    boundary_node_vm
        .await_status_is_healthy()
        .expect("Boundary node did not come up healthy.");
}

/* tag::catalog[]
Title:: Boundary nodes SNP Kernel test

Goal:: Verify that an image with snp kernel is booted.

Runbook:
. Set up a subnet with one node and a boundary node.
. SSH into the boundary node and execute `uname -a`.
. The output of above command should look like this:
    `Linux 5.17.0-rc6-snp-guest-xxxxxxxxxxxx`

Success:: The output contains the string `snp`

Coverage:: Boundary Node VM boots an image with SNP support

end::catalog[] */
const KERNEL_TEST_BASH: &str = "uname -a 2>&1";

pub fn snp_kernel_test(env: TestEnv) {
    let logger = env.logger();
    let deployed_boundary_node = env
        .get_deployed_boundary_node(BOUNDARY_NODE_SNP_NAME)
        .unwrap();
    let boundary_node_vm = deployed_boundary_node.get_snapshot().unwrap();
    // SSH into Boundary Nodes and execute "uname -a"
    let result = boundary_node_vm
        .block_on_bash_script(ADMIN, KERNEL_TEST_BASH)
        .unwrap();
    info!(logger, "kernel test result = '{}'", result.trim(),);
    if !result.trim().contains("snp") {
        panic!("Kernel does not provide SNP.");
    }
}

/* tag::catalog[]
Title:: Boundary nodes SNP Basic test

Goal:: Verify that an SNP enabled image is booted.

Runbook:
. Set up a subnet with one node and a boundary node.
. SSH into the boundary node and execute `dmesg | grep -i sev`.
. The output of above command should contain this:
    `AMD Memory Encryption Features active: SEV SEV-ES SEV-SNP`

Success:: The output contains the string `snp`

Coverage:: Boundary Node VM boots an image with SNP support

end::catalog[] */
const SNP_TEST_BASH: &str = "dmesg | grep -i sev";
const SNP_BASH_OUTPUT: &str = "AMD Memory Encryption Features active: SEV SEV-ES SEV-SNP";
pub fn snp_basic_test(env: TestEnv) {
    let logger = env.logger();
    let deployed_boundary_node = env
        .get_deployed_boundary_node(BOUNDARY_NODE_SNP_NAME)
        .unwrap();
    let boundary_node_vm = deployed_boundary_node.get_snapshot().unwrap();
    // SSH into Boundary Nodes and execute test bash to check that SNP is enabled
    let result = boundary_node_vm
        .block_on_bash_script(ADMIN, SNP_TEST_BASH)
        .unwrap();
    info!(logger, "SNP test result = '{}'", result.trim(),);
    if !result.trim().contains(SNP_BASH_OUTPUT) {
        panic!("SNP is not enabled.");
    }
}
