/* tag::catalog[]
Title:: Boundary nodes SNP system tests
end::catalog[] */

use crate::driver::{
    boundary_node::{BoundaryNode, BoundaryNodeVm},
    // TODO: Uncomment this once spm41 is fixed for virsh
    //farm::HostFeature,
    ic::{AmountOfMemoryKiB, InternetComputer, Subnet, VmResources},
    pot_dsl::get_ic_handle_and_ctx,
    test_env::{HasIcPrepDir, TestEnv},
    test_env_api::{HasTopologySnapshot, IcNodeContainer, NnsInstallationExt, SshSession, ADMIN},
};
use ic_registry_subnet_type::SubnetType;
use slog::info;

const BOUNDARY_NODE_SNP_NAME: &str = "boundary-node-snp-1";

pub fn config(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    let (handle, _ctx) = get_ic_handle_and_ctx(env.clone());

    env.topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap()
        .install_nns_canisters()
        .expect("Could not install NNS canisters");

    let nns_urls = handle
        .public_api_endpoints
        .iter()
        .filter(|ep| ep.is_root_subnet)
        .map(|ep| ep.url.clone())
        .collect();

    BoundaryNode::new(String::from(BOUNDARY_NODE_SNP_NAME))
        .with_nns_urls(nns_urls)
        .with_nns_public_key(env.prep_dir("").unwrap().root_public_key_path())
        .with_vm_resources(VmResources {
            vcpus: None,
            memory_kibibytes: Some(AmountOfMemoryKiB::new(4194304)),
            boot_image_minimal_size_gibibytes: None,
        })
        .enable_sev()
        .with_snp_boot_img(&env)
        .start(&env)
        .expect("failed to setup BoundaryNode VM");
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
