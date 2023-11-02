use crate::driver::{boundary_node::BoundaryNodeVm, test_env::TestEnv, test_env_api::SshSession};

use crate::boundary_nodes::constants::BOUNDARY_NODE_SNP_NAME;

use slog::info;

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
        .block_on_bash_script(KERNEL_TEST_BASH)
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
        .block_on_bash_script(SNP_TEST_BASH)
        .unwrap();
    info!(logger, "SNP test result = '{}'", result.trim(),);
    if !result.trim().contains(SNP_BASH_OUTPUT) {
        panic!("SNP is not enabled.");
    }
}
