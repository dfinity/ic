pub mod ic_crypto_csp_metrics_test;
pub mod ic_crypto_csp_socket_test;
pub mod ic_crypto_csp_umask_test;
pub mod ic_crypto_fstrim_tool_test;
pub mod request_signature_test;
pub mod rpc_csp_vault_reconnection_test;

use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::{
    ic::{InternetComputer, Subnet},
    test_env::TestEnv,
};

pub fn config(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        .add_subnet(Subnet::fast_single_node(SubnetType::VerifiedApplication))
        .add_subnet(Subnet::fast_single_node(SubnetType::Application))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}
