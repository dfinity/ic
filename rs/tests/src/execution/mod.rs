pub mod api_tests;
pub mod big_stable_memory;
pub mod call_on_cleanup;
pub mod canister_heartbeat;
pub mod canister_lifecycle;
pub mod cycles_transfer;
pub mod ingress_rate_limiting;
pub mod inter_canister_queries;
pub mod malicious_input;
pub mod nns_shielding;
pub mod queries;
pub mod system_api_security_test;
pub mod wasm_chunk_store;

use crate::driver::{
    ic::{InternetComputer, Subnet},
    test_env::TestEnv,
};
use ic_registry_subnet_type::SubnetType;

pub fn config_system_verified_application_subnets(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        .add_subnet(Subnet::fast_single_node(SubnetType::VerifiedApplication))
        .add_subnet(Subnet::fast_single_node(SubnetType::Application))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

pub fn config_system_verified_subnets(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        .add_subnet(Subnet::fast_single_node(SubnetType::VerifiedApplication))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

pub fn config_many_system_subnets(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        .add_subnet(Subnet::fast_single_node(SubnetType::VerifiedApplication))
        .add_subnet(Subnet::fast_single_node(SubnetType::Application))
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

// A special configuration for testing the maximum number of canisters on a
// subnet. The value is set to 3 for the tests.
pub fn config_max_number_of_canisters(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::System).with_max_number_of_canisters(3))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}
