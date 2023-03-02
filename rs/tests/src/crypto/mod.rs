pub mod request_signature_test;

use crate::driver::{
    ic::{InternetComputer, Subnet},
    test_env::TestEnv,
    test_env_api::HasGroupSetup,
};
use ic_registry_subnet_type::SubnetType;

pub fn config(env: TestEnv) {
    env.ensure_group_setup_created();
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        .add_subnet(Subnet::fast_single_node(SubnetType::VerifiedApplication))
        .add_subnet(Subnet::fast_single_node(SubnetType::Application))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}
