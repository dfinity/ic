pub mod api_tests;
pub mod big_stable_memory;
pub mod call_on_cleanup;
pub mod canister_heartbeat;
pub mod canister_lifecycle;
pub mod cycles_transfer;
pub mod ingress_rate_limiting;
pub mod instructions_limit;
pub mod inter_canister_queries;
pub mod nns_shielding;
pub mod queries;
pub mod subnet_capacity;
pub mod upgraded_pots;

use ic_fondue::ic_instance::{LegacyInternetComputer, Subnet as LegacySubnet};
use ic_fondue::prod_tests::ic::{InternetComputer, Subnet};
use ic_registry_subnet_type::SubnetType;

pub fn config_system_verified_application_subnets() -> InternetComputer {
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        .add_subnet(Subnet::fast_single_node(SubnetType::VerifiedApplication))
        .add_subnet(Subnet::fast_single_node(SubnetType::Application))
}

pub fn legacy_config_system_verified_application_subnets() -> LegacyInternetComputer {
    LegacyInternetComputer::new()
        .add_subnet(LegacySubnet::fast_single_node(SubnetType::System))
        .add_subnet(LegacySubnet::fast_single_node(
            SubnetType::VerifiedApplication,
        ))
        .add_subnet(LegacySubnet::fast_single_node(SubnetType::Application))
}

pub fn config_system_verified_subnets() -> InternetComputer {
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        .add_subnet(Subnet::fast_single_node(SubnetType::VerifiedApplication))
}

pub fn legacy_config_system_verified_subnets() -> LegacyInternetComputer {
    LegacyInternetComputer::new()
        .add_subnet(LegacySubnet::fast_single_node(SubnetType::System))
        .add_subnet(LegacySubnet::fast_single_node(
            SubnetType::VerifiedApplication,
        ))
}

pub fn config_many_system_subnets() -> InternetComputer {
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        .add_subnet(Subnet::fast_single_node(SubnetType::VerifiedApplication))
        .add_subnet(Subnet::fast_single_node(SubnetType::Application))
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
}

pub fn legacy_config_many_system_subnets() -> LegacyInternetComputer {
    LegacyInternetComputer::new()
        .add_subnet(LegacySubnet::fast_single_node(SubnetType::System))
        .add_subnet(LegacySubnet::fast_single_node(
            SubnetType::VerifiedApplication,
        ))
        .add_subnet(LegacySubnet::fast_single_node(SubnetType::Application))
        .add_subnet(LegacySubnet::fast_single_node(SubnetType::System))
}

// A special configuration for testing memory capacity limits.
pub fn legacy_config_memory_capacity() -> LegacyInternetComputer {
    LegacyInternetComputer::new().add_subnet(
        LegacySubnet::fast_single_node(SubnetType::System)
            // A tiny memory capacity
            .with_memory_capacity(20 * 1024 * 1024 /* 20 MiB */),
    )
}
