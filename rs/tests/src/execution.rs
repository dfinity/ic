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

use ic_fondue::internet_computer::{InternetComputer, Subnet};
use ic_registry_subnet_type::SubnetType;

use crate::util::CYCLES_LIMIT_PER_CANISTER;

pub fn config_system_verified_application_subnets() -> InternetComputer {
    InternetComputer::new()
        .add_subnet(Subnet::fast(SubnetType::System))
        .add_subnet(Subnet::fast(SubnetType::VerifiedApplication))
        .add_subnet(Subnet::fast(SubnetType::Application))
}

pub fn config_system_verified_subnets() -> InternetComputer {
    InternetComputer::new()
        .add_subnet(Subnet::fast(SubnetType::System))
        .add_subnet(Subnet::fast(SubnetType::VerifiedApplication))
}

pub fn pot1_config() -> InternetComputer {
    InternetComputer::new()
        .add_subnet(
            Subnet::fast(SubnetType::System)
                .with_max_cycles_per_canister(Some(CYCLES_LIMIT_PER_CANISTER)),
        )
        .add_subnet(
            Subnet::fast(SubnetType::Application)
                .with_max_cycles_per_canister(Some(CYCLES_LIMIT_PER_CANISTER)),
        )
}

pub fn config_many_system_subnets() -> InternetComputer {
    InternetComputer::new()
        .add_subnet(Subnet::fast(SubnetType::System))
        .add_subnet(Subnet::fast(SubnetType::VerifiedApplication))
        .add_subnet(Subnet::fast(SubnetType::Application))
        .add_subnet(Subnet::fast(SubnetType::System))
}

// A special configuration for testing memory capacity limits.
pub fn config_memory_capacity() -> InternetComputer {
    InternetComputer::new().add_subnet(
        Subnet::fast(SubnetType::System)
            // A tiny memory capacity
            .with_memory_capacity(20 * 1024 * 1024 /* 20 MiB */),
    )
}
