use ic_config::embedders::FeatureFlags;
use ic_config::flag_status::FlagStatus;
use ic_config::{
    embedders::Config as EmbeddersConfig, execution_environment::Config as HypervisorConfig,
};

pub fn hypervisor_config() -> HypervisorConfig {
    HypervisorConfig {
        // Enables the `flexible_http_request` management canister endpoint, which
        // is also what puts every HTTP outcall of the subnet on the pay-as-you-go
        // pricing model.
        flexible_http_requests: FlagStatus::Enabled,
        embedders_config: EmbeddersConfig {
            feature_flags: FeatureFlags {
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    }
}
