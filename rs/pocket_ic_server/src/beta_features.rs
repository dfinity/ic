use ic_config::embedders::FeatureFlags;
use ic_config::flag_status::FlagStatus;
use ic_config::{
    embedders::Config as EmbeddersConfig, execution_environment::Config as HypervisorConfig,
};

pub fn hypervisor_config() -> HypervisorConfig {
    HypervisorConfig {
        // Enables the `flexible_http_request` management canister endpoint, whose
        // outcalls are always priced with the pay-as-you-go pricing model. The same
        // flag gates that pricing model for `http_request`, whose outcalls may then
        // select it through their `pricing_version` (they keep using the legacy
        // pricing model unless they do).
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
