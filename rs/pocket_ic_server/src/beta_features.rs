use ic_config::embedders::FeatureFlags;
use ic_config::flag_status::FlagStatus;
use ic_config::{
    embedders::Config as EmbeddersConfig, execution_environment::Config as HypervisorConfig,
};

pub fn hypervisor_config() -> HypervisorConfig {
    HypervisorConfig {
        embedders_config: EmbeddersConfig {
            feature_flags: FeatureFlags {
                environment_variables: FlagStatus::Enabled,
                ..Default::default()
            },
            ..Default::default()
        },
        environment_variables: FlagStatus::Enabled,
        ..Default::default()
    }
}
