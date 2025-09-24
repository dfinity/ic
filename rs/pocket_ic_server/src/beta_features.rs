use ic_config::embedders::FeatureFlags;
use ic_config::{
    embedders::Config as EmbeddersConfig, execution_environment::Config as HypervisorConfig,
};

pub fn hypervisor_config() -> HypervisorConfig {
    HypervisorConfig {
        embedders_config: EmbeddersConfig {
            feature_flags: FeatureFlags {
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    }
}
