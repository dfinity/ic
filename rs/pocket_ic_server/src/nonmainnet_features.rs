use ic_config::embedders::FeatureFlags;
use ic_config::flag_status::FlagStatus;
use ic_config::{
    embedders::Config as EmbeddersConfig, execution_environment::Config as HypervisorConfig,
};

pub fn hypervisor_config(canister_sandboxing: bool) -> HypervisorConfig {
    HypervisorConfig {
        canister_sandboxing_flag: if canister_sandboxing {
            FlagStatus::Enabled
        } else {
            FlagStatus::Disabled
        },
        embedders_config: EmbeddersConfig {
            feature_flags: FeatureFlags {
                rate_limiting_of_debug_prints: FlagStatus::Disabled,
                wasm64: FlagStatus::Enabled,
                canister_backtrace: FlagStatus::Enabled,
                ..FeatureFlags::default()
            },
            ..EmbeddersConfig::default()
        },
        rate_limiting_of_heap_delta: FlagStatus::Disabled,
        rate_limiting_of_instructions: FlagStatus::Disabled,
        query_stats_epoch_length: 60,
        canister_snapshot_download: FlagStatus::Enabled,
        canister_snapshot_upload: FlagStatus::Enabled,
        ..HypervisorConfig::default()
    }
}
