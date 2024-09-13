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
                best_effort_responses: FlagStatus::Enabled,
                wasm64: FlagStatus::Enabled,
                ..FeatureFlags::default()
            },
            ..EmbeddersConfig::default()
        },
        rate_limiting_of_heap_delta: FlagStatus::Disabled,
        rate_limiting_of_instructions: FlagStatus::Disabled,
        canister_snapshots: FlagStatus::Enabled,
        query_stats_epoch_length: 60,
        ..HypervisorConfig::default()
    }
}
