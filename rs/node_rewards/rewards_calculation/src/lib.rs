pub mod performance_based_algorithm;
pub mod types;

pub trait AlgorithmVersion {
    const VERSION: u32;
}

/// From constant [NODE_PROVIDER_REWARD_PERIOD_SECONDS]
/// const NODE_PROVIDER_REWARD_PERIOD_SECONDS: u64 = 2629800;
/// const SECONDS_IN_DAY: u64 = 86400;
/// 2629800 / 86400 = 30.4375 days of rewards
pub const REWARDS_TABLE_DAYS: f64 = 30.4375;
