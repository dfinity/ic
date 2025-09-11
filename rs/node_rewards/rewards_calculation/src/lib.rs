use crate::performance_based_algorithm::{InputProvider, PerformanceBasedAlgorithm};
use crate::types::DayUtc;

pub mod performance_based_algorithm;
pub mod types;
pub mod versions;

pub fn calculate_rewards<Algorithm: PerformanceBasedAlgorithm>(
    from_day: &DayUtc,
    to_day: &DayUtc,
    input_provider: impl InputProvider,
) -> Result<Algorithm::Results, String> {
    Algorithm::calculate(from_day, to_day, input_provider)
}
