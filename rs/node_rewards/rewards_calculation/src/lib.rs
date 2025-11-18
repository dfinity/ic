pub mod performance_based_algorithm;
pub mod types;

pub trait AlgorithmVersion {
    const VERSION: u32;
}
