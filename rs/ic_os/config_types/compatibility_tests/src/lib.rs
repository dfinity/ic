use std::path::PathBuf;

mod fixture;

pub use fixture::generate_fixtures;
pub use fixture::ConfigFixture;

pub fn version_greater_than(v1: &str, v2: &str) -> bool {
    let v1_parts: Vec<u32> = v1.split('.').map(|s| s.parse().unwrap_or(0)).collect();
    let v2_parts: Vec<u32> = v2.split('.').map(|s| s.parse().unwrap_or(0)).collect();

    v1_parts
        .iter()
        .zip(v2_parts.iter())
        .find(|(&a, &b)| a != b)
        .map(|(a, b)| a > b)
        .unwrap_or(false)
}
