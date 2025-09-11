pub mod test_utils;
pub mod v1;

pub enum Version {
    V1,
}

trait RewardsCalculation {
    const VERSION: Version;
}
