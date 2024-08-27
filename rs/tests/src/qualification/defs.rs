use futures::SinkExt;
use ic_system_test_driver::driver::test_env::TestEnv;
use tokio::runtime::{Builder, Runtime};

use super::steps::Step;

pub struct QualificationExecutor<T: Step> {
    from_version: String,
    to_version: String,
    rt: Runtime,
    steps: Vec<T>,
}

impl<T: Step> QualificationExecutor<T> {
    pub fn new(from_version: String, to_version: String, rt: Runtime, steps: Vec<T>) -> Self {
        Self {
            from_version,
            to_version,
            rt,
            steps,
        }
    }

    pub fn qualify(&self, env: TestEnv) -> anyhow::Result<()> {
        // Ensure blessed initial version

        // Update app subnets

        // Update system subnet

        // Update unassigned nodes

        // workload test

        // xnet test

        // Downgrade app subnets

        // Downgrade system subnet

        // Downgrade unassigned nodes

        // workload test

        // xnet text

        Ok(())
    }
}
