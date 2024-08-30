use super::Step;

#[derive(Clone)]
pub struct Workload {
    pub message_size: usize,
    pub rps: f64,
}

impl Step for Workload {
    fn execute(
        &self,
        env: ic_system_test_driver::driver::test_env::TestEnv,
        rt: tokio::runtime::Handle,
    ) -> anyhow::Result<()> {
        // Small messages
        ic_consensus_system_test_utils::performance::test_with_rt_handle(
            env,
            self.message_size,
            self.rps,
            rt,
            false,
        )
        .map(|_| ())
    }

    fn max_retries(&self) -> usize {
        3
    }
}
