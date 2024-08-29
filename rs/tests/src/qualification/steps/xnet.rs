use super::Step;

#[derive(Clone)]
pub struct XNet {}

impl Step for XNet {
    fn execute(
        &self,
        _env: ic_system_test_driver::driver::test_env::TestEnv,
        _rt: tokio::runtime::Handle,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    fn max_retries(&self) -> usize {
        3
    }
}
