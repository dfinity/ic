use ic_system_test_driver::driver::test_env::TestEnv;
use slog::{error, info};
use tokio::runtime::Handle;

pub mod ensure_blessed_version;
pub mod retire_blessed_version;
pub mod update_subnet_type;
pub mod workload;
pub mod xnet;

pub trait Step: Sync + Send {
    fn execute(&self, env: TestEnv, rt: Handle) -> anyhow::Result<()>;

    fn max_retries(&self) -> usize;

    fn name(&self) -> &'static str {
        std::any::type_name::<Self>()
    }

    fn do_step(&self, env: TestEnv, rt: Handle) -> anyhow::Result<()> {
        let logger = env.logger();
        info!(logger, "Running step: {}", self.name());

        let mut max_retries = self.max_retries();
        loop {
            max_retries -= 1;
            match self.execute(env.clone(), rt.clone()) {
                Ok(_) => break,
                Err(e) => {
                    let formatted = format!("Step `{}` failed with error: {:?}", self.name(), e);
                    error!(logger, "{}", formatted);
                    if max_retries.eq(&0) {
                        env.emit_report(formatted);
                        return Err(e);
                    }
                }
            }
        }

        info!(
            logger,
            "Step `{}` finished successfully after {} retries",
            self.name(),
            self.max_retries() - max_retries
        );
        Ok(())
    }
}
