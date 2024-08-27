use std::fmt::Display;

use ic_system_test_driver::driver::test_env::TestEnv;
use slog::{error, info};

pub mod ensure_blessed_version;

trait Step {
    fn execute(&self, env: TestEnv)
        -> impl std::future::Future<Output = anyhow::Result<()>> + Send;

    fn max_retries(&self) -> usize;

    fn name(&self) -> &'static str {
        std::any::type_name::<Self>()
    }

    async fn do_step(&self, env: TestEnv) -> anyhow::Result<()> {
        let logger = env.logger();
        info!(logger, "Running step: {}", self.name());

        let mut max_retries = self.max_retries();
        loop {
            max_retries -= 1;
            match self.execute(env.clone()).await {
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
