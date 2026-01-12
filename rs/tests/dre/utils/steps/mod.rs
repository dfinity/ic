use async_trait::async_trait;
use ic_system_test_driver::driver::test_env::TestEnv;
use slog::info;

pub mod ensure_elected_version;
pub mod retire_elected_version;
pub mod update_subnet_type;
pub mod workload;
pub mod xnet;

#[async_trait]
pub trait Step: Sync + Send {
    async fn execute(&self, env: TestEnv) -> anyhow::Result<()>;

    fn name(&self) -> &'static str {
        std::any::type_name::<Self>()
    }

    async fn do_step(&self, env: TestEnv) -> anyhow::Result<()> {
        let logger = env.logger();
        info!(logger, "Running step: {}", self.name());

        self.execute(env.clone()).await.map_err(|e| {
            let formatted = format!("Step `{}` failed with error: {:?}", self.name(), e);
            env.emit_report(formatted);
            e
        })?;

        info!(logger, "Step `{}` finished successfully", self.name());
        Ok(())
    }
}
