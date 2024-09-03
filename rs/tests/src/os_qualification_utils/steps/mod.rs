use ic_system_test_driver::driver::test_env::TestEnv;
use slog::info;
use tokio::runtime::Handle;

pub mod ensure_elected_version;
pub mod retire_elected_version;
pub mod update_subnet_type;
pub mod workload;
pub mod xnet;

pub trait Step: Sync + Send {
    fn execute(&self, env: TestEnv, rt: Handle) -> anyhow::Result<()>;

    fn name(&self) -> &'static str {
        std::any::type_name::<Self>()
    }

    fn do_step(&self, env: TestEnv, rt: Handle) -> anyhow::Result<()> {
        let logger = env.logger();
        info!(logger, "Running step: {}", self.name());

        self.execute(env.clone(), rt.clone()).map_err(|e| {
            let formatted = format!("Step `{}` failed with error: {:?}", self.name(), e);
            env.emit_report(formatted);
            e
        })?;

        info!(logger, "Step `{}` finished successfully", self.name());
        Ok(())
    }
}
