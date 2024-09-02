use ic_system_test_driver::driver::test_env::TestEnv;
use slog::{error, info};
use tokio::runtime::Handle;

pub mod ensure_elected_version;
pub mod retire_elected_version;
pub mod update_subnet_type;
pub mod workload;
pub mod xnet;

const DEFAULT_TOTAL_RUNS: usize = 1;

pub trait Step: Sync + Send {
    fn execute(&self, env: TestEnv, rt: Handle) -> anyhow::Result<()>;

    // Specify the total number of runs for a step
    //
    // Useful for flaky steps like workload testing or
    // xnet testing. In general, the whole test will be
    // retried 3 times, but since it's a long test, this
    // mechianism allows us to retry flaky steps quickly
    // and cut down the time needed for the overall test.
    fn total_runs(&self) -> usize {
        DEFAULT_TOTAL_RUNS
    }

    fn name(&self) -> &'static str {
        std::any::type_name::<Self>()
    }

    fn do_step(&self, env: TestEnv, rt: Handle) -> anyhow::Result<()> {
        let logger = env.logger();
        info!(logger, "Running step: {}", self.name());

        let mut total_runs = self.total_runs();
        loop {
            total_runs -= 1;
            match self.execute(env.clone(), rt.clone()) {
                Ok(_) => break,
                Err(e) => {
                    let formatted = format!("Step `{}` failed with error: {:?}", self.name(), e);
                    error!(logger, "{}", formatted);
                    if total_runs.eq(&0) {
                        env.emit_report(formatted);
                        return Err(e);
                    }
                }
            }
        }

        info!(
            logger,
            "Step `{}` finished successfully after {} runs",
            self.name(),
            self.total_runs() - total_runs
        );
        Ok(())
    }
}
