use ic_system_test_driver::driver::test_env::TestEnv;
use tokio::runtime::{Builder, Runtime};

#[derive(Default)]
pub struct QualificationExecutorBuilder {
    from_version: Option<String>,
    to_version: Option<String>,
}

impl QualificationExecutorBuilder {
    pub fn with_from_version<S: ToString>(self, from_version: S) -> Self {
        Self {
            from_version: Some(from_version.to_string()),
            ..self
        }
    }

    pub fn with_to_version<S: ToString>(self, to_version: S) -> Self {
        Self {
            to_version: Some(to_version.to_string()),
            ..self
        }
    }

    pub fn build(self) -> anyhow::Result<QualificationExecutor> {
        let from_version = self
            .from_version
            .ok_or(anyhow::anyhow!("From version is required"))?;
        let to_version = self
            .to_version
            .ok_or(anyhow::anyhow!("To version is required"))?;
        let rt = Builder::new_multi_thread()
            .worker_threads(16)
            .max_blocking_threads(16)
            .enable_all()
            .build()?;
        Ok(QualificationExecutor::new(from_version, to_version, rt))
    }
}

pub struct QualificationExecutor {
    from_version: String,
    to_version: String,
    rt: Runtime,
    steps: Vec<usize>,
}

impl QualificationExecutor {
    fn new(from_version: String, to_version: String, rt: Runtime) -> Self {
        Self {
            from_version,
            to_version,
            rt,
            steps: vec![],
        }
    }

    pub fn qualify(&self, env: TestEnv) -> anyhow::Result<()> {
        let logger = env.logger();

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
