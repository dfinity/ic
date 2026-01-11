use super::steps::Step;
use ic_system_test_driver::driver::test_env::TestEnv;

pub struct QualificationExecutor {
    steps: Vec<Box<dyn Step>>,
}

impl QualificationExecutor {
    pub fn new(steps: Vec<Box<dyn Step>>) -> Self {
        Self { steps }
    }

    pub async fn qualify(&self, env: TestEnv) -> anyhow::Result<()> {
        for step in &self.steps {
            step.do_step(env.clone()).await?
        }
        Ok(())
    }
}
