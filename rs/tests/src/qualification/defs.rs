use ic_system_test_driver::driver::test_env::TestEnv;
use tokio::runtime::Runtime;

use super::steps::Step;

pub struct QualificationExecutor {
    rt: Runtime,
    steps: Vec<Box<dyn Step>>,
}

impl QualificationExecutor {
    pub fn new(rt: Runtime, steps: Vec<Box<dyn Step>>) -> Self {
        Self { rt, steps }
    }

    pub fn qualify(&self, env: TestEnv) -> anyhow::Result<()> {
        for step in &self.steps {
            step.do_step(env.clone(), self.rt.handle().clone())?
        }

        // xnet test

        // xnet text

        Ok(())
    }
}
