#![allow(dead_code)]
#[rustfmt::skip]

use std::{
    collections::BTreeMap,
    panic::UnwindSafe,
    path::{Path},
};

use crate::driver::{
    pot_dsl::{PotSetupFn, SysTestFn},
    test_env::TestEnv,
};
use slog::Logger;

#[macro_export]
macro_rules! systest {
    ($a:path) => {
        ic_system_test_driver::driver::dsl::TestFunction::new(std::stringify!($a), $a)
    };
}

pub struct SystemTestGroup {
    setup: Option<Box<dyn PotSetupFn>>,
    tests: BTreeMap<String, Box<dyn SysTestFn>>,
}

pub struct TestFunction {
    name: String,
    f: Box<dyn SysTestFn>,
}

impl TestFunction {
    pub fn new<F: SysTestFn>(name: &str, f: F) -> Self {
        Self {
            name: name.to_string(),
            f: Box::new(f),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn f(self) -> Box<dyn SysTestFn> {
        self.f
    }
}

pub trait SubprocessFn: FnOnce() + UnwindSafe + Send + Sync + 'static {}
impl<T: FnOnce() + UnwindSafe + Send + Sync + 'static> SubprocessFn for T {}

// Create a SubprocessFn from source and target environment.
fn lift<P, R, F: SysTestFn>(logger: Logger, source_env: P, target_env: R, f: F) -> impl SubprocessFn
where
    P: AsRef<Path>,
    R: AsRef<Path>,
{
    let source_env_path = source_env.as_ref().to_owned();
    let target_env_path = target_env.as_ref().to_owned();
    move || {
        let src_env = TestEnv::new(&source_env_path, logger.clone())
            .expect("could not create source environment");
        let test_env = src_env
            .fork(logger, target_env_path)
            .expect("could not create test env");
        (f)(test_env);
    }
}
