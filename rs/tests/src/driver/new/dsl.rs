#![allow(dead_code)]
#[rustfmt::skip]

use std::{
    collections::BTreeMap,
    panic::UnwindSafe,
    path::{Path, PathBuf},
};

use crate::driver::{
    pot_dsl::{PotSetupFn, SysTestFn},
    test_env::TestEnv,
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use slog::Logger;
use url::Url;

#[macro_export]
macro_rules! systest {
    ($a:path) => {
        ic_tests::driver::new::dsl::TestFunction::new(std::stringify!($a), $a)
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

#[derive(Clone, Debug)]
struct Dependencies(BTreeMap<String, Dependency>);

impl Dependencies {
    // This function is essentially the interface between bazel and the test
    // driver.

    // btw, bazel allows assembling json objects
    fn from_env() -> Result<Self> {
        Ok(Self(Default::default()))
    }
}

// this should be some internally stable representation of available
// dependencies
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type")]
pub enum Dependency {
    RemoteApi { url: Url },
    // for example, wasm files that are required by the test drivers are
    // certainly locally available
    LocalFile { path: PathBuf },
    // for example, disk image
    RemoteFile { url: Url, sha256: String },
}

pub trait ChildFn: FnOnce(Logger) + UnwindSafe + Send + Sync + 'static {}
impl<T: FnOnce(Logger) + UnwindSafe + Send + Sync + 'static> ChildFn for T {}

// (TestEnv -> ()) -> (WorkingDir -> ())
fn lift<P, R, F: SysTestFn>(source_env: P, target_env: R, f: F) -> impl ChildFn
where
    P: AsRef<Path>,
    R: AsRef<Path>,
{
    let source_env_path = source_env.as_ref().to_owned();
    let target_env_path = target_env.as_ref().to_owned();
    move |logger: Logger| {
        let src_env = TestEnv::new(&source_env_path, logger.clone())
            .expect("could not create source environment");
        let test_env = src_env
            .fork(logger, target_env_path)
            .expect("could not create test env");
        (f)(test_env);
    }
}
