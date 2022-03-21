use std::fmt::Display;
use std::panic::{catch_unwind, UnwindSafe};

use serde::{Deserialize, Serialize};
use slog::Logger;

use crate::ic_manager::IcHandle;
use crate::pot::{Context, FondueTestFn};
use crate::prod_tests::ic::InternetComputer;
use crate::prod_tests::test_env::TestEnv;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::driver_setup::tee_logger;
use super::test_setup::IcHandleConstructor;

pub trait PotSetupFn: FnOnce(TestEnv) + UnwindSafe + Send + Sync + 'static {}
impl<T: FnOnce(TestEnv) + UnwindSafe + Send + Sync + 'static> PotSetupFn for T {}

pub trait SysTestFn: FnOnce(TestEnv, Logger) + UnwindSafe + Send + Sync + 'static {}
impl<T: FnOnce(TestEnv, Logger) + UnwindSafe + Send + Sync + 'static> SysTestFn for T {}

pub fn suite(name: &str, pots: Vec<Pot>) -> Suite {
    let name = name.to_string();
    Suite { name, pots }
}

pub fn pot_with_time_limit(
    name: &str,
    mut ic: InternetComputer,
    testset: TestSet,
    time_limit: Duration,
) -> Pot {
    Pot::new(
        name,
        ExecutionMode::Run,
        move |env| ic.setup_and_start(&env).expect("failed to start IC"),
        testset,
        Some(time_limit),
    )
}

pub fn pot_with_setup<F: PotSetupFn>(name: &str, setup: F, testset: TestSet) -> Pot {
    Pot::new(name, ExecutionMode::Run, setup, testset, None)
}

pub fn pot(name: &str, mut ic: InternetComputer, testset: TestSet) -> Pot {
    pot_with_setup(
        name,
        move |env| ic.setup_and_start(&env).expect("failed to start IC"),
        testset,
    )
}

pub fn seq(tests: Vec<Test>) -> TestSet {
    TestSet::Sequence(tests)
}

pub fn par(tests: Vec<Test>) -> TestSet {
    TestSet::Parallel(tests)
}

pub fn t<F>(name: &str, test: F) -> Test
where
    F: FondueTestFn<IcHandle>,
{
    Test {
        name: name.to_string(),
        execution_mode: ExecutionMode::Run,
        f: Box::new(|test_env: TestEnv, log: Logger| {
            // Todo instantiate from test env
            let rng = rand_core::SeedableRng::seed_from_u64(42);
            let test_ctx = Context::new(rng, tee_logger(&test_env, log));
            let ic_handle = test_env
                .ic_handle()
                .expect("Could not create ic handle from test env");
            (test)(ic_handle, &test_ctx);
        }),
    }
}

pub fn sys_t<F>(name: &str, test: F) -> Test
where
    F: SysTestFn,
{
    Test {
        name: name.to_string(),
        execution_mode: ExecutionMode::Run,
        f: Box::new(test),
    }
}

pub struct Pot {
    pub name: String,
    pub execution_mode: ExecutionMode,
    pub setup: ConfigState,
    pub testset: TestSet,
    pub pot_timeout: Option<Duration>,
}

// In order to evaluate this function in a catch_unwind(), we need to take
// ownership of it and thus move it out of the object.
#[allow(clippy::large_enum_variant)]
pub enum ConfigState {
    Function(Box<dyn PotSetupFn>),
    Evaluated(std::thread::Result<()>),
}

impl ConfigState {
    pub fn evaluate(&mut self, test_env: &TestEnv) -> &std::thread::Result<()> {
        fn dummy(_: TestEnv) {
            unimplemented!()
        }
        let mut tmp = Self::Function(Box::new(dummy));
        std::mem::swap(&mut tmp, self);
        let env = test_env.clone();
        tmp = match tmp {
            ConfigState::Function(f) => ConfigState::Evaluated(catch_unwind(move || f(env))),
            r @ ConfigState::Evaluated(_) => r,
        };
        std::mem::swap(&mut tmp, self);
        if let Self::Evaluated(r) = self {
            return r;
        }
        unreachable!()
    }
}

impl Pot {
    pub fn new<F: PotSetupFn>(
        name: &str,
        execution_mode: ExecutionMode,
        config: F,
        testset: TestSet,
        pot_timeout: Option<Duration>,
    ) -> Self {
        Self {
            name: name.to_string(),
            execution_mode,
            setup: ConfigState::Function(Box::new(config)),
            testset,
            pot_timeout,
        }
    }
}

pub enum TestSet {
    Sequence(Vec<Test>),
    Parallel(Vec<Test>),
}

pub struct Test {
    pub name: String,
    pub execution_mode: ExecutionMode,
    pub f: Box<dyn SysTestFn>,
}

pub struct Suite {
    pub name: String,
    pub pots: Vec<Pot>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionMode {
    Run,
    Skip,
    Ignore,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TestPath(Vec<String>);

impl Display for TestPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.join("::"))
    }
}

impl TestPath {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn to_filepath(&self, base_dir: &Path) -> PathBuf {
        let filepath = PathBuf::new();
        filepath.join(base_dir).join(self.0.join("/"))
    }

    pub fn new_with_root<S: ToString>(root: S) -> Self {
        Self(vec![root.to_string()])
    }

    pub fn url_string(&self) -> String {
        self.0.join("__")
    }

    pub fn join<S: ToString>(&self, p: S) -> TestPath {
        let p = p.to_string();
        if !Self::is_c_like_ident(&p) {
            panic!("Invalid identifiers (must be c-like): {}", p);
        }
        let mut copy = self.0.clone();
        copy.push(p);
        TestPath(copy)
    }

    pub fn pop(&mut self) -> String {
        self.0.pop().expect("cannot pop from empty testpath")
    }

    pub fn is_c_like_ident(s: &str) -> bool {
        if s.is_empty() {
            return false;
        }

        let first = s.chars().next().unwrap();
        if !(first.is_ascii_alphabetic() || first == '_') {
            return false;
        }

        for c in s.chars().skip(1) {
            if !(c.is_ascii_alphanumeric() || c == '_') {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_can_be_lazily_evaluated() {
        let mut config_state = ConfigState::Function(Box::new(|_| {}));
        config_state.evaluate(&TestEnv::new(PathBuf::new()));
    }

    #[test]
    fn failing_config_evaluation_can_be_caught() {
        let mut config_state = ConfigState::Function(Box::new(|_| panic!("magic error!")));
        let e = config_state
            .evaluate(&TestEnv::new(PathBuf::new()))
            .as_ref()
            .unwrap_err();
        if let Some(s) = e.downcast_ref::<&str>() {
            assert!(s.contains("magic error!"));
        } else {
            panic!("Error is not string")
        }
    }
}
