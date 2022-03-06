use std::fmt::Display;
use std::panic::{catch_unwind, UnwindSafe};

use crate::ic_manager::IcHandle;
use crate::pot::FondueTestFn;
use crate::prod_tests::ic::InternetComputer;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub trait PotConfigFn: FnOnce() -> InternetComputer + UnwindSafe + Send + Sync + 'static {}
impl<T: FnOnce() -> InternetComputer + UnwindSafe + Send + Sync + 'static> PotConfigFn for T {}

pub fn suite(name: &str, pots: Vec<Pot>) -> Suite {
    let name = name.to_string();
    Suite { name, pots }
}

pub fn pot_with_time_limit<F: PotConfigFn>(
    name: &str,
    config: F,
    testset: TestSet,
    time_limit: Duration,
) -> Pot {
    Pot::new(name, ExecutionMode::Run, config, testset, Some(time_limit))
}

pub fn pot<F: PotConfigFn>(name: &str, config: F, testset: TestSet) -> Pot {
    Pot::new(name, ExecutionMode::Run, config, testset, None)
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
        f: Box::new(test),
    }
}

pub struct Pot {
    pub name: String,
    pub execution_mode: ExecutionMode,
    pub config: ConfigState,
    pub testset: TestSet,
    pub pot_timeout: Option<Duration>,
}

// In order to evaluate this function in a catch_unwind(), we need to take
// ownership of it and thus move it out of the object.
#[allow(clippy::large_enum_variant)]
pub enum ConfigState {
    Function(Box<dyn PotConfigFn>),
    Evaluated(std::thread::Result<InternetComputer>),
}

impl ConfigState {
    pub fn evaluate(&mut self) -> &std::thread::Result<InternetComputer> {
        fn dummy() -> InternetComputer {
            unimplemented!()
        }
        let mut tmp = Self::Function(Box::new(dummy));
        std::mem::swap(&mut tmp, self);
        tmp = match tmp {
            ConfigState::Function(f) => ConfigState::Evaluated(catch_unwind(f)),
            r @ ConfigState::Evaluated(_) => r,
        };
        std::mem::swap(&mut tmp, self);
        if let Self::Evaluated(r) = self {
            return r;
        }
        unreachable!()
    }

    pub fn unwrap_ref(&self) -> &InternetComputer {
        match self {
            ConfigState::Function(_) => panic!("Called unwrap on not evaluated result!"),
            ConfigState::Evaluated(r) => r.as_ref().unwrap(),
        }
    }
}

impl Pot {
    pub fn new<F: PotConfigFn>(
        name: &str,
        execution_mode: ExecutionMode,
        config: F,
        testset: TestSet,
        pot_timeout: Option<Duration>,
    ) -> Self {
        Self {
            name: name.to_string(),
            execution_mode,
            config: ConfigState::Function(Box::new(config)),
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
    pub f: Box<dyn FondueTestFn<IcHandle>>,
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

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
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
        let mut config_state = ConfigState::Function(Box::new(InternetComputer::new));
        config_state.evaluate().as_ref().unwrap();
    }

    #[test]
    fn failing_config_evaluation_can_be_caught() {
        let mut config_state = ConfigState::Function(Box::new(|| panic!("magic error!")));
        let e = config_state.evaluate().as_ref().unwrap_err();
        if let Some(s) = e.downcast_ref::<&str>() {
            assert!(s.contains("magic error!"));
        } else {
            panic!("Error is not string")
        }
    }
}
