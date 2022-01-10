use std::fmt::Display;

use crate::pot::FondueTestFn;
use crate::{ic_instance::InternetComputer, ic_manager::IcHandle};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub fn suite(name: &str, pots: Vec<Pot>) -> Suite {
    let name = name.to_string();
    Suite { name, pots }
}

pub fn pot_with_time_limit(
    name: &str,
    config: InternetComputer,
    testset: TestSet,
    time_limit: Duration,
) -> Pot {
    Pot::new(name, ExecutionMode::Run, config, testset, Some(time_limit))
}

pub fn pot(name: &str, config: InternetComputer, testset: TestSet) -> Pot {
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
    pub config: InternetComputer,
    pub testset: TestSet,
    pub pot_timeout: Option<Duration>,
}

impl Pot {
    pub fn new(
        name: &str,
        execution_mode: ExecutionMode,
        config: InternetComputer,
        testset: TestSet,
        pot_timeout: Option<Duration>,
    ) -> Self {
        Self {
            name: name.to_string(),
            execution_mode,
            config,
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
