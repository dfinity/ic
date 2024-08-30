use std::{fmt::Display, panic::UnwindSafe};

use crate::driver::test_env::TestEnv;
use serde::{Deserialize, Serialize};

pub trait PotSetupFn: FnOnce(TestEnv) + UnwindSafe + Send + Sync + 'static {}
impl<T: FnOnce(TestEnv) + UnwindSafe + Send + Sync + 'static> PotSetupFn for T {}

pub trait SysTestFn: FnOnce(TestEnv) + UnwindSafe + Send + Sync + 'static {}
impl<T: FnOnce(TestEnv) + UnwindSafe + Send + Sync + 'static> SysTestFn for T {}

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TestPath(Vec<String>);

impl Display for TestPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.join("::"))
    }
}
