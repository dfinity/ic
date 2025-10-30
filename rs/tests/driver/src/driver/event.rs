use std::{fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
pub enum TaskId {
    // Argument x must be unique across all TaskId::Test(x)
    Test(String),
    // Argument x in TaskId::Timeout(x) corresponds to x in TaskId::Test(x)
    Timeout(String),
}

impl Display for TaskId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaskId::Test(test_name) => write!(f, "{test_name}"),
            TaskId::Timeout(task_id) => write!(f, "timeout({task_id})"),
        }
    }
}

/// invariant: Display . FromStr == id
impl FromStr for TaskId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let to = "timeout(";
        match s {
            s if s.starts_with(to) => {
                let name = &s[to.len()..s.len() - 1];
                Ok(TaskId::Timeout(name.to_string()))
            }
            s => Ok(TaskId::Test(s.to_string())),
        }
    }
}

impl TaskId {
    pub fn name(&self) -> String {
        format!("{self}")
    }
}
