use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    state_root: PathBuf,
}

impl Config {
    pub fn new(state_root: PathBuf) -> Self {
        Self { state_root }
    }

    pub fn state_root(&self) -> PathBuf {
        self.state_root.clone()
    }
}
