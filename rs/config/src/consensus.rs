use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusConfig {
    detect_starvation: bool,
}

impl ConsensusConfig {
    pub fn new(detect_starvation: bool) -> Self {
        Self { detect_starvation }
    }

    pub fn detect_starvation(&self) -> bool {
        self.detect_starvation
    }
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            detect_starvation: true,
        }
    }
}
