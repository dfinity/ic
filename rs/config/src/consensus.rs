use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ConsensusConfig {
    #[serde(default = "detect_starvation_default")]
    pub detect_starvation: bool,
}

fn detect_starvation_default() -> bool {
    true
}
