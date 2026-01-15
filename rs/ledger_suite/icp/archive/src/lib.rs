use candid::CandidType;
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize, CandidType)]
pub struct ArchiveUpgradeArgument {
    pub max_memory_size_bytes: Option<u64>,
}
