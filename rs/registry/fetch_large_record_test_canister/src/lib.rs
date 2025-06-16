use candid::CandidType;
use serde::Deserialize;

// Normally, we'd put these sorts of thing in a separate API crate, but since
// this is just a super simple canister and it's only for test, this is ok.

#[derive(Clone, Copy, Debug, PartialEq, Eq, CandidType, Deserialize)]
pub struct CallRegistryGetChangesSinceRequest {}

#[derive(Clone, Debug, PartialEq, Eq, CandidType, Deserialize)]
pub struct ContentSummary {
    pub key: Vec<u8>,
    pub len: u64,
    pub sha256: Vec<u8>,
}
