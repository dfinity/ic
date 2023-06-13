use candid::CandidType;
use serde::Deserialize;

/// Payload to upgrade the root canister.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Deserialize, CandidType)]
pub struct UpgradeRootProposal {
    pub wasm_module: Vec<u8>,
    pub module_arg: Vec<u8>,
    pub stop_upgrade_start: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Deserialize, CandidType)]
pub struct HardResetNnsRootToVersionPayload {
    pub wasm_module: Vec<u8>,
    pub init_arg: Vec<u8>,
}
