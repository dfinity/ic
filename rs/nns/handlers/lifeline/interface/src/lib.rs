use candid::CandidType;
use ic_crypto_sha2::Sha256;
use serde::{Deserialize, Serialize};

/// Payload to upgrade the root canister.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, CandidType)]
pub struct UpgradeRootProposal {
    pub wasm_module: Vec<u8>,
    pub module_arg: Vec<u8>,
    pub stop_upgrade_start: bool,
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, CandidType)]
pub struct HardResetNnsRootToVersionPayload {
    pub wasm_module: Vec<u8>,
    pub init_arg: Vec<u8>,
}

impl std::fmt::Debug for UpgradeRootProposal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut wasm_sha = Sha256::new();
        wasm_sha.write(&self.wasm_module);
        let wasm_sha = wasm_sha.finish();
        let mut arg_sha = Sha256::new();
        arg_sha.write(&self.module_arg);
        let arg_sha = arg_sha.finish();

        f.debug_struct("UpgradeRootProposalPayload")
            .field("stop_upgrade_start", &self.stop_upgrade_start)
            .field("wasm_module_sha256", &format!("{:x?}", wasm_sha))
            .field("module_arg_sha256", &format!("{:x?}", arg_sha))
            .finish()
    }
}

impl std::fmt::Debug for HardResetNnsRootToVersionPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut wasm_sha = Sha256::new();
        wasm_sha.write(&self.wasm_module);
        let wasm_sha = wasm_sha.finish();
        let mut arg_sha = Sha256::new();
        arg_sha.write(&self.init_arg);
        let arg_sha = arg_sha.finish();

        f.debug_struct("UpgradeRootProposalPayload")
            .field("wasm_module_sha256", &format!("{:x?}", wasm_sha))
            .field("module_arg_sha256", &format!("{:x?}", arg_sha))
            .finish()
    }
}
