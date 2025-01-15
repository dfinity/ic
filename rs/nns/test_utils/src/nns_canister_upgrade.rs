use crate::common::modify_wasm_bytes;
use candid::Encode;
use cycles_minting_canister::CyclesCanisterInitPayload;
use ic_base_types::{CanisterId, PrincipalId};
use ic_crypto_sha2::Sha256;
use ic_nns_constants::{
    CYCLES_LEDGER_CANISTER_ID, CYCLES_MINTING_CANISTER_ID, GENESIS_TOKEN_CANISTER_ID,
    GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID, LIFELINE_CANISTER_ID, REGISTRY_CANISTER_ID,
    ROOT_CANISTER_ID, SNS_WASM_CANISTER_ID,
};
use std::{
    env,
    fmt::{Debug, Formatter},
    fs,
};

pub struct NnsCanisterUpgrade {
    pub nns_canister_name: String,
    pub canister_id: CanisterId,
    pub environment_variable_name: &'static str,
    pub wasm_path: String,
    pub wasm_content: Vec<u8>,
    pub module_arg: Vec<u8>,
    pub wasm_hash: [u8; 32],
}

impl NnsCanisterUpgrade {
    pub fn new(nns_canister_name: &str) -> Self {
        #[rustfmt::skip]
        let (canister_id, environment_variable_name) = match nns_canister_name {
            // NNS Backend
            "cycles-minting" => (CYCLES_MINTING_CANISTER_ID,"CYCLES_MINTING_CANISTER_WASM_PATH"),
            "genesis-token"  => (GENESIS_TOKEN_CANISTER_ID,"GENESIS_TOKEN_CANISTER_WASM_PATH"),
            "governance"     => (GOVERNANCE_CANISTER_ID, "GOVERNANCE_CANISTER_WASM_PATH"),
            "governance-test" => (GOVERNANCE_CANISTER_ID, "GOVERNANCE_CANISTER_TEST_WASM_PATH"),
            "ledger"         => (LEDGER_CANISTER_ID, "LEDGER_CANISTER_WASM_PATH"),
            "lifeline"       => (LIFELINE_CANISTER_ID, "LIFELINE_CANISTER_WASM_PATH"),
            "registry"       => (REGISTRY_CANISTER_ID, "REGISTRY_CANISTER_WASM_PATH"),
            "root"           => (ROOT_CANISTER_ID, "ROOT_CANISTER_WASM_PATH"),
            "sns-wasm"       => (SNS_WASM_CANISTER_ID, "SNS_WASM_CANISTER_WASM_PATH"),

            _ => panic!("Not a known NNS canister type: {}", nns_canister_name,),
        };

        let module_arg = if nns_canister_name == "cycles-minting" {
            Encode!(
                &(Some(CyclesCanisterInitPayload {
                    cycles_ledger_canister_id: Some(CYCLES_LEDGER_CANISTER_ID),
                    ledger_canister_id: None,
                    governance_canister_id: None,
                    minting_account_id: None,
                    last_purged_notification: None,
                    exchange_rate_canister: None,
                }))
            )
            .unwrap()
        } else {
            Encode!(&()).unwrap()
        };

        let nns_canister_name = nns_canister_name.to_string();
        let wasm_path = env::var(environment_variable_name)
            .unwrap_or_else(|err| panic!("{}: {}", err, environment_variable_name,));
        let wasm_content = fs::read(&wasm_path).unwrap();
        let wasm_hash = Sha256::hash(&wasm_content);

        Self {
            nns_canister_name,
            canister_id,
            environment_variable_name,
            wasm_path,
            wasm_content,
            module_arg,
            wasm_hash,
        }
    }

    pub fn modify_wasm_but_preserve_behavior(&mut self) {
        let old_wasm_hash = self.wasm_hash;

        self.wasm_content = modify_wasm_bytes(&self.wasm_content, 42);
        self.wasm_hash = Sha256::hash(&self.wasm_content);

        assert_ne!(self.wasm_hash, old_wasm_hash, "{:#?}", self);
    }

    pub fn controller_principal_id(&self) -> PrincipalId {
        let result = if self.nns_canister_name == "root" {
            LIFELINE_CANISTER_ID
        } else {
            ROOT_CANISTER_ID
        };

        PrincipalId::from(result)
    }
}

impl Debug for NnsCanisterUpgrade {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let Self {
            nns_canister_name,
            canister_id,
            environment_variable_name,
            wasm_path,
            wasm_hash,
            module_arg,

            wasm_content: _,
        } = self;

        let wasm_hash = wasm_hash.map(|element| format!("{:02X}", element)).join("");
        let wasm_hash = &wasm_hash;

        let module_arg = module_arg
            .iter()
            .map(|element| format!("{:02X}", element))
            .collect::<Vec<_>>()
            .join("");
        let module_arg = &module_arg;

        formatter
            .debug_struct("NnsCanisterUpgrade")
            .field("nns_canister_name", nns_canister_name)
            .field("wasm_path", wasm_path)
            .field("wasm_hash", wasm_hash)
            .field("module_arg", module_arg)
            .field("canister_id", canister_id)
            .field("environment_variable_name", environment_variable_name)
            .finish()
    }
}
