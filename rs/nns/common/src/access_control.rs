use ic_base_types::PrincipalId;

fn caller() -> PrincipalId {
    PrincipalId::from(ic_cdk::api::msg_caller())
}

pub fn check_caller_is_root() {
    if caller() != PrincipalId::from(ic_nns_constants::ROOT_CANISTER_ID) {
        panic!("Only the root canister is allowed to call this method.");
    }
}

pub fn check_caller_is_ledger() {
    if caller() != PrincipalId::from(ic_nns_constants::LEDGER_CANISTER_ID) {
        panic!("Only the ledger canister is allowed to call this method.");
    }
}

pub fn check_caller_is_gtc() {
    if caller() != PrincipalId::from(ic_nns_constants::GENESIS_TOKEN_CANISTER_ID) {
        panic!("Only the GTC is allowed to call this method.");
    }
}

pub fn check_caller_is_governance() {
    if caller() != PrincipalId::from(ic_nns_constants::GOVERNANCE_CANISTER_ID) {
        panic!("Only the Governance canister is allowed to call this method");
    }
}

pub fn check_caller_is_sns_w() {
    if caller() != PrincipalId::from(ic_nns_constants::SNS_WASM_CANISTER_ID) {
        panic!("Only the SNS-W canister is allowed to call this method");
    }
}
