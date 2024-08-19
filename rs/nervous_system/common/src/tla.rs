use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use icp_ledger::{AccountIdentifier, Subaccount};
pub use tla_instrumentation::{Destination, InstrumentationState, TlaValue, ToTla, UpdateTrace};
use tokio::task_local;

use std::sync::RwLock;

task_local! {
    pub static TLA_INSTRUMENTATION_STATE: InstrumentationState;
}

pub static TLA_TRACES: RwLock<Vec<UpdateTrace>> = RwLock::new(Vec::new());

pub fn subaccount_to_tla(subaccount: &Subaccount) -> TlaValue {
    opt_subaccount_to_tla(&Some(subaccount.clone()))
}

pub fn opt_subaccount_to_tla(subaccount: &Option<Subaccount>) -> TlaValue {
    let account = AccountIdentifier::new(
        ic_base_types::PrincipalId::from(GOVERNANCE_CANISTER_ID),
        subaccount.clone(),
    );
    TlaValue::Literal(account.to_string())
}

pub fn account_to_tla(account: AccountIdentifier) -> TlaValue {
    account.to_string().as_str().to_tla_value()
}
