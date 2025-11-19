use tla_instrumentation::{
    GlobalState, Label, TlaConstantAssignment, TlaValue, Update, VarAssignment,
};

pub use retrieve_btc::RETRIEVE_BTC_DESC;
pub use store::{TLA_INSTRUMENTATION_STATE, TLA_TRACES_LKEY, TLA_TRACES_MUTEX};
pub use update_balance::UPDATE_BALANCE_DESC;

mod retrieve_btc;
mod store;
mod update_balance;

pub fn get_tla_globals() -> GlobalState {
    // TODO: populate with actual minter state.
    let mut state = GlobalState::new();
    state.add("placeholder", TlaValue::Constant("UNIT".to_string()));
    state
}

fn empty_update(model: &str) -> Update {
    Update {
        default_start_locals: VarAssignment::new(),
        default_end_locals: VarAssignment::new(),
        start_label: Label::new("Start"),
        end_label: Label::new("Done"),
        process_id: model.to_string(),
        canister_name: "ckbtc_minter".to_string(),
        post_process: |_| TlaConstantAssignment {
            constants: vec![],
        },
    }
}
