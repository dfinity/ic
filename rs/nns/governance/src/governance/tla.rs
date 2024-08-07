use super::Governance;
pub use tla_instrumentation::{
    tla_log_all_globals, tla_log_locals, tla_log_request, tla_log_response,
};
pub use tla_instrumentation::{
    Destination, GlobalState, InstrumentationState, Label, ResolvedStatePair, TlaValue, ToTla,
    Update, VarAssignment,
};
pub use tla_instrumentation_proc_macros::tla_update_method;
use tokio::task_local;

use std::sync::RwLock;

task_local! {
    pub static TLA_INSTRUMENTATION_STATE: InstrumentationState;
}

pub static TLA_TRACES: RwLock<Vec<ResolvedStatePair>> = RwLock::new(Vec::new());

pub fn get_tla_globals(gov: &Governance) -> GlobalState {
    let mut state = GlobalState::new();
    state.add(
        "locks",
        TlaValue::Set(
            gov.heap_data
                .in_flight_commands
                .keys()
                .map(|v| v.to_tla_value())
                .collect(),
        ),
    );
    state
}

#[macro_export]
macro_rules! tla_get_globals {
    ($self:expr) => {
        tla::get_tla_globals($self)
    };
}

pub fn split_neuron_desc() -> Update {
    Update {
        default_start_locals: VarAssignment::new(),
        default_end_locals: VarAssignment::new(),
        start_label: Label::new("Start_Label"),
        end_label: Label::new("End_Label"),
        process_id: "Split_Neuron_PID".to_string(),
        canister_name: "governance".to_string(),
    }
}
