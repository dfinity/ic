use super::Governance;

pub use tla_instrumentation::{
    Destination, GlobalState, InstrumentationState, Label, ResolvedStatePair, TlaValue, ToTla,
    Update, VarAssignment,
};
pub use tla_instrumentation_proc_macros::tla_update_method;

pub use ic_nervous_system_common::tla::{TLA_INSTRUMENTATION_STATE, TLA_TRACES};
pub use ic_nervous_system_common::{tla_log_locals, tla_log_request, tla_log_response};

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
