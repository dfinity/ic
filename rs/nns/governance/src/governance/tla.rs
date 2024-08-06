use super::Governance;
pub use tla_instrumentation::{tla_log_all_globals, tla_log_locals};
pub use tla_instrumentation::{
    GlobalState, InstrumentationState, Label, MethodInstrumentationState, ResolvedStatePair,
    TlaValue, ToTla, Update, VarAssignment,
};
pub use tla_instrumentation_proc_macros::tla_update_method;
use tokio::task_local;

use std::cell::RefCell;
use std::rc::Rc;

task_local! {
    pub static TLA_STATE: Rc<RefCell<MethodInstrumentationState>>;
}

#[macro_export]
macro_rules! tla_start_scope {
    ($state:expr, $f:expr) => {
        TLA_STATE.scope($state, $f)
    };
}

#[macro_export]
macro_rules! tla_get_scope {
    () => {
        TLA_STATE.get()
    };
}

static mut STATE_PAIRS: Vec<ResolvedStatePair> = Vec::new();

pub static mut TLA_STATE_PAIRS: Vec<ResolvedStatePair> = Vec::new();

#[macro_export]
macro_rules! tla_add_state_pairs {
    ($pairs:expr) => {
        unsafe {
            TLA_STATE_PAIRS.extend($pairs);
        }
    };
}

static mut STATE: Option<InstrumentationState> = None;

pub fn init_tla_state(s: InstrumentationState) -> () {
    unsafe {
        assert!(
            STATE.is_none(),
            "Starting a new update with state {:?} without finishing the previous one",
            s
        );
        STATE = Some(s);
    }
}

pub fn with_tla_state<F>(f: F)
where
    F: FnOnce(&mut InstrumentationState) -> (),
{
    unsafe {
        if let Some(ref mut state) = STATE {
            // print!("State before with_tla_state: {:?}", state);
            f(state);
            // print!("State after with_tla_state: {:?}", state)
        } else {
            panic!("Instrumentation state not initialized");
        }
    }
}

pub fn with_tla_state_pairs<F>(f: F)
where
    F: FnOnce(&mut Vec<ResolvedStatePair>) -> (),
{
    unsafe {
        // As unsafe as anything else, but see
        // https://github.com/rust-lang/rust/issues/114447
        // for why this particular syntax here
        f(&mut *std::ptr::addr_of_mut!(STATE_PAIRS));
    }
}

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
macro_rules! get_tla_globals {
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

pub fn get_state_pairs() -> Vec<ResolvedStatePair> {
    unsafe { STATE_PAIRS.clone() }
}
