pub mod checker;
pub mod tla_state;
pub mod tla_value;
use std::fmt::Formatter;
use std::mem;
use std::sync::{Arc, Mutex};

use candid::{CandidType, Deserialize};
pub use tla_state::*;
pub use tla_value::*;

pub struct UnsafeSendPtr<T: ?Sized>(pub *const T);
unsafe impl<T: ?Sized> Send for UnsafeSendPtr<T> {}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SourceLocation {
    pub file: String,
    pub line: String,
}

impl std::fmt::Display for SourceLocation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{}: Line {}", self.file, self.line))
    }
}

#[derive(Clone, Debug)]
pub struct Update {
    // TODO: do we want checks that only declared variables are set?
    // vars: BTreeSet<String>,
    pub default_start_locals: VarAssignment,
    pub default_end_locals: VarAssignment,
    // Only for top-level methods
    pub start_label: Label,
    pub end_label: Label,
    // TODO: do we want checks that all labels come from an allowed set?
    // labels: BTreeSet<Label>,
    pub process_id: String,
    /// Used for naming the buffers; convention is to use
    /// "<canister_name>_to_destination" for requests and
    /// "destination_to_<canister_name>" for responses
    pub canister_name: String,
    /// Cleans up the trace and extracts the constants from it
    pub post_process: fn(&mut Vec<ResolvedStatePair>) -> TlaConstantAssignment,
}

#[derive(Debug, Clone, CandidType, Deserialize)]
pub struct UpdateTrace {
    pub model_name: String,
    pub state_pairs: Vec<ResolvedStatePair>,
    pub constants: TlaConstantAssignment,
}

#[derive(Clone, Debug)]
enum LocationStackElem {
    Label(Label),
    Placeholder,
}
#[derive(Clone, Debug)]
pub struct LocationStack(Vec<LocationStackElem>);

impl LocationStack {
    pub fn merge_labels(&self) -> Label {
        self.0
            .iter()
            .map(|e| match e {
                LocationStackElem::Label(l) => l.clone(),
                _ => panic!("Placeholder found in the location stack while trying to merge labels {:?}. You may have too many nested `tla_function` attributes. Make sure to have one log_label or log_request/response for each function in the call stack", self.0),
            })
            .reduce(|acc, l| acc.merge(&l))
            .expect("No labels in the location stack")
    }
}

#[derive(Clone, Debug)]
pub struct Context {
    pub update: Update,
    pub global: GlobalState,
    pub locals: VarAssignment,
    pub location: LocationStack,
}

impl Context {
    fn new(update: Update) -> Self {
        let location = LocationStack(vec![LocationStackElem::Label(update.start_label.clone())]);
        let locals = VarAssignment::new();
        Self {
            update,
            global: GlobalState::new(),
            locals,
            location,
        }
    }

    pub fn call_function(&mut self) {
        self.location.0.push(LocationStackElem::Placeholder);
    }

    pub fn return_from_function(&mut self) {
        let _f = self.location.0.pop().expect("No function in call stack");
    }

    fn end_update(&mut self) -> Result<LocalState, MergeError> {
        Ok(LocalState {
            locals: self
                .update
                .default_end_locals
                .clone()
                .merge(self.locals.clone())?,
            label: self.update.end_label.clone(),
        })
    }

    fn get_state(&self) -> LocalState {
        let label = self.location.merge_labels();
        LocalState {
            locals: self.locals.clone(),
            label,
        }
    }

    // TODO: handle passing &mut locals to called functions somehow; what if they're called differently?
    fn log_locals(&mut self, locals: VarAssignment) -> Result<(), MergeError> {
        self.locals = self.locals.merge(locals)?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
enum Stage {
    Start,
    End(StartState),
}

#[derive(Clone, Debug)]
pub struct MessageHandlerState {
    pub context: Context,
    stage: Stage,
}

impl MessageHandlerState {
    pub fn new(update: Update, global: GlobalState, source_location: SourceLocation) -> Self {
        let locals = update.default_start_locals.clone();
        let label = update.start_label.clone();
        Self {
            context: Context::new(update),
            stage: Stage::End(StartState {
                global,
                local: LocalState { locals, label },
                responses: Vec::new(),
                source_location,
            }),
        }
    }
}

#[derive(Clone)]
pub struct InstrumentationState {
    pub handler_state: Arc<Mutex<MessageHandlerState>>,
    pub state_pairs: Arc<Mutex<Vec<ResolvedStatePair>>>,
    pub globals_snapshotter: Arc<Mutex<dyn Fn() -> GlobalState + Send>>,
}

impl InstrumentationState {
    pub fn new(
        update: Update,
        global: GlobalState,
        globals_snapshotter: Arc<Mutex<dyn Fn() -> GlobalState + Send>>,
        source_location: SourceLocation,
    ) -> Self {
        let state = MessageHandlerState::new(update, global, source_location);
        Self {
            handler_state: Arc::new(Mutex::new(state)),
            state_pairs: Arc::new(Mutex::new(Vec::new())),
            globals_snapshotter,
        }
    }
}

pub fn log_locals(
    state: &mut MessageHandlerState,
    locals: Vec<(&str, TlaValue)>,
) -> Result<(), MergeError> {
    let mut assignment = VarAssignment::new();
    for (name, value) in locals {
        assignment.push(name, value);
    }
    state.context.log_locals(assignment)
}

pub fn log_globals(state: &mut MessageHandlerState, global: GlobalState) {
    state.context.global.extend(global);
}

pub fn log_request(
    state: &mut MessageHandlerState,
    label: &str,
    to: Destination,
    method: &str,
    args: TlaValue,
    global: GlobalState,
    source_location: SourceLocation,
) -> ResolvedStatePair {
    *state
        .context
        .location
        .0
        .last_mut()
        .expect("Asked to log a request, but the location stack is empty.") =
        LocationStackElem::Label(Label::new(label));
    let old_stage = mem::replace(&mut state.stage, Stage::Start);
    let start_state = match old_stage {
        Stage::End(start) => start,
        _ => panic!("Issuing request {args} to {to}, but stage is start"),
    };
    let unresolved = StatePair {
        start: start_state,
        end: EndState {
            global,
            local: state.context.get_state(),
            requests: vec![RequestBuffer {
                to,
                method: method.to_string(),
                args,
            }],
            source_location,
        },
    };
    ResolvedStatePair::resolve(
        unresolved,
        state.context.update.process_id.as_str(),
        state.context.update.canister_name.as_str(),
    )
}

pub fn log_response(
    state: &mut MessageHandlerState,
    from: Destination,
    message: TlaValue,
    global: GlobalState,
    source_location: SourceLocation,
) {
    let local = state.context.get_state();
    let stage = &mut state.stage;
    assert!(
        matches!(stage, Stage::Start),
        "Receiving response {message} from {from} in end stage"
    );
    *stage = Stage::End(StartState {
        global,
        local,
        responses: vec![ResponseBuffer { from, message }],
        source_location,
    });
    state.context.global = GlobalState::new();
    state.context.locals = VarAssignment::new();
}

pub fn log_fn_call(state: &mut MessageHandlerState) {
    state.context.call_function();
}

pub fn log_fn_return(state: &mut MessageHandlerState) {
    state.context.return_from_function()
}

pub fn log_method_return(
    state: &mut MessageHandlerState,
    global: GlobalState,
    source_location: SourceLocation,
) -> ResolvedStatePair {
    let local = state.context.end_update().unwrap_or_else(|e| {
        panic!(
            "Failed to merge locals in log_method_return: {}; label_stack={:?}, existing_locals={:?}, default_end_locals={:?}, handler_state={:?}",
            e,
            state.context.location,
            state.context.locals,
            state.context.update.default_end_locals,
            state,
        )
    });

    let start_state = match mem::replace(&mut state.stage, Stage::Start) {
        Stage::End(start) => start,
        _ => panic!("Returning from method, but not in an end state"),
    };
    let unresolved = StatePair {
        start: start_state,
        end: EndState {
            global,
            local,
            requests: Vec::new(),
            source_location,
        },
    };
    ResolvedStatePair::resolve(
        unresolved,
        state.context.update.process_id.as_str(),
        state.context.update.canister_name.as_str(),
    )
}

pub fn log_label(state: &mut MessageHandlerState, label: &str) {
    *state
        .context
        .location
        .0
        .last_mut()
        .unwrap_or_else(|| panic!("Asked to log label {label}, but the location stack empty")) =
        LocationStackElem::Label(Label::new(label));
}

/// Logs the value of local variables at the end of the current message handler.
/// This might be called multiple times in a single message handler, in particular
/// if the message handler is implemented through several functions, each of which
/// has local variables that are reflected in the TLA model.
/// It assumes that there is a function:
/// `with_tla_state<F>(f: F) where F: FnOnce(&mut InstrumentationState) -> ()`
/// in scope (typically providing a way to mutate some global canister variable).
#[macro_export]
macro_rules! tla_log_locals {
    ($($name:ident : $value:expr_2021),*) => {
        {
            let mut locals = Vec::new();
            $(
                locals.push((stringify!($name), $value.to_tla_value()));
            )*
            let res = TLA_INSTRUMENTATION_STATE.try_with(|state| {
                let mut handler_state = state.handler_state.lock().expect("Failed to lock handler state in log_locals");
                $crate::log_locals(&mut handler_state, locals.clone())
            });
            match res {
                Ok(Ok(())) => (),
                Ok(Err(e)) => {
                    let handler_snapshot = TLA_INSTRUMENTATION_STATE
                        .try_with(|state| {
                            let handler_state = state
                                .handler_state
                                .lock()
                                .expect("Failed to lock handler state for snapshot in log_locals");
                            let label = handler_state.context.location.merge_labels();
                            let existing_keys: Vec<_> = handler_state
                                .context
                                .locals
                                .0
                                .keys()
                                .cloned()
                                .collect();
                            format!(
                                "label={:?}, existing_keys={:?}, existing_locals={:?}, handler_state={:?}",
                                label, existing_keys, handler_state.context.locals, handler_state
                            )
                        })
                        .unwrap_or_else(|_| "handler state unavailable".to_string());
                    panic!("tla_log_locals merge failure: {}; handler_state: {}", e, handler_snapshot);
                }
                Err(_) => {
                    println!("Asked to log locals {:?}, but instrumentation not initialized", locals);
                }
            };
        }
    };
}

/// Logs the value of global variables at the end of the current message handler.
/// This might be called multiple times in a single message handler, in particular
/// if the message handler is implemented through several functions, each of which
/// changes the global state, but some of which have access only to part of the global
/// state variables that are reflected in the TLA model.
/// It assumes that there is a function:
/// `with_tla_state<F>(f: F) where F: FnOnce(&mut InstrumentationState) -> ()`
/// in scope (typically providing a way to mutate some global canister variable).
#[macro_export]
macro_rules! tla_log_globals {
    (($($name:ident : $value:expr_2021),*)) => {
        {
            let mut globals = GlobalState::new();
            $(
                globals.add((stringify!($name), $value.to_tla_value()));
            )*
            with_tla_state(|state| {
                $crate::log_globals(state, globals);
            });
        }
    };
}

#[macro_export]
macro_rules! tla_log_all_globals {
    ($self:expr_2021) => {{
        let mut globals = tla_get_globals!($self);
        let state_with_pairs = TLA_INSTRUMENTATION_STATE.get();
        let mut state = state_with_pairs
            .state
            .lock()
            .expect("Failed to lock handler state in log_globals");
        $crate::log_globals(&mut state, globals);
    }};
}

/// Logs the sending of a request (ending a message handler).
/// It assumes that there are the following three functions in scope:
/// TODO: update the comment here after the design is stabilized
/// 1. `tla_get_globals() -> GlobalState
/// 2. `with_tla_state<F>(f: F) where F: FnOnce(&mut InstrumentationState) -> ()
/// 3. `with_tla_state_pairs<F>(f: F) where F: FnOnce(&mut Vec<StatePair>) -> ()
#[macro_export]
macro_rules! tla_log_request {
    ($label:expr_2021, $to:expr_2021, $method:expr_2021, $message:expr_2021) => {{
        let message = $message.to_tla_value();
        let res = TLA_INSTRUMENTATION_STATE.try_with(|state| {
            let mut handler_state = state.handler_state.lock().expect("Failed to lock handler state in log_request");
            let globals = (*state.globals_snapshotter.lock().expect("Couldn't lock the snapshotter in the_log_request"))();
            let location = $crate::SourceLocation { file: file!().to_string(), line: line!().to_string() };
            let new_state_pair = $crate::log_request(&mut handler_state, $label, $to, $method, message.clone(), globals, location);
            let mut state_pairs = state.state_pairs.lock().expect("Failed to lock state pairs in log_request");
            state_pairs.push(new_state_pair);
        });
        match res {
            Ok(_) => (),
            Err(_) => {
                println!("Asked to log request to {} with message {}, but instrumentation not initialized", $to, message);
            }
        };
    }};
}

/// Logs the receipt of a response (that starts a new message handler).
/// It assumes that there are the following two functions in scope:
/// TODO: update the comment here after the design is stabilized
/// 1. `tla_get_globals() -> GlobalState`
/// 2. with_tla_state<F>(f: F) where F: FnOnce(&mut InstrumentationState) -> ()
#[macro_export]
macro_rules! tla_log_response {
    ($from:expr_2021, $message:expr_2021) => {{
        let message = $message.to_tla_value();
        let location = $crate::SourceLocation { file: file!().to_string(), line: line!().to_string() };
        let res = TLA_INSTRUMENTATION_STATE.try_with(|state| {
            let mut handler_state = state.handler_state.lock().expect("Failed to lock handler state in log_response");
            let globals = (*state.globals_snapshotter.lock().expect("Couldn't lock the snapshotter in tla_log_response"))();
            $crate::log_response(&mut handler_state, $from, message.clone(), globals, location);
        });
        match res {
            Ok(_) => (),
            Err(_) => {
                println!("Asked to log response from {} with message {}, but instrumentation not initialized", $from, message);
            }
        };
    }};
}

/// Logs the start of a method (top-level update)
/// It assumes that there are the following two functions in scope:
/// 1. `tla_get_globals() -> GlobalState`
/// 2. with_tla_state<F>(f: F) where F: FnOnce(&mut InstrumentationState) -> ()
///
/// This macro is normally not called directly; rather, the attribute proc macro tla_update
/// is used instead.
#[macro_export]
macro_rules! tla_log_method_call {
    ($update:expr_2021, $global:expr_2021) => {{ $crate::log_method_call($update, $global) }};
}

#[macro_export]
macro_rules! tla_log_label {
    ($label:expr_2021) => {{
        let res = TLA_INSTRUMENTATION_STATE.try_with(|state| {
            let mut handler_state = state
                .handler_state
                .lock()
                .expect("Failed to lock handler state in log_label");
            $crate::log_label(&mut handler_state, $label);
        });
        match res {
            Ok(_) => (),
            Err(_) => {
                println!(
                    "Asked to log label {}, but instrumentation not initialized",
                    $label
                );
            }
        };
    }};
}
