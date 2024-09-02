pub mod checker;
pub mod tla_state;
pub mod tla_value;
use std::cell::RefCell;
use std::mem;
use std::rc::Rc;

pub use tla_state::*;
pub use tla_value::*;

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

#[derive(Debug)]
pub struct UpdateTrace {
    pub update: Update,
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
                _ => panic!("Placeholder found in the location stack while trying to merge labels"),
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

    fn call_function(&mut self) {
        self.location.0.push(LocationStackElem::Placeholder);
    }

    fn return_from_function(&mut self) -> () {
        let _f = self.location.0.pop().expect("No function in call stack");
    }

    fn end_update(&mut self) -> LocalState {
        LocalState {
            locals: self
                .update
                .default_end_locals
                .clone()
                .merge(self.locals.clone()),
            label: self.update.end_label.clone(),
        }
    }

    fn get_state(&self) -> LocalState {
        let label = self.location.merge_labels();
        LocalState {
            locals: self.locals.clone(),
            label,
        }
    }

    // TODO: handle passing &mut locals to called functions somehow; what if they're called differently?
    fn log_locals(&mut self, locals: VarAssignment) {
        self.locals = self.locals.merge(locals);
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
    pub fn new(update: Update, global: GlobalState) -> Self {
        let locals = update.default_start_locals.clone();
        let label = update.start_label.clone();
        Self {
            context: Context::new(update),
            stage: Stage::End(StartState {
                global,
                local: LocalState { locals, label },
                responses: Vec::new(),
            }),
        }
    }
}

#[derive(Clone)]
pub struct InstrumentationState {
    pub handler_state: Rc<RefCell<MessageHandlerState>>,
    pub state_pairs: Rc<RefCell<Vec<ResolvedStatePair>>>,
    pub globals_snapshotter: Rc<dyn Fn() -> GlobalState>,
}

impl InstrumentationState {
    pub fn new(
        update: Update,
        global: GlobalState,
        globals_snapshotter: Rc<dyn Fn() -> GlobalState>,
    ) -> Self {
        let state = MessageHandlerState::new(update, global);
        Self {
            handler_state: Rc::new(RefCell::new(state)),
            state_pairs: Rc::new(RefCell::new(Vec::new())),
            globals_snapshotter,
        }
    }
}

pub fn log_locals(state: &mut MessageHandlerState, locals: Vec<(&str, TlaValue)>) {
    let mut assignment = VarAssignment::new();
    for (name, value) in locals {
        assignment.push(name, value);
    }
    state.context.log_locals(assignment);
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
) -> ResolvedStatePair {
    // TODO: do we want to push the label to the location stack here, or just replace it?
    state.context.location.0 = vec![LocationStackElem::Label(Label::new(label))];
    let old_stage = mem::replace(&mut state.stage, Stage::Start);
    let start_state = match old_stage {
        Stage::End(start) => start,
        _ => panic!("Issuing request {} to {}, but stage is start", args, to),
    };
    let unresolved = StatePair {
        start: start_state,
        end: EndState {
            global: global,
            local: state.context.get_state(),
            requests: vec![RequestBuffer {
                to,
                method: method.to_string(),
                args,
            }],
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
) {
    let local = state.context.get_state();
    let stage = &mut state.stage;
    assert!(
        matches!(stage, Stage::Start),
        "Receiving response {} from {} in end stage",
        message,
        from
    );
    *stage = Stage::End(StartState {
        global: global,
        local,
        responses: vec![ResponseBuffer { from, message }],
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

// TODO: Does this work for modeling arguments as non-deterministically chosen locals?
pub fn log_method_call(function: Update, global: GlobalState) -> MessageHandlerState {
    MessageHandlerState::new(function, global)
}

pub fn log_method_return(
    state: &mut MessageHandlerState,
    global: GlobalState,
) -> ResolvedStatePair {
    let local = state.context.end_update();

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
        },
    };
    ResolvedStatePair::resolve(
        unresolved,
        state.context.update.process_id.as_str(),
        state.context.update.canister_name.as_str(),
    )
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
    ($($name:ident : $value:expr),*) => {
        {
            let mut locals = Vec::new();
            $(
                locals.push((stringify!($name), $value.to_tla_value()));
            )*
            let res = TLA_INSTRUMENTATION_STATE.try_with(|state| {
                let mut handler_state = state.handler_state.borrow_mut();
                $crate::log_locals(&mut handler_state, locals.clone());
            });
            match res {
                Ok(_) => (),
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
    (($($name:ident : $value:expr),*)) => {
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
    ($self:expr) => {{
        let mut globals = tla_get_globals!($self);
        let state_with_pairs = TLA_INSTRUMENTATION_STATE.get();
        let mut state = state_with_pairs.state.borrow_mut();
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
    ($label:expr, $to:expr, $method:expr, $message:expr) => {{
        let message = $message.to_tla_value();
        let res = TLA_INSTRUMENTATION_STATE.try_with(|state| {
            let mut handler_state = state.handler_state.borrow_mut();
            let globals = (*state.globals_snapshotter)();
            let new_state_pair = $crate::log_request(&mut handler_state, $label, $to, $method, message.clone(), globals);
            let mut state_pairs = state.state_pairs.borrow_mut();
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
    ($from:expr, $message:expr) => {{
        let message = $message.to_tla_value();
        let res = TLA_INSTRUMENTATION_STATE.try_with(|state| {
            let mut handler_state = state.handler_state.borrow_mut();
            let globals = (*state.globals_snapshotter)();
            $crate::log_response(&mut handler_state, $from, message.clone(), globals);
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
/// This macro is normally not called directly; rather, the attribute proc macro tla_update
/// is used instead.
#[macro_export]
macro_rules! tla_log_method_call {
    ($update:expr, $global:expr) => {{
        $crate::log_method_call($update, $global)
    }};
}
