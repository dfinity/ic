use local_key::task_local;
use std::sync::{Arc, Mutex, RwLock};
use tla_instrumentation::{InstrumentationState, UpdateTrace};

task_local! {
    pub static TLA_INSTRUMENTATION_STATE: InstrumentationState;
    pub static TLA_TRACES_LKEY: Arc<Mutex<Vec<UpdateTrace>>>;
}

#[cfg(target_family = "wasm")]
pub static TLA_TRACES_MUTEX: Option<RwLock<Vec<UpdateTrace>>> = Some(RwLock::new(vec![]));

#[cfg(not(target_family = "wasm"))]
pub static TLA_TRACES_MUTEX: Option<RwLock<Vec<UpdateTrace>>> = None;

