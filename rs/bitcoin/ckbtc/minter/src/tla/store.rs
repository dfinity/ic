use local_key::task_local;
use std::sync::{Arc, Mutex, RwLock};
use tla_instrumentation::{InstrumentationState, UpdateTrace};

#[cfg(feature = "tla")]
task_local! {
    pub static TLA_INSTRUMENTATION_STATE: InstrumentationState;
    pub static TLA_TRACES_LKEY: Arc<Mutex<Vec<UpdateTrace>>>;
}

#[cfg(all(target_family = "wasm", feature = "tla"))]
pub static TLA_TRACES_MUTEX: Option<RwLock<Vec<UpdateTrace>>> = Some(RwLock::new(vec![]));

#[cfg(all(not(target_family = "wasm"), feature = "tla"))]
pub static TLA_TRACES_MUTEX: Option<RwLock<Vec<UpdateTrace>>> = None;

