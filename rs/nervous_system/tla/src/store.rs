use local_key::task_local;
use std::sync::RwLock;
pub use tla_instrumentation::{InstrumentationState, UpdateTrace};

#[cfg(feature = "tla")]
task_local! {
    pub static TLA_INSTRUMENTATION_STATE: InstrumentationState;
}

#[cfg(feature = "tla")]
pub static TLA_TRACES: RwLock<Vec<UpdateTrace>> = RwLock::new(Vec::new());
