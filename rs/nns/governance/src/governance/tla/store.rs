use local_key::task_local;
use std::sync::{Arc, Mutex, RwLock};
pub use tla_instrumentation::{InstrumentationState, UpdateTrace};

// The entire module should only ever be imported if the tla feature is enabled,
// but use another directive here just to make sure, as we really don't want to
// leak this into the production code.
#[cfg(feature = "tla")]
task_local! {
    pub static TLA_INSTRUMENTATION_STATE: InstrumentationState;
    pub static TLA_TRACES_LKEY: Arc<Mutex<Vec<UpdateTrace>>>;
}

// When compiled to a canister, we won't be able to use the task local storage to store
// the traces, so use a global lock instead.
#[cfg(all(feature = "tla", target_family = "wasm"))]
pub static TLA_TRACES_MUTEX: Option<RwLock<Vec<UpdateTrace>>> = Some(RwLock::new(vec![]));

// When compiled to a non-canister target (i.e., Rust tests), we can use the task local storage to
// store the traces. When the task local is not available, we can skip storing the traces as this
// (currently) indicates that we don't look at the traces in the test.
#[cfg(all(feature = "tla", not(target_family = "wasm")))]
pub static TLA_TRACES_MUTEX: Option<RwLock<Vec<UpdateTrace>>> = None;
