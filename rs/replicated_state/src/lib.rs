mod bitcoin;
pub mod canister_state;
pub(crate) mod hash;
pub mod metadata_state;
pub mod page_map;
pub mod replicated_state;
pub mod testing {
    pub use super::canister_state::system_state::testing::SystemStateTesting;
    pub use super::canister_state::testing::CanisterQueuesTesting;
    pub use super::replicated_state::testing::ReplicatedStateTesting;
}
pub use canister_state::{
    execution_state::Memory,
    num_bytes_try_from,
    system_state::{
        memory_required_to_push_request, CallContext, CallContextAction, CallContextManager,
        CallOrigin, CanisterMetrics, CanisterStatus, ExecutionTask, SystemState,
    },
    CanisterQueues, CanisterState, EmbedderCache, ExecutionState, ExportedFunctions, Global,
    NumWasmPages, SchedulerState,
};
pub use metadata_state::{
    IngressHistoryState, NetworkTopology, Stream, SubnetTopology, SystemMetadata,
};
pub use page_map::{PageIndex, PageMap};
pub use replicated_state::{InputQueueType, NextInputQueue, ReplicatedState, StateError};

/// Encapsulates metrics related to errors that can occur on checkpoint loading.
/// The intention is to pass an implementation of this trait along with the actual
/// struct to deserialize to the deserialization logic so that there is a way
/// to record metrics from there.
pub trait CheckpointLoadingMetrics {
    fn raise_critical_error(&self, msg: String);
}
