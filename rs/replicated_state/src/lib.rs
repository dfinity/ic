//! Replicated state types.
//!
//! Note [Replicated State Invariants]
//! ==================================
//!
//! Guidelines for handling invariants that are internal to datastructures in the
//! replicated state:
//!
//! - In this context, the term invariant is used to refer to something that (1) holds
//!   all the time, and (2) whose violation would affect code correctness:
//!   - We check these during deserialization and return an error if they don't hold.
//!   - It is also fine to assert/debug_assert (depending on how expensive these checks
//!     are) for them in production code.
//!   - Proptests for these invariants are recommended, but can be skipped if there is
//!     consensus that they are not needed.
//! - There can also be soft invariants which are a superset of the invariants above.
//!   - These include things that don't affect correctness of the code, but we still
//!     aim to uphold them at all times.
//!   - They can be self healing, i.e., a violation will be fixed upon the next
//!     modification of after the next couple of modifications.
//!   - We don't assert for them in production code, but may debug_assert and raise
//!     critical errors in case of a violation upon deserialization (cf. deserialization
//!     of `BlockmakerMetricsTimeSeries`)
//!   - An example for a soft invariant is an upper bound on the number of elements
//!     in a datastructure which maintains a sliding window of snapshots, where the
//!     actual number of snapshots does not affect correctness and we just want to make
//!     sure it doesn't grow indefinitely.
//! - We don't attempt to restore invariants or soft invariants upon deserializing
//!   as it could change the past.
//!
//! Note [Handling changes to Enums in Replicated State]
//! ========================================
//!
//! Enums that are persisted in the Replicated State require special handling
//! to ensure that changes to them are compatible across replica releases.
//!
//! Changes to such enums must be rolled out in stages, across multiple replica
//! releases. You must ensure that the release with the first stage of the change
//! is deployed to each subnet before proceeding with the second stage.
//!
//!  * If you are removing a variant, in the first stage remove all
//!    uses of said variant from production code (except its definition and any
//!    conversion logic); only once this change has been deployed to all subnets,
//!    in the second phase, remove the variant and update this test.
//!
//!  * If you are adding a variant, in the first stage define the
//!    variant and the necessary conversion logic, without using it anywhere (and
//!    update this test); once the replica release has been deployed to all
//!    subnets, it is safe to begin using the new variant in production code.
//!
//!  * If you are remapping the numeric code behind a variant, you must do it as
//!    concurrent removal and addition operations (see above). You can also
//!    rename the variant you are removing to `Deprecated<Name>` as part of the
//!    first step, so you can concurrently define the new variant and preserve
//!    the name.
//!
mod bitcoin;
pub mod canister_snapshots;
pub mod canister_state;
pub(crate) mod hash;
pub mod metadata_state;
pub mod page_map;
pub mod replicated_state;
pub use canister_state::{
    CanisterQueues, CanisterState, EmbedderCache, ExecutionState, ExportedFunctions, NumWasmPages,
    RefundPool, SchedulerState,
    execution_state::Memory,
    num_bytes_try_from,
    system_state::{
        CallContext, CallContextAction, CallContextManager, CallOrigin, CanisterMetrics,
        CanisterStatus, ExecutionTask, SystemState, memory_usage_of_request,
    },
};
pub use metadata_state::{
    IngressHistoryState, NetworkTopology, Stream, SubnetTopology, SystemMetadata,
};
pub use page_map::{PageIndex, PageMap};
pub use replicated_state::{InputQueueType, InputSource, ReplicatedState, StateError};

/// Encapsulates metrics related to errors that can occur on checkpoint loading.
/// The intention is to pass an implementation of this trait along with the actual
/// struct to deserialize to the deserialization logic so that there is a way
/// to record metrics from there.
pub trait CheckpointLoadingMetrics {
    fn observe_broken_soft_invariant(&self, msg: String);
}

pub const KIND_REQUEST: &str = "request";
pub const KIND_RESPONSE: &str = "response";
pub const CONTEXT_INBOUND: &str = "inbound";
pub const CONTEXT_OUTBOUND: &str = "outbound";
pub const CLASS_GUARANTEED_RESPONSE: &str = "guaranteed response";
pub const CLASS_BEST_EFFORT: &str = "best-effort";

/// Exposes methods for observing timed out and shed messages.
pub trait DroppedMessageMetrics {
    /// Observes a timed out message with the given kind, context and class.
    fn observe_timed_out_message(
        &self,
        kind: &'static str,
        context: &'static str,
        class: &'static str,
    );

    /// Observes a shed message with the given kind and context,
    fn observe_shed_message(&self, kind: &'static str, context: &'static str, size_bytes: usize);
}

pub mod testing {
    pub use super::canister_state::system_state::testing::SystemStateTesting;
    pub use super::canister_state::testing::CanisterQueuesTesting;
    pub use super::replicated_state::testing::ReplicatedStateTesting;

    use super::DroppedMessageMetrics;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    #[derive(Default, Debug)]
    pub struct FakeDropMessageMetrics {
        pub timed_out_messages:
            RefCell<BTreeMap<(&'static str, &'static str, &'static str), usize>>,
        pub shed_messages: RefCell<BTreeMap<(&'static str, &'static str), usize>>,
        pub shed_message_bytes: RefCell<BTreeMap<(&'static str, &'static str), usize>>,
    }

    impl DroppedMessageMetrics for FakeDropMessageMetrics {
        fn observe_timed_out_message(
            &self,
            kind: &'static str,
            context: &'static str,
            class: &'static str,
        ) {
            *self
                .timed_out_messages
                .borrow_mut()
                .entry((kind, context, class))
                .or_default() += 1;
        }

        fn observe_shed_message(
            &self,
            kind: &'static str,
            context: &'static str,
            size_bytes: usize,
        ) {
            *self
                .shed_messages
                .borrow_mut()
                .entry((kind, context))
                .or_default() += 1;
            *self
                .shed_message_bytes
                .borrow_mut()
                .entry((kind, context))
                .or_default() += size_bytes;
        }
    }
}
