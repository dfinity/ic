//! This crate contains assorted types that other component crates
//! depend upon.  The only types that should be included in this crate
//! should be the ones that more than one component crate share.
//! This should generally imply that the types used here should also
//! be getting used in the `interfaces` crate although there might be
//! exceptions to this rule.

// Note [ExecutionRound vs Height]
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// A batch received by Message Routing has some `Height` `h` attached to it.
// Once the batch is received, Message Routing needs to retrieve the `State`
// at `Height` `h-1` as a base for the current `ExecutionRound` `h`.
// After `ExecutionRound` `h` is complete, the resulting `State` is going to be
// marked with `Height` `h`.
//
// The main reason to have 2 different types and not use a single one is that
// each type is meaningful in a specific context and represents slightly
// different ideas which cannot always be mapped 1-1 to each other. More
// concretely, `ExecutionRound` which is triggered by batch `Height` `h`
// might process messages that were introduced in previous batch `Height`s.
//
// Furthermore, different subcomponents should have different
// capabilities.  E.g. Message Routing is allowed to
// increment/decrement `Height`s while the Scheduler is not supposed
// to perform any arithmetics on `ExecutionRound`.

// Note [Scheduler and AccumulatedPriority]
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Public Specification of IC describes `compute_allocation`. Each canister is
// initiated with an `accumulated_priority` of 0. The scheduler uses these values
// while calculating the priority of a canister at each round. The canisters
// are scheduled at each round in the following way:
//
// * For each canister, we compute the `round_priority` of that canister as the
// sum of its `accumulated_priority` and the multiplication of its
// `compute_allocation` with the `multiplier` (see the scheduler).
// * We distribute the free capacity equally to all the canisters.
// * For new executions:
//   - We sort the canisters according to their round priorities in
//     descending order.
// * For pending long executions:
//   - Sort the canisters first according to their execution mode,
//     and then round priorities.
//   - Calculate how many scheduler cores we dedicate for long executions
//     in this round using compute allocations of these long executions.
//   - The first `long_execution_cores` many canisters are given the top
//     priority in this round and get into the prioritized long execution mode.
//   - The rest of the long executions are given an opportunity to be executed
//     by scheduling them at the very end.
// * The first `scheduler_cores` many canisters are given the top priority in
// this round. Therefore, they are expected to be executed as the first of
// their threads.
// * As the last step, we credit the first `scheduler_cores` canisters
//   with the sum of compute allocations of all canisters times `multiplier`
//   divided by the number of canisters that are given top priority in
//   this round. This `priority_credit` will be subtracted from the
//   `accumulated_priority` at the end of the execution or at the checkpoint.
//
// As a result, at each round, the sum of accumulated priorities minus
// the sum of priority credits remains 0.
// Similarly, the sum of all round priorities equals to the multiplication of
// the sum of all compute allocations with the multiplier.

pub mod artifact;
pub mod batch;
pub mod canister_http;
pub mod chunkable;
pub mod consensus;
pub mod crypto;
pub mod filetree_sync;
pub mod funds;
pub mod ingress;
pub mod malicious_behaviour;
pub mod malicious_flags;
pub mod messages;
pub mod methods;
pub mod nominal_cycles;
pub mod p2p;
pub mod registry;
pub mod replica_config;
pub mod replica_version;
pub mod signature;
pub mod single_chunked;
pub mod state_sync;
pub mod time;
pub mod xnet;

pub use crate::replica_version::ReplicaVersion;
pub use crate::time::Time;
pub use funds::*;
pub use ic_base_types::{
    subnet_id_into_protobuf, subnet_id_try_from_protobuf, CanisterId, CanisterIdBlobParseError,
    NodeId, NodeTag, NumBytes, PrincipalId, PrincipalIdBlobParseError, PrincipalIdParseError,
    RegistryVersion, SubnetId,
};
pub use ic_crypto_internal_types::NodeIndex;
use ic_protobuf::types::v1 as pb;
use phantom_newtype::{AmountOf, Id};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fmt;
use std::fmt::Display;

pub struct UserTag {}
/// An end-user's [`PrincipalId`].
pub type UserId = Id<UserTag, PrincipalId>;

/// Converts a UserId into its protobuf definition.  Normally, we would use
/// `impl From<UserId> for pb::UserId` here however we cannot as both
/// `Id` and `pb::UserId` are defined in other crates.
pub fn user_id_into_protobuf(id: UserId) -> pb::UserId {
    pb::UserId {
        principal_id: Some(pb::PrincipalId::from(id.get())),
    }
}

/// From its protobuf definition convert to a UserId.  Normally, we would
/// use `impl TryFrom<pb::UserId> for UserId` here however we cannot as
/// both `Id` and `pb::UserId` are defined in other crates.
pub fn user_id_try_from_protobuf(value: pb::UserId) -> Result<UserId, PrincipalIdBlobParseError> {
    // All fields in Protobuf definition are required hence they are encoded in
    // `Option`.  We simply treat them as required here though.
    let principal_id = PrincipalId::try_from(value.principal_id.unwrap())?;
    Ok(UserId::from(principal_id))
}

/// The ID for interactive DKG.
#[derive(Copy, Clone, Debug, Deserialize, Eq, PartialOrd, Ord, Hash, PartialEq, Serialize)]
pub struct IDkgId {
    pub instance_id: Height,
    pub subnet_id: SubnetId,
}

impl Display for IDkgId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "instance_id: '{}', subnet_id: '{}'",
            self.instance_id, self.subnet_id
        )
    }
}

impl IDkgId {
    pub fn start_height(&self) -> Height {
        self.instance_id
    }
}

/// A non-negative amount of nodes, typically used in DKG.
pub type NumberOfNodes = AmountOf<NodeTag, NodeIndex>;

pub struct HeightTag {}
/// The block height.
// Note [ExecutionRound vs Height]
pub type Height = AmountOf<HeightTag, u64>;

/// Converts a NodeId into its protobuf definition.  Normally, we would use
/// `impl From<NodeId> for pb::NodeId` here however we cannot as both
/// `Id` and `pb::NodeId` are defined in other crates.
pub fn node_id_into_protobuf(id: NodeId) -> pb::NodeId {
    pb::NodeId {
        principal_id: Some(pb::PrincipalId::from(id.get())),
    }
}

/// From its protobuf definition convert to a NodeId.  Normally, we would
/// use `impl TryFrom<pb::NodeId> for NodeId` here however we cannot as
/// both `Id` and `pb::NodeId` are defined in other crates.
pub fn node_id_try_from_protobuf(value: pb::NodeId) -> Result<NodeId, PrincipalIdBlobParseError> {
    // All fields in Protobuf definition are required hence they are encoded in
    // `Option`.  We simply treat them as required here though.
    let principal_id = PrincipalId::try_from(value.principal_id.unwrap())?;
    Ok(NodeId::from(principal_id))
}

pub struct NumInstructionsTag;
/// Represents an amount of weighted instructions that can be used as the
/// execution cutoff point for messages. This amount can be used to charge the
/// respective amount of `Cycles` on a canister's balance for message execution.
pub type NumInstructions = AmountOf<NumInstructionsTag, u64>;

pub struct NumMessagesTag;
/// Represents the number of messages.
pub type NumMessages = AmountOf<NumMessagesTag, u64>;

pub struct NumSlicesTag;
/// Represents the number of slices.
pub type NumSlices = AmountOf<NumSlicesTag, u64>;

pub struct RandomnessTag;
/// Randomness produced by Consensus which is used in the
/// deterministic state machine (Message Routing and Execution Environment).
pub type Randomness = Id<RandomnessTag, [u8; 32]>;

pub struct ExecutionRoundTag {}
/// The id of an execution round in the scheduler.
// Note [ExecutionRound vs Height]
pub type ExecutionRound = Id<ExecutionRoundTag, u64>;

pub enum CanonicalPartialStateTag {}
/// A cryptographic hash of the part of the canonical replicated state at some
/// height required for certification (cross-net streams, etc.).
pub type CryptoHashOfPartialState = crypto::CryptoHashOf<CanonicalPartialStateTag>;

pub enum CanonicalStateTag {}
/// A cryptographic hash of a full canonical replicated state at some height.
pub type CryptoHashOfState = crypto::CryptoHashOf<CanonicalStateTag>;

pub enum NumPagesTag {}
/// A number of OS-sized pages.
pub type NumPages = AmountOf<NumPagesTag, u64>;

/// `AccumulatedPriority` is a part of the SchedulerState. It is the value by
/// which we prioritize canisters for execution. It is reset to 0 in the round
/// where a canister is scheduled and incremented by the canister allocation in
/// each round where the canister is not scheduled.
// Note [Scheduler and AccumulatedPriority]
#[derive(Copy, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AccumulatedPriority(i64);

impl AccumulatedPriority {
    pub fn value(self) -> i64 {
        self.0
    }
}

// The initial accumulated priority is 0.
#[allow(clippy::derivable_impls)]
impl Default for AccumulatedPriority {
    fn default() -> Self {
        AccumulatedPriority(0)
    }
}

impl From<i64> for AccumulatedPriority {
    fn from(value: i64) -> Self {
        AccumulatedPriority(value)
    }
}

#[derive(Copy, Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize, Hash)]
/// Type to track how much budget the IC can spend on executing queries on
/// canisters.  See `execution_environment/rs/query_handler.rs:Charging for
/// queries` for more details.
pub struct QueryAllocation(u64);

impl QueryAllocation {
    /// Returns a 0 `QueryAllocation`.
    pub fn zero() -> QueryAllocation {
        QueryAllocation(0)
    }

    pub fn get(&self) -> u64 {
        self.0
    }
}

impl Default for QueryAllocation {
    fn default() -> Self {
        Self(MAX_QUERY_ALLOCATION)
    }
}

impl std::ops::Add for QueryAllocation {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self(self.0 + other.0)
    }
}

impl std::ops::Sub for QueryAllocation {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }
}

impl From<QueryAllocation> for NumInstructions {
    fn from(val: QueryAllocation) -> Self {
        NumInstructions::from(val.0)
    }
}

impl From<NumInstructions> for QueryAllocation {
    fn from(num_instructions: NumInstructions) -> QueryAllocation {
        QueryAllocation(num_instructions.get())
    }
}

/// The error returned when an invalid [`QueryAllocation`] is specified by the
/// end-user.
#[derive(Clone, Debug)]
pub struct InvalidQueryAllocationError {
    pub min: u64,
    pub max: u64,
    pub given: u64,
}

const MIN_QUERY_ALLOCATION: u64 = 0;
const MAX_QUERY_ALLOCATION: u64 = 1_000_000_000_000_000;

impl InvalidQueryAllocationError {
    pub fn new(given: u64) -> Self {
        Self {
            min: MIN_QUERY_ALLOCATION,
            max: MAX_QUERY_ALLOCATION,
            given,
        }
    }
}

impl TryFrom<u64> for QueryAllocation {
    type Error = InvalidQueryAllocationError;

    fn try_from(given: u64) -> Result<Self, Self::Error> {
        if given > MAX_QUERY_ALLOCATION {
            return Err(InvalidQueryAllocationError::new(given));
        }
        Ok(QueryAllocation(given))
    }
}

impl fmt::Display for QueryAllocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// `ComputeAllocation` is a percent between 0 and 100 attached to a canister or
/// equivalently a rational number A/100. Having an `ComputeAllocation` of A/100
/// guarantees that the canister will get a full round at least A out of 100
/// execution rounds.
#[derive(Copy, Clone, Debug, Deserialize, Eq, PartialEq, Serialize, Hash)]
pub struct ComputeAllocation(u64);

impl ComputeAllocation {
    /// Returns the raw percent contained in this `ComputeAllocation`.
    pub fn as_percent(self) -> u64 {
        self.0
    }

    pub const fn zero() -> Self {
        ComputeAllocation(0)
    }
}

// The default `ComputeAllocation` is 0: https://sdk.dfinity.org/docs/interface-spec/index.html#ic-install_code.
#[allow(clippy::derivable_impls)]
impl Default for ComputeAllocation {
    fn default() -> Self {
        ComputeAllocation(0)
    }
}

/// The error that occurs when an end-user specifies an invalid
/// [`ComputeAllocation`].
#[derive(Clone, Debug)]
pub struct InvalidComputeAllocationError {
    min: candid::Nat,
    max: candid::Nat,
    given: candid::Nat,
}

const MIN_COMPUTE_ALLOCATION: u64 = 0;
const MAX_COMPUTE_ALLOCATION: u64 = 100;

impl InvalidComputeAllocationError {
    pub fn new(given: candid::Nat) -> Self {
        Self {
            min: candid::Nat::from(MIN_COMPUTE_ALLOCATION),
            max: candid::Nat::from(MAX_COMPUTE_ALLOCATION),
            given,
        }
    }

    pub fn min(&self) -> candid::Nat {
        self.min.clone()
    }

    pub fn max(&self) -> candid::Nat {
        self.max.clone()
    }

    pub fn given(&self) -> candid::Nat {
        self.given.clone()
    }
}

impl TryFrom<u64> for ComputeAllocation {
    type Error = InvalidComputeAllocationError;

    // Constructs a `ComputeAllocation` from a percent in the range [0..100].
    //
    // # Errors
    //
    // Returns an `InvalidComputeAllocationError` if the input percent is not in
    // the expected range.
    fn try_from(percent: u64) -> Result<Self, Self::Error> {
        if percent > MAX_COMPUTE_ALLOCATION {
            return Err(InvalidComputeAllocationError::new(candid::Nat::from(
                percent,
            )));
        }
        Ok(ComputeAllocation(percent))
    }
}

impl fmt::Display for ComputeAllocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}%", self.0)
    }
}

#[test]
fn display_canister_id() {
    assert_eq!(
        "2chl6-4hpzw-vqaaa-aaaaa-c",
        format!(
            "{}",
            CanisterId::new(
                PrincipalId::try_from(&[0xef, 0xcd, 0xab, 0, 0, 0, 0, 0, 1][..]).unwrap()
            )
            .unwrap()
        )
    );
}

/// Represents Canister timer.
#[derive(Clone, Copy, Debug, PartialEq, Deserialize, Serialize)]
pub enum CanisterTimer {
    /// The canister timer is not set.
    Inactive,
    /// The canister timer is set at the specific time.
    Active(Time),
}

impl CanisterTimer {
    /// Convert this canister timer to time.
    pub fn to_time(&self) -> Time {
        match self {
            CanisterTimer::Inactive => time::UNIX_EPOCH,
            CanisterTimer::Active(time) => *time,
        }
    }

    /// Create a canister timer from time.
    pub fn from_time(time: Time) -> Self {
        if time == time::UNIX_EPOCH {
            CanisterTimer::Inactive
        } else {
            CanisterTimer::Active(time)
        }
    }

    /// Returns true if timer has reached the deadline.
    pub fn has_reached_deadline(&self, now: Time) -> bool {
        match self {
            CanisterTimer::Inactive => false,
            CanisterTimer::Active(time) => now >= *time,
        }
    }

    /// Convert this canister timer to nanoseconds since Unix epoch option.
    pub fn to_nanos_since_unix_epoch(&self) -> Option<u64> {
        match self {
            CanisterTimer::Inactive => None,
            CanisterTimer::Active(time) => Some(time.as_nanos_since_unix_epoch()),
        }
    }

    /// Create a canister timer from nanoseconds since Unix epoch option.
    pub fn from_nanos_since_unix_epoch(nanos: Option<u64>) -> Self {
        match nanos {
            None => CanisterTimer::Inactive,
            Some(nanos) => CanisterTimer::Active(Time::from_nanos_since_unix_epoch(nanos)),
        }
    }
}

/// Represents scheduling strategy for Canisters with long execution in progress.
/// All long execution start in the Opportunistic mode, and then the scheduler
/// prioritizes top `long_execution_cores` some of them. This is to enforce FIFO
/// behavior, and guarantee the progress for long executions.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize, Hash)]
pub enum LongExecutionMode {
    /// The long execution might be opportunistically scheduled on the new execution cores,
    /// so its progress depends on the number of new messages to execute.
    Opportunistic = 0,
    /// The long execution is prioritized to be scheduled on the long execution cores,
    /// so it's quite likely the execution will be finished with no aborts.
    Prioritized = 1,
}

impl Default for LongExecutionMode {
    fn default() -> Self {
        LongExecutionMode::Opportunistic
    }
}

/// Represents the memory allocation of a canister.
#[derive(Copy, Clone, Debug, Deserialize, Eq, PartialEq, Serialize, Hash)]
pub enum MemoryAllocation {
    /// A reserved number of bytes between 0 and 2^48 inclusively that is
    /// guaranteed to be available to the canister. Charging happens based on
    /// the reserved amount of memory, regardless of how much of it is in use.
    Reserved(NumBytes),
    /// Memory growth of the canister happens dynamically and is subject to the
    /// available memory of the subnet. The canister will be charged for the
    /// memory it's using at any given time.
    BestEffort,
}

impl MemoryAllocation {
    /// Returns the number of bytes associated with this memory allocation.
    pub fn bytes(&self) -> NumBytes {
        match self {
            MemoryAllocation::Reserved(bytes) => *bytes,
            // A best-effort memory allocation is equivalent to a zero memory allocation per the
            // interface spec.
            MemoryAllocation::BestEffort => NumBytes::from(0),
        }
    }
}

impl fmt::Display for MemoryAllocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemoryAllocation::Reserved(bytes) => write!(f, "{}", bytes.display()),
            MemoryAllocation::BestEffort => write!(f, "best-effort"),
        }
    }
}

impl Default for MemoryAllocation {
    fn default() -> Self {
        MemoryAllocation::BestEffort
    }
}

/// The error that occurs when an end-user specifies an invalid
/// [`MemoryAllocation`].
#[derive(Clone, Debug)]
pub struct InvalidMemoryAllocationError {
    pub min: candid::Nat,
    pub max: candid::Nat,
    pub given: candid::Nat,
}

const GB: u64 = 1024 * 1024 * 1024;

/// The upper limit on the stable memory size.
/// This constant is used by other crates to define other constants, that's why
/// it is public and `u64` (`NumBytes` cannot be used in const expressions).
pub const MAX_STABLE_MEMORY_IN_BYTES: u64 = 48 * GB;

/// The upper limit on the Wasm memory size.
/// This constant is used by other crates to define other constants, that's why
/// it is public and `u64` (`NumBytes` cannot be used in const expressions).
pub const MAX_WASM_MEMORY_IN_BYTES: u64 = 4 * GB;

const MIN_MEMORY_ALLOCATION: NumBytes = NumBytes::new(0);
pub const MAX_MEMORY_ALLOCATION: NumBytes =
    NumBytes::new(MAX_STABLE_MEMORY_IN_BYTES + MAX_WASM_MEMORY_IN_BYTES);

impl InvalidMemoryAllocationError {
    pub fn new(given: candid::Nat) -> Self {
        Self {
            min: candid::Nat::from(MIN_MEMORY_ALLOCATION.get()),
            max: candid::Nat::from(MAX_MEMORY_ALLOCATION.get()),
            given,
        }
    }
}

impl TryFrom<NumBytes> for MemoryAllocation {
    type Error = InvalidMemoryAllocationError;

    fn try_from(bytes: NumBytes) -> Result<Self, Self::Error> {
        if bytes > MAX_MEMORY_ALLOCATION {
            return Err(InvalidMemoryAllocationError::new(candid::Nat::from(
                bytes.get(),
            )));
        }
        // A memory allocation of 0 means that the canister's memory growth will be
        // best-effort.
        if bytes.get() == 0 {
            Ok(MemoryAllocation::BestEffort)
        } else {
            Ok(MemoryAllocation::Reserved(bytes))
        }
    }
}

/// Allow an object to report its own byte size. It is only meant to be an
/// estimate, and not an exact measure of its heap usage or length of serialized
/// bytes.
pub trait CountBytes {
    fn count_bytes(&self) -> usize;
}

impl CountBytes for Time {
    fn count_bytes(&self) -> usize {
        8
    }
}
