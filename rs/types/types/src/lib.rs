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
// Public Specification of IC describes compute allocation. Each canister is
// initiated with an accumulated priority of 0. The scheduler uses these values
// while calculating the priority of a canister at each round. The canisters
// are scheduled at each round in the following way:
//
// * For each canister, we compute the round priority of that canister as the
// sum of its accumulated priority and the multiplication of its compute
// allocation with the multiplier (see the scheduler).
// * We distribute the free capacity equally to all the canisters.
// * We sort the canisters according to their round priorities in descending
// order.
// * The first scheduler_cores many canisters are given the top priority in
// this round. Therefore, they are expected to be executed as the first of
// their threads.
// * As the last step, we update the accumulated priorities of all canisters.
// Canisters which did not get the top priority in this round, have their
// accumulated priority replaced with the value of their round_priority. The
// top scheduler_cores many canisters' accumulated priority is updated with
// the value of their round priorities subtracted by (the sum of compute
// allocations of all canisters times multiplier divided by the number of
// canisters that are given top priority in this round.
//
// As a result, at each round, the sum of accumulated priorities remains 0.
// Similarly, the sum of all round priorities equals to the multiplication of
// the sum of all compute allocations with the multiplier.

pub mod artifact;
pub mod batch;
pub mod chunkable;
pub mod consensus;
pub mod crypto;
pub mod filetree_sync;
pub mod funds;
pub mod ic00;
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
pub mod state_sync;
pub mod time;
pub mod transport;
pub mod user_error;
pub mod xnet;

use crate::messages::CanisterInstallMode;
pub use crate::replica_version::ReplicaVersion;
pub use crate::time::Time;
pub use funds::icp::{ICPError, ICP};
pub use funds::*;
use ic_base_types::NumSeconds;
pub use ic_base_types::{
    subnet_id_into_protobuf, subnet_id_try_from_protobuf, CanisterId, CanisterIdBlobParseError,
    CanisterIdError, CanisterStatusType, NodeId, NodeTag, NumBytes, PrincipalId,
    PrincipalIdBlobParseError, PrincipalIdParseError, RegistryVersion, SubnetId,
};
pub use ic_crypto_internal_types::NodeIndex;
use ic_error_types::{ErrorCode, UserError};
use ic_ic00_types::InstallCodeArgs;
use ic_protobuf::types::v1 as pb;
use num_traits::cast::ToPrimitive;
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

pub struct QueueIndexTag;
/// Index into a queue; used in the context of `InputQueue` / `OutputQueue` to
/// define message order.
pub type QueueIndex = AmountOf<QueueIndexTag, u64>;

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

    /// Returns the maximum allowed query allocation per message.
    pub fn max_per_message() -> QueryAllocation {
        QueryAllocation(10_000_000_000)
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

impl Into<NumInstructions> for QueryAllocation {
    fn into(self) -> NumInstructions {
        NumInstructions::from(self.0)
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
impl Default for ComputeAllocation {
    fn default() -> Self {
        ComputeAllocation(0)
    }
}

/// The error that occurs when an end-user specifies an invalid
/// [`ComputeAllocation`].
#[derive(Clone, Debug)]
pub struct InvalidComputeAllocationError {
    min: u64,
    max: u64,
    given: u64,
}

const MIN_COMPUTE_ALLOCATION: u64 = 0;
const MAX_COMPUTE_ALLOCATION: u64 = 100;

impl InvalidComputeAllocationError {
    pub fn new(given: u64) -> Self {
        Self {
            min: MIN_COMPUTE_ALLOCATION,
            max: MAX_COMPUTE_ALLOCATION,
            given,
        }
    }

    pub fn min(&self) -> u64 {
        self.min
    }

    pub fn max(&self) -> u64 {
        self.max
    }

    pub fn given(&self) -> u64 {
        self.given
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
            return Err(InvalidComputeAllocationError::new(percent));
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

/// `MemoryAllocation` is a number of bytes between 0 and 2^48 inclusively that
/// represents the memory allocation requested by a user during a canister
/// installation/upgrade.
#[derive(Copy, Clone, Debug, Deserialize, Eq, PartialEq, Serialize, Hash)]
pub struct MemoryAllocation(NumBytes);

impl MemoryAllocation {
    pub fn get(&self) -> NumBytes {
        self.0
    }
}

impl fmt::Display for MemoryAllocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}B", self.0.get())
    }
}

/// The error that occurs when an end-user specifies an invalid
/// [`MemoryAllocation`].
#[derive(Clone, Debug)]
pub struct InvalidMemoryAllocationError {
    pub min: NumBytes,
    pub max: NumBytes,
    pub given: NumBytes,
}

const MIN_MEMORY_ALLOCATION: NumBytes = NumBytes::new(0);
const MAX_MEMORY_ALLOCATION: NumBytes = NumBytes::new(8 * 1024 * 1024 * 1024);

impl InvalidMemoryAllocationError {
    pub fn new(given: NumBytes) -> Self {
        Self {
            min: MIN_MEMORY_ALLOCATION,
            max: MAX_MEMORY_ALLOCATION,
            given,
        }
    }
}

impl TryFrom<NumBytes> for MemoryAllocation {
    type Error = InvalidMemoryAllocationError;

    fn try_from(bytes: NumBytes) -> Result<Self, Self::Error> {
        if bytes > MAX_MEMORY_ALLOCATION {
            return Err(InvalidMemoryAllocationError::new(bytes));
        }
        Ok(MemoryAllocation(bytes))
    }
}

#[derive(Clone, Debug)]
pub struct InstallCodeContext {
    pub sender: PrincipalId,
    pub mode: CanisterInstallMode,
    pub canister_id: CanisterId,
    pub wasm_module: Vec<u8>,
    pub arg: Vec<u8>,
    pub compute_allocation: Option<ComputeAllocation>,
    pub memory_allocation: Option<MemoryAllocation>,
    pub query_allocation: QueryAllocation,
}

/// Errors that can occur when converting from (sender, [`InstallCodeArgs`]) to
/// an [`InstallCodeContext`].
#[derive(Debug)]
pub enum InstallCodeContextError {
    ComputeAllocation(InvalidComputeAllocationError),
    MemoryAllocation(InvalidMemoryAllocationError),
    QueryAllocation(InvalidQueryAllocationError),
    InvalidCanisterId(String),
}

impl From<InstallCodeContextError> for UserError {
    fn from(err: InstallCodeContextError) -> Self {
        match err {
            InstallCodeContextError::ComputeAllocation(err) => UserError::new(
                ErrorCode::CanisterContractViolation,
                format!(
                    "ComputeAllocation expected to be in the range [{}..{}], got {}",
                    err.min(),
                    err.max(),
                    err.given()
                ),
            ),
            InstallCodeContextError::QueryAllocation(err) => UserError::new(
                ErrorCode::CanisterContractViolation,
                format!(
                    "QueryAllocation expected to be in the range [{}..{}], got {}",
                    err.min, err.max, err.given
                ),
            ),
            InstallCodeContextError::MemoryAllocation(err) => UserError::new(
                ErrorCode::CanisterContractViolation,
                format!(
                    "MemoryAllocation expected to be in the range [{}..{}], got {}",
                    err.min, err.max, err.given
                ),
            ),
            InstallCodeContextError::InvalidCanisterId(bytes) => UserError::new(
                ErrorCode::CanisterContractViolation,
                format!(
                    "Specified canister id is not a valid principal id {}",
                    hex::encode(&bytes[..])
                ),
            ),
        }
    }
}

impl From<InvalidComputeAllocationError> for InstallCodeContextError {
    fn from(err: InvalidComputeAllocationError) -> Self {
        Self::ComputeAllocation(err)
    }
}

impl From<InvalidQueryAllocationError> for InstallCodeContextError {
    fn from(err: InvalidQueryAllocationError) -> Self {
        Self::QueryAllocation(err)
    }
}

impl From<InvalidMemoryAllocationError> for InstallCodeContextError {
    fn from(err: InvalidMemoryAllocationError) -> Self {
        Self::MemoryAllocation(err)
    }
}

impl TryFrom<(PrincipalId, InstallCodeArgs)> for InstallCodeContext {
    type Error = InstallCodeContextError;

    fn try_from(input: (PrincipalId, InstallCodeArgs)) -> Result<Self, Self::Error> {
        let (sender, args) = input;
        let canister_id = CanisterId::new(args.canister_id).map_err(|err| {
            InstallCodeContextError::InvalidCanisterId(format!(
                "Converting canister id {} failed with {}",
                args.canister_id, err
            ))
        })?;
        let compute_allocation = match args.compute_allocation {
            Some(ca) => Some(ComputeAllocation::try_from(ca.0.to_u64().unwrap())?),
            None => None,
        };
        let memory_allocation = match args.memory_allocation {
            Some(ma) => Some(MemoryAllocation::try_from(NumBytes::from(
                ma.0.to_u64().unwrap(),
            ))?),
            None => None,
        };
        let query_allocation = match args.query_allocation {
            Some(qa) => QueryAllocation::try_from(qa.0.to_u64().unwrap())?,
            None => QueryAllocation::default(),
        };

        Ok(InstallCodeContext {
            sender,
            mode: args.mode,
            canister_id,
            wasm_module: args.wasm_module,
            arg: args.arg,
            compute_allocation,
            memory_allocation,
            query_allocation,
        })
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

/// Figure out how many cycles a canister should have so that it can support the
/// given amount of storage for the given amount of time, given the storage fee.
pub fn freeze_threshold_cycles(
    freeze_threshold: NumSeconds,
    gib_storage_per_second_fee: Cycles,
    expected_canister_size: NumBytes,
) -> Cycles {
    let one_gib = 1024 * 1024 * 1024;
    Cycles::from(
        expected_canister_size.get() as u128
            * gib_storage_per_second_fee.get()
            * freeze_threshold.get() as u128
            / one_gib,
    )
}
