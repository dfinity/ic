use ic_protobuf::proxy::ProxyDecodeError;
use ic_types::{CanisterId, NodeId, QueryStatsEpoch, state_manager::StateManagerError};

#[derive(Debug)]
pub enum InvalidQueryStatsPayloadReason {
    /// The payload could not be deserialized
    DeserializationFailed(ProxyDecodeError),
    /// The NodeId on the payload does not correspond to the proposer of the block
    InvalidNodeId { expected: NodeId, reported: NodeId },
    /// The epoch is lower than the aggregated height in the state manager
    EpochAlreadyAggregated {
        highest_aggregated_epoch: QueryStatsEpoch,
        payload_epoch: QueryStatsEpoch,
    },
    /// The epoch is higher than the certified height would allow for
    EpochTooHigh {
        max_valid_epoch: QueryStatsEpoch,
        payload_epoch: QueryStatsEpoch,
    },
    /// Stats for a [`CanisterId`] have been send twice
    DuplicateCanisterId(CanisterId),
}

#[derive(Debug)]
pub enum QueryStatsPayloadValidationFailure {
    /// The feature is not enabled
    Disabled,
    /// The state was not available for a height
    StateUnavailable(StateManagerError),
}
