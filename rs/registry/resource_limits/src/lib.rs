use ic_protobuf::registry::subnet::v1 as pb;
use candid::CandidType;
use serde::{Serialize, Deserialize};

/// Limits on resource consumption (e.g., disk usage).
#[derive(CandidType, Copy, Clone, Eq, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct ResourceLimits {
    // The maximum size of the (replicated) state in bytes.
    pub maximum_state_size: Option<u64>,
}

impl From<ResourceLimits> for pb::ResourceLimits {
    fn from(resource_limits: ResourceLimits) -> Self {
        Self {
            maximum_state_size: resource_limits.maximum_state_size,
        }
    }
}

impl From<pb::ResourceLimits> for ResourceLimits {
    fn from(resource_limits: pb::ResourceLimits) -> Self {
        Self {
            maximum_state_size: resource_limits.maximum_state_size,
        }
    }
}
