use candid::CandidType;
use ic_protobuf::registry::subnet::v1 as pb;
use ic_types::NumBytes;
use serde::{Deserialize, Serialize};

/// Limits on resource consumption (e.g., disk usage).
#[derive(CandidType, Copy, Clone, Eq, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct ResourceLimits {
    // The maximum size of the (replicated) state in bytes.
    pub maximum_state_size: Option<NumBytes>,
}

impl From<ResourceLimits> for pb::ResourceLimits {
    fn from(resource_limits: ResourceLimits) -> Self {
        Self {
            maximum_state_size: resource_limits.maximum_state_size.map(|x| x.get()),
        }
    }
}

impl From<pb::ResourceLimits> for ResourceLimits {
    fn from(resource_limits: pb::ResourceLimits) -> Self {
        Self {
            maximum_state_size: resource_limits.maximum_state_size.map(NumBytes::from),
        }
    }
}
