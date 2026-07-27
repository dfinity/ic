//! This crate contains types used as:
//! - registry canister API types;
//! - `ic-admin` CLI args;
//! - and internal replica implementation types.

use candid::CandidType;
use clap::Args;
use ic_protobuf::registry::subnet::v1 as pb;
use ic_types::{NumBytes, NumInstructions};
use serde::{Deserialize, Serialize};

/// Limits on resource consumption (e.g., memory usage).
#[derive(Args, CandidType, Copy, Clone, Eq, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// The maximum size of the (replicated) state in bytes.
    /// This is a hard limit, i.e., messages that attempt to increase the state size
    /// beyond the limit fail.
    /// The protocol uses a default value if the limit of `0` is specified.
    #[arg(long)]
    pub maximum_state_size: Option<NumBytes>,
    /// The maximum size of the (replicated) state *delta* (kept in main memory) in bytes.
    /// This is a soft limit, i.e., the actual size of the state delta can exceed the limit,
    /// but no more messages are executed while the limit is exceeded.
    /// The protocol uses a default value if the limit of `0` is specified.
    #[arg(long)]
    pub maximum_state_delta: Option<NumBytes>,
    /// The maximum number of instructions a query may consume. This applies both to a single
    /// (non-composite) query method execution and to the total across an entire composite query
    /// call graph.
    /// The protocol uses a default value if the limit of `0` is specified.
    #[arg(long)]
    pub maximum_query_instructions: Option<NumInstructions>,
}

impl ResourceLimits {
    /// Returns a copy of `self` where every unset (`None`) field inherits its value from `base`.
    ///
    /// This is used when updating a subnet: fields not specified in the update keep the value
    /// currently used in production (taken from the existing subnet record).
    pub fn inherit_from(&self, base: &Self) -> Self {
        Self {
            maximum_state_size: self.maximum_state_size.or(base.maximum_state_size),
            maximum_state_delta: self.maximum_state_delta.or(base.maximum_state_delta),
            maximum_query_instructions: self
                .maximum_query_instructions
                .or(base.maximum_query_instructions),
        }
    }

    /// Returns the subnet memory capacity.
    ///
    /// This is `maximum_state_size` if not `0`, otherwise the provided `default`.
    pub fn maximum_state_size_or(&self, default: NumBytes) -> NumBytes {
        self.maximum_state_size
            .filter(|maximum_state_size| maximum_state_size.get() != 0)
            .unwrap_or(default)
    }

    /// Returns the subnet heap delta capacity.
    ///
    /// This is `maximum_state_delta` if not `0`, otherwise the provided `default`.
    pub fn maximum_state_delta_or(&self, default: NumBytes) -> NumBytes {
        self.maximum_state_delta
            .filter(|maximum_state_delta| maximum_state_delta.get() != 0)
            .unwrap_or(default)
    }
}

impl From<ResourceLimits> for pb::ResourceLimits {
    fn from(resource_limits: ResourceLimits) -> Self {
        Self {
            maximum_state_size: resource_limits.maximum_state_size.map(|x| x.get()),
            maximum_state_delta: resource_limits.maximum_state_delta.map(|x| x.get()),
            maximum_query_instructions: resource_limits.maximum_query_instructions.map(|x| x.get()),
        }
    }
}

impl From<pb::ResourceLimits> for ResourceLimits {
    fn from(resource_limits: pb::ResourceLimits) -> Self {
        Self {
            maximum_state_size: resource_limits.maximum_state_size.map(NumBytes::from),
            maximum_state_delta: resource_limits.maximum_state_delta.map(NumBytes::from),
            maximum_query_instructions: resource_limits
                .maximum_query_instructions
                .map(NumInstructions::from),
        }
    }
}
