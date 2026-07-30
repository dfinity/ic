//! Read-side handling of the NNS delegation fetched by the NNS delegation manager:
//! building delegations with the desired canister ranges filter from the parsed
//! delegation certificate, and validating the delegation against the subnet
//! information recorded in a replicated state.
mod builder;
mod reader;
mod validation;

pub use builder::NNSDelegationBuilder;
pub use reader::{CanisterRangesFilter, NNSDelegationReader};
pub use validation::{CanisterRangesCheck, DelegationValidationError};
