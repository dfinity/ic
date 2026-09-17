//! Read-side handling of the NNS delegation fetched by the NNS delegation manager:
//! building delegations with the desired canister ranges filter from the parsed
//! delegation certificate, and validating the delegation against the subnet
//! information recorded in a replicated state.
mod reader;
mod validation;

pub use reader::{CanisterRangesFilter, NNSDelegationBuilder, NNSDelegationReader};
pub use validation::{CanisterRangesCheck, DelegationValidationError, DelegationVerificationError};
