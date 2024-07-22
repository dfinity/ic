use crate::pb::v1::{governance_error::ErrorType, GovernanceError};

#[allow(clippy::all)]
#[path = "./ic_nns_governance.pb.v1.rs"]
pub mod v1;

impl GovernanceError {
    pub fn new(error_type: ErrorType) -> Self {
        Self {
            error_type: error_type as i32,
            ..Default::default()
        }
    }

    pub fn new_with_message(error_type: ErrorType, message: impl ToString) -> Self {
        Self {
            error_type: error_type as i32,
            error_message: message.to_string(),
        }
    }
}
