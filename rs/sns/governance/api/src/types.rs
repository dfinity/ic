use std::fmt;

impl fmt::Display for crate::pb::v1::GovernanceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}: {}", self.error_type, self.error_message)
    }
}

impl std::error::Error for crate::pb::v1::GovernanceError {}
