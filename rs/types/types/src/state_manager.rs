use crate::Height;
use thiserror::Error;

#[derive(Clone, Eq, PartialEq, Hash, Debug, Error)]
pub enum StateManagerError {
    /// The state at the specified height was removed and cannot be recovered
    /// anymore.
    #[error("state at height {0} has already been removed")]
    StateRemoved(Height),
    /// The state at the specified height is not committed yet.
    #[error("state at height {0} is not committed yet")]
    StateNotCommittedYet(Height),
}

pub type StateManagerResult<T> = Result<T, StateManagerError>;
