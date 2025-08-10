//! Convert error types
use super::*;

impl From<InvalidArgumentError> for CryptoError {
    fn from(error: InvalidArgumentError) -> CryptoError {
        let InvalidArgumentError { message } = error;
        CryptoError::InvalidArgument { message }
    }
}
