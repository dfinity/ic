//! Errors related to transcript creation.
use crate::crypto::error::{InvalidArgumentError, MalformedPublicKeyError};
use core::fmt;

/// Occurs if creating a transcript using `NiDkgAlgorithm::create_transcript`
/// fails.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DkgCreateTranscriptError {
    InsufficientDealings(InvalidArgumentError),
    MalformedResharingTranscriptInConfig(MalformedPublicKeyError),
    // Reminder: document error definition changes on `NiDkgAlgorithm::create_transcript`.
}

impl fmt::Display for DkgCreateTranscriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prefix = "Failed to create transcript: ";
        match self {
            DkgCreateTranscriptError::InsufficientDealings(error) => {
                write!(f, "{}{}", prefix, error)
            }
            DkgCreateTranscriptError::MalformedResharingTranscriptInConfig(error) => {
                write!(f, "{}{}", prefix, error)
            }
        }
    }
}
