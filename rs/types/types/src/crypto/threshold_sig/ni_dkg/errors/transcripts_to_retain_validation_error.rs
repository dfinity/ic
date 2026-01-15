//! Errors related to transcripts that should be retained.
use std::fmt;

/// Occurs if creating `TranscriptsToRetain` using its constructor fails.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum TranscriptsToRetainValidationError {
    NoLowTranscripts,
    NoHighTranscripts,
}

impl fmt::Display for TranscriptsToRetainValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
