//! These are boilerplate implementations of standard traits that either:
//! - cannot be auto-generated in the normal way because Rust doesn't have const
//!   generics yet.
//! - keep sensitive information from being logged via Debug.
//!
//! This code is in a separate file to avoid cluttering the types file with
//! implementation details.

use super::*;
use std::fmt;

#[cfg(test)]
mod tests;

impl fmt::Debug for IndividualSignatureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", base64::encode(&self.0[..]))
    }
}

impl fmt::Debug for CombinedSignatureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", base64::encode(&self.0[..]))
    }
}

// Note: This is needed to keep sensitive material from getting Debug logged.
impl fmt::Debug for SecretKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "REDACTED")
    }
}
