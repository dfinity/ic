//! These are boilerplate implementations of standard traits that cannot be
//! auto-generated in the normal way because Rust doesn't have const generics
//! yet
//!
//! This code is in a separate file to avoid cluttering the types file with
//! implementation details.

use super::*;
use base64::prelude::*;
use std::fmt;

#[cfg(test)]
mod tests;

impl fmt::Debug for SignatureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SignatureBytes({:?})",
            BASE64_STANDARD.encode(&self.0[..])
        )
    }
}
impl fmt::Debug for PublicKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PublicKeyBytes({:?})",
            BASE64_STANDARD.encode(&self.0[..])
        )
    }
}
