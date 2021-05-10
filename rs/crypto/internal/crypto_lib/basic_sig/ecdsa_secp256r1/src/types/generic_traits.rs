//! These are boilerplate implementations of standard traits that cannot be
//! auto-generated in the normal way because Rust doesn't have const generics
//! yet. This code is in a separate file to avoid cluttering the types file with
//! implementation details.

use super::*;
use std::fmt;

impl fmt::Debug for SignatureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", base64::encode(&self.0[..]))
    }
}

impl fmt::Debug for PublicKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", base64::encode(&self.0[..]))
    }
}

impl Clone for PublicKeyBytes {
    fn clone(&self) -> Self {
        PublicKeyBytes(self.0.clone())
    }
}

impl PartialEq for SignatureBytes {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}

impl Eq for SignatureBytes {}
