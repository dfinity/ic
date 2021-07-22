//! These are boilerplate implementations of standard traits that cannot be
//! auto-generated in the normal way because Rust doesn't have const generics
//! yet
//!
//! This code is in a separate file to avoid cluttering the types file with
//! implementation details.

use super::*;
use std::fmt;

// Note: This is needed because Rust doesn't support const generics yet.
impl fmt::Debug for SignatureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", &self.0[..])
    }
}
impl PartialEq for SignatureBytes {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}
impl Eq for SignatureBytes {}
