//! Simple process-wide unique ID
//!
//! Implement simple facility to generate process-wide unique IDs. The IDs
//! are unique during their lifetime, that is the following always holds:
//!
//!   let id1 = UniqueId();
//!   let id2 = UniqueId();
//!   assert_ne!(id1, id2);
//!
//! IDs are copyable and internally use reference counting to ensure that no
//! two independently created IDs are ever the same.
//!
//! The IDs can be turned into strings or integers (for use in protocol),
//! but beware that the reference counting does not extend to the string /
//! integer representation.

use std::cmp::Eq;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

/// A unique identifier (within a process). Instantiating an object of this
/// creates a new identifier that is guaranted to be distinct from all
/// other unique identifiers existing at same point in time.
#[derive(Clone)]
pub struct UniqueId {
    // Simply use a pointer to a unique object on heap.
    repr: Arc<()>,
}

impl UniqueId {
    /// Create new unique identifier
    pub fn new() -> Self {
        Self { repr: Arc::new(()) }
    }

    pub fn as_usize(&self) -> usize {
        Arc::<()>::as_ptr(&self.repr) as usize
    }
}

impl PartialEq for UniqueId {
    fn eq(&self, other: &Self) -> bool {
        Arc::<()>::as_ptr(&self.repr) == Arc::<()>::as_ptr(&other.repr)
    }
}

impl Eq for UniqueId {}

impl Hash for UniqueId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Arc::<()>::as_ptr(&self.repr).hash(state);
    }
}

impl fmt::Debug for UniqueId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Arc::<()>::as_ptr(&self.repr).fmt(f)
    }
}

impl ToString for UniqueId {
    fn to_string(&self) -> String {
        format!("{:p}", Arc::<()>::as_ptr(&self.repr))
    }
}

impl Default for UniqueId {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity() {
        let a = UniqueId::new();
        let b = UniqueId::new();
        let c = a.clone();

        assert_eq!(a, c);
        assert_ne!(a, b);

        assert_eq!(a.as_usize(), c.as_usize());
        assert_ne!(a.as_usize(), b.as_usize());

        assert_eq!(a.to_string(), c.to_string());
        assert_ne!(a.to_string(), b.to_string());
    }
}
