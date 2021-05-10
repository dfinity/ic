//! An object that is hashable can be bundled together with its hash, which
//! becomes a `Hashed<H, V>` object parameterized by the actual hash type `H`
//! and value type `V`. There are a number of benefits of doing this:
//!
//! 1. Equality check can be done just on the hash, which is often cheaper than
//! traversing the object recursively.
//!
//! 2. Computing hashes over `Hashed<H, V>` can also take a shortcut by just
//! hashing the hash of type `H`, instead of the value of type `V`. Note that
//! this does not lead to the same hash result as directly hashing the value.
//!
//! 3. Using Hash also gives a strawman implementation of `Ord` if the order
//! does not have to be consistent with the actual order of the object's value.
//!
//! The serialization of `Hashed<H, V>` will serialize both the hash and the
//! value.

use serde::{Deserialize, Serialize};
use std::cmp::{Eq, Ordering, PartialOrd};

/// Bundle of both a value and its hash. Once created it remains immutable,
/// which is why both fields are only accessible through member functions, not
/// as record fields.
#[derive(Clone, Serialize, Deserialize)]
pub struct Hashed<H, V> {
    pub(crate) hash: H,
    pub(crate) value: V,
}

impl<H: PartialEq, V> PartialEq for Hashed<H, V> {
    fn eq(&self, other: &Hashed<H, V>) -> bool {
        self.hash.eq(&other.hash)
    }
}

// The Eq instance is derived from PartialEq.
impl<H: Eq, V> Eq for Hashed<H, V> {}

impl<H: PartialOrd, V> PartialOrd for Hashed<H, V> {
    fn partial_cmp(&self, other: &Hashed<H, V>) -> Option<Ordering> {
        self.hash.partial_cmp(&other.hash)
    }
}

impl<H: Ord, V> Ord for Hashed<H, V> {
    fn cmp(&self, other: &Hashed<H, V>) -> Ordering {
        self.hash.cmp(&other.hash)
    }
}

impl<H: std::hash::Hash, V> std::hash::Hash for Hashed<H, V> {
    fn hash<Hasher: std::hash::Hasher>(&self, state: &mut Hasher) {
        self.hash.hash(state);
    }
}

impl<H: std::fmt::Debug, V> std::fmt::Debug for Hashed<H, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        self.hash.fmt(f)
    }
}

impl<H, V> AsRef<V> for Hashed<H, V> {
    fn as_ref(&self) -> &V {
        self.get_value()
    }
}

impl<H, V> AsMut<V> for Hashed<H, V> {
    fn as_mut(&mut self) -> &mut V {
        &mut self.value
    }
}

impl<H, V> Hashed<H, V> {
    /// Create a `<Hashed<H, V>` object by apply a hash function to a value.
    pub fn new<F: FnOnce(&V) -> H>(hash_func: F, value: V) -> Self {
        Hashed {
            hash: hash_func(&value),
            value,
        }
    }

    /// Return the hash field as reference.
    pub fn get_hash(&self) -> &H {
        &self.hash
    }

    /// Return the value field as reference.
    pub fn get_value(&self) -> &V {
        &self.value
    }

    /// Destruct a `Hashed<H, V>` into a tuple of hash and value.
    pub fn decompose(self) -> (H, V) {
        (self.hash, self.value)
    }

    /// Create a `Hashed<H, V>` from a hash and value
    pub fn recompose(hash: H, value: V) -> Self {
        Self { hash, value }
    }

    /// Destruct a `Hashed<H, V>` and extract only its value.
    pub fn into_inner(self) -> V {
        self.value
    }
}

impl<H, T> std::borrow::Borrow<H> for Hashed<H, T> {
    fn borrow(&self) -> &H {
        &self.hash
    }
}
