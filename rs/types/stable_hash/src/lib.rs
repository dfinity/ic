//! Stable hashing trait for types whose hash encoding must not change across
//! Rust compiler versions.
//!
//! The [`StableHash`] trait mirrors the behavior of `derive(Hash)` as of
//! Rust 1.93 on x86_64, but with explicitly pinned encoding so that a future
//! compiler update cannot silently change the byte stream fed into a hasher.
//!
//! # Encoding rules (matching current `derive(Hash)` on x86_64)
//!
//! - **Integers**: little-endian bytes (`u8` = 1 byte, `u64` = 8 bytes, etc.)
//! - **`usize`/`isize`**: always encoded as 8-byte little-endian (i.e. as
//!   `u64`/`i64`), regardless of target pointer width.
//! - **`bool`**: single byte, `0` or `1`.
//! - **Structs**: hash each field in declaration order.
//! - **Enums (2+ variants, no `#[repr]`)**: 8-byte LE discriminant (as `i64`,
//!   values 0, 1, 2, …) followed by variant fields.
//! - **Enums (1 variant)**: no discriminant bytes, just fields.
//! - **`Option<T>`**: 8-byte LE discriminant (0 = `None`, 1 = `Some`) + value.
//! - **`Vec<T>` / `[T]`**: 8-byte LE length prefix + each element.
//! - **`[T; N]`**: 8-byte LE length prefix (`N`) + each element.
//! - **`str` / `String`**: raw bytes + `0xFF` sentinel.
//! - **`Box<T>` / `Arc<T>`**: transparent (hash inner value).
//! - **`BTreeMap<K,V>`**: 8-byte LE length prefix + each (key, value) pair.
//! - **`BTreeSet<T>`**: 8-byte LE length prefix + each element.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

/// A type whose hash encoding is stable across Rust compiler versions.
///
/// Implementations must produce the exact same byte sequence as `derive(Hash)`
/// on Rust 1.93 / x86_64. The `derive(StableHash)` proc-macro generates
/// conforming implementations automatically.
pub trait StableHash {
    fn stable_hash<H: std::hash::Hasher>(&self, state: &mut H);
}

// ---------------------------------------------------------------------------
// Primitive integer types
// ---------------------------------------------------------------------------

impl StableHash for u8 {
    #[inline]
    fn stable_hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(&[*self]);
    }
}

impl StableHash for i8 {
    #[inline]
    fn stable_hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(&self.to_le_bytes());
    }
}

macro_rules! impl_stable_hash_int {
    ($($t:ty),*) => {
        $(
            impl StableHash for $t {
                #[inline]
                fn stable_hash<H: std::hash::Hasher>(&self, state: &mut H) {
                    state.write(&self.to_le_bytes());
                }
            }
        )*
    };
}

impl_stable_hash_int!(u16, u32, u64, u128, i16, i32, i64, i128);

// usize/isize: always 8 bytes LE, matching x86_64 behavior.
impl StableHash for usize {
    #[inline]
    fn stable_hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(&(*self as u64).to_le_bytes());
    }
}

impl StableHash for isize {
    #[inline]
    fn stable_hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(&(*self as i64).to_le_bytes());
    }
}

impl StableHash for bool {
    #[inline]
    fn stable_hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(&[*self as u8]);
    }
}

// ---------------------------------------------------------------------------
// Slices, Vec, arrays
// ---------------------------------------------------------------------------

impl<T: StableHash> StableHash for [T] {
    fn stable_hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.len().stable_hash(state);
        for item in self {
            item.stable_hash(state);
        }
    }
}

impl<T: StableHash> StableHash for Vec<T> {
    #[inline]
    fn stable_hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_slice().stable_hash(state);
    }
}

impl<T: StableHash, const N: usize> StableHash for [T; N] {
    fn stable_hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Matches [T; N]::hash which calls Hash::hash_slice (Rust 1.77+):
        // write_length_prefix(N) + each element.
        N.stable_hash(state);
        for item in self {
            item.stable_hash(state);
        }
    }
}

// ---------------------------------------------------------------------------
// Strings
// ---------------------------------------------------------------------------

impl StableHash for str {
    #[inline]
    fn stable_hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Matches Hasher::write_str default: raw bytes + 0xFF sentinel.
        state.write(self.as_bytes());
        state.write(&[0xFF]);
    }
}

impl StableHash for String {
    #[inline]
    fn stable_hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_str().stable_hash(state);
    }
}

// ---------------------------------------------------------------------------
// Option
// ---------------------------------------------------------------------------

impl<T: StableHash> StableHash for Option<T> {
    fn stable_hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Option uses mem::discriminant which hashes as isize.
        match self {
            None => (0i64).stable_hash(state),
            Some(val) => {
                (1i64).stable_hash(state);
                val.stable_hash(state);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Smart pointers (transparent)
// ---------------------------------------------------------------------------

impl<T: StableHash + ?Sized> StableHash for Box<T> {
    #[inline]
    fn stable_hash<H: std::hash::Hasher>(&self, state: &mut H) {
        (**self).stable_hash(state);
    }
}

impl<T: StableHash + ?Sized> StableHash for Arc<T> {
    #[inline]
    fn stable_hash<H: std::hash::Hasher>(&self, state: &mut H) {
        (**self).stable_hash(state);
    }
}

impl<T: StableHash + ?Sized> StableHash for &T {
    #[inline]
    fn stable_hash<H: std::hash::Hasher>(&self, state: &mut H) {
        (**self).stable_hash(state);
    }
}

// ---------------------------------------------------------------------------
// Collections
// ---------------------------------------------------------------------------

impl<K: StableHash, V: StableHash> StableHash for BTreeMap<K, V> {
    fn stable_hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.len().stable_hash(state);
        for (k, v) in self {
            k.stable_hash(state);
            v.stable_hash(state);
        }
    }
}

impl<T: StableHash> StableHash for BTreeSet<T> {
    fn stable_hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.len().stable_hash(state);
        for item in self {
            item.stable_hash(state);
        }
    }
}

// ---------------------------------------------------------------------------
// Tuples (used by BTreeMap iteration)
// ---------------------------------------------------------------------------

impl StableHash for () {
    #[inline]
    fn stable_hash<H: std::hash::Hasher>(&self, _state: &mut H) {}
}

impl<A: StableHash, B: StableHash> StableHash for (A, B) {
    #[inline]
    fn stable_hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.stable_hash(state);
        self.1.stable_hash(state);
    }
}

impl<A: StableHash, B: StableHash, C: StableHash> StableHash for (A, B, C) {
    #[inline]
    fn stable_hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.stable_hash(state);
        self.1.stable_hash(state);
        self.2.stable_hash(state);
    }
}

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------

impl<T: StableHash, E: StableHash> StableHash for Result<T, E> {
    fn stable_hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Result is a 2-variant enum: Ok = discriminant 0, Err = discriminant 1.
        match self {
            Ok(val) => {
                (0i64).stable_hash(state);
                val.stable_hash(state);
            }
            Err(val) => {
                (1i64).stable_hash(state);
                val.stable_hash(state);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// VecDeque
// ---------------------------------------------------------------------------

impl<T: StableHash> StableHash for VecDeque<T> {
    fn stable_hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.len().stable_hash(state);
        for item in self {
            item.stable_hash(state);
        }
    }
}

#[cfg(test)]
mod tests;
