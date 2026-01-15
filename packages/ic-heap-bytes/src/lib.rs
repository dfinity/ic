pub use ic_heap_bytes_derive::{DeterministicHeapBytes, HeapBytes};
use paste::paste;

////////////////////////////////////////////////////////////////////////
// DeterministicHeapBytes
////////////////////////////////////////////////////////////////////////

/// A trait to deterministically report heap memory usage.
///
/// It can be derived for structs and enums. The `#[deterministic_heap_bytes(with = ...)]`
/// attribute can be used on variants and fields to specify a custom function
/// to calculate heap bytes for that variant or field.
pub trait DeterministicHeapBytes {
    /// Returns the deterministic total size of heap-allocated data.
    ///
    /// This method performs a deterministic, recursive heap memory calculation.
    /// For large collections, this can be slow. In such cases, consider
    /// using the `#[deterministic_heap_bytes(with = ...)]` attribute and providing a constant
    /// time estimation for that variant or field.
    ///
    /// The default implementation returns 0, which is correct for
    /// types that do not have any heap allocations.
    fn deterministic_heap_bytes(&self) -> usize {
        0
    }
}

/// Returns the deterministic total size of the object in bytes.
pub fn deterministic_total_bytes<T: DeterministicHeapBytes>(t: &T) -> usize {
    size_of_val(t) + t.deterministic_heap_bytes()
}

////////////////////////////////////////////////////////////////////////
// DeterministicHeapBytes scalar types.

impl DeterministicHeapBytes for u8 {}
impl DeterministicHeapBytes for u16 {}
impl DeterministicHeapBytes for u32 {}
impl DeterministicHeapBytes for u64 {}
impl DeterministicHeapBytes for u128 {}
impl DeterministicHeapBytes for usize {}
impl DeterministicHeapBytes for i8 {}
impl DeterministicHeapBytes for i16 {}
impl DeterministicHeapBytes for i32 {}
impl DeterministicHeapBytes for i64 {}
impl DeterministicHeapBytes for i128 {}
impl DeterministicHeapBytes for isize {}
impl DeterministicHeapBytes for f32 {}
impl DeterministicHeapBytes for f64 {}
impl DeterministicHeapBytes for bool {}
impl DeterministicHeapBytes for char {}

////////////////////////////////////////////////////////////////////////
// DeterministicHeapBytes standard library types.

impl DeterministicHeapBytes for std::sync::atomic::AtomicU64 {}
impl DeterministicHeapBytes for std::time::Duration {}
impl DeterministicHeapBytes for std::fs::File {}

impl DeterministicHeapBytes for String {
    fn deterministic_heap_bytes(&self) -> usize {
        self.len()
    }
}

impl<T: DeterministicHeapBytes, const N: usize> DeterministicHeapBytes for [T; N] {
    /// Calculates the precise heap size by summing the heap usage of all elements.
    ///
    /// WARNING: This performs a full scan of the array and is `O(n)`.
    fn deterministic_heap_bytes(&self) -> usize {
        self.iter()
            .map(DeterministicHeapBytes::deterministic_heap_bytes)
            .sum()
    }
}

impl<T: DeterministicHeapBytes> DeterministicHeapBytes for Vec<T> {
    /// Calculates the precise heap size by summing the heap usage of all elements.
    ///
    /// WARNING: This performs a full scan of the vector and is `O(n)`.
    fn deterministic_heap_bytes(&self) -> usize {
        let self_heap_bytes = self.len() * size_of::<T>();
        let elements_heap_bytes: usize = self
            .iter()
            .map(DeterministicHeapBytes::deterministic_heap_bytes)
            .sum();
        self_heap_bytes + elements_heap_bytes
    }
}

impl<K: DeterministicHeapBytes, V: DeterministicHeapBytes> DeterministicHeapBytes
    for std::collections::BTreeMap<K, V>
{
    /// Calculates the precise heap size by summing the heap usage of all elements.
    ///
    /// WARNING: This performs a full scan of the map and is `O(n)`.
    fn deterministic_heap_bytes(&self) -> usize {
        // In addition to the key and value sizes, we also account for edges,
        // i.e. pointers to child nodes. Depending on the map's operational history,
        // the number of edges can be proportional to the number of elements.
        // See: https://github.com/rust-lang/rust/blob/master/library/alloc/src/collections/btree/node.rs
        let self_heap_bytes = self.len() * (size_of::<K>() + size_of::<V>() + size_of::<usize>());
        let elements_heap_bytes: usize = self
            .iter()
            .map(|(k, v)| k.deterministic_heap_bytes() + v.deterministic_heap_bytes())
            .sum();
        self_heap_bytes + elements_heap_bytes
    }
}

impl<T: DeterministicHeapBytes> DeterministicHeapBytes for std::sync::Arc<T> {
    fn deterministic_heap_bytes(&self) -> usize {
        self.as_ref().deterministic_heap_bytes()
    }
}

impl<T: DeterministicHeapBytes> DeterministicHeapBytes for std::sync::Mutex<T> {
    fn deterministic_heap_bytes(&self) -> usize {
        self.lock().unwrap().deterministic_heap_bytes()
    }
}

impl<T: DeterministicHeapBytes> DeterministicHeapBytes for Option<T> {
    fn deterministic_heap_bytes(&self) -> usize {
        match self {
            Some(s) => s.deterministic_heap_bytes(),
            None => 0,
        }
    }
}

impl<T: DeterministicHeapBytes, E: DeterministicHeapBytes> DeterministicHeapBytes for Result<T, E> {
    fn deterministic_heap_bytes(&self) -> usize {
        match self {
            Ok(ok) => ok.deterministic_heap_bytes(),
            Err(err) => err.deterministic_heap_bytes(),
        }
    }
}

////////////////////////////////////////////////////////////////////////
// DeterministicHeapBytes tuples.

macro_rules! impl_heap_bytes_for_tuple {
    ( $( $idx:tt ),* ) => {
        paste! {
            impl< $([<T $idx>]: DeterministicHeapBytes),* > DeterministicHeapBytes for ( $([<T $idx>],)* ) {
                fn deterministic_heap_bytes(&self) -> usize {
                    0 $(+ self.$idx.deterministic_heap_bytes())*
                }
            }
        }
    };
}

impl DeterministicHeapBytes for () {}
impl_heap_bytes_for_tuple!(0);
impl_heap_bytes_for_tuple!(0, 1);
impl_heap_bytes_for_tuple!(0, 1, 2);
impl_heap_bytes_for_tuple!(0, 1, 2, 3);
impl_heap_bytes_for_tuple!(0, 1, 2, 3, 4);
impl_heap_bytes_for_tuple!(0, 1, 2, 3, 4, 5);
impl_heap_bytes_for_tuple!(0, 1, 2, 3, 4, 5, 6);
impl_heap_bytes_for_tuple!(0, 1, 2, 3, 4, 5, 6, 7);

////////////////////////////////////////////////////////////////////////
// DeterministicHeapBytes external types.

impl DeterministicHeapBytes for candid::Principal {}
impl DeterministicHeapBytes for candid::types::principal::PrincipalError {}

////////////////////////////////////////////////////////////////////////
// HeapBytes
////////////////////////////////////////////////////////////////////////

/// A trait to estimate heap memory usage.
///
/// It can be derived for structs and enums. The `#[heap_bytes(with = ...)]`
/// attribute can be used on variants and fields to specify a custom function
/// to estimate heap bytes for that variant or field.
pub trait HeapBytes {
    /// Returns the total estimated size of heap-allocated data.
    ///
    /// This method performs a recursive heap memory estimation.
    /// For large collections, this can be slow. In such cases, consider
    /// using the `#[heap_bytes(with = ...)]` attribute and providing a constant
    /// time estimation for that variant or field.
    ///
    /// The default implementation returns 0, which is correct for
    /// types that do not have any heap allocations.
    fn heap_bytes(&self) -> usize {
        0
    }
}

/// Returns the total estimated size of the object in bytes.
pub fn total_bytes<T: HeapBytes>(t: &T) -> usize {
    size_of_val(t) + t.heap_bytes()
}

// Use DeterministicHeapBytes as a fallback implementation for HeapBytes.
impl<T: DeterministicHeapBytes> HeapBytes for T {
    fn heap_bytes(&self) -> usize {
        self.deterministic_heap_bytes()
    }
}

////////////////////////////////////////////////////////////////////////
// HeapBytes external types.

impl HeapBytes for prometheus::Histogram {
    fn heap_bytes(&self) -> usize {
        let num_buckets = prometheus::DEFAULT_BUCKETS.len();
        // To get the actual buckets and labels, we need to collect the metric,
        // which is slow. Instead, we just assume that histogram allocates
        // a default vector of buckets with no labels.
        num_buckets * size_of::<f64>()
    }
}
impl HeapBytes for prometheus::IntCounter {}
impl HeapBytes for prometheus::IntGauge {}
impl HeapBytes for tempfile::TempDir {
    fn heap_bytes(&self) -> usize {
        // TempDir allocates a string for the path.
        self.path().as_os_str().len()
    }
}

#[cfg(test)]
mod tests;
