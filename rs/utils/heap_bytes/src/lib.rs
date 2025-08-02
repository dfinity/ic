pub use ic_heap_bytes_derive::HeapBytes;
use paste::paste;
use std::collections::BTreeMap;

/// A trait to deterministically report heap memory usage.
///
/// It can be derived for structs and enums. The `#[heap_bytes(with = ...)]`
/// attribute can be used on variants and fields to specify a custom function
/// to calculate heap bytes for that variant or field.
pub trait HeapBytes {
    /// Returns the deterministic total size of heap-allocated data.
    ///
    /// This method performs a deterministic, recursive heap memory calculation.
    /// For large collections, this can be slow. In such cases, consider
    /// using the `#[heap_bytes(with = ...)]` attribute and providing a constant
    /// time estimation for that variant or field.
    ///
    /// The default implementation returns 0, which is correct for
    /// types that do not have any heap allocations.
    fn heap_bytes(&self) -> usize {
        0
    }

    /// Returns the total size of the object in bytes.
    fn total_bytes(&self) -> usize {
        size_of_val(self) + self.heap_bytes()
    }
}

impl HeapBytes for u8 {}
impl HeapBytes for u16 {}
impl HeapBytes for u32 {}
impl HeapBytes for u64 {}
impl HeapBytes for u128 {}
impl HeapBytes for usize {}
impl HeapBytes for i8 {}
impl HeapBytes for i16 {}
impl HeapBytes for i32 {}
impl HeapBytes for i64 {}
impl HeapBytes for i128 {}
impl HeapBytes for isize {}
impl HeapBytes for f32 {}
impl HeapBytes for f64 {}
impl HeapBytes for bool {}
impl HeapBytes for char {}

impl HeapBytes for String {
    fn heap_bytes(&self) -> usize {
        self.len()
    }
}

impl<T: HeapBytes, const N: usize> HeapBytes for [T; N] {
    /// Calculates the precise heap size by summing the heap usage of all elements.
    ///
    /// WARNING: This performs a full scan of the array and is `O(N)`.
    fn heap_bytes(&self) -> usize {
        self.iter().map(HeapBytes::heap_bytes).sum()
    }
}

impl<T: HeapBytes> HeapBytes for Vec<T> {
    /// Calculates the precise heap size by summing the heap usage of all elements.
    ///
    /// WARNING: This performs a full scan of the vector and is `O(N)`.
    fn heap_bytes(&self) -> usize {
        let self_heap_bytes = self.len() * size_of::<T>();
        let elements_heap_bytes: usize = self.iter().map(HeapBytes::heap_bytes).sum();
        self_heap_bytes + elements_heap_bytes
    }
}

impl<K: HeapBytes, V: HeapBytes> HeapBytes for BTreeMap<K, V> {
    /// Calculates the precise heap size by summing the heap usage of all elements.
    ///
    /// WARNING: This performs a full scan of the map and is `O(N)`.
    fn heap_bytes(&self) -> usize {
        let self_heap_bytes = self.len() * (size_of::<K>() + size_of::<V>());
        let elements_heap_bytes: usize = self
            .iter()
            .map(|(k, v)| k.heap_bytes() + v.heap_bytes())
            .sum();
        self_heap_bytes + elements_heap_bytes
    }
}

macro_rules! impl_heap_bytes_for_tuple {
    ( $( $idx:tt ),* ) => {
        paste! {
            impl< $([<T $idx>]: HeapBytes),* > HeapBytes for ( $([<T $idx>],)* ) {
                fn heap_bytes(&self) -> usize {
                    0 $(+ self.$idx.heap_bytes())*
                }
            }
        }
    };
}

impl HeapBytes for () {}
impl_heap_bytes_for_tuple!(0);
impl_heap_bytes_for_tuple!(0, 1);
impl_heap_bytes_for_tuple!(0, 1, 2);
impl_heap_bytes_for_tuple!(0, 1, 2, 3);
impl_heap_bytes_for_tuple!(0, 1, 2, 3, 4);
impl_heap_bytes_for_tuple!(0, 1, 2, 3, 4, 5);
impl_heap_bytes_for_tuple!(0, 1, 2, 3, 4, 5, 6);
impl_heap_bytes_for_tuple!(0, 1, 2, 3, 4, 5, 6, 7);

impl<T: HeapBytes> HeapBytes for Option<T> {
    fn heap_bytes(&self) -> usize {
        match self {
            Some(s) => s.heap_bytes(),
            None => 0,
        }
    }
}

impl<T: HeapBytes, E: HeapBytes> HeapBytes for Result<T, E> {
    fn heap_bytes(&self) -> usize {
        match self {
            Ok(ok) => ok.heap_bytes(),
            Err(err) => err.heap_bytes(),
        }
    }
}

impl HeapBytes for ic_types::CanisterId {}
impl HeapBytes for ic_types::Cycles {}
impl HeapBytes for ic_types::batch::QueryStats {}
impl HeapBytes for ic_types::Time {}

#[cfg(test)]
mod tests;
