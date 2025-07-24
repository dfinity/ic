use paste::paste;
use std::collections::BTreeMap;

/// A trait for types that can report their total memory usage,
/// including heap allocations.
///
/// This trait provides a `byte_count` method and allows for both
/// precise (`heap_bytes`) and fast, approximate (`approx_heap_bytes`)
/// calculations of heap-allocated memory.
///
/// It can be derived for structs and enums. The `#[byte_count(approx)]`
/// attribute can be used on fields to specify that the `approx_heap_bytes`
/// method should be used instead of the slower `heap_bytes`.
pub trait ByteCount {
    /// Returns the total size of the object in bytes.
    fn byte_count(&self) -> usize {
        size_of_val(self) + self.heap_bytes()
    }

    /// Returns the total size of heap-allocated data.
    ///
    /// This method performs a precise, recursive heap memory calculation.
    /// For large collections, this can be slow. In such cases, consider
    /// using the `#[byte_count(approx)]` attribute in derive macros.
    ///
    /// The default implementation returns 0, which is correct for
    /// types that do not have any heap allocations.
    fn heap_bytes(&self) -> usize {
        0
    }

    /// Returns a fast, constant-time approximation of heap-allocated data.
    ///
    /// By default, this method calls `heap_bytes` for a precise count.
    /// Types can override it to provide a faster, less precise estimate,
    /// which is useful for large data collections.
    fn approx_heap_bytes(&self) -> usize {
        self.heap_bytes()
    }
}

// Basic types.
impl ByteCount for u8 {}
impl ByteCount for u16 {}
impl ByteCount for u32 {}
impl ByteCount for u64 {}
impl ByteCount for u128 {}
impl ByteCount for usize {}
impl ByteCount for i8 {}
impl ByteCount for i16 {}
impl ByteCount for i32 {}
impl ByteCount for i64 {}
impl ByteCount for i128 {}
impl ByteCount for isize {}
impl ByteCount for f32 {}
impl ByteCount for f64 {}
impl ByteCount for bool {}
impl ByteCount for char {}

impl ByteCount for String {
    fn heap_bytes(&self) -> usize {
        self.len()
    }
}

impl<T: ByteCount, const N: usize> ByteCount for [T; N] {
    /// Calculates the precise heap size by summing the heap usage of all elements.
    fn heap_bytes(&self) -> usize {
        self.iter().map(ByteCount::heap_bytes).sum()
    }

    /// Provides a fast approximation based only on the number of elements.
    /// Since an array itself has no heap allocation, this is 0.
    fn approx_heap_bytes(&self) -> usize {
        0
    }
}

impl<T: ByteCount> ByteCount for Vec<T> {
    /// Calculates the precise heap size by summing the heap usage of all elements.
    fn heap_bytes(&self) -> usize {
        let self_heap_bytes = self.len() * size_of::<T>();
        let elements_heap_bytes: usize = self.iter().map(ByteCount::heap_bytes).sum();
        self_heap_bytes + elements_heap_bytes
    }

    /// Provides a fast approximation based only on the number of elements.
    fn approx_heap_bytes(&self) -> usize {
        self.len() * size_of::<T>()
    }
}

impl<K: ByteCount, V: ByteCount> ByteCount for BTreeMap<K, V> {
    /// Calculates the precise heap size by summing the heap usage of all elements.
    ///
    /// WARNING: This performs a full scan of the map and is `O(N)`.
    /// It is implemented for completeness but should be avoided on large maps.
    /// The `#[byte_count(approx)]` attribute uses `approx_heap_bytes` instead.
    fn heap_bytes(&self) -> usize {
        let self_heap_bytes = self.len() * (size_of::<K>() + size_of::<V>());
        let elements_heap_bytes: usize = self
            .iter()
            .map(|(k, v)| k.heap_bytes() + v.heap_bytes())
            .sum();
        self_heap_bytes + elements_heap_bytes
    }

    /// Provides a fast approximation based only on the number of elements.
    fn approx_heap_bytes(&self) -> usize {
        self.len() * (size_of::<K>() + size_of::<V>())
    }
}

macro_rules! impl_byte_count_for_tuple {
    ( $( $idx:tt ),* ) => {
        paste! {
            impl< $([<T $idx>]: ByteCount),* > ByteCount for ( $([<T $idx>],)* ) {
                fn heap_bytes(&self) -> usize {
                    0 $(+ self.$idx.heap_bytes())*
                }

                fn approx_heap_bytes(&self) -> usize {
                    0 $(+ self.$idx.approx_heap_bytes())*
                }
            }
        }
    };
}

impl ByteCount for () {}
impl_byte_count_for_tuple!(0);
impl_byte_count_for_tuple!(0, 1);
impl_byte_count_for_tuple!(0, 1, 2);
impl_byte_count_for_tuple!(0, 1, 2, 3);
impl_byte_count_for_tuple!(0, 1, 2, 3, 4);
impl_byte_count_for_tuple!(0, 1, 2, 3, 4, 5);
impl_byte_count_for_tuple!(0, 1, 2, 3, 4, 5, 6);
impl_byte_count_for_tuple!(0, 1, 2, 3, 4, 5, 6, 7);

impl<T: ByteCount> ByteCount for Option<T> {
    fn heap_bytes(&self) -> usize {
        match self {
            Some(s) => s.heap_bytes(),
            None => 0,
        }
    }

    fn approx_heap_bytes(&self) -> usize {
        match self {
            Some(s) => s.approx_heap_bytes(),
            None => 0,
        }
    }
}

impl<T: ByteCount, E: ByteCount> ByteCount for Result<T, E> {
    fn heap_bytes(&self) -> usize {
        match self {
            Ok(ok) => ok.heap_bytes(),
            Err(err) => err.heap_bytes(),
        }
    }

    fn approx_heap_bytes(&self) -> usize {
        match self {
            Ok(ok) => ok.approx_heap_bytes(),
            Err(err) => err.approx_heap_bytes(),
        }
    }
}

#[cfg(test)]
mod tests;
