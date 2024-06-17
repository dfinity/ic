// NOTES:
// 1) We cannot use `CountBytes` here because it is implemented in an
//    upstream crate `rs/types/types`.
// 2) We cannot move `CountBytes` to a downstream crate `rs/types/base_types`
//    either because it breaks Rust's orphan rule.
//    Namely, `CountBytes` becomes a foreign trait for `rs/types/types` crate
//    which in combination with type aliases for `phantom_type::Id`
//    (also a foreign type) does not allow implementing `CountBytes` for
//    type aliases using `phantom_type::Id`.
// Workaround: we implement a standalone trait `DataSize` here and use it
// instead of `CountBytes`.

/// Trait to reasonably estimate the memory usage of a value in bytes.
///
/// Default implementation returns zero.
pub trait DataSize {
    /// Default implementation returns zero.
    fn data_size(&self) -> usize {
        0
    }
}

impl DataSize for u8 {
    fn data_size(&self) -> usize {
        std::mem::size_of::<u8>()
    }
}

impl DataSize for [u8] {
    fn data_size(&self) -> usize {
        std::mem::size_of_val(self)
    }
}

impl DataSize for u64 {
    fn data_size(&self) -> usize {
        std::mem::size_of::<u64>()
    }
}

impl DataSize for &str {
    fn data_size(&self) -> usize {
        self.as_bytes().data_size()
    }
}

impl DataSize for String {
    fn data_size(&self) -> usize {
        self.as_bytes().data_size()
    }
}

impl<T: DataSize> DataSize for Vec<T> {
    fn data_size(&self) -> usize {
        std::mem::size_of::<Self>() + self.iter().map(|x| x.data_size()).sum::<usize>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_size_u8() {
        assert_eq!(0_u8.data_size(), 1);
        assert_eq!(42_u8.data_size(), 1);
    }

    #[test]
    fn test_data_size_u8_slice() {
        let a: [u8; 0] = [];
        assert_eq!(a.data_size(), 0);
        assert_eq!([1_u8].data_size(), 1);
        assert_eq!([1_u8, 2_u8].data_size(), 2);
    }

    #[test]
    fn test_data_size_u64() {
        assert_eq!(0_u64.data_size(), 8);
        assert_eq!(42_u64.data_size(), 8);
    }

    #[test]
    fn test_data_size_u8_vec() {
        let base = 24;
        assert_eq!(Vec::<u8>::from([]).data_size(), base);
        assert_eq!(Vec::<u8>::from([1]).data_size(), base + 1);
        assert_eq!(Vec::<u8>::from([1, 2]).data_size(), base + 2);
    }

    #[test]
    fn test_data_size_str() {
        assert_eq!("a".data_size(), 1);
        assert_eq!("ab".data_size(), 2);
    }

    #[test]
    fn test_data_size_string() {
        assert_eq!(String::from("a").data_size(), 1);
        assert_eq!(String::from("ab").data_size(), 2);
        for size_bytes in 0..1_024 {
            assert_eq!(
                String::from_utf8(vec![b'x'; size_bytes])
                    .unwrap()
                    .data_size(),
                size_bytes
            );
        }
    }
}
