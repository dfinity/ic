use crate::DataSize;
use candid::{CandidType, Deserialize};
use serde::Deserializer;
use std::fmt;

/// Indicates that `BoundedVec<...>` template parameter (eg. length, total data size, etc) is unbounded.
pub const UNBOUNDED: usize = usize::MAX;

/// Struct for bounding vector by different parameters:
/// - number of elements
/// - total data size in bytes
/// - single element data size in bytes
#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType)]
pub struct BoundedVec<
    const MAX_ALLOWED_LEN: usize,
    const MAX_ALLOWED_TOTAL_DATA_SIZE: usize,
    const MAX_ALLOWED_ELEMENT_DATA_SIZE: usize,
    T,
>(Vec<T>);

impl<
    const MAX_ALLOWED_LEN: usize,
    const MAX_ALLOWED_TOTAL_DATA_SIZE: usize,
    const MAX_ALLOWED_ELEMENT_DATA_SIZE: usize,
    T,
> BoundedVec<MAX_ALLOWED_LEN, MAX_ALLOWED_TOTAL_DATA_SIZE, MAX_ALLOWED_ELEMENT_DATA_SIZE, T>
{
    pub fn new(data: Vec<T>) -> Self {
        assert!(
            MAX_ALLOWED_LEN != UNBOUNDED
                || MAX_ALLOWED_TOTAL_DATA_SIZE != UNBOUNDED
                || MAX_ALLOWED_ELEMENT_DATA_SIZE != UNBOUNDED,
            "BoundedVec must be bounded by at least one parameter."
        );

        Self(data)
    }

    pub fn get(&self) -> &Vec<T> {
        &self.0
    }
}

impl<
    'de,
    const MAX_ALLOWED_LEN: usize,
    const MAX_ALLOWED_TOTAL_DATA_SIZE: usize,
    const MAX_ALLOWED_ELEMENT_DATA_SIZE: usize,
    T: Deserialize<'de> + DataSize,
> Deserialize<'de>
    for BoundedVec<MAX_ALLOWED_LEN, MAX_ALLOWED_TOTAL_DATA_SIZE, MAX_ALLOWED_ELEMENT_DATA_SIZE, T>
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SeqVisitor<
            const MAX_ALLOWED_LEN: usize,
            const MAX_ALLOWED_TOTAL_DATA_SIZE: usize,
            const MAX_ALLOWED_ELEMENT_DATA_SIZE: usize,
            T,
        > {
            _marker: std::marker::PhantomData<T>,
        }

        use serde::de::{SeqAccess, Visitor};

        impl<
            'de,
            const MAX_ALLOWED_LEN: usize,
            const MAX_ALLOWED_TOTAL_DATA_SIZE: usize,
            const MAX_ALLOWED_ELEMENT_DATA_SIZE: usize,
            T: Deserialize<'de> + DataSize,
        > Visitor<'de>
            for SeqVisitor<
                MAX_ALLOWED_LEN,
                MAX_ALLOWED_TOTAL_DATA_SIZE,
                MAX_ALLOWED_ELEMENT_DATA_SIZE,
                T,
            >
        {
            type Value = BoundedVec<
                MAX_ALLOWED_LEN,
                MAX_ALLOWED_TOTAL_DATA_SIZE,
                MAX_ALLOWED_ELEMENT_DATA_SIZE,
                T,
            >;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(
                    formatter,
                    "{}",
                    describe_sequence(
                        MAX_ALLOWED_LEN,
                        MAX_ALLOWED_TOTAL_DATA_SIZE,
                        MAX_ALLOWED_ELEMENT_DATA_SIZE,
                    )
                )
            }

            fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
            where
                S: SeqAccess<'de>,
            {
                let mut total_data_size = 0;
                let mut elements = if MAX_ALLOWED_LEN == UNBOUNDED {
                    Vec::new()
                } else {
                    Vec::with_capacity(MAX_ALLOWED_LEN)
                };
                while let Some(element) = seq.next_element::<T>()? {
                    if elements.len() >= MAX_ALLOWED_LEN {
                        return Err(serde::de::Error::custom(format!(
                            "The number of elements exceeds maximum allowed {MAX_ALLOWED_LEN}"
                        )));
                    }
                    // Check that the new element data size is below the maximum allowed limit.
                    let new_element_data_size = element.data_size();
                    if new_element_data_size > MAX_ALLOWED_ELEMENT_DATA_SIZE {
                        return Err(serde::de::Error::custom(format!(
                            "The single element data size exceeds maximum allowed {MAX_ALLOWED_ELEMENT_DATA_SIZE}"
                        )));
                    }
                    // Check that the new total data size (including new element data size)
                    // is below the maximum allowed limit.
                    let new_total_data_size = total_data_size + new_element_data_size;
                    if new_total_data_size > MAX_ALLOWED_TOTAL_DATA_SIZE {
                        return Err(serde::de::Error::custom(format!(
                            "The total data size exceeds maximum allowed {MAX_ALLOWED_TOTAL_DATA_SIZE}"
                        )));
                    }
                    total_data_size = new_total_data_size;
                    elements.push(element);
                }
                Ok(BoundedVec::new(elements))
            }
        }

        deserializer.deserialize_seq(SeqVisitor::<
            MAX_ALLOWED_LEN,
            MAX_ALLOWED_TOTAL_DATA_SIZE,
            MAX_ALLOWED_ELEMENT_DATA_SIZE,
            T,
        > {
            _marker: std::marker::PhantomData,
        })
    }
}

fn describe_sequence(
    max_allowed_len: usize,
    max_allowed_total_data_size: usize,
    max_allowed_element_data_size: usize,
) -> String {
    let mut msg = String::new();
    if max_allowed_len != UNBOUNDED {
        msg.push_str(&format!("max {max_allowed_len} elements"));
    };
    if max_allowed_total_data_size != UNBOUNDED {
        if !msg.is_empty() {
            msg.push_str(", ");
        }
        msg.push_str(&format!("max {max_allowed_total_data_size} bytes total"));
    };
    if max_allowed_element_data_size != UNBOUNDED {
        if !msg.is_empty() {
            msg.push_str(", ");
        }
        msg.push_str(&format!(
            "max {max_allowed_element_data_size} bytes per element"
        ));
    };
    format!("a sequence with {msg}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Payload;
    use ic_error_types::ErrorCode;

    #[test]
    fn test_describe_sequence() {
        assert_eq!(
            describe_sequence(42, UNBOUNDED, UNBOUNDED),
            "a sequence with max 42 elements".to_string()
        );
        assert_eq!(
            describe_sequence(UNBOUNDED, 256, UNBOUNDED),
            "a sequence with max 256 bytes total".to_string(),
        );
        assert_eq!(
            describe_sequence(UNBOUNDED, UNBOUNDED, 64),
            "a sequence with max 64 bytes per element".to_string(),
        );
        assert_eq!(
            describe_sequence(42, 256, UNBOUNDED),
            "a sequence with max 42 elements, max 256 bytes total".to_string(),
        );
        assert_eq!(
            describe_sequence(42, UNBOUNDED, 64),
            "a sequence with max 42 elements, max 64 bytes per element".to_string(),
        );
        assert_eq!(
            describe_sequence(UNBOUNDED, 256, 64),
            "a sequence with max 256 bytes total, max 64 bytes per element".to_string(),
        );
        assert_eq!(
            describe_sequence(42, 256, 64),
            "a sequence with max 42 elements, max 256 bytes total, max 64 bytes per element"
                .to_string(),
        );
    }

    #[test]
    #[should_panic]
    fn test_not_bounded_vector_fails() {
        type NotBoundedVec = BoundedVec<UNBOUNDED, UNBOUNDED, UNBOUNDED, u8>;

        let _ = NotBoundedVec::new(vec![1, 2, 3]);
    }

    #[test]
    fn test_bounded_vector_lengths() {
        // This test verifies that the structures containing BoundedVec correctly
        // throw an error when the number of elements exceeds the maximum allowed.
        type BoundedLen = BoundedVec<MAX_ALLOWED_LEN, UNBOUNDED, UNBOUNDED, u8>;

        impl Payload<'_> for BoundedLen {}

        const MAX_ALLOWED_LEN: usize = 30;
        const TEST_START: usize = 20;
        const TEST_END: usize = 40;
        for i in TEST_START..=TEST_END {
            // Arrange.
            let data = BoundedLen::new(vec![42; i]);

            // Act.
            let result = BoundedLen::decode(&data.encode());

            // Assert.
            if i <= MAX_ALLOWED_LEN {
                // Verify decoding without errors for allowed sizes.
                assert!(result.is_ok());
                assert_eq!(result.unwrap(), data);
            } else {
                // Verify decoding with errors for disallowed sizes.
                assert!(result.is_err());
                let error = result.unwrap_err();
                assert_eq!(error.code(), ErrorCode::InvalidManagementPayload);
                assert!(
                    error.description().contains(&format!(
                        "Deserialize error: The number of elements exceeds maximum allowed {MAX_ALLOWED_LEN}"
                    )),
                    "Actual: {}",
                    error.description()
                );
            }
        }
    }

    #[test]
    fn test_bounded_vector_total_data_sizes() {
        // This test verifies that the structures containing BoundedVec correctly
        // throw an error when the total data size exceeds the maximum allowed.
        const MAX_ALLOWED_TOTAL_DATA_SIZE: usize = 100;
        const ELEMENT_SIZE: usize = 37;
        // Assert element size is not a multiple of total size.
        assert_ne!(MAX_ALLOWED_TOTAL_DATA_SIZE % ELEMENT_SIZE, 0);
        for aimed_total_size in 64..=256 {
            // Arrange.
            type BoundedSize =
                BoundedVec<UNBOUNDED, MAX_ALLOWED_TOTAL_DATA_SIZE, UNBOUNDED, Vec<u8>>;
            impl Payload<'_> for BoundedSize {}
            let element = vec![b'a'; ELEMENT_SIZE - std::mem::size_of::<Vec<u8>>()];
            let elements_count = aimed_total_size / element.data_size();
            let data = BoundedSize::new(vec![element; elements_count]);
            let actual_total_size = data.get().data_size();

            // Act.
            let result = BoundedSize::decode(&data.encode());

            // Assert.
            if actual_total_size <= MAX_ALLOWED_TOTAL_DATA_SIZE {
                // Verify decoding without errors for allowed sizes.
                assert!(result.is_ok());
                assert_eq!(result.unwrap(), data);
            } else {
                // Verify decoding with errors for disallowed sizes.
                assert!(result.is_err());
                let error = result.unwrap_err();
                assert_eq!(error.code(), ErrorCode::InvalidManagementPayload);
                assert!(
                    error.description().contains(&format!(
                        "Deserialize error: The total data size exceeds maximum allowed {MAX_ALLOWED_TOTAL_DATA_SIZE}"
                    )),
                    "Actual: {}",
                    error.description()
                );
            }
        }
    }

    #[test]
    fn test_bounded_vector_element_data_sizes() {
        // This test verifies that the structures containing BoundedVec correctly
        // throw an error when the element data size exceeds the maximum allowed.
        const MAX_ALLOWED_ELEMENT_DATA_SIZE: usize = 100;
        for element_size in 64..=256 {
            // Arrange.
            type BoundedSize =
                BoundedVec<UNBOUNDED, UNBOUNDED, MAX_ALLOWED_ELEMENT_DATA_SIZE, Vec<u8>>;
            impl Payload<'_> for BoundedSize {}
            let element = vec![b'a'; element_size - std::mem::size_of::<Vec<u8>>()];
            let data = BoundedSize::new(vec![element; 42]);

            // Act.
            let result = BoundedSize::decode(&data.encode());

            // Assert.
            if element_size <= MAX_ALLOWED_ELEMENT_DATA_SIZE {
                // Verify decoding without errors for allowed sizes.
                assert!(result.is_ok());
                assert_eq!(result.unwrap(), data);
            } else {
                // Verify decoding with errors for disallowed sizes.
                assert!(result.is_err());
                let error = result.unwrap_err();
                assert_eq!(error.code(), ErrorCode::InvalidManagementPayload);
                assert!(
                    error.description().contains(&format!(
                        "Deserialize error: The single element data size exceeds maximum allowed {MAX_ALLOWED_ELEMENT_DATA_SIZE}"
                    )),
                    "Actual: {}",
                    error.description()
                );
            }
        }
    }
}
