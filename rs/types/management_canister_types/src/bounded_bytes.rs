//! Deserializers for blobs and text bounded in length or of an exact length,
//! for use with `#[serde(deserialize_with = "...")]` on fields whose Rust type
//! stays a plain `Vec<u8>`, `ByteBuf` or `String`.
//!
//! Each helper reads the value with the deserializer an unbounded field of the
//! same type uses and only adds a length check, so a bounded field accepts the
//! same encodings as an unbounded one. The length is checked once the value
//! has been read: the size of a blob or text in memory equals its size on the
//! wire, so reading it first costs no more than the payload itself.

use crate::{BOUND_EXCEEDED_MARKER, LENGTH_MISMATCH_MARKER};
use serde::{Deserialize, Deserializer, de::Error};
use serde_bytes::ByteBuf;

fn check_max_len<E: Error>(kind: &str, len: usize, max_allowed_len: usize) -> Result<(), E> {
    if len > max_allowed_len {
        return Err(E::custom(format!(
            "The {kind} length {len} {BOUND_EXCEEDED_MARKER} {max_allowed_len}"
        )));
    }
    Ok(())
}

fn length_mismatch_error<E: Error>(len: usize, expected: impl std::fmt::Display) -> E {
    E::custom(format!(
        "The blob length {len} {LENGTH_MISMATCH_MARKER} {expected}"
    ))
}

/// Checks that a blob is exactly `expected_len` bytes long.
pub(crate) fn check_exact_len<E: Error>(len: usize, expected_len: usize) -> Result<(), E> {
    if len != expected_len {
        return Err(length_mismatch_error(len, expected_len));
    }
    Ok(())
}

/// Checks that a blob is either empty or exactly `expected_len` bytes long.
fn check_empty_or_exact_len<E: Error>(len: usize, expected_len: usize) -> Result<(), E> {
    if len != 0 && len != expected_len {
        return Err(length_mismatch_error(len, format!("0 or {expected_len}")));
    }
    Ok(())
}

/// Deserializes a blob of at most `MAX_ALLOWED_LEN` bytes into a `ByteBuf`.
pub(crate) fn deserialize_bounded_byte_buf<'de, D, const MAX_ALLOWED_LEN: usize>(
    deserializer: D,
) -> Result<ByteBuf, D::Error>
where
    D: Deserializer<'de>,
{
    let blob = ByteBuf::deserialize(deserializer)?;
    check_max_len("blob", blob.len(), MAX_ALLOWED_LEN)?;
    Ok(blob)
}

/// Deserializes a blob of at most `MAX_ALLOWED_LEN` bytes.
pub(crate) fn deserialize_bounded_blob<'de, D, const MAX_ALLOWED_LEN: usize>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_byte_buf::<D, MAX_ALLOWED_LEN>(deserializer).map(ByteBuf::into_vec)
}

/// Deserializes a blob of exactly `LEN` bytes.
pub(crate) fn deserialize_exact_len_blob<'de, D, const LEN: usize>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let blob = ByteBuf::deserialize(deserializer)?;
    check_exact_len(blob.len(), LEN)?;
    Ok(blob.into_vec())
}

/// Deserializes a blob that is either empty or exactly `LEN` bytes long into
/// a `ByteBuf`.
pub(crate) fn deserialize_empty_or_exact_len_byte_buf<'de, D, const LEN: usize>(
    deserializer: D,
) -> Result<ByteBuf, D::Error>
where
    D: Deserializer<'de>,
{
    let blob = ByteBuf::deserialize(deserializer)?;
    check_empty_or_exact_len(blob.len(), LEN)?;
    Ok(blob)
}

/// Deserializes an optional blob of at most `MAX_ALLOWED_LEN` bytes.
pub(crate) fn deserialize_bounded_option_blob<'de, D, const MAX_ALLOWED_LEN: usize>(
    deserializer: D,
) -> Result<Option<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let blob = ic_utils::deserialize::deserialize_option_blob(deserializer)?;
    if let Some(blob) = &blob {
        check_max_len("blob", blob.len(), MAX_ALLOWED_LEN)?;
    }
    Ok(blob)
}

/// Deserializes a text of at most `MAX_ALLOWED_LEN` bytes.
pub(crate) fn deserialize_bounded_text<'de, D, const MAX_ALLOWED_LEN: usize>(
    deserializer: D,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let text = String::deserialize(deserializer)?;
    check_max_len("text", text.len(), MAX_ALLOWED_LEN)?;
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Payload;
    use candid::CandidType;
    use ic_error_types::ErrorCode;

    const MAX_LEN: usize = 8;

    #[derive(Eq, PartialEq, Debug, CandidType, Deserialize)]
    struct Bounded {
        #[serde(deserialize_with = "deserialize_bounded_blob::<_, MAX_LEN>")]
        blob: Vec<u8>,
        #[serde(deserialize_with = "deserialize_bounded_byte_buf::<_, MAX_LEN>")]
        byte_buf: ByteBuf,
        #[serde(deserialize_with = "deserialize_bounded_option_blob::<_, MAX_LEN>")]
        option_blob: Option<Vec<u8>>,
        #[serde(deserialize_with = "deserialize_bounded_text::<_, MAX_LEN>")]
        text: String,
    }
    impl Payload<'_> for Bounded {}

    /// Has the Candid type of `Bounded`, but the fields are declared the way
    /// unbounded blobs and text are declared.
    #[derive(Eq, PartialEq, Debug, CandidType, Deserialize)]
    struct Unbounded {
        #[serde(with = "serde_bytes")]
        blob: Vec<u8>,
        byte_buf: ByteBuf,
        #[serde(deserialize_with = "ic_utils::deserialize::deserialize_option_blob")]
        option_blob: Option<Vec<u8>>,
        text: String,
    }
    impl Payload<'_> for Unbounded {}

    fn value(blob: usize, byte_buf: usize, option_blob: Option<usize>, text: usize) -> Bounded {
        Bounded {
            blob: vec![1; blob],
            byte_buf: ByteBuf::from(vec![2; byte_buf]),
            option_blob: option_blob.map(|len| vec![3; len]),
            text: "x".repeat(text),
        }
    }

    fn assert_bound_exceeded(value: Bounded, kind: &str, len: usize) {
        let error = Bounded::decode(&value.encode()).unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidManagementPayload);
        assert!(
            error.description().contains(&format!(
                "Deserialize error: The {kind} length {len} exceeds maximum allowed {MAX_LEN}"
            )),
            "Actual: {}",
            error.description()
        );
    }

    #[test]
    fn values_within_bounds_are_decoded() {
        for len in 0..=MAX_LEN {
            let value = value(len, len, Some(len), len);
            assert_eq!(Bounded::decode(&value.encode()).unwrap(), value);
        }
        let value = value(MAX_LEN, MAX_LEN, None, MAX_LEN);
        assert_eq!(Bounded::decode(&value.encode()).unwrap(), value);
    }

    #[test]
    fn values_exceeding_bounds_are_rejected() {
        for len in MAX_LEN + 1..=MAX_LEN + 3 {
            assert_bound_exceeded(value(len, 0, None, 0), "blob", len);
            assert_bound_exceeded(value(0, len, None, 0), "blob", len);
            assert_bound_exceeded(value(0, 0, Some(len), 0), "blob", len);
            assert_bound_exceeded(value(0, 0, None, len), "text", len);
        }
    }

    #[test]
    fn text_is_bounded_in_bytes() {
        // Four characters taking two bytes each.
        let mut value = value(0, 0, None, 0);
        value.text = "é".repeat(MAX_LEN / 2);
        assert_eq!(Bounded::decode(&value.encode()).unwrap(), value);

        value.text.push('é');
        assert_bound_exceeded(value, "text", MAX_LEN + 2);
    }

    #[test]
    fn bounded_and_unbounded_fields_have_the_same_wire_format() {
        let bounded = value(MAX_LEN, 1, Some(2), 3);
        let unbounded = Unbounded {
            blob: bounded.blob.clone(),
            byte_buf: bounded.byte_buf.clone(),
            option_blob: bounded.option_blob.clone(),
            text: bounded.text.clone(),
        };
        assert_eq!(bounded.encode(), unbounded.encode());
        assert_eq!(Unbounded::decode(&bounded.encode()).unwrap(), unbounded);
        assert_eq!(Bounded::decode(&unbounded.encode()).unwrap(), bounded);
    }

    /// Candid turns an optional value of an unexpected type into `None`. A
    /// value exceeding its bound must be rejected instead.
    #[test]
    fn bound_exceeded_in_optional_value_is_rejected() {
        #[derive(Eq, PartialEq, Debug, CandidType, Deserialize)]
        struct Optional {
            bounded: Option<Bounded>,
        }
        impl Payload<'_> for Optional {}

        let within_bounds = Optional {
            bounded: Some(value(MAX_LEN, MAX_LEN, Some(MAX_LEN), MAX_LEN)),
        };
        assert_eq!(
            Optional::decode(&within_bounds.encode()).unwrap(),
            within_bounds
        );

        for bounded in [
            value(MAX_LEN + 1, 0, None, 0),
            value(0, MAX_LEN + 1, None, 0),
            value(0, 0, Some(MAX_LEN + 1), 0),
            value(0, 0, None, MAX_LEN + 1),
        ] {
            let exceeding = Optional {
                bounded: Some(bounded),
            };
            let error = Optional::decode(&exceeding.encode()).unwrap_err();
            assert!(
                error.description().contains("exceeds maximum allowed"),
                "Actual: {}",
                error.description()
            );
        }
    }

    #[derive(Eq, PartialEq, Debug, CandidType, Deserialize)]
    struct ExactLen {
        #[serde(deserialize_with = "deserialize_exact_len_blob::<_, MAX_LEN>")]
        blob: Vec<u8>,
        #[serde(deserialize_with = "deserialize_empty_or_exact_len_byte_buf::<_, MAX_LEN>")]
        byte_buf: ByteBuf,
    }
    impl Payload<'_> for ExactLen {}

    fn exact_len_value(blob: usize, byte_buf: usize) -> ExactLen {
        ExactLen {
            blob: vec![1; blob],
            byte_buf: ByteBuf::from(vec![2; byte_buf]),
        }
    }

    fn assert_length_mismatch(value: ExactLen, expected: &str) {
        let error = ExactLen::decode(&value.encode()).unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidManagementPayload);
        assert!(
            error
                .description()
                .contains(&format!("Deserialize error: {expected}")),
            "Actual: {}",
            error.description()
        );
    }

    #[test]
    fn values_of_expected_length_are_decoded() {
        for byte_buf in [0, MAX_LEN] {
            let value = exact_len_value(MAX_LEN, byte_buf);
            assert_eq!(ExactLen::decode(&value.encode()).unwrap(), value);
        }
    }

    #[test]
    fn values_of_unexpected_length_are_rejected() {
        for len in (0..=MAX_LEN + 3).filter(|len| *len != MAX_LEN) {
            assert_length_mismatch(
                exact_len_value(len, 0),
                &format!("The blob length {len} does not match expected {MAX_LEN}"),
            );
            if len != 0 {
                assert_length_mismatch(
                    exact_len_value(MAX_LEN, len),
                    &format!("The blob length {len} does not match expected 0 or {MAX_LEN}"),
                );
            }
        }
    }
}
