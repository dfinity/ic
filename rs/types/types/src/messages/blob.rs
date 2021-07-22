use ic_utils::byte_slice_fmt::truncate_and_format;
#[cfg(test)]
use proptest_derive::Arbitrary;
use serde::{Deserialize, Serialize};
use std::{fmt, ops::Deref};

/// A binary "blob", i.e. a byte array.
///
/// Use `serde_bytes` so that the `Vec<u8>` is deserialized as a sequence
/// (array) of bytes, whereas we want an actual CBOR "byte array", e.g. a
/// bytestring.
#[derive(Clone, Serialize, Deserialize, Hash, Default, PartialEq, Eq)]
#[cfg_attr(test, derive(Arbitrary))]
pub struct Blob(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl Blob {
    fn format(&self, f: &mut fmt::Formatter<'_>, max_bytes_to_format: usize) -> fmt::Result {
        f.write_fmt(format_args!(
            "Blob{{{}}}",
            truncate_and_format(self.0.as_slice(), max_bytes_to_format)
        ))
    }
}

impl Deref for Blob {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Debug for Blob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.format(f, usize::MAX)
    }
}

impl fmt::Display for Blob {
    // Just like Debug, except we truncate long ones
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.format(f, 40_usize)
    }
}

impl<'a, T: AsRef<[u8]>> From<T> for Blob {
    fn from(v: T) -> Blob {
        Blob(v.as_ref().to_vec())
    }
}
