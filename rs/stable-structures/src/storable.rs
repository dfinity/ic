use std::convert::TryInto;

/// A trait with convenience methods for storing an element into a stable structure.
pub trait Storable {
    /// Converts an element into bytes.
    ///
    /// NOTE: `Cow` is used here to avoid unnecessary cloning.
    fn to_bytes(&self) -> std::borrow::Cow<[u8]>;

    /// Converts bytes into an element.
    ///
    /// NOTE: The bytes are passed as a `Vec<u8>` as opposed to `&[u8]` because
    /// in the vast majority of cases, the caller will no longer need the bytes,
    /// and passing a `Vec<u8>` prevents unnecessary cloning.
    fn from_bytes(bytes: Vec<u8>) -> Self;
}

// NOTE: Below are a few implementations of `Storable` for common types.
// Some of these implementations use `unwrap`, as opposed to returning a `Result`
// with a possible error. The reason behind this decision is that these
// `unwrap`s would be triggered in one of the following cases:
//
// 1) The implementation of `Storable` has a bug.
// 2) The data being stored in the stable structure is corrupt.
//
// Both of these errors are irrecoverable at runtime, and given the additional
// complexity of exposing these errors in the API of stable structures, an `unwrap`
// in case of a detected error is preferable and safer.

impl Storable for Vec<u8> {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        std::borrow::Cow::Borrowed(self)
    }

    fn from_bytes(bytes: Vec<u8>) -> Self {
        bytes
    }
}

impl Storable for String {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        std::borrow::Cow::Borrowed(self.as_bytes())
    }

    fn from_bytes(bytes: Vec<u8>) -> Self {
        String::from_utf8(bytes).unwrap()
    }
}

impl Storable for u128 {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        std::borrow::Cow::Owned(self.to_le_bytes().to_vec())
    }

    fn from_bytes(bytes: Vec<u8>) -> Self {
        Self::from_le_bytes(bytes.try_into().unwrap())
    }
}

impl Storable for u64 {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        std::borrow::Cow::Owned(self.to_le_bytes().to_vec())
    }

    fn from_bytes(bytes: Vec<u8>) -> Self {
        Self::from_le_bytes(bytes.try_into().unwrap())
    }
}

impl Storable for u32 {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        std::borrow::Cow::Owned(self.to_le_bytes().to_vec())
    }

    fn from_bytes(bytes: Vec<u8>) -> Self {
        Self::from_le_bytes(bytes.try_into().unwrap())
    }
}

impl Storable for u16 {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        std::borrow::Cow::Owned(self.to_le_bytes().to_vec())
    }

    fn from_bytes(bytes: Vec<u8>) -> Self {
        Self::from_le_bytes(bytes.try_into().unwrap())
    }
}

impl Storable for u8 {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        std::borrow::Cow::Owned(self.to_le_bytes().to_vec())
    }

    fn from_bytes(bytes: Vec<u8>) -> Self {
        Self::from_le_bytes(bytes.try_into().unwrap())
    }
}
