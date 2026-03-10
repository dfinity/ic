pub mod api;
pub mod dashboard;
pub mod query;
pub mod storage;
pub mod update;

#[cfg(test)]
mod tests;

use ic_stable_structures::Storable;
use ic_stable_structures::storable::Bound;
use std::borrow::Cow;
use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Hash([u8; 32]);

impl Hash {
    pub fn sha256(data: &[u8]) -> Self {
        use sha2::Digest;
        Hash(sha2::Sha256::digest(data).into())
    }
}

impl FromStr for Hash {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use hex::FromHex;
        let s = s.strip_prefix("0x").unwrap_or(s);
        <[u8; 32]>::from_hex(s).map(Hash)
    }
}

impl Display for Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Storable for Hash {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(&self.0)
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Hash(arr)
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: 32,
        is_fixed_size: true,
    };
}

const MAX_TAG_LENGTH: usize = 100;

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Tag(String);

impl Tag {
    pub fn new(s: String) -> Result<Self, InvalidTagError> {
        if s.len() > MAX_TAG_LENGTH {
            return Err(InvalidTagError::TooLong {
                max: MAX_TAG_LENGTH,
                actual: s.len(),
            });
        }
        Ok(Self(s))
    }
}

impl Display for Tag {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum InvalidTagError {
    TooLong { max: usize, actual: usize },
}

impl Display for InvalidTagError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            InvalidTagError::TooLong { max, actual } => {
                write!(
                    f,
                    "tag is too long: expected at most {max} bytes, got {actual} bytes"
                )
            }
        }
    }
}

impl std::error::Error for InvalidTagError {}

pub struct Blob {
    data: Vec<u8>,
    hash: Hash,
}

impl Blob {
    pub fn new(data: Vec<u8>) -> Self {
        let hash = Hash::sha256(&data);
        Self { data, hash }
    }

    pub fn new_unchecked(data: Vec<u8>, hash: Hash) -> Self {
        Self { data, hash }
    }

    pub fn hash(&self) -> &Hash {
        &self.hash
    }

    pub fn into_data(self) -> Vec<u8> {
        self.data
    }
}

impl From<Vec<u8>> for Blob {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Metadata {
    pub uploader: candid::Principal,
    pub inserted_at_ns: u64,
    pub size: u64,
    pub tags: BTreeSet<Tag>,
}
