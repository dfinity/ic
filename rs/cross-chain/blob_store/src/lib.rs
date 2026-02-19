pub mod api;
pub mod storage;
pub mod update;

#[cfg(test)]
mod tests;

use ic_stable_structures::Storable;
use ic_stable_structures::storable::Bound;
use std::borrow::Cow;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
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

pub struct Blob {
    data: Vec<u8>,
    hash: Hash,
}

impl Blob {
    pub fn new(data: Vec<u8>) -> Self {
        let hash = Hash::sha256(&data);
        Self { data, hash }
    }

    pub fn hash(&self) -> &Hash {
        &self.hash
    }
}

impl From<Vec<u8>> for Blob {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}
