use std::fmt;
use std::fmt::Formatter;

#[cfg(test)]
mod tests;

/// An id of a key. These ids are used to refer to entries in the crypto secret
/// key store.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct KeyId(pub [u8; 32]);
ic_crypto_internal_types::derive_serde!(KeyId, 32);

impl KeyId {
    pub fn get(&self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "KeyId(0x{})", hex::encode(self.0))
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "KeyId(0x{})", hex::encode(self.0))
    }
}

impl From<[u8; 32]> for KeyId {
    fn from(bytes: [u8; 32]) -> Self {
        KeyId(bytes)
    }
}

// TODO CRP-468: migrate all functions generating a KeyId into an implementation of the From trait here.
