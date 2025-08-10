//! Data types for the Edwards-curve Digital Signature Algorithm.

pub mod ed25519 {
    //! Data types for Ed25519.
    use std::convert::TryFrom;
    use std::fmt;
    use std::hash::{Hash, Hasher};

    #[cfg(test)]
    mod tests;

    /// An Ed25519 public key.
    #[derive(Copy, Clone, Eq, PartialEq, Hash)]
    pub struct PublicKey(pub [u8; PublicKey::SIZE]);
    crate::derive_serde!(PublicKey, PublicKey::SIZE);

    impl PublicKey {
        pub const SIZE: usize = 32;

        /// The bytes of a public key, in raw encoding.
        pub fn as_bytes(&self) -> &[u8] {
            &self.0[..]
        }
    }
    impl fmt::Debug for PublicKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "PublicKey(0x{})", hex::encode(&self.0[..]))
        }
    }

    impl TryFrom<&[u8]> for PublicKey {
        type Error = PublicKeyByteConversionError;
        fn try_from(bytes: &[u8]) -> Result<Self, PublicKeyByteConversionError> {
            if bytes.len() != Self::SIZE {
                Err(PublicKeyByteConversionError {
                    length: bytes.len(),
                })
            } else {
                let mut buffer = [0u8; Self::SIZE];
                buffer.copy_from_slice(bytes);
                Ok(Self(buffer))
            }
        }
    }

    /// An Ed25519 secret key.
    #[derive(Copy, Clone, Eq, PartialEq, Hash)]
    pub struct SecretKey(pub [u8; SecretKey::SIZE]);
    crate::derive_serde!(SecretKey, SecretKey::SIZE);

    impl SecretKey {
        pub const SIZE: usize = 32;

        /// The bytes of a secret key, in raw encoding.
        pub fn as_bytes(&self) -> &[u8] {
            &self.0[..]
        }
    }

    impl fmt::Debug for SecretKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "REDACTED")
        }
    }

    impl TryFrom<&[u8]> for SecretKey {
        type Error = SecretKeyByteConversionError;
        fn try_from(bytes: &[u8]) -> Result<Self, SecretKeyByteConversionError> {
            if bytes.len() != Self::SIZE {
                Err(SecretKeyByteConversionError {
                    length: bytes.len(),
                })
            } else {
                let mut buffer = [0u8; Self::SIZE];
                buffer.copy_from_slice(bytes);
                Ok(Self(buffer))
            }
        }
    }

    /// An Ed25519 signature.
    #[derive(Copy, Clone)]
    pub struct Signature(pub [u8; Signature::SIZE]);
    crate::derive_serde!(Signature, Signature::SIZE);

    impl Signature {
        pub const SIZE: usize = 64;
    }
    impl fmt::Debug for Signature {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let hex_sig = hex::encode(&self.0[..]);
            write!(f, "Signature(0x{})", hex_sig)
        }
    }
    impl PartialEq for Signature {
        fn eq(&self, other: &Self) -> bool {
            self.0[..] == other.0[..]
        }
    }
    impl Eq for Signature {}
    impl Hash for Signature {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.0[..].hash(state);
        }
    }

    /// The conversion from Ed25519 public key bytes failed.
    pub struct PublicKeyByteConversionError {
        pub length: usize,
    }
    impl fmt::Debug for PublicKeyByteConversionError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "ERROR: ED25519 public key must have {} bytes but received {}",
                PublicKey::SIZE,
                self.length
            )
        }
    }

    /// The conversion from Ed25519 secret key bytes failed.
    pub struct SecretKeyByteConversionError {
        pub length: usize,
    }
    impl fmt::Debug for SecretKeyByteConversionError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "ERROR: ED25519 secret key must have {} bytes but received {}",
                SecretKey::SIZE,
                self.length
            )
        }
    }
}
