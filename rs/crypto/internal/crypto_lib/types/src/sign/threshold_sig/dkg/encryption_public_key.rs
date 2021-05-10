//! Data types for DKG encryption public keys.
use serde::{Deserialize, Serialize};
use std::hash::Hash;
use strum_macros::IntoStaticStr;

/// An encryption public key.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialOrd, Ord, PartialEq, Serialize, Deserialize)]
pub struct CspEncryptionPublicKey {
    pub internal: InternalCspEncryptionPublicKey,
}

/// An internal encryption public key.
#[derive(
    Copy, Clone, Debug, Eq, IntoStaticStr, Hash, PartialOrd, Ord, PartialEq, Serialize, Deserialize,
)]
pub enum InternalCspEncryptionPublicKey {
    Secp256k1(secp256k1::EphemeralPublicKeyBytes),
}

impl Default for CspEncryptionPublicKey {
    fn default() -> Self {
        // TODO (CRP-328): This default is temporary to make the code consuming the
        // crypto types compile.
        CspEncryptionPublicKey {
            internal: InternalCspEncryptionPublicKey::Secp256k1(
                secp256k1::EphemeralPublicKeyBytes([42; secp256k1::EphemeralPublicKeyBytes::SIZE]),
            ),
        }
    }
}

impl From<&InternalCspEncryptionPublicKey> for CspEncryptionPublicKey {
    fn from(internal_pk: &InternalCspEncryptionPublicKey) -> Self {
        CspEncryptionPublicKey {
            internal: *internal_pk,
        }
    }
}

impl From<&CspEncryptionPublicKey> for InternalCspEncryptionPublicKey {
    fn from(pk: &CspEncryptionPublicKey) -> Self {
        pk.internal
    }
}

pub mod secp256k1 {
    //! Secp256k1 encryption public keys.
    use super::*;
    use std::cmp::Ordering;
    use std::fmt;
    use std::hash::Hasher;

    /// The public key as byte array.
    #[derive(Copy, Clone)]
    pub struct EphemeralPublicKeyBytes(pub [u8; EphemeralPublicKeyBytes::SIZE]);
    crate::derive_serde!(EphemeralPublicKeyBytes, EphemeralPublicKeyBytes::SIZE);

    impl EphemeralPublicKeyBytes {
        pub const SIZE: usize = 33;
    }

    impl fmt::Debug for EphemeralPublicKeyBytes {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{:?}", &self.0[..])
        }
    }

    impl PartialEq for EphemeralPublicKeyBytes {
        fn eq(&self, other: &Self) -> bool {
            self.0[..] == other.0[..]
        }
    }

    impl Eq for EphemeralPublicKeyBytes {}

    impl Ord for EphemeralPublicKeyBytes {
        fn cmp(&self, other: &Self) -> Ordering {
            self.0.cmp(&other.0)
        }
    }

    impl PartialOrd for EphemeralPublicKeyBytes {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    impl Hash for EphemeralPublicKeyBytes {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.0[..].hash(state);
        }
    }
}
