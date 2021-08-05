use super::serialisation::{TAG_PUBKEY_EVEN, TAG_PUBKEY_ODD};
use super::{
    CLibTranscriptBytes, EncryptedShareBytes, EphemeralPublicKey, EphemeralPublicKeyBytes,
    EphemeralSecretKey, EphemeralSecretKeyBytes,
};
use ic_types::NodeIndex;
use rand::{CryptoRng, Rng};
use std::convert::TryFrom;

impl CLibTranscriptBytes {
    /// Given a receiver's public key, get their index and encrypted share.
    pub fn get_receiver_data(
        &self,
        key: EphemeralPublicKeyBytes,
    ) -> Option<(NodeIndex, EncryptedShareBytes)> {
        (0_u32..)
            .zip(&self.receiver_data)
            .filter_map(|(index, record)| record.map(|record| (index, record))) // Discard None
            .filter_map(|(index, (public_key_bytes, encrypted_share_bytes))| {
                if public_key_bytes == key {
                    Some((index, encrypted_share_bytes))
                } else {
                    None
                }
            })
            .next()
    }
}

impl EphemeralPublicKey {
    /// Returns the public key corresponding to the secret key 1.
    pub fn one() -> Self {
        EphemeralPublicKey(libsecp256k1::curve::Jacobian::from_ge(
            &libsecp256k1::curve::AFFINE_G,
        ))
    }

    /// Returns the point at infinity.
    pub fn infinity() -> Self {
        let mut ans = libsecp256k1::curve::Jacobian::default();
        ans.set_infinity();
        EphemeralPublicKey(ans)
    }

    /// Checks whether this is the point at infinity.
    pub fn is_infinity(&self) -> bool {
        self.0.is_infinity()
    }

    /// Random-oracle map to finite points on the curve such that the
    /// dlog of the point is not known.
    pub fn random<R: Rng + CryptoRng>(rng: &mut R) -> EphemeralPublicKey {
        let _bytes = [0; EphemeralPublicKeyBytes::SIZE];
        loop {
            let mut bytes = EphemeralPublicKeyBytes([0u8; EphemeralPublicKeyBytes::SIZE]);
            rng.fill(&mut bytes.0[..]);
            bytes.0[0] = if (bytes.0[0] & 0x01) == 0x00 {
                TAG_PUBKEY_EVEN
            } else {
                TAG_PUBKEY_ODD
            };
            if let Ok(key) = EphemeralPublicKey::try_from(&bytes) {
                return key;
            }
        }
    }
}

impl EphemeralSecretKey {
    /// Returns the additive identity
    pub fn zero() -> Self {
        Self(libsecp256k1::curve::Scalar::from_int(0))
    }

    /// Returns the multiplicative identity
    pub fn one() -> Self {
        Self(libsecp256k1::curve::Scalar::from_int(1))
    }

    pub fn random<R: Rng + CryptoRng>(rng: &mut R) -> EphemeralSecretKey {
        loop {
            let bytes = EphemeralSecretKeyBytes(rng.gen::<[u8; EphemeralSecretKeyBytes::SIZE]>());
            let scalar_maybe = EphemeralSecretKey::try_from(bytes);
            if let Ok(scalar) = scalar_maybe {
                return scalar;
            }
        }
    }
    pub fn inv(&self) -> Self {
        Self(self.0.inv())
    }
}
