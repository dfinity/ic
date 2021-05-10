use super::*;
use crate::api::dkg_errors::{
    MalformedDataError, MalformedPopError, MalformedPublicKeyError, MalformedSecretKeyError,
};
use ff::PrimeField;
use ic_crypto_internal_bls12381_common::{fr_from_bytes, fr_to_bytes};
use ic_types::crypto::AlgorithmId;
use ic_types::Randomness;
use pairing::bls12_381::FrRepr;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use secp256k1::curve::{Affine, Field, Jacobian, Scalar};
use serialisation::{TAG_PUBKEY_EVEN, TAG_PUBKEY_INFINITE, TAG_PUBKEY_ODD};
use std::convert::{TryFrom, TryInto};

#[cfg(test)]
mod tests;

impl From<&EphemeralSecretKey> for EphemeralSecretKeyBytes {
    fn from(key: &EphemeralSecretKey) -> Self {
        EphemeralSecretKeyBytes(key.0.b32())
    }
}
impl From<EphemeralSecretKey> for EphemeralSecretKeyBytes {
    fn from(key: EphemeralSecretKey) -> Self {
        EphemeralSecretKeyBytes::from(&key)
    }
}
/// Parses the value and returns an error if it is larger than the modulus.
impl TryFrom<&EphemeralSecretKeyBytes> for EphemeralSecretKey {
    type Error = MalformedSecretKeyError;
    fn try_from(bytes: &EphemeralSecretKeyBytes) -> Result<EphemeralSecretKey, Self::Error> {
        let mut scalar = Scalar::default();
        let overflow = scalar.set_b32(&bytes.0);
        if overflow.into() {
            Err(MalformedSecretKeyError {
                algorithm: AlgorithmId::Secp256k1,
                internal_error: "Unable to parse EphemeralSecretKey".to_string(),
            })
        } else {
            Ok(EphemeralSecretKey(scalar))
        }
    }
}
impl TryFrom<EphemeralSecretKeyBytes> for EphemeralSecretKey {
    type Error = MalformedSecretKeyError;
    fn try_from(bytes: EphemeralSecretKeyBytes) -> Result<EphemeralSecretKey, Self::Error> {
        EphemeralSecretKey::try_from(&bytes)
    }
}
impl From<Randomness> for EphemeralSecretKey {
    fn from(seed: Randomness) -> Self {
        let mut rng = ChaChaRng::from_seed(seed.get());
        Self::random(&mut rng)
    }
}

impl From<&EphemeralPublicKey> for EphemeralPublicKeyBytes {
    fn from(key: &EphemeralPublicKey) -> Self {
        let mut ans = [0u8; EphemeralPublicKeyBytes::SIZE];
        if key.0.is_infinity() {
            ans[0] = TAG_PUBKEY_INFINITE
        } else {
            let mut affine = Affine::from_gej(&key.0);
            affine.x.normalize_var();
            affine.y.normalize_var();
            let mut bytes = [0u8; 32];
            affine.x.fill_b32(&mut bytes);
            ans[1..].copy_from_slice(&bytes);
            ans[0] = if affine.y.is_odd() {
                TAG_PUBKEY_ODD
            } else {
                TAG_PUBKEY_EVEN
            };
        }

        EphemeralPublicKeyBytes(ans)
    }
}
impl From<EphemeralPublicKey> for EphemeralPublicKeyBytes {
    fn from(key: EphemeralPublicKey) -> Self {
        EphemeralPublicKeyBytes::from(&key)
    }
}
impl TryFrom<&EphemeralPublicKeyBytes> for EphemeralPublicKey {
    type Error = MalformedPublicKeyError;
    fn try_from(key: &EphemeralPublicKeyBytes) -> Result<EphemeralPublicKey, Self::Error> {
        fn malformed(key: &EphemeralPublicKeyBytes, message: String) -> MalformedPublicKeyError {
            MalformedPublicKeyError {
                algorithm: AlgorithmId::Secp256k1,
                key_bytes: Some(key.0.to_vec()),
                internal_error: format!("Invalid public key ({}): {:?}", message, key),
            }
        }
        fn try_from_finite(
            key: &EphemeralPublicKeyBytes,
        ) -> Result<EphemeralPublicKey, MalformedPublicKeyError> {
            let mut x = Field::default();
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&key.0[1..]);
            if !x.set_b32(&bytes) {
                return Err(malformed(key, "invalid field element".to_string()));
            }
            let mut elem = Affine::default();
            if elem.set_xo_var(&x, key.0[0] == TAG_PUBKEY_ODD) {
                Ok(EphemeralPublicKey(Jacobian::from_ge(&elem)))
            } else {
                Err(malformed(key, "point not on curve".to_string()))
            }
        }
        fn try_from_infinite(
            key: &EphemeralPublicKeyBytes,
        ) -> Result<EphemeralPublicKey, MalformedPublicKeyError> {
            let bad_index = key.0[1..].iter().find(|byte| **byte != 0);
            if bad_index == None {
                Ok(EphemeralPublicKey::infinity())
            } else {
                Err(malformed(
                    key,
                    "invalid representation of zero/infinity".to_string(),
                ))
            }
        }
        match key.0[0] {
            TAG_PUBKEY_INFINITE => try_from_infinite(key),
            TAG_PUBKEY_ODD => try_from_finite(key),
            TAG_PUBKEY_EVEN => try_from_finite(key),
            _ => Err(malformed(key, format!("invalid tag '{}'", key.0[0]))),
        }
    }
}
impl TryFrom<EphemeralPublicKeyBytes> for EphemeralPublicKey {
    type Error = MalformedPublicKeyError;
    fn try_from(bytes: EphemeralPublicKeyBytes) -> Result<EphemeralPublicKey, Self::Error> {
        EphemeralPublicKey::try_from(&bytes)
    }
}
impl From<Randomness> for EphemeralPublicKey {
    fn from(seed: Randomness) -> Self {
        let mut rng = ChaChaRng::from_seed(seed.get());
        Self::random(&mut rng)
    }
}
impl From<&EphemeralSecretKey> for EphemeralPublicKey {
    fn from(secret_key: &EphemeralSecretKey) -> Self {
        EphemeralPublicKey::one() * secret_key
    }
}

impl From<&EphemeralPop> for EphemeralPopBytes {
    fn from(pop: &EphemeralPop) -> Self {
        let mut bytes = [0; EphemeralPopBytes::SIZE];
        let EphemeralPop {
            spec_ext,
            spec_c,
            spec_s,
        } = pop;
        let offset = 0;
        bytes[offset..offset + EphemeralPublicKeyBytes::SIZE]
            .copy_from_slice(&EphemeralPublicKeyBytes::from(spec_ext).0);
        let offset = offset + EphemeralPublicKeyBytes::SIZE;
        bytes[offset..offset + EphemeralSecretKeyBytes::SIZE]
            .copy_from_slice(&EphemeralSecretKeyBytes::from(spec_c).0);
        let offset = offset + EphemeralSecretKeyBytes::SIZE;
        bytes[offset..offset + EphemeralSecretKeyBytes::SIZE]
            .copy_from_slice(&EphemeralSecretKeyBytes::from(spec_s).0);
        EphemeralPopBytes(bytes)
    }
}
impl From<EphemeralPop> for EphemeralPopBytes {
    fn from(key: EphemeralPop) -> Self {
        EphemeralPopBytes::from(&key)
    }
}
impl TryFrom<&EphemeralPopBytes> for EphemeralPop {
    type Error = MalformedPopError;
    fn try_from(pop_bytes: &EphemeralPopBytes) -> Result<EphemeralPop, Self::Error> {
        let offset = 0;
        let spec_ext = {
            let mut bytes = [0u8; EphemeralPublicKeyBytes::SIZE];
            bytes.copy_from_slice(&pop_bytes.0[offset..offset + EphemeralPublicKeyBytes::SIZE]);
            EphemeralPublicKey::try_from(&EphemeralPublicKeyBytes(bytes)).map_err(|_| {
                MalformedPopError {
                    algorithm: AlgorithmId::Secp256k1,
                    internal_error: "Invalid ext".to_string(),
                    bytes: Some(bytes.to_vec()),
                }
            })?
        };
        let offset = offset + EphemeralPublicKeyBytes::SIZE;
        let spec_c = {
            let mut bytes = [0u8; EphemeralSecretKeyBytes::SIZE];
            bytes.copy_from_slice(&pop_bytes.0[offset..offset + EphemeralSecretKeyBytes::SIZE]);
            EphemeralSecretKey::try_from(EphemeralSecretKeyBytes(bytes)).map_err(|_| {
                MalformedPopError {
                    algorithm: AlgorithmId::Secp256k1,
                    internal_error: "Invalid c".to_string(),
                    bytes: Some(bytes.to_vec()),
                }
            })?
        };
        let offset = offset + EphemeralSecretKeyBytes::SIZE;
        let spec_s = {
            let mut bytes = [0u8; EphemeralSecretKeyBytes::SIZE];
            bytes.copy_from_slice(&pop_bytes.0[offset..offset + EphemeralSecretKeyBytes::SIZE]);
            EphemeralSecretKey::try_from(EphemeralSecretKeyBytes(bytes)).map_err(|_| {
                MalformedPopError {
                    algorithm: AlgorithmId::Secp256k1,
                    internal_error: "Invalid s".to_string(),
                    bytes: Some(bytes.to_vec()),
                }
            })?
        };
        Ok(EphemeralPop {
            spec_ext,
            spec_c,
            spec_s,
        })
    }
}
impl TryFrom<EphemeralPopBytes> for EphemeralPop {
    type Error = MalformedPopError;
    fn try_from(bytes: EphemeralPopBytes) -> Result<EphemeralPop, Self::Error> {
        EphemeralPop::try_from(&bytes)
    }
}

impl From<&EncryptedShare> for EncryptedShareBytes {
    fn from(key: &EncryptedShare) -> Self {
        Self(fr_to_bytes(&FrRepr::from(*key)))
    }
}
impl From<EncryptedShare> for EncryptedShareBytes {
    fn from(key: EncryptedShare) -> Self {
        Self::from(&key)
    }
}
impl TryFrom<&EncryptedShareBytes> for EncryptedShare {
    type Error = MalformedDataError;
    fn try_from(bytes: &EncryptedShareBytes) -> Result<EncryptedShare, Self::Error> {
        Fr::from_repr(fr_from_bytes(&bytes.0)).map_err(|_| MalformedDataError {
            algorithm: AlgorithmId::Secp256k1,
            internal_error: "Malformed encrypted share".to_string(),
            data: Some(bytes.0.to_vec()),
        })
    }
}
impl TryFrom<EncryptedShareBytes> for EncryptedShare {
    type Error = MalformedDataError;
    fn try_from(key: EncryptedShareBytes) -> Result<EncryptedShare, Self::Error> {
        (&key).try_into()
    }
}

impl From<&CLibComplaint> for CLibComplaintBytes {
    fn from(complaint: &CLibComplaint) -> Self {
        let CLibComplaint {
            diffie_hellman,
            pok_challenge,
            pok_response,
        } = complaint;
        CLibComplaintBytes {
            diffie_hellman: EphemeralPublicKeyBytes::from(diffie_hellman),
            pok_challenge: EphemeralSecretKeyBytes::from(pok_challenge),
            pok_response: EphemeralSecretKeyBytes::from(pok_response),
        }
    }
}
impl From<CLibComplaint> for CLibComplaintBytes {
    fn from(complaint: CLibComplaint) -> Self {
        CLibComplaintBytes::from(&complaint)
    }
}
impl TryFrom<&CLibComplaintBytes> for CLibComplaint {
    type Error = MalformedDataError;
    fn try_from(bytes: &CLibComplaintBytes) -> Result<CLibComplaint, Self::Error> {
        Ok(CLibComplaint {
            diffie_hellman: EphemeralPublicKey::try_from(&bytes.diffie_hellman).map_err(|_| {
                MalformedDataError {
                    algorithm: AlgorithmId::Secp256k1,
                    internal_error: "Complaint has a malformed Diffie Hellman".to_string(),
                    data: Some(bytes.diffie_hellman.0.to_vec()),
                }
            })?,
            pok_challenge: EphemeralSecretKey::try_from(&bytes.pok_challenge).map_err(|_| {
                MalformedDataError {
                    algorithm: AlgorithmId::Secp256k1,
                    internal_error: "Complaint has a malformed PoK challenge".to_string(),
                    data: Some(bytes.pok_challenge.0.to_vec()),
                }
            })?,
            pok_response: EphemeralSecretKey::try_from(&bytes.pok_response).map_err(|_| {
                MalformedDataError {
                    algorithm: AlgorithmId::Secp256k1,
                    internal_error: "Complaint has a malformed PoK response".to_string(),
                    data: Some(bytes.pok_response.0.to_vec()),
                }
            })?,
        })
    }
}
impl TryFrom<CLibComplaintBytes> for CLibComplaint {
    type Error = MalformedDataError;
    fn try_from(bytes: CLibComplaintBytes) -> Result<CLibComplaint, Self::Error> {
        CLibComplaint::try_from(&bytes)
    }
}
impl TryFrom<&CLibDealingBytes> for CLibDealing {
    type Error = MalformedDataError;
    fn try_from(bytes: &CLibDealingBytes) -> Result<CLibDealing, Self::Error> {
        let public_coefficients = PublicCoefficients::try_from(&bytes.public_coefficients)
            .map_err(|_|
                // TODO(CRP-442): Make the PublicCoefficients conversion return a MalformedDataError.
                MalformedDataError {
                    algorithm: AlgorithmId::Secp256k1,
                    internal_error: "Dealing has malformed public coefficients".to_string(),
                    data: None,
                })?;
        let receiver_data: Result<Vec<Option<EncryptedShare>>, _> = bytes
            .receiver_data
            .iter()
            .map(|share_maybe| share_maybe.map(EncryptedShare::try_from).transpose())
            .collect();
        let receiver_data = receiver_data?;
        Ok(CLibDealing {
            public_coefficients,
            receiver_data,
        })
    }
}
