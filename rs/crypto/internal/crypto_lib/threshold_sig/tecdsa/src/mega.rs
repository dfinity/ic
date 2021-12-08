use crate::group::*;
use crate::seed::Seed;
use crate::*;
use core::fmt::{self, Debug};
use paste::paste;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::convert::{TryFrom, TryInto};
use zeroize::Zeroize;

const MEGA_SINGLE_ENC_DOMAIN_SEPARATOR: &str = "ic-crypto-tecdsa-mega-encryption-single-encrypt";
const MEGA_SINGLE_SEED_DOMAIN_SEPARATOR: &str = "ic-crypto-tecdsa-mega-encryption-single-seed";

const MEGA_PAIR_ENC_DOMAIN_SEPARATOR: &str = "ic-crypto-tecdsa-mega-encryption-pair-encrypt";
const MEGA_PAIR_SEED_DOMAIN_SEPARATOR: &str = "ic-crypto-tecdsa-mega-encryption-pair-seed";

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MEGaPublicKey {
    point: EccPoint,
}

impl MEGaPublicKey {
    pub fn curve(&self) -> EccCurve {
        self.point.curve()
    }

    pub fn curve_type(&self) -> EccCurveType {
        self.point.curve_type()
    }

    pub fn new(point: EccPoint) -> Self {
        Self { point }
    }

    pub fn deserialize(curve: EccCurveType, value: &[u8]) -> ThresholdEcdsaResult<Self> {
        let point = EccPoint::deserialize(curve, value)
            .map_err(|e| ThresholdEcdsaError::SerializationError(format!("{:?}", e)))?;
        Ok(Self { point })
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.point.serialize()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct MEGaPrivateKey {
    secret: EccScalar,
}

impl MEGaPrivateKey {
    pub fn curve(&self) -> EccCurve {
        self.secret.curve()
    }

    pub fn curve_type(&self) -> EccCurveType {
        self.secret.curve_type()
    }

    pub fn public_key(&self) -> ThresholdEcdsaResult<MEGaPublicKey> {
        let curve = self.curve();
        Ok(MEGaPublicKey::new(
            curve.generator_g()?.scalar_mul(&self.secret)?,
        ))
    }

    pub fn generate<R: RngCore + CryptoRng>(
        curve: EccCurveType,
        rng: &mut R,
    ) -> ThresholdEcdsaResult<Self> {
        let secret = EccScalar::random(curve, rng)?;
        Ok(Self { secret })
    }

    pub fn deserialize(curve: EccCurveType, value: &[u8]) -> ThresholdEcdsaResult<Self> {
        let secret = EccScalar::deserialize(curve, value)
            .map_err(|_| ThresholdEcdsaError::SerializationError("REDACTED".to_string()))?;
        Ok(Self { secret })
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.secret.serialize()
    }
}

impl Debug for MEGaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.secret {
            EccScalar::K256(_) => write!(f, "MEGaPrivateKey(EccScalar::K256) - REDACTED"),
            EccScalar::P256(_) => write!(f, "MEGaPrivateKey(EccScalar::P256) - REDACTED"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MEGaCiphertextSingle {
    pub ephemeral_key: EccPoint, // "v" in the paper
    pub ctexts: Vec<EccScalar>,
}

impl MEGaCiphertextSingle {
    pub fn new(ephemeral_key: EccPoint, ctexts: Vec<EccScalar>) -> Self {
        Self {
            ephemeral_key,
            ctexts,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MEGaCiphertextPair {
    pub ephemeral_key: EccPoint, // "v" in the paper
    pub ctexts: Vec<(EccScalar, EccScalar)>,
}

impl MEGaCiphertextPair {
    pub fn new(ephemeral_key: EccPoint, ctexts: Vec<(EccScalar, EccScalar)>) -> Self {
        Self {
            ephemeral_key,
            ctexts,
        }
    }
}

/// The type of MEGa ciphertext
#[derive(Debug, Copy, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum MEGaCiphertextType {
    Single,
    Pairs,
}

/// Some type of MEGa ciphertext
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MEGaCiphertext {
    Single(MEGaCiphertextSingle),
    Pairs(MEGaCiphertextPair),
}

impl MEGaCiphertext {
    pub fn recipients(&self) -> usize {
        match self {
            MEGaCiphertext::Single(c) => c.ctexts.len(),
            MEGaCiphertext::Pairs(c) => c.ctexts.len(),
        }
    }

    pub fn ctype(&self) -> MEGaCiphertextType {
        match self {
            MEGaCiphertext::Single(_) => MEGaCiphertextType::Single,
            MEGaCiphertext::Pairs(_) => MEGaCiphertextType::Pairs,
        }
    }

    pub fn verify_is(
        &self,
        ctype: MEGaCiphertextType,
        curve: EccCurveType,
    ) -> ThresholdEcdsaResult<()> {
        let curves_ok = match self {
            MEGaCiphertext::Single(c) => c.ctexts.iter().all(|x| x.curve_type() == curve),
            MEGaCiphertext::Pairs(c) => c
                .ctexts
                .iter()
                .all(|(x, y)| x.curve_type() == curve && y.curve_type() == curve),
        };

        if !curves_ok {
            return Err(ThresholdEcdsaError::CurveMismatch);
        }

        if self.ctype() != ctype {
            return Err(ThresholdEcdsaError::InconsistentCiphertext);
        }

        Ok(())
    }
}

impl From<MEGaCiphertextSingle> for MEGaCiphertext {
    fn from(c: MEGaCiphertextSingle) -> Self {
        Self::Single(c)
    }
}

impl From<MEGaCiphertextPair> for MEGaCiphertext {
    fn from(c: MEGaCiphertextPair) -> Self {
        Self::Pairs(c)
    }
}

fn check_plaintexts(
    plaintexts: &[EccScalar],
    recipients: &[MEGaPublicKey],
) -> ThresholdEcdsaResult<EccCurve> {
    if plaintexts.len() != recipients.len() {
        return Err(ThresholdEcdsaError::InvalidArguments(
            "Must be as many plaintexts as recipients".to_string(),
        ));
    }

    if plaintexts.is_empty() {
        return Err(ThresholdEcdsaError::InvalidArguments(
            "Must encrypt at least one plaintext".to_string(),
        ));
    }

    let curve = plaintexts[0].curve();

    for pt in plaintexts {
        if pt.curve() != curve {
            return Err(ThresholdEcdsaError::CurveMismatch);
        }
    }

    for recipient in recipients {
        if recipient.curve() != curve {
            return Err(ThresholdEcdsaError::CurveMismatch);
        }
    }

    Ok(curve)
}

fn check_plaintexts_pair(
    plaintexts: &[(EccScalar, EccScalar)],
    recipients: &[MEGaPublicKey],
) -> ThresholdEcdsaResult<EccCurve> {
    if plaintexts.len() != recipients.len() {
        return Err(ThresholdEcdsaError::InvalidArguments(
            "Must be as many plaintexts as recipients".to_string(),
        ));
    }

    if plaintexts.is_empty() {
        return Err(ThresholdEcdsaError::InvalidArguments(
            "Must encrypt at least one plaintext".to_string(),
        ));
    }

    let curve = plaintexts[0].0.curve();

    for pt in plaintexts {
        if pt.0.curve() != curve || pt.1.curve() != curve {
            return Err(ThresholdEcdsaError::CurveMismatch);
        }
    }

    for recipient in recipients {
        if recipient.curve() != curve {
            return Err(ThresholdEcdsaError::CurveMismatch);
        }
    }

    Ok(curve)
}

fn format_hash_to_scalar_inputs(
    dealer_index: usize,
    recipient_index: usize,
    associated_data: &[u8],
    public_key: &[u8],
    v_bytes: &[u8],
    ubeta_bytes: &[u8],
) -> ThresholdEcdsaResult<Vec<u8>> {
    // The public key, v, and ubeta are all points, and so have the same length
    if public_key.len() != v_bytes.len() || public_key.len() != ubeta_bytes.len() {
        return Err(ThresholdEcdsaError::CurveMismatch);
    }

    let point_len = public_key.len();

    // 8 byte dealer index
    // 8 byte recipient index
    // 3 points each of point_len bytes
    // 8 byte length prefix for associated_data
    // associated_data
    let mut output = Vec::with_capacity(8 + 8 + 3 * point_len + 8 + associated_data.len());

    output.extend_from_slice(&(dealer_index as u64).to_be_bytes());
    output.extend_from_slice(&(recipient_index as u64).to_be_bytes());

    output.extend_from_slice(public_key);
    output.extend_from_slice(v_bytes);
    output.extend_from_slice(ubeta_bytes);

    output.extend_from_slice(&(associated_data.len() as u64).to_be_bytes());
    output.extend_from_slice(associated_data);

    Ok(output)
}

pub fn mega_encrypt_single(
    seed: Seed,
    plaintexts: &[EccScalar],
    recipients: &[MEGaPublicKey],
    dealer_index: usize,
    associated_data: &[u8],
) -> ThresholdEcdsaResult<MEGaCiphertextSingle> {
    let curve = check_plaintexts(plaintexts, recipients)?;

    let mut rng = seed.derive(MEGA_SINGLE_SEED_DOMAIN_SEPARATOR).into_rng();

    let beta = curve.random_scalar(&mut rng)?;

    let v = curve.generator_g()?.scalar_mul(&beta)?;
    let v_bytes = v.serialize();

    let mut ctexts = Vec::with_capacity(recipients.len());

    for (index, (pubkey, ptext)) in recipients.iter().zip(plaintexts).enumerate() {
        let ubeta = pubkey.point.scalar_mul(&beta)?;

        let hash_to_scalar_input = format_hash_to_scalar_inputs(
            dealer_index,
            index,
            associated_data,
            &pubkey.serialize(),
            &v_bytes,
            &ubeta.serialize(),
        )?;

        let hm = curve.hash_to_scalar(
            1,
            &hash_to_scalar_input,
            MEGA_SINGLE_ENC_DOMAIN_SEPARATOR.as_bytes(),
        )?;
        let ctext = hm[0].add(ptext)?;

        ctexts.push(ctext);
    }

    Ok(MEGaCiphertextSingle::new(v, ctexts))
}

pub fn mega_encrypt_pair(
    seed: Seed,
    plaintexts: &[(EccScalar, EccScalar)],
    recipients: &[MEGaPublicKey],
    dealer_index: usize,
    associated_data: &[u8],
) -> ThresholdEcdsaResult<MEGaCiphertextPair> {
    let curve = check_plaintexts_pair(plaintexts, recipients)?;

    let mut rng = seed.derive(MEGA_PAIR_SEED_DOMAIN_SEPARATOR).into_rng();

    let beta = curve.random_scalar(&mut rng)?;

    let v = curve.generator_g()?.scalar_mul(&beta)?;
    let v_bytes = v.serialize();

    let mut ctexts = Vec::with_capacity(recipients.len());

    for (index, (pubkey, ptext)) in recipients.iter().zip(plaintexts).enumerate() {
        let ubeta = pubkey.point.scalar_mul(&beta)?;

        let hash_to_scalar_input = format_hash_to_scalar_inputs(
            dealer_index,
            index,
            associated_data,
            &pubkey.serialize(),
            &v_bytes,
            &ubeta.serialize(),
        )?;

        let hm = curve.hash_to_scalar(
            2,
            &hash_to_scalar_input,
            MEGA_PAIR_ENC_DOMAIN_SEPARATOR.as_bytes(),
        )?;

        let ctext0 = hm[0].add(&ptext.0)?;
        let ctext1 = hm[1].add(&ptext.1)?;

        ctexts.push((ctext0, ctext1));
    }

    Ok(MEGaCiphertextPair::new(v, ctexts))
}

pub fn mega_decrypt_single(
    ctext: &MEGaCiphertextSingle,
    associated_data: &[u8],
    dealer_index: usize,
    our_index: usize,
    our_private_key: &MEGaPrivateKey,
    our_public_key: &MEGaPublicKey,
) -> ThresholdEcdsaResult<EccScalar> {
    if ctext.ctexts.len() <= our_index {
        return Err(ThresholdEcdsaError::InvalidArguments(
            "Invalid index".to_string(),
        ));
    }

    let curve = our_private_key.curve();
    let ubeta = ctext.ephemeral_key.scalar_mul(&our_private_key.secret)?;
    let v_bytes = ctext.ephemeral_key.serialize();

    let hash_to_scalar_input = format_hash_to_scalar_inputs(
        dealer_index,
        our_index,
        associated_data,
        &our_public_key.serialize(),
        &v_bytes,
        &ubeta.serialize(),
    )?;

    let hm = curve.hash_to_scalar(
        1,
        &hash_to_scalar_input,
        MEGA_SINGLE_ENC_DOMAIN_SEPARATOR.as_bytes(),
    )?;
    ctext.ctexts[our_index].sub(&hm[0])
}

pub fn mega_decrypt_pair(
    ctext: &MEGaCiphertextPair,
    associated_data: &[u8],
    dealer_index: usize,
    our_index: usize,
    our_private_key: &MEGaPrivateKey,
    our_public_key: &MEGaPublicKey,
) -> ThresholdEcdsaResult<(EccScalar, EccScalar)> {
    if ctext.ctexts.len() <= our_index {
        return Err(ThresholdEcdsaError::InvalidArguments(
            "Invalid index".to_string(),
        ));
    }

    let curve = our_private_key.curve();
    let ubeta = ctext.ephemeral_key.scalar_mul(&our_private_key.secret)?;
    let v_bytes = ctext.ephemeral_key.serialize();

    let hash_to_scalar_input = format_hash_to_scalar_inputs(
        dealer_index,
        our_index,
        associated_data,
        &our_public_key.serialize(),
        &v_bytes,
        &ubeta.serialize(),
    )?;

    let hm = curve.hash_to_scalar(
        2,
        &hash_to_scalar_input,
        MEGA_PAIR_ENC_DOMAIN_SEPARATOR.as_bytes(),
    )?;

    let ptext0 = ctext.ctexts[our_index].0.sub(&hm[0])?;
    let ptext1 = ctext.ctexts[our_index].1.sub(&hm[1])?;

    Ok((ptext0, ptext1))
}

// Decrypt a MEGa ciphertext and return the encrypted commitment opening
pub(crate) fn decrypt_and_check(
    ciphertext: &MEGaCiphertext,
    commitment: &PolynomialCommitment,
    associated_data: &[u8],
    dealer_index: usize,
    receiver_index: usize,
    secret_key: &MEGaPrivateKey,
    public_key: &MEGaPublicKey,
) -> ThresholdEcdsaResult<CommitmentOpening> {
    let opening = match ciphertext {
        MEGaCiphertext::Single(ciphertext) => {
            let opening = mega_decrypt_single(
                ciphertext,
                associated_data,
                dealer_index,
                receiver_index,
                secret_key,
                public_key,
            )?;
            CommitmentOpening::Simple(opening)
        }

        MEGaCiphertext::Pairs(ciphertext) => {
            let opening = mega_decrypt_pair(
                ciphertext,
                associated_data,
                dealer_index,
                receiver_index,
                secret_key,
                public_key,
            )?;
            CommitmentOpening::Pedersen(opening.0, opening.1)
        }
    };

    let commitment_eval_point =
        EccScalar::from_u64(secret_key.curve().curve_type(), (receiver_index as u64) + 1);
    if commitment.check_opening(&commitment_eval_point, &opening)? {
        Ok(opening)
    } else {
        Err(ThresholdEcdsaError::InconsistentCommitments)
    }
}

/// Generate serializable public and private keys, and keyset struct.
///
/// # Arguments:
/// - curve: Curve type variant (cf. `EccCurveType`)
/// - pub_size: Serialized size of a public key (in bytes)
/// - priv_size: Serialized size of a private key (in bytes)
macro_rules! generate_serializable_keyset {
    ($curve:ident, $pub_size:expr, $priv_size:expr) => {
        paste! {
            impl TryFrom<&[<MEGaPublicKey $curve Bytes>]> for MEGaPublicKey {
                type Error = ThresholdEcdsaError;

                fn try_from(raw: &[<MEGaPublicKey $curve Bytes>]) -> ThresholdEcdsaResult<Self> {
                    Self::deserialize(EccCurveType::$curve, &raw.0)
                }
            }

            #[derive(Clone, Debug, Eq, PartialEq, Zeroize)]
            #[zeroize(drop)]
            pub struct [<MEGaPublicKey $curve Bytes>]([u8; Self::SIZE]);
            ic_crypto_internal_types::derive_serde!([<MEGaPublicKey $curve Bytes>], [<MEGaPublicKey $curve Bytes>]::SIZE);

            impl [<MEGaPublicKey $curve Bytes>] {
                pub const SIZE: usize = $pub_size;
            }

            impl TryFrom<&MEGaPublicKey> for [<MEGaPublicKey $curve Bytes>] {
                type Error = ThresholdEcdsaError;

                fn try_from(key: &MEGaPublicKey) -> ThresholdEcdsaResult<Self> {
                    match key.curve_type() {
                        EccCurveType::$curve => {
                            Ok(Self(key.serialize().try_into().map_err(|e| {
                                ThresholdEcdsaError::SerializationError(format!("{:?}", e))
                            })?))
                        }
                        _ => Err(ThresholdEcdsaError::SerializationError(
                            "Wrong curve".to_string(),
                        )),
                    }
                }
            }

            impl TryFrom<&[<MEGaPrivateKey $curve Bytes>]> for MEGaPrivateKey {
                type Error = ThresholdEcdsaError;

                fn try_from(raw: &[<MEGaPrivateKey $curve Bytes>]) -> ThresholdEcdsaResult<Self> {
                    Self::deserialize(EccCurveType::$curve, &raw.0)
                }
            }

            #[derive(Clone, Eq, PartialEq, Zeroize)]
            #[zeroize(drop)]
            pub struct [<MEGaPrivateKey $curve Bytes>]([u8; Self::SIZE]);
            ic_crypto_internal_types::derive_serde!([<MEGaPrivateKey $curve Bytes>], [<MEGaPrivateKey $curve Bytes>]::SIZE);

            impl [<MEGaPrivateKey $curve Bytes>] {
                pub const SIZE: usize = $priv_size;
            }

            impl Debug for [<MEGaPrivateKey $curve Bytes>] {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    write!(f, "{} - REDACTED", stringify!([<MEGaPrivateKey $curve Bytes>]))
                }
            }

            impl TryFrom<&MEGaPrivateKey> for [<MEGaPrivateKey $curve Bytes>] {
                type Error = ThresholdEcdsaError;

                fn try_from(key: &MEGaPrivateKey) -> ThresholdEcdsaResult<Self> {
                    match key.curve_type() {
                        EccCurveType::$curve => {
                            Ok(Self(key.serialize().try_into().map_err(|e| {
                                ThresholdEcdsaError::SerializationError(format!("{:?}", e))
                            })?))
                        }
                        _ => Err(ThresholdEcdsaError::SerializationError(
                            "Wrong curve".to_string(),
                        )),
                    }
                }
            }

            #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Zeroize)]
            #[zeroize(drop)]
            pub struct [<MEGaKeySet $curve Bytes>] {
                pub public_key: [<MEGaPublicKey $curve Bytes>],
                pub private_key: [<MEGaPrivateKey $curve Bytes>],
            }
        }
    };
}

generate_serializable_keyset!(K256, 33, 32);
