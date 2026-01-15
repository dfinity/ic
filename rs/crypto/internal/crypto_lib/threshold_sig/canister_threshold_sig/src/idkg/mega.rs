use crate::*;
use core::fmt::{self, Debug};
use ic_crypto_secrets_containers::SecretArray;
use paste::paste;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::convert::{TryFrom, TryInto};
use strum_macros::EnumIter;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(test)]
mod tests;

/// The type of MEGa ciphertext
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deserialize, EnumIter, Serialize)]
pub enum MEGaCiphertextType {
    Single,
    Pairs,
}

impl MEGaCiphertextType {
    pub(crate) fn tag(&self) -> &'static str {
        match self {
            Self::Single => "single",
            Self::Pairs => "pairs",
        }
    }

    pub(crate) fn old_tag(&self) -> &'static str {
        match self {
            Self::Single => "single",
            Self::Pairs => "pair",
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct MEGaPublicKey {
    point: EccPoint,
}

impl MEGaPublicKey {
    pub fn curve_type(&self) -> EccCurveType {
        self.point.curve_type()
    }

    pub fn new(point: EccPoint) -> Self {
        Self { point }
    }

    /// Deserializes a byte array into a MEGa public key.
    ///
    /// A successful deserialization also guarantees that the public
    /// key is valid, that is, that it is a point on the curve.
    pub fn deserialize(
        curve: EccCurveType,
        value: &[u8],
    ) -> CanisterThresholdSerializationResult<Self> {
        let point = EccPoint::deserialize(curve, value).map_err(|e| {
            CanisterThresholdSerializationError(format!(
                "failed to deserialize MEGaPublicKey: {e:?}"
            ))
        })?;
        Ok(Self { point })
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.point.serialize()
    }

    pub(crate) fn public_point(&self) -> &EccPoint {
        &self.point
    }
}

#[derive(Clone, Eq, PartialEq, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct MEGaPrivateKey {
    secret: EccScalar,
}

impl MEGaPrivateKey {
    pub fn curve_type(&self) -> EccCurveType {
        self.secret.curve_type()
    }

    pub fn public_key(&self) -> MEGaPublicKey {
        MEGaPublicKey::new(EccPoint::mul_by_g(&self.secret))
    }

    pub fn generate<R: RngCore + CryptoRng>(curve: EccCurveType, rng: &mut R) -> Self {
        let secret = EccScalar::random(curve, rng);
        Self { secret }
    }

    pub fn deserialize(
        curve: EccCurveType,
        value: &[u8],
    ) -> CanisterThresholdSerializationResult<Self> {
        let secret = EccScalar::deserialize(curve, value).map_err(|_| {
            CanisterThresholdSerializationError(
                "failed to deserialize MEGaPrivateKey: REDACTED".to_string(),
            )
        })?;
        Ok(Self { secret })
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.secret.serialize()
    }

    pub fn secret_scalar(&self) -> &EccScalar {
        &self.secret
    }
}

impl Debug for MEGaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MEGaPrivateKey({}) - REDACTED", self.curve_type())
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct MEGaCiphertextSingle {
    pub ephemeral_key: EccPoint,  // "v" in the paper
    pub pop_public_key: EccPoint, // "v'" in the paper
    pub pop_proof: zk::ProofOfDLogEquivalence,
    pub ctexts: Vec<EccScalar>,
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct MEGaCiphertextPair {
    pub ephemeral_key: EccPoint,  // "v" in the paper
    pub pop_public_key: EccPoint, // "v'" in the paper
    pub pop_proof: zk::ProofOfDLogEquivalence,
    pub ctexts: Vec<(EccScalar, EccScalar)>,
}

/// Some type of MEGa ciphertext
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
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

    pub fn ephemeral_key(&self) -> &EccPoint {
        match self {
            MEGaCiphertext::Single(c) => &c.ephemeral_key,
            MEGaCiphertext::Pairs(c) => &c.ephemeral_key,
        }
    }

    pub fn pop_public_key(&self) -> &EccPoint {
        match self {
            MEGaCiphertext::Single(c) => &c.pop_public_key,
            MEGaCiphertext::Pairs(c) => &c.pop_public_key,
        }
    }

    pub fn pop_proof(&self) -> &zk::ProofOfDLogEquivalence {
        match self {
            MEGaCiphertext::Single(c) => &c.pop_proof,
            MEGaCiphertext::Pairs(c) => &c.pop_proof,
        }
    }

    /// Check the validity of a MEGa ciphertext
    ///
    /// Specifically this checks the ZK proof of the ephemeral key,
    /// and also checks that the ciphertext has the expected number of
    /// recipients.
    pub fn check_validity(
        &self,
        alg: IdkgProtocolAlgorithm,
        expected_recipients: usize,
        associated_data: &[u8],
        dealer_index: NodeIndex,
    ) -> CanisterThresholdResult<()> {
        if self.recipients() != expected_recipients {
            return Err(CanisterThresholdError::InvalidRecipients);
        }

        match self {
            MEGaCiphertext::Single(c) => c.verify_pop(alg, associated_data, dealer_index),
            MEGaCiphertext::Pairs(c) => c.verify_pop(alg, associated_data, dealer_index),
        }
    }

    /// Simple type verification for MEGa ciphertexts
    ///
    /// Verifies that the ciphertext is of the expected type (single or pairs)
    /// and is for the expected curve.
    pub fn verify_is(
        &self,
        ctype: MEGaCiphertextType,
        key_curve: EccCurveType,
        plaintext_curve: EccCurveType,
    ) -> CanisterThresholdResult<()> {
        if self.ephemeral_key().curve_type() != key_curve {
            return Err(CanisterThresholdError::CurveMismatch);
        }

        if self.pop_public_key().curve_type() != key_curve {
            return Err(CanisterThresholdError::CurveMismatch);
        }
        if self.pop_proof().curve_type()? != key_curve {
            return Err(CanisterThresholdError::CurveMismatch);
        }

        let curves_ok = match self {
            MEGaCiphertext::Single(c) => c.ctexts.iter().all(|x| x.curve_type() == plaintext_curve),
            MEGaCiphertext::Pairs(c) => c.ctexts.iter().all(|(x, y)| {
                x.curve_type() == plaintext_curve && y.curve_type() == plaintext_curve
            }),
        };

        if !curves_ok {
            return Err(CanisterThresholdError::CurveMismatch);
        }

        if self.ctype() != ctype {
            return Err(CanisterThresholdError::InconsistentCiphertext);
        }

        Ok(())
    }

    /// Decrypt a MEGa ciphertext and return the encrypted commitment opening
    ///
    /// # Arguments:
    /// * `alg`: the IDKG protocol type being executed
    /// * `commitment`: a commitment to the coefficients of the polynomial being shared.
    /// * `associated_data` context data that identifies the protocol instance.
    /// * `dealer_index`: index of the dealer that encrypted the dealing.
    /// * `receiver_index`: index of the receiver decrypting the cipher text.
    /// * `secret_key`: decryption key of the receiver.
    /// * `public_key`: encryption key of the receiver corresponding to the `secret_key`.
    /// # Errors:
    /// * `InvalidCommitment` if the decrypted share does not match with the commitment.
    /// * `InvalidProof` if the proof of possession is incorrect.
    /// * Any other error if the ciphertext could not be decrypted for some reason.
    pub(crate) fn decrypt_and_check(
        &self,
        alg: IdkgProtocolAlgorithm,
        commitment: &PolynomialCommitment,
        associated_data: &[u8],
        dealer_index: NodeIndex,
        receiver_index: NodeIndex,
        secret_key: &MEGaPrivateKey,
        public_key: &MEGaPublicKey,
    ) -> CanisterThresholdResult<CommitmentOpening> {
        let opening = match self {
            MEGaCiphertext::Single(ciphertext) => {
                let opening = ciphertext.decrypt(
                    alg,
                    associated_data,
                    dealer_index,
                    receiver_index,
                    secret_key,
                    public_key,
                )?;
                CommitmentOpening::Simple(opening)
            }

            MEGaCiphertext::Pairs(ciphertext) => {
                let opening = ciphertext.decrypt(
                    alg,
                    associated_data,
                    dealer_index,
                    receiver_index,
                    secret_key,
                    public_key,
                )?;
                CommitmentOpening::Pedersen(opening.0, opening.1)
            }
        };

        commitment.return_opening_if_consistent(receiver_index, &opening)
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
) -> CanisterThresholdResult<(EccCurveType, EccCurveType)> {
    if plaintexts.len() != recipients.len() {
        return Err(CanisterThresholdError::InvalidArguments(
            "Must be as many plaintexts as recipients".to_string(),
        ));
    }

    if plaintexts.is_empty() {
        return Err(CanisterThresholdError::InvalidArguments(
            "Must encrypt at least one plaintext".to_string(),
        ));
    }

    let plaintext_curve = plaintexts[0].curve_type();

    for pt in plaintexts {
        if pt.curve_type() != plaintext_curve {
            return Err(CanisterThresholdError::CurveMismatch);
        }
    }

    let key_curve = recipients[0].curve_type();

    for recipient in recipients {
        if recipient.curve_type() != key_curve {
            return Err(CanisterThresholdError::InvalidRecipients);
        }
    }

    Ok((plaintext_curve, key_curve))
}

fn check_plaintexts_pair(
    plaintexts: &[(EccScalar, EccScalar)],
    recipients: &[MEGaPublicKey],
) -> CanisterThresholdResult<(EccCurveType, EccCurveType)> {
    if plaintexts.len() != recipients.len() {
        return Err(CanisterThresholdError::InvalidArguments(
            "Must be as many plaintexts as recipients".to_string(),
        ));
    }

    if plaintexts.is_empty() {
        return Err(CanisterThresholdError::InvalidArguments(
            "Must encrypt at least one plaintext".to_string(),
        ));
    }

    let plaintext_curve = plaintexts[0].0.curve_type();

    for pt in plaintexts {
        if pt.0.curve_type() != plaintext_curve || pt.1.curve_type() != plaintext_curve {
            return Err(CanisterThresholdError::CurveMismatch);
        }
    }

    let key_curve = recipients[0].curve_type();

    for recipient in recipients {
        if recipient.curve_type() != key_curve {
            return Err(CanisterThresholdError::InvalidRecipients);
        }
    }

    Ok((plaintext_curve, key_curve))
}

fn mega_hash_to_scalars(
    alg: IdkgProtocolAlgorithm,
    plaintext_curve: EccCurveType,
    ctype: MEGaCiphertextType,
    dealer_index: NodeIndex,
    recipient_index: NodeIndex,
    associated_data: &[u8],
    public_key: &EccPoint,
    ephemeral_key: &EccPoint,
    shared_secret: &EccPoint,
) -> CanisterThresholdResult<Vec<EccScalar>> {
    let count = match ctype {
        MEGaCiphertextType::Single => 1,
        MEGaCiphertextType::Pairs => 2,
    };

    let mut ro = RandomOracle::new(DomainSep::MegaEncryption(
        ctype,
        alg,
        public_key.curve_type(),
    ));
    ro.add_usize("dealer_index", dealer_index as usize)?;
    ro.add_usize("recipient_index", recipient_index as usize)?;
    ro.add_bytestring("associated_data", associated_data)?;
    ro.add_point("public_key", public_key)?;
    ro.add_point("ephemeral_key", ephemeral_key)?;
    ro.add_point("shared_secret", shared_secret)?;
    ro.output_scalars(plaintext_curve, count)
}

/// Compute the Proof Of Possession (PoP) base element
///
/// This is used in conjunction with a DLOG equality ZK proof in order
/// for the sender to prove to recipients that it knew the discrete
/// log of the ephemeral key.
fn compute_pop_base(
    alg: IdkgProtocolAlgorithm,
    ctype: MEGaCiphertextType,
    curve_type: EccCurveType,
    associated_data: &[u8],
    dealer_index: NodeIndex,
    ephemeral_key: &EccPoint,
) -> CanisterThresholdResult<EccPoint> {
    let mut ro = RandomOracle::new(DomainSep::MegaPopBase(ctype, alg, curve_type));
    ro.add_bytestring("associated_data", associated_data)?;
    ro.add_u32("dealer_index", dealer_index)?;
    ro.add_point("ephemeral_key", ephemeral_key)?;
    ro.output_point(curve_type)
}

/// Verify the Proof Of Possession (PoP)
fn verify_pop(
    alg: IdkgProtocolAlgorithm,
    ctype: MEGaCiphertextType,
    associated_data: &[u8],
    dealer_index: NodeIndex,
    ephemeral_key: &EccPoint,
    pop_public_key: &EccPoint,
    pop_proof: &zk::ProofOfDLogEquivalence,
) -> CanisterThresholdResult<()> {
    let curve_type = ephemeral_key.curve_type();

    let pop_base = compute_pop_base(
        alg,
        ctype,
        curve_type,
        associated_data,
        dealer_index,
        ephemeral_key,
    )?;

    pop_proof.verify(
        alg,
        &EccPoint::generator_g(curve_type),
        &pop_base,
        ephemeral_key,
        pop_public_key,
        associated_data,
    )
}

/// Compute the ephemeral key and associated Proof Of Possession
///
/// The ephemeral key (here, `v`) is simply an ECDH public key, whose secret key
/// is `beta`.
///
/// We also compute a proof of possession by hashing various information,
/// including the ephemeral key, to another elliptic curve point
/// (`pop_base`). We compute a scalar multiplication of the `pop_base` and
/// `beta`, producing `pop_public_key`. Finally we create a ZK proof that the
/// discrete logarithms of `pop_public_key` and `v` are the same value (`beta`)
/// in the respective bases.
fn compute_eph_key_and_pop(
    alg: IdkgProtocolAlgorithm,
    ctype: MEGaCiphertextType,
    curve_type: EccCurveType,
    seed: Seed,
    associated_data: &[u8],
    dealer_index: NodeIndex,
) -> CanisterThresholdResult<(EccScalar, EccPoint, EccPoint, zk::ProofOfDLogEquivalence)> {
    let domain_sep = DomainSep::SeedForMegaEncryption(ctype, alg, curve_type);
    let beta = EccScalar::from_seed(curve_type, seed.derive(&domain_sep.to_string()));
    let v = EccPoint::mul_by_g(&beta);

    let pop_base = compute_pop_base(alg, ctype, curve_type, associated_data, dealer_index, &v)?;
    let pop_public_key = pop_base.scalar_mul(&beta)?;
    let pop_proof = zk::ProofOfDLogEquivalence::create(
        seed.derive(&DomainSep::SeedForMegaPopProof(ctype, alg, curve_type).to_string()),
        alg,
        &beta,
        &EccPoint::generator_g(curve_type),
        &pop_base,
        associated_data,
    )?;

    Ok((beta, v, pop_public_key, pop_proof))
}

impl MEGaCiphertextSingle {
    pub fn encrypt(
        seed: Seed,
        alg: IdkgProtocolAlgorithm,
        plaintexts: &[EccScalar],
        recipients: &[MEGaPublicKey],
        dealer_index: NodeIndex,
        associated_data: &[u8],
    ) -> CanisterThresholdResult<Self> {
        let (plaintext_curve, key_curve) = check_plaintexts(plaintexts, recipients)?;

        let ctype = MEGaCiphertextType::Single;

        let (beta, v, pop_public_key, pop_proof) =
            compute_eph_key_and_pop(alg, ctype, key_curve, seed, associated_data, dealer_index)?;

        let mut ctexts = Vec::with_capacity(recipients.len());

        for (index, (pubkey, ptext)) in recipients.iter().zip(plaintexts).enumerate() {
            let ubeta = pubkey.point.scalar_mul(&beta)?;

            let hm = mega_hash_to_scalars(
                alg,
                plaintext_curve,
                ctype,
                dealer_index,
                index as NodeIndex,
                associated_data,
                &pubkey.point,
                &v,
                &ubeta,
            )?;

            let ctext = hm[0].add(ptext)?;

            ctexts.push(ctext);
        }

        Ok(Self {
            ephemeral_key: v,
            pop_public_key,
            pop_proof,
            ctexts,
        })
    }

    pub fn verify_pop(
        &self,
        alg: IdkgProtocolAlgorithm,
        associated_data: &[u8],
        dealer_index: NodeIndex,
    ) -> CanisterThresholdResult<()> {
        verify_pop(
            alg,
            MEGaCiphertextType::Single,
            associated_data,
            dealer_index,
            &self.ephemeral_key,
            &self.pop_public_key,
            &self.pop_proof,
        )
    }

    pub fn decrypt_from_shared_secret(
        &self,
        alg: IdkgProtocolAlgorithm,
        associated_data: &[u8],
        dealer_index: NodeIndex,
        recipient_index: NodeIndex,
        recipient_public_key: &MEGaPublicKey,
        shared_secret: &EccPoint,
    ) -> CanisterThresholdResult<EccScalar> {
        if self.ctexts.len() <= recipient_index as usize {
            return Err(CanisterThresholdError::InvalidArguments(
                "Invalid index".to_string(),
            ));
        }

        let plaintext_curve = self.ctexts[recipient_index as usize].curve_type();

        let hm = mega_hash_to_scalars(
            alg,
            plaintext_curve,
            MEGaCiphertextType::Single,
            dealer_index,
            recipient_index,
            associated_data,
            &recipient_public_key.point,
            &self.ephemeral_key,
            shared_secret,
        )?;

        self.ctexts[recipient_index as usize].sub(&hm[0])
    }

    pub fn decrypt(
        &self,
        alg: IdkgProtocolAlgorithm,
        associated_data: &[u8],
        dealer_index: NodeIndex,
        recipient_index: NodeIndex,
        our_private_key: &MEGaPrivateKey,
        recipient_public_key: &MEGaPublicKey,
    ) -> CanisterThresholdResult<EccScalar> {
        // We could verify the PoP here. However we assume that it was
        // already checked when the dealing was verified, and we only
        // decrypt verified dealings.
        //self.verify_pop(associated_data, dealer_index)?;

        let ubeta = self.ephemeral_key.scalar_mul(&our_private_key.secret)?;

        self.decrypt_from_shared_secret(
            alg,
            associated_data,
            dealer_index,
            recipient_index,
            recipient_public_key,
            &ubeta,
        )
    }
}

impl MEGaCiphertextPair {
    pub fn encrypt(
        seed: Seed,
        alg: IdkgProtocolAlgorithm,
        plaintexts: &[(EccScalar, EccScalar)],
        recipients: &[MEGaPublicKey],
        dealer_index: NodeIndex,
        associated_data: &[u8],
    ) -> CanisterThresholdResult<Self> {
        let (plaintext_curve, key_curve) = check_plaintexts_pair(plaintexts, recipients)?;

        let ctype = MEGaCiphertextType::Pairs;

        let (beta, v, pop_public_key, pop_proof) =
            compute_eph_key_and_pop(alg, ctype, key_curve, seed, associated_data, dealer_index)?;

        let mut ctexts = Vec::with_capacity(recipients.len());

        for (index, (pubkey, ptext)) in recipients.iter().zip(plaintexts).enumerate() {
            let ubeta = pubkey.point.scalar_mul(&beta)?;

            let hm = mega_hash_to_scalars(
                alg,
                plaintext_curve,
                ctype,
                dealer_index,
                index as NodeIndex,
                associated_data,
                &pubkey.point,
                &v,
                &ubeta,
            )?;

            let ctext0 = hm[0].add(&ptext.0)?;
            let ctext1 = hm[1].add(&ptext.1)?;

            ctexts.push((ctext0, ctext1));
        }

        Ok(Self {
            ephemeral_key: v,
            pop_public_key,
            pop_proof,
            ctexts,
        })
    }

    pub fn verify_pop(
        &self,
        alg: IdkgProtocolAlgorithm,
        associated_data: &[u8],
        dealer_index: NodeIndex,
    ) -> CanisterThresholdResult<()> {
        verify_pop(
            alg,
            MEGaCiphertextType::Pairs,
            associated_data,
            dealer_index,
            &self.ephemeral_key,
            &self.pop_public_key,
            &self.pop_proof,
        )
    }

    pub fn decrypt_from_shared_secret(
        &self,
        alg: IdkgProtocolAlgorithm,
        associated_data: &[u8],
        dealer_index: NodeIndex,
        recipient_index: NodeIndex,
        recipient_public_key: &MEGaPublicKey,
        shared_secret: &EccPoint,
    ) -> CanisterThresholdResult<(EccScalar, EccScalar)> {
        if self.ctexts.len() <= recipient_index as usize {
            return Err(CanisterThresholdError::InvalidArguments(
                "Invalid index".to_string(),
            ));
        }

        let plaintext_curve = self.ctexts[recipient_index as usize].0.curve_type();

        let hm = mega_hash_to_scalars(
            alg,
            plaintext_curve,
            MEGaCiphertextType::Pairs,
            dealer_index,
            recipient_index,
            associated_data,
            &recipient_public_key.point,
            &self.ephemeral_key,
            shared_secret,
        )?;

        let ptext0 = self.ctexts[recipient_index as usize].0.sub(&hm[0])?;
        let ptext1 = self.ctexts[recipient_index as usize].1.sub(&hm[1])?;

        Ok((ptext0, ptext1))
    }

    pub fn decrypt(
        &self,
        alg: IdkgProtocolAlgorithm,
        associated_data: &[u8],
        dealer_index: NodeIndex,
        recipient_index: NodeIndex,
        our_private_key: &MEGaPrivateKey,
        recipient_public_key: &MEGaPublicKey,
    ) -> CanisterThresholdResult<(EccScalar, EccScalar)> {
        // We could verify the PoP here. However we assume that it was
        // already checked when the dealing was verified, and we only
        // decrypt verified dealings.
        //self.verify_pop(associated_data, dealer_index)?;

        let ubeta = self.ephemeral_key.scalar_mul(&our_private_key.secret)?;

        self.decrypt_from_shared_secret(
            alg,
            associated_data,
            dealer_index,
            recipient_index,
            recipient_public_key,
            &ubeta,
        )
    }
}

/// Generate serializable public and private keys, and keyset struct.
///
/// # Arguments:
/// - curve: Curve type variant (cf. `EccCurveType`)
/// - pub_size: Serialized size of a public key (in bytes)
/// - priv_size: Serialized size of a private key (in bytes)
macro_rules! generate_serializable_keyset {
    ($curve:ident, $pub_size:expr_2021, $priv_size:expr_2021) => {
        paste! {
            impl TryFrom<&[<MEGaPublicKey $curve Bytes>]> for MEGaPublicKey {
                type Error = CanisterThresholdSerializationError;

                fn try_from(raw: &[<MEGaPublicKey $curve Bytes>]) -> CanisterThresholdSerializationResult<Self> {
                    Self::deserialize(EccCurveType::$curve, &raw.0)
                }
            }

            #[derive(Clone, Eq, PartialEq, Debug, Zeroize, ZeroizeOnDrop)]
            pub struct [<MEGaPublicKey $curve Bytes>]([u8; Self::SIZE]);
            ic_crypto_internal_types::derive_serde!([<MEGaPublicKey $curve Bytes>], [<MEGaPublicKey $curve Bytes>]::SIZE);

            impl [<MEGaPublicKey $curve Bytes>] {
                pub const SIZE: usize = $pub_size;
            }

            impl TryFrom<&MEGaPublicKey> for [<MEGaPublicKey $curve Bytes>] {
                type Error = CanisterThresholdSerializationError;

                fn try_from(key: &MEGaPublicKey) -> CanisterThresholdSerializationResult<Self> {
                    match key.curve_type() {
                        EccCurveType::$curve => {
                            Ok(Self(key.serialize().try_into().map_err(|e| {
                                CanisterThresholdSerializationError(format!("{:?}", e))
                            })?))
                        }
                        _ => Err(CanisterThresholdSerializationError(
                            "Wrong curve".to_string(),
                        )),
                    }
                }
            }

            impl TryFrom<&[<MEGaPrivateKey $curve Bytes>]> for MEGaPrivateKey {
                type Error = CanisterThresholdSerializationError;

                fn try_from(raw: &[<MEGaPrivateKey $curve Bytes>]) -> CanisterThresholdSerializationResult<Self> {
                    Self::deserialize(EccCurveType::$curve, raw.0.expose_secret().as_ref())
                }
            }

            #[derive(Clone, Eq, PartialEq, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
            pub struct [<MEGaPrivateKey $curve Bytes>](SecretArray<{ $priv_size }>);

            impl [<MEGaPrivateKey $curve Bytes>] {
                pub const SIZE: usize = $priv_size;
            }

            impl Debug for [<MEGaPrivateKey $curve Bytes>] {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    write!(f, "{} - REDACTED", stringify!([<MEGaPrivateKey $curve Bytes>]))
                }
            }

            impl TryFrom<&MEGaPrivateKey> for [<MEGaPrivateKey $curve Bytes>] {
                type Error = CanisterThresholdSerializationError;

                fn try_from(key: &MEGaPrivateKey) -> CanisterThresholdSerializationResult<Self> {
                    match key.curve_type() {
                        EccCurveType::$curve => {
                            let mut bits: [u8; Self::SIZE] = key.serialize().try_into().map_err(|e| {
                                CanisterThresholdSerializationError(format!("{:?}", e))
                            })?;

                            let arr = SecretArray::new_and_zeroize_argument(&mut bits);

                            Ok(Self(arr))
                        }
                        _ => Err(CanisterThresholdSerializationError(
                            "Wrong curve".to_string(),
                        )),
                    }
                }
            }

            #[derive(
                Clone, Eq, PartialEq, Debug, Deserialize, Serialize, Zeroize, ZeroizeOnDrop,
            )]
            pub struct [<MEGaKeySet $curve Bytes>] {
                pub public_key: [<MEGaPublicKey $curve Bytes>],
                pub private_key: [<MEGaPrivateKey $curve Bytes>],
            }
        }
    };
}

generate_serializable_keyset!(K256, 33, 32);
