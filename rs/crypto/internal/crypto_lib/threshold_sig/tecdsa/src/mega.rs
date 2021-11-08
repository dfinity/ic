use crate::group::*;
use crate::seed::Seed;
use crate::*;
use rand_core::{CryptoRng, RngCore};

const MEGA_SINGLE_ENC_DOMAIN_SEPARATOR: &str = "ic-crypto-tecdsa-mega-encryption-single-encrypt";
const MEGA_SINGLE_SEED_DOMAIN_SEPARATOR: &str = "ic-crypto-tecdsa-mega-encryption-single-seed";

const MEGA_PAIR_ENC_DOMAIN_SEPARATOR: &str = "ic-crypto-tecdsa-mega-encryption-pair-encrypt";
const MEGA_PAIR_SEED_DOMAIN_SEPARATOR: &str = "ic-crypto-tecdsa-mega-encryption-pair-seed";

#[derive(Copy, Clone, Debug)]
pub struct MEGaPublicKey {
    point: EccPoint,
}

impl MEGaPublicKey {
    pub fn curve(&self) -> EccCurve {
        self.point.curve()
    }

    pub fn new(point: EccPoint) -> Self {
        Self { point }
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.point.serialize()
    }
}

#[derive(Copy, Clone, Debug)]
pub struct MEGaPrivateKey {
    secret: EccScalar,
}

impl MEGaPrivateKey {
    pub fn curve(&self) -> EccCurve {
        self.secret.curve()
    }

    pub fn public_key(&self) -> ThresholdEcdsaResult<MEGaPublicKey> {
        let curve = self.curve();
        Ok(MEGaPublicKey::new(
            curve.generator_g()?.scalar_mul(&self.secret)?,
        ))
    }

    pub fn generate<R: RngCore + CryptoRng>(
        group: EccCurve,
        rng: &mut R,
    ) -> ThresholdEcdsaResult<Self> {
        let secret = group.random_scalar(rng)?;
        Ok(Self { secret })
    }

    pub fn deserialize(group: EccCurve, value: &[u8]) -> ThresholdEcdsaResult<Self> {
        let secret = group.deserialize_scalar(value)?;
        Ok(Self { secret })
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.secret.serialize()
    }
}

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
    associated_data: &[u8],
    recipient_index: u64,
    public_key: &[u8],
    v_bytes: &[u8],
    ubeta_bytes: &[u8],
) -> ThresholdEcdsaResult<Vec<u8>> {
    // The public key, v, and ubeta are all points, and so have the same length
    if public_key.len() != v_bytes.len() || public_key.len() != ubeta_bytes.len() {
        return Err(ThresholdEcdsaError::CurveMismatch);
    }

    let point_len = public_key.len();

    // 8 byte recipient_index
    // 3 points each of point_len bytes
    // 8 byte length prefix for associated_data
    // associated_data
    let mut output = Vec::with_capacity(8 + 3 * point_len + 8 + associated_data.len());

    output.extend_from_slice(&recipient_index.to_be_bytes());

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
            associated_data,
            index as u64,
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
            associated_data,
            index as u64,
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
        associated_data,
        our_index as u64,
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
        associated_data,
        our_index as u64,
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
