use crate::group::*;
use crate::seed::Seed;
use crate::*;
use rand_core::{CryptoRng, RngCore};

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

pub struct MEGaPrivateKey {
    secret: EccScalar,
}

impl MEGaPrivateKey {
    pub fn curve(&self) -> EccCurve {
        self.secret.curve()
    }

    pub fn public_key(&self) -> ThresholdSignatureResult<MEGaPublicKey> {
        let curve = self.curve();
        Ok(MEGaPublicKey::new(
            curve.generator_g().scalar_mul(&self.secret)?,
        ))
    }

    pub fn generate<R: RngCore + CryptoRng>(
        group: EccCurve,
        rng: &mut R,
    ) -> ThresholdSignatureResult<Self> {
        let secret = group.random_scalar(rng)?;
        Ok(Self { secret })
    }

    pub fn deserialize(group: EccCurve, value: &[u8]) -> ThresholdSignatureResult<Self> {
        let secret = group.deserialize_scalar(value)?;
        Ok(Self { secret })
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.secret.serialize()
    }
}

pub struct MEGaCiphertext {
    pub v: EccPoint,
    pub ctexts: Vec<EccScalar>,
}

impl MEGaCiphertext {
    pub fn new(v: EccPoint, ctexts: Vec<EccScalar>) -> Self {
        Self { v, ctexts }
    }
}

pub fn mega_encryption_single(
    seed: Seed,
    plaintexts: &[EccScalar],
    recipients: &[(Vec<u8>, MEGaPublicKey)],
    associated_data: &[u8],
) -> ThresholdSignatureResult<MEGaCiphertext> {
    if plaintexts.len() != recipients.len() {
        return Err(ThresholdSignatureError::InvalidArguments(
            "Must be as many plaintexts as recipients".to_string(),
        ));
    }

    if plaintexts.is_empty() {
        return Err(ThresholdSignatureError::InvalidArguments(
            "Must have at least one plaintext".to_string(),
        ));
    }

    let curve = plaintexts[0].curve();

    for pt in plaintexts {
        if pt.curve() != curve {
            return Err(ThresholdSignatureError::CurveMismatch);
        }
    }

    let domain_sep = "MEGa encryption single";

    let mut rng = seed.derive(domain_sep).into_rng();

    let beta = curve.random_scalar(&mut rng)?;

    // g*beta = v
    // g*sk = u
    // ubeta = u*beta = g*sk*beta = v*sk
    let v = curve.generator_g().scalar_mul(&beta)?;

    let mut ctexts = Vec::with_capacity(recipients.len());

    for ((recipient, pubkey), ptext) in recipients.iter().zip(plaintexts) {
        if pubkey.curve() != curve {
            return Err(ThresholdSignatureError::CurveMismatch);
        }

        let ubeta = pubkey.point.scalar_mul(&beta)?;

        let mut hash_inputs = vec![];
        hash_inputs.extend_from_slice(domain_sep.as_bytes()); // domain seperator
        hash_inputs.extend_from_slice(associated_data);
        hash_inputs.extend_from_slice(recipient);
        hash_inputs.extend_from_slice(&pubkey.serialize());
        hash_inputs.extend_from_slice(&v.serialize());
        hash_inputs.extend_from_slice(&ubeta.serialize());

        let hm = curve.hash_to_scalar(&hash_inputs)?;
        let ctext = hm.add(ptext)?;

        ctexts.push(ctext);
    }

    Ok(MEGaCiphertext::new(v, ctexts))
}

pub fn mega_decryption_single(
    ctext: &MEGaCiphertext,
    our_index: usize,
    recipient_id: &[u8],
    our_private_key: &MEGaPrivateKey,
    associated_data: &[u8],
) -> ThresholdSignatureResult<EccScalar> {
    let domain_sep = "MEGa encryption single";

    if ctext.ctexts.len() <= our_index {
        return Err(ThresholdSignatureError::InvalidArguments(
            "Invalid index".to_string(),
        ));
    }

    let our_pubkey = our_private_key.public_key()?;

    let curve = our_private_key.curve();

    let ubeta = ctext.v.scalar_mul(&our_private_key.secret)?;

    let mut hash_inputs = vec![];
    hash_inputs.extend_from_slice(domain_sep.as_bytes()); // domain seperator
    hash_inputs.extend_from_slice(associated_data);
    hash_inputs.extend_from_slice(recipient_id);
    hash_inputs.extend_from_slice(&our_pubkey.serialize());
    hash_inputs.extend_from_slice(&ctext.v.serialize());
    hash_inputs.extend_from_slice(&ubeta.serialize());

    let hm = curve.hash_to_scalar(&hash_inputs)?;
    ctext.ctexts[our_index].sub(&hm)
}
