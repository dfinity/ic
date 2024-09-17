use crate::*;
use ic_crypto_internal_hmac::{hkdf, Hmac, Sha512};

/// Derivation Index
///
/// In BIP32 and SLIP-0010, derivation indicies are 32 bit
/// integers. We support an extension of BIP32 which uses arbitrary
/// byte strings. If each of the index values is 4 bytes long
/// then the derivation is compatable with standard BIP32 / SLIP-0010
#[derive(Clone, Debug)]
pub struct DerivationIndex(pub Vec<u8>);

/// Derivation Path for BIP32 / SLIP-0010
///
/// A derivation path is simply a sequence of DerivationIndex
///
/// Implements SLIP-0010
/// <https://github.com/satoshilabs/slips/blob/master/slip-0010.md>
/// which is an extension of BIP32 to additional curves.
#[derive(Clone, Debug)]
pub struct DerivationPath {
    path: Vec<DerivationIndex>,
}

impl DerivationPath {
    /// The maximum length of a BIP32 derivation path
    ///
    /// The extended public key format uses a byte to represent the derivation
    /// level of a key, thus BIP32 derivations with more than 255 path elements
    /// are not interoperable with other software.
    ///
    /// See https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format
    /// for details
    pub const MAXIMUM_DERIVATION_PATH_LENGTH: usize = 255;

    /// Create a standard BIP32 derivation path
    pub fn new_bip32(bip32: &[u32]) -> Self {
        let mut path = Vec::with_capacity(bip32.len());
        for n in bip32 {
            path.push(DerivationIndex(n.to_be_bytes().to_vec()));
        }
        Self::new(path)
    }

    /// Create a free-form derivation path
    pub fn new(path: Vec<DerivationIndex>) -> Self {
        Self { path }
    }

    /// Return the length of this path
    pub fn len(&self) -> usize {
        self.path.len()
    }

    /// Return if this path is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn path(&self) -> &[DerivationIndex] {
        &self.path
    }

    /// BIP32 CKD used to implement CKDpub and CKDpriv
    ///
    /// See <https://en.bitcoin.it/wiki/BIP_0032#Child_key_derivation_.28CKD.29_functions>
    /// and <https://github.com/satoshilabs/slips/blob/master/slip-0010.md>
    ///
    /// Extended to support larger inputs, which is needed for
    /// deriving the canister public key.
    ///
    /// This handles both public and private derivation, depending on the value of key_input
    ///
    /// We handle the exceptional case that the HMAC output is larger than the
    /// group order following SLIP-0010 rather than BIP32. This allows us to
    /// easily support other curves beyond secp256k1.
    fn bip32_ckd(
        key_input: &[u8],
        curve_type: EccCurveType,
        chain_key: &[u8],
        index: &DerivationIndex,
    ) -> CanisterThresholdResult<(Vec<u8>, EccScalar)> {
        let mut hmac = Hmac::<Sha512>::new(chain_key);

        hmac.write(key_input);
        hmac.write(&index.0);

        let hmac_output = hmac.finish();

        let key_offset = EccScalar::from_bytes_wide(curve_type, &hmac_output[..32])?;

        let new_chain_key = hmac_output[32..64].to_vec();

        // If iL >= order, try again with the "next" index
        if key_offset.serialize() != hmac_output[..32] {
            let mut next_input = [0u8; 33];
            next_input[0] = 0x01;
            next_input[1..].copy_from_slice(&new_chain_key);
            Self::bip32_ckd(&next_input, curve_type, chain_key, index)
        } else {
            Ok((new_chain_key, key_offset))
        }
    }

    /// BIP32 CKDpub
    ///
    /// See <https://en.bitcoin.it/wiki/BIP_0032#Child_key_derivation_.28CKD.29_functions>
    ///
    /// In addition to the derived point and chain code described in BIP32, this function
    /// also returns the scalar which is the discrete logarithm of the difference between
    /// the input and output points.
    ///
    /// Extended to support larger inputs, which is needed for
    /// deriving the canister public key
    ///
    /// This follows SLIP-0010 to accomodate other curves. For K256, SLIP-0010
    /// and BIP32 are identical (with overwhelming probability; they differ in
    /// an exceptional case that occurs ~1 in 2**128 key derivations)
    fn bip32_ckdpub(
        public_key: &EccPoint,
        chain_key: &[u8],
        index: &DerivationIndex,
    ) -> CanisterThresholdResult<(EccPoint, Vec<u8>, EccScalar)> {
        let mut ckd_input = public_key.serialize();

        loop {
            let (new_chain_key, key_offset) =
                Self::bip32_ckd(&ckd_input, public_key.curve_type(), chain_key, index)?;

            let new_key = public_key.add_points(&EccPoint::mul_by_g(&key_offset))?;

            // If the new key is not infinity, we're done: return the new key
            if !new_key.is_infinity()? {
                return Ok((new_key, new_chain_key, key_offset));
            }

            // Otherwise set up the next input as defined by SLIP-0010
            ckd_input[0] = 0x01;
            ckd_input[1..].copy_from_slice(&new_chain_key);
        }
    }

    fn eddsa_ckd(
        public_key: &EccPoint,
        chain_key: &[u8],
        index: &DerivationIndex,
    ) -> CanisterThresholdResult<(EccPoint, Vec<u8>, EccScalar)> {
        if public_key.curve_type() != EccCurveType::Ed25519 {
            return Err(CanisterThresholdError::CurveMismatch);
        }

        let mut ikm = public_key.serialize();
        ikm.extend_from_slice(&index.0);

        /*
        We derive the next additive offset and chain code using HKDF,
        using the parent chain key as the salt, the public key and
        index as the IKM (input key material) and the constant string
        "Ed25519" as the info/label field.
         */
        let info = "Ed25519".as_bytes();

        // Only way HKDF can fail is if output is too long, which can't
        // happen here.
        let okm = hkdf::<Sha512>(96, &ikm, chain_key, info).expect("HKDF failed unexpectedly");

        let key_offset = EccScalar::from_bytes_wide(EccCurveType::Ed25519, &okm[0..64])?;
        let new_key = public_key.add_points(&EccPoint::mul_by_g(&key_offset))?;
        let new_chain_key = okm[64..96].to_vec();

        Ok((new_key, new_chain_key, key_offset))
    }

    pub fn derive_tweak(
        &self,
        master_public_key: &EccPoint,
    ) -> CanisterThresholdResult<(EccScalar, Vec<u8>)> {
        let zeros = [0u8; 32];
        self.derive_tweak_with_chain_code(master_public_key, &zeros)
    }

    pub fn derive_tweak_with_chain_code(
        &self,
        master_public_key: &EccPoint,
        chain_code: &[u8],
    ) -> CanisterThresholdResult<(EccScalar, Vec<u8>)> {
        if chain_code.len() != 32 {
            return Err(CanisterThresholdError::InvalidArguments(format!(
                "Invalid chain code length {}",
                chain_code.len()
            )));
        }

        if self.len() > Self::MAXIMUM_DERIVATION_PATH_LENGTH {
            return Err(CanisterThresholdError::InvalidArguments(format!(
                "Derivation path len {} larger than allowed maximum of {}",
                self.len(),
                Self::MAXIMUM_DERIVATION_PATH_LENGTH
            )));
        }

        let curve_type = master_public_key.curve_type();

        let mut derived_key = master_public_key.clone();
        let mut derived_chain_key = chain_code.to_vec();
        let mut derived_offset = EccScalar::zero(curve_type);

        for idx in self.path() {
            let (next_derived_key, next_chain_key, next_offset) = match curve_type {
                EccCurveType::Ed25519 => Self::eddsa_ckd(&derived_key, &derived_chain_key, idx)?,
                _ => Self::bip32_ckdpub(&derived_key, &derived_chain_key, idx)?,
            };

            derived_key = next_derived_key;
            derived_chain_key = next_chain_key;
            derived_offset = derived_offset.add(&next_offset)?;
        }

        Ok((derived_offset, derived_chain_key))
    }
}
