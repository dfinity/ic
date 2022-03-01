use crate::*;
use ic_crypto_internal_hmac::{Hmac, Sha512};

#[derive(Debug, Clone)]
pub struct DerivationIndex(pub Vec<u8>);

impl DerivationIndex {
    /// Return the BIP32 "next" derivation path
    ///
    /// This is only used very rarely. In the case that a derivation index is a
    /// 4 byte big-endian encoding of an integer less than 2**31-1, the behavior
    /// matches that of standard BIP32.
    ///
    /// For the index 2**31-1, if the exceptional condition occurs, this will
    /// return a BIP32 "hardened" derivation index, which is non-sensical for BIP32.
    /// This is a corner case in the BIP32 spec and it seems that few implementations
    /// handle it correctly.
    pub fn next(&self) -> Self {
        let mut n = self.0.clone();

        n.reverse();

        let mut carry = 1u8;
        for w in &mut n {
            let (v, c) = w.overflowing_add(carry);
            *w = v;
            carry = if c { 1 } else { 0 };
        }

        if carry != 0 {
            n.push(carry);
        }

        n.reverse();

        Self(n)
    }
}

#[derive(Debug, Clone)]
pub struct DerivationPath {
    path: Vec<DerivationIndex>,
}

impl DerivationPath {
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

    /// BIP32 Public parent key -> public child key (aka CKDpub)
    ///
    /// See <https://en.bitcoin.it/wiki/BIP_0032#Child_key_derivation_.28CKD.29_functions>
    ///
    /// Extended to support larger inputs, which is needed for
    /// deriving the canister public key
    fn bip32_ckdpub(
        public_key: &EccPoint,
        chain_key: &[u8],
        index: &DerivationIndex,
    ) -> ThresholdEcdsaResult<(EccPoint, Vec<u8>, EccScalar)> {
        // BIP32 is only defined for secp256k1
        if public_key.curve_type() != EccCurveType::K256 {
            return Err(ThresholdEcdsaError::CurveMismatch);
        }

        let mut hmac = Hmac::<Sha512>::new(chain_key);

        hmac.write(&public_key.serialize());
        hmac.write(&index.0);

        let hmac_output = hmac.finish();

        let key_offset = EccScalar::from_bytes_wide(public_key.curve_type(), &hmac_output[..32])?;

        let new_chain_key = hmac_output[32..].to_vec();

        let new_key = public_key.add_points(&EccPoint::mul_by_g(&key_offset)?)?;

        // If iL >= order or new_key=inf, try again with the "next" index
        if key_offset.serialize() != hmac_output[..32] || new_key.is_infinity()? {
            Self::bip32_ckdpub(public_key, chain_key, &index.next())
        } else {
            Ok((new_key, new_chain_key, key_offset))
        }
    }

    pub fn derive_tweak(
        &self,
        master_public_key: &EccPoint,
    ) -> ThresholdEcdsaResult<(EccScalar, Vec<u8>)> {
        let curve_type = master_public_key.curve_type();

        if curve_type == EccCurveType::K256 {
            let mut derived_key = *master_public_key;
            let mut derived_chain_key = vec![0; 32];
            let mut derived_offset = EccScalar::zero(curve_type);

            for idx in &self.path {
                let (next_derived_key, next_chain_key, next_offset) =
                    Self::bip32_ckdpub(&derived_key, &derived_chain_key, idx)?;

                derived_key = next_derived_key;
                derived_chain_key = next_chain_key;
                derived_offset = derived_offset.add(&next_offset)?;
            }

            Ok((derived_offset, derived_chain_key))
        } else {
            // Key derivation is not currently defined for curves other than secp256k1
            Err(ThresholdEcdsaError::InvalidArguments(format!(
                "Currently key derivation not defined for {}",
                curve_type
            )))
        }
    }
}
