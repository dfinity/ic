use crate::*;
use ic_crypto_internal_hmac::{Hmac, Sha512};
use ic_types::PrincipalId;

#[derive(Debug, Clone)]
pub enum DerivationIndex {
    U32(u32),
    Generalized(Vec<u8>),
}

impl DerivationIndex {
    /// Return the BIP32 "next" derivation path
    ///
    /// This is only used very rarely. The +1 behavior for u32's matches
    /// standard BIP32. For the generalized case, the "next" value is not
    /// necessarily obvious, so instead we cause key derivation to fails.
    ///
    /// This does mean that with ~ 1/2**127 chance, a canister will not be
    /// able to derive a public key for itself.
    fn next(&self) -> ThresholdEcdsaResult<Self> {
        match self {
            Self::U32(i) => Ok(Self::U32(i + 1)),
            Self::Generalized(_) => Err(ThresholdEcdsaError::InvalidDerivationPath),
        }
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
            path.push(DerivationIndex::U32(*n));
        }
        Self::new_arbitrary(path)
    }

    /// Create a derivation path from a principal ID and a BIP32 path
    pub fn new_with_principal(principal: PrincipalId, bip32: &[u32]) -> Self {
        let mut path = Vec::with_capacity(1 + bip32.len());
        path.push(DerivationIndex::Generalized(principal.to_vec()));
        for n in bip32 {
            path.push(DerivationIndex::U32(*n));
        }
        Self::new_arbitrary(path)
    }

    /// Create a free-form derivation path
    pub fn new_arbitrary(path: Vec<DerivationIndex>) -> Self {
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

        match index {
            DerivationIndex::U32(u) => {
                if (u >> 31) != 0 {
                    // hard derivation not supported
                    return Err(ThresholdEcdsaError::InvalidDerivationPath);
                }
                hmac.write(&u.to_be_bytes());
            }
            DerivationIndex::Generalized(v) => {
                hmac.write(v);
            }
        }

        let hmac_output = hmac.finish();

        let key_offset = EccScalar::from_bytes_wide(public_key.curve_type(), &hmac_output[..32])?;

        let new_chain_key = hmac_output[32..].to_vec();

        let new_key = public_key.add_points(&EccPoint::mul_by_g(&key_offset)?)?;

        // If iL >= order or new_key=inf, try again with the "next" index
        if key_offset.serialize() != hmac_output[..32] || new_key.is_infinity()? {
            Self::bip32_ckdpub(public_key, chain_key, &index.next()?)
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
            Err(ThresholdEcdsaError::InvalidDerivationPath)
        }
    }
}
