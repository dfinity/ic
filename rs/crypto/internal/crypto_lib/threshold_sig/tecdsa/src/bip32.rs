use crate::*;
use ic_crypto_sha::Sha256;
use ic_types::PrincipalId;

#[derive(Debug, Clone)]
pub enum DerivationIndex {
    U32(u32),
    Generalized(Vec<u8>),
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

    pub fn derive_tweak(&self, curve_type: EccCurveType) -> ThresholdEcdsaResult<EccScalar> {
        // this is a stopgap until proper BIP32 support:

        let mut sha256 = Sha256::new();

        for elem in &self.path {
            match elem {
                DerivationIndex::U32(u) => {
                    if (u >> 31) != 0 {
                        // hard derivation not supported
                        return Err(ThresholdEcdsaError::InvalidDerivationPath);
                    }
                    sha256.write(&u.to_be_bytes());
                }
                DerivationIndex::Generalized(v) => {
                    sha256.write(v);
                }
            }
        }

        let s = EccScalar::hash_to_scalar(
            curve_type,
            &sha256.finish(),
            "ic-crypto-tecdsa-path-derivation".as_bytes(),
        )?;

        Ok(s)
    }
}
