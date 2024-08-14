use ic_crypto_internal_threshold_sig_ecdsa::{
    CanisterThresholdError, DerivationPath as DerivationPathImpl, EccCurveType, EccPoint, EccScalar,
};

#[derive(Debug, Clone)]
pub enum ExtendedBip32DerivationError {
    InvalidChainCodeLength,
    InvalidDerivationPath,
    InvalidPublicKeyEncoding,
    InternalError(CanisterThresholdError),
}

const CURVE_TYPE: EccCurveType = EccCurveType::K256;

pub type ExtendedBip32DerivationResult<T> = std::result::Result<T, ExtendedBip32DerivationError>;

pub use ic_crypto_internal_threshold_sig_ecdsa::DerivationIndex;

impl From<CanisterThresholdError> for ExtendedBip32DerivationError {
    fn from(e: CanisterThresholdError) -> Self {
        match e {
            CanisterThresholdError::InvalidPoint => Self::InvalidPublicKeyEncoding,
            e => Self::InternalError(e),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExtendedBip32DerivationOutput {
    pub derived_public_key: Vec<u8>,
    pub derived_chain_code: Vec<u8>,
}

impl ExtendedBip32DerivationOutput {
    fn new(derived_public_key: EccPoint, chain_code: Vec<u8>) -> Self {
        Self {
            derived_public_key: derived_public_key.serialize(),
            derived_chain_code: chain_code,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExtendedPrivateBip32DerivationOutput {
    pub derived_private_key: Vec<u8>,
    pub derived_chain_code: Vec<u8>,
}

impl ExtendedPrivateBip32DerivationOutput {
    fn new(derived_private_key: EccScalar, chain_code: Vec<u8>) -> Self {
        Self {
            derived_private_key: derived_private_key.serialize(),
            derived_chain_code: chain_code,
        }
    }
}

// We wrap DerivationPath in order to add an additional method
#[derive(Debug, Clone)]
pub struct DerivationPath {
    path: DerivationPathImpl,
}

impl DerivationPath {
    /// Create a standard BIP32 derivation path
    pub fn new_bip32(bip32: &[u32]) -> Self {
        Self {
            path: DerivationPathImpl::new_bip32(bip32),
        }
    }

    /// Create a free-form derivation path
    pub fn new(path: Vec<DerivationIndex>) -> Self {
        Self {
            path: DerivationPathImpl::new(path),
        }
    }

    /// Deprecated equivalent for public_key_derivation
    pub fn key_derivation(
        &self,
        public_key: &[u8],
        chain_code: &[u8],
    ) -> ExtendedBip32DerivationResult<ExtendedBip32DerivationOutput> {
        self.public_key_derivation(public_key, chain_code)
    }

    /// Perform extended BIP32 key derivation on the specified path
    ///
    /// # Arguments
    ///  * `public_key` is the SEC1 encoding of a secp256k1 point in
    ///    compressed format. This is a 33 byte format whose first byte
    ///    must be either 02 or 03.
    ///  * `chain_code` is the BIP32 chain code, which must be a 32 byte value.
    ///
    /// Returns a result struct containing the SEC1 compressed secp256k1 of
    /// the derived child public key, and the new chain code.
    pub fn public_key_derivation(
        &self,
        public_key: &[u8],
        chain_code: &[u8],
    ) -> ExtendedBip32DerivationResult<ExtendedBip32DerivationOutput> {
        if chain_code.len() != 32 {
            return Err(ExtendedBip32DerivationError::InvalidChainCodeLength);
        }

        if self.path.len() > DerivationPathImpl::MAXIMUM_DERIVATION_PATH_LENGTH {
            return Err(ExtendedBip32DerivationError::InvalidDerivationPath);
        }

        let public_key = EccPoint::deserialize(CURVE_TYPE, public_key)
            .map_err(|_| ExtendedBip32DerivationError::InvalidPublicKeyEncoding)?;

        let (offset, chain_code) = self
            .path
            .derive_tweak_with_chain_code(&public_key, chain_code)?;

        let new_key = public_key.add_points(&EccPoint::mul_by_g(&offset))?;

        Ok(ExtendedBip32DerivationOutput::new(new_key, chain_code))
    }

    /// Perform extended BIP32 key derivation on the specified path
    ///
    /// # Arguments
    ///  * `private_key` is the SEC1 encoding of a secp256k1 scalar.
    ///    This should be exactly 32 bytes long.
    ///  * `chain_code` is the BIP32 chain code, which must be a 32 byte value.
    ///
    /// Returns a result struct containing the derived child private
    /// key, and the new chain code.
    pub fn private_key_derivation(
        &self,
        private_key: &[u8],
        chain_code: &[u8],
    ) -> ExtendedBip32DerivationResult<ExtendedPrivateBip32DerivationOutput> {
        if chain_code.len() != 32 {
            return Err(ExtendedBip32DerivationError::InvalidChainCodeLength);
        }

        if self.path.len() > DerivationPathImpl::MAXIMUM_DERIVATION_PATH_LENGTH {
            return Err(ExtendedBip32DerivationError::InvalidDerivationPath);
        }

        let private_key = EccScalar::deserialize(CURVE_TYPE, private_key).unwrap();

        let public_key = EccPoint::mul_by_g(&private_key);

        let (offset, derived_chain_key) = self
            .path
            .derive_tweak_with_chain_code(&public_key, chain_code)?;

        let derived_key = private_key.add(&offset)?;

        Ok(ExtendedPrivateBip32DerivationOutput::new(
            derived_key,
            derived_chain_key,
        ))
    }
}
