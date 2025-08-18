#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]
#![warn(future_incompatible)]
#![forbid(missing_docs)]

//! A package created for the Internet Computer Protocol for handling offline derivation of threshold public keys

pub use ic_management_canister_types::{
    CanisterId, EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgs, EcdsaPublicKeyResult, SchnorrAlgorithm,
    SchnorrKeyId, SchnorrPublicKeyArgs, SchnorrPublicKeyResult,
};

/// Error that can occur during public key derivation
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// The specified master public key is not known
    UnknownKeyIdentifier,
    /// The algorithm is not supported (possibly due to an unset feature)
    AlgorithmNotSupported,
    /// Currently the canister must be specified
    CanisterIdMissing,
}

/// Derive an ECDSA public key
pub fn derive_ecdsa_key(args: EcdsaPublicKeyArgs) -> Result<EcdsaPublicKeyResult, Error> {
    #[cfg(not(feature = "secp256k1"))]
    {
        return Err(Error::AlgorithmNotSupported);
    }

    #[cfg(feature = "secp256k1")]
    {
        use ic_secp256k1::{MasterPublicKeyId, PublicKey};

        if args.key_id.curve != EcdsaCurve::Secp256k1 {
            return Err(Error::AlgorithmNotSupported);
        }

        let canister_id = args.canister_id.ok_or(Error::CanisterIdMissing)?;

        let key_id = match (args.key_id.curve, args.key_id.name.as_ref()) {
            (EcdsaCurve::Secp256k1, "key_1") => MasterPublicKeyId::EcdsaKey1,
            (EcdsaCurve::Secp256k1, "test_key_1") => MasterPublicKeyId::EcdsaTestKey1,
            (_, _) => return Err(Error::UnknownKeyIdentifier),
        };

        let dk = PublicKey::derive_mainnet_key(key_id, &canister_id, &args.derivation_path);

        Ok(EcdsaPublicKeyResult {
            public_key: dk.0.serialize_sec1(true),
            chain_code: dk.1.to_vec(),
        })
    }
}

/// Derive a Schnorr public key
pub fn derive_schnorr_key(args: SchnorrPublicKeyArgs) -> Result<SchnorrPublicKeyResult, Error> {
    let canister_id = args.canister_id.ok_or(Error::CanisterIdMissing)?;

    #[cfg(feature = "secp256k1")]
    if args.key_id.algorithm == SchnorrAlgorithm::Bip340secp256k1 {
        use ic_secp256k1::{MasterPublicKeyId, PublicKey};

        let key_id = match args.key_id.name.as_ref() {
            "key_1" => MasterPublicKeyId::SchnorrKey1,
            "test_key_1" => MasterPublicKeyId::SchnorrTestKey1,
            _ => return Err(Error::UnknownKeyIdentifier),
        };

        let dk = PublicKey::derive_mainnet_key(key_id, &canister_id, &args.derivation_path);

        return Ok(SchnorrPublicKeyResult {
            public_key: dk.0.serialize_sec1(true),
            chain_code: dk.1.to_vec(),
        });
    }

    #[cfg(feature = "ed25519")]
    if args.key_id.algorithm == SchnorrAlgorithm::Ed25519 {
        use ic_ed25519::{MasterPublicKeyId, PublicKey};

        let key_id = match args.key_id.name.as_ref() {
            "key_1" => MasterPublicKeyId::Key1,
            "test_key_1" => MasterPublicKeyId::TestKey1,
            _ => return Err(Error::UnknownKeyIdentifier),
        };

        let dk = PublicKey::derive_mainnet_key(key_id, &canister_id, &args.derivation_path);

        return Ok(SchnorrPublicKeyResult {
            public_key: dk.0.serialize_raw().to_vec(),
            chain_code: dk.1.to_vec(),
        });
    }

    Err(Error::AlgorithmNotSupported)
}
