#![forbid(unsafe_code)]
#![forbid(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::nursery)]
#![warn(future_incompatible)]
#![warn(rust_2018_idioms)]
#![warn(rustdoc::broken_intra_doc_links)]
#![warn(rustdoc::missing_crate_level_docs)]
#![deny(unused_must_use)]
#![deny(unused_results)]

//! A crate for performing derivation of threshold public keys
//!
//! The Internet Computer platform offers a threshold signing interface
//! supporting ECDSA, Ed25519, BIP340-Schnorr, and BLS. The signing interface
//! allows signing under many different keys which are derived from a master key
//! using a derivation algorithm.
//!
//! The management canister interface allows for *online* derivation of public
//! keys: a canister running on the IC can invoke the call to determine what
//! public key will be used for any particular context argument.
//!
//! This crate mirrors that functionality in an offline way: it can be called either
//! by canisters that do not wish to call the management canister interface, or
//! by applications not running on that IC at all.
//!
//! As an extension of the management canister interface, this crate also allows
//! deriving keys relative to the hardcoded test master keys used by PocketIC.

#[cfg(not(any(feature = "secp256k1", feature = "ed25519", feature = "vetkeys")))]
compile_error!("At least one of the features (secp256k1, ed25519, vetkeys) must be enabled");

pub use ic_management_canister_types::{
    CanisterId, EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgs, EcdsaPublicKeyResult, SchnorrAlgorithm,
    SchnorrKeyId, SchnorrPublicKeyArgs, SchnorrPublicKeyResult, VetKDCurve, VetKDKeyId,
    VetKDPublicKeyArgs, VetKDPublicKeyResult,
};

/// Error that can occur during public key derivation
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// The specified master public key is not known
    UnknownKeyIdentifier,
    /// The algorithm is not supported (possibly due to an unset feature)
    AlgorithmNotSupported,
    /// The canister must be specified in the argument structs since the library
    /// has no other way of determining the correct value, and the canister id
    /// is a necessary component of the key derivation.
    CanisterIdMissing,
    /// The derivation path is not valid for this algorithm
    ///
    /// This mostly affects VetKD derivation, which only supports a single
    /// context string rather than a sequence of them.
    InvalidPath,
}

enum MasterPublicKeyInner {
    #[cfg(feature = "secp256k1")]
    EcdsaSecp256k1(ic_secp256k1::PublicKey),
    #[cfg(feature = "secp256k1")]
    Bip340Secp256k1(ic_secp256k1::PublicKey),
    #[cfg(feature = "ed25519")]
    Ed25519(ic_ed25519::PublicKey),
    #[cfg(feature = "vetkeys")]
    VetKD(ic_vetkeys::MasterPublicKey),
}

/// The master public key of a threshold signature system
pub struct MasterPublicKey {
    inner: MasterPublicKeyInner,
}

impl MasterPublicKey {
    /// Derive the master key for a canister
    pub fn derive_canister_key(&self, canister_id: &CanisterId) -> CanisterMasterKey {
        let inner = match &self.inner {
            #[cfg(feature = "secp256k1")]
            MasterPublicKeyInner::EcdsaSecp256k1(mk) => {
                let path = ic_secp256k1::DerivationPath::new(vec![ic_secp256k1::DerivationIndex(
                    canister_id.as_slice().to_vec(),
                )]);
                DerivedPublicKeyInner::EcdsaSecp256k1(mk.derive_subkey(&path))
            }
            #[cfg(feature = "secp256k1")]
            MasterPublicKeyInner::Bip340Secp256k1(mk) => {
                let path = ic_secp256k1::DerivationPath::new(vec![ic_secp256k1::DerivationIndex(
                    canister_id.as_slice().to_vec(),
                )]);
                DerivedPublicKeyInner::Bip340Secp256k1(mk.derive_subkey(&path))
            }
            #[cfg(feature = "ed25519")]
            MasterPublicKeyInner::Ed25519(mk) => {
                let path = ic_ed25519::DerivationPath::new(vec![ic_ed25519::DerivationIndex(
                    canister_id.as_slice().to_vec(),
                )]);
                DerivedPublicKeyInner::Ed25519(mk.derive_subkey(&path))
            }
            #[cfg(feature = "vetkeys")]
            MasterPublicKeyInner::VetKD(mk) => {
                DerivedPublicKeyInner::VetKD(mk.derive_canister_key(canister_id.as_slice()))
            }
        };
        CanisterMasterKey { inner }
    }
}

impl TryFrom<&EcdsaKeyId> for MasterPublicKey {
    type Error = Error;

    fn try_from(key_id: &EcdsaKeyId) -> Result<Self, Self::Error> {
        if key_id.curve != EcdsaCurve::Secp256k1 {
            return Err(Error::AlgorithmNotSupported);
        }

        #[cfg(feature = "secp256k1")]
        {
            let mk = match (key_id.curve, key_id.name.as_ref()) {
                (EcdsaCurve::Secp256k1, "key_1") => {
                    ic_secp256k1::PublicKey::mainnet_key(ic_secp256k1::MasterPublicKeyId::EcdsaKey1)
                }
                (EcdsaCurve::Secp256k1, "test_key_1") => ic_secp256k1::PublicKey::mainnet_key(
                    ic_secp256k1::MasterPublicKeyId::EcdsaTestKey1,
                ),
                (EcdsaCurve::Secp256k1, "pocketic_key_1") => ic_secp256k1::PublicKey::pocketic_key(
                    ic_secp256k1::PocketIcMasterPublicKeyId::EcdsaKey1,
                ),
                (EcdsaCurve::Secp256k1, "pocketic_test_key_1") => {
                    ic_secp256k1::PublicKey::pocketic_key(
                        ic_secp256k1::PocketIcMasterPublicKeyId::EcdsaTestKey1,
                    )
                }
                (EcdsaCurve::Secp256k1, "dfx_test_key") => ic_secp256k1::PublicKey::pocketic_key(
                    ic_secp256k1::PocketIcMasterPublicKeyId::EcdsaDfxTestKey,
                ),
                (_, _) => return Err(Error::UnknownKeyIdentifier),
            };

            let inner = MasterPublicKeyInner::EcdsaSecp256k1(mk);
            Ok(Self { inner })
        }

        #[cfg(not(feature = "secp256k1"))]
        {
            Err(Error::AlgorithmNotSupported)
        }
    }
}

impl TryFrom<&SchnorrKeyId> for MasterPublicKey {
    type Error = Error;

    fn try_from(key_id: &SchnorrKeyId) -> Result<Self, Self::Error> {
        #[cfg(feature = "secp256k1")]
        {
            if key_id.algorithm == SchnorrAlgorithm::Bip340secp256k1 {
                let mk = match key_id.name.as_ref() {
                    "key_1" => ic_secp256k1::PublicKey::mainnet_key(
                        ic_secp256k1::MasterPublicKeyId::SchnorrKey1,
                    ),
                    "test_key_1" => ic_secp256k1::PublicKey::mainnet_key(
                        ic_secp256k1::MasterPublicKeyId::SchnorrTestKey1,
                    ),
                    "pocketic_key_1" => ic_secp256k1::PublicKey::pocketic_key(
                        ic_secp256k1::PocketIcMasterPublicKeyId::SchnorrKey1,
                    ),
                    "pocketic_test_key_1" => ic_secp256k1::PublicKey::pocketic_key(
                        ic_secp256k1::PocketIcMasterPublicKeyId::SchnorrTestKey1,
                    ),
                    "dfx_test_key" => ic_secp256k1::PublicKey::pocketic_key(
                        ic_secp256k1::PocketIcMasterPublicKeyId::SchnorrDfxTestKey,
                    ),
                    _ => return Err(Error::UnknownKeyIdentifier),
                };

                let inner = MasterPublicKeyInner::Bip340Secp256k1(mk);
                return Ok(Self { inner });
            }
        }

        #[cfg(feature = "ed25519")]
        {
            if key_id.algorithm == SchnorrAlgorithm::Ed25519 {
                let mk = match key_id.name.as_ref() {
                    "key_1" => {
                        ic_ed25519::PublicKey::mainnet_key(ic_ed25519::MasterPublicKeyId::Key1)
                    }
                    "test_key_1" => {
                        ic_ed25519::PublicKey::mainnet_key(ic_ed25519::MasterPublicKeyId::TestKey1)
                    }
                    "pocketic_key_1" => ic_ed25519::PublicKey::pocketic_key(
                        ic_ed25519::PocketIcMasterPublicKeyId::Key1,
                    ),
                    "pocketic_test_key_1" => ic_ed25519::PublicKey::pocketic_key(
                        ic_ed25519::PocketIcMasterPublicKeyId::TestKey1,
                    ),
                    "dfx_test_key" => ic_ed25519::PublicKey::pocketic_key(
                        ic_ed25519::PocketIcMasterPublicKeyId::DfxTestKey,
                    ),
                    _ => return Err(Error::UnknownKeyIdentifier),
                };

                let inner = MasterPublicKeyInner::Ed25519(mk);
                return Ok(Self { inner });
            }
        }

        Err(Error::AlgorithmNotSupported)
    }
}

impl TryFrom<&VetKDKeyId> for MasterPublicKey {
    type Error = Error;

    fn try_from(key_id: &VetKDKeyId) -> Result<Self, Self::Error> {
        #[cfg(feature = "vetkeys")]
        {
            if let Some(mk) = ic_vetkeys::MasterPublicKey::for_mainnet_key(key_id) {
                let inner = MasterPublicKeyInner::VetKD(mk);
                return Ok(Self { inner });
            }
        }

        Err(Error::AlgorithmNotSupported)
    }
}

enum DerivedPublicKeyInner {
    #[cfg(feature = "secp256k1")]
    EcdsaSecp256k1((ic_secp256k1::PublicKey, [u8; 32])),
    #[cfg(feature = "secp256k1")]
    Bip340Secp256k1((ic_secp256k1::PublicKey, [u8; 32])),
    #[cfg(feature = "ed25519")]
    Ed25519((ic_ed25519::PublicKey, [u8; 32])),
    #[cfg(feature = "vetkeys")]
    VetKD(ic_vetkeys::DerivedPublicKey),
}

/// The canister's master public key of a threshold signature system
///
/// Each canister gets its own canister master key, which is derived from
/// the system master key.
pub struct CanisterMasterKey {
    inner: DerivedPublicKeyInner,
}

impl CanisterMasterKey {
    /// Derive the public key from a canister key and a single contextual input
    ///
    /// VetKeys requires exactly one contextual input be supplied. In addition,
    /// if that contextual input is the empty bytestring then the "derived key"
    /// is identical to the canister master public key. This matches the
    /// behavior of the management canister interface.
    ///
    /// For other keys, which support a path of inputs, this is equivalent to deriving
    /// using a path of length 1
    pub fn derive_key_with_context(&self, context: &[u8]) -> DerivedPublicKey {
        let inner = match &self.inner {
            #[cfg(feature = "secp256k1")]
            DerivedPublicKeyInner::EcdsaSecp256k1(ck) => {
                let path = ic_secp256k1::DerivationPath::new(vec![ic_secp256k1::DerivationIndex(
                    context.to_vec(),
                )]);
                DerivedPublicKeyInner::EcdsaSecp256k1(
                    ck.0.derive_subkey_with_chain_code(&path, &ck.1),
                )
            }
            #[cfg(feature = "secp256k1")]
            DerivedPublicKeyInner::Bip340Secp256k1(ck) => {
                let path = ic_secp256k1::DerivationPath::new(vec![ic_secp256k1::DerivationIndex(
                    context.to_vec(),
                )]);
                DerivedPublicKeyInner::Bip340Secp256k1(
                    ck.0.derive_subkey_with_chain_code(&path, &ck.1),
                )
            }
            #[cfg(feature = "ed25519")]
            DerivedPublicKeyInner::Ed25519(ck) => {
                let path = ic_ed25519::DerivationPath::new(vec![ic_ed25519::DerivationIndex(
                    context.to_vec(),
                )]);
                DerivedPublicKeyInner::Ed25519(ck.0.derive_subkey_with_chain_code(&path, &ck.1))
            }
            #[cfg(feature = "vetkeys")]
            DerivedPublicKeyInner::VetKD(ck) => {
                DerivedPublicKeyInner::VetKD(ck.derive_sub_key(context))
            }
        };
        DerivedPublicKey { inner }
    }

    /// Derive a public key using a path of contextual inputs
    ///
    /// Note that VetKD does not support derivation paths, but only a single context string,
    /// so VetKD is not supported by this function.
    pub fn derive_key(&self, path: &[Vec<u8>]) -> Result<DerivedPublicKey, Error> {
        let inner = match &self.inner {
            #[cfg(feature = "secp256k1")]
            DerivedPublicKeyInner::EcdsaSecp256k1(ck) => {
                let path = ic_secp256k1::DerivationPath::new(
                    path.iter()
                        .cloned()
                        .map(ic_secp256k1::DerivationIndex)
                        .collect(),
                );
                DerivedPublicKeyInner::EcdsaSecp256k1(
                    ck.0.derive_subkey_with_chain_code(&path, &ck.1),
                )
            }
            #[cfg(feature = "secp256k1")]
            DerivedPublicKeyInner::Bip340Secp256k1(ck) => {
                let path = ic_secp256k1::DerivationPath::new(
                    path.iter()
                        .cloned()
                        .map(ic_secp256k1::DerivationIndex)
                        .collect(),
                );
                DerivedPublicKeyInner::Bip340Secp256k1(
                    ck.0.derive_subkey_with_chain_code(&path, &ck.1),
                )
            }
            #[cfg(feature = "ed25519")]
            DerivedPublicKeyInner::Ed25519(ck) => {
                let path = ic_ed25519::DerivationPath::new(
                    path.iter()
                        .cloned()
                        .map(ic_ed25519::DerivationIndex)
                        .collect(),
                );
                DerivedPublicKeyInner::Ed25519(ck.0.derive_subkey_with_chain_code(&path, &ck.1))
            }
            #[cfg(feature = "vetkeys")]
            DerivedPublicKeyInner::VetKD(_ck) => {
                // VetKD has a somewhat different design for derivation than used by
                // the other threshold schemes - it supports only a single input rather
                // than a path. To avoid risk of confusing behavior, just reject
                return Err(Error::AlgorithmNotSupported);
            }
        };
        Ok(DerivedPublicKey { inner })
    }

    /// Return the serialized encoding of the canister master public key
    pub fn serialize(&self) -> Vec<u8> {
        match &self.inner {
            #[cfg(feature = "secp256k1")]
            DerivedPublicKeyInner::EcdsaSecp256k1(ck) => ck.0.serialize_sec1(true),
            #[cfg(feature = "secp256k1")]
            DerivedPublicKeyInner::Bip340Secp256k1(ck) => ck.0.serialize_sec1(true),
            #[cfg(feature = "ed25519")]
            DerivedPublicKeyInner::Ed25519(ck) => ck.0.serialize_raw().to_vec(),
            #[cfg(feature = "vetkeys")]
            DerivedPublicKeyInner::VetKD(ck) => ck.serialize(),
        }
    }

    /// Return the chain code used for further derivation, if relevant
    ///
    /// Returns None if not applicable for this algorithm
    pub fn chain_code(&self) -> Option<Vec<u8>> {
        match &self.inner {
            #[cfg(feature = "secp256k1")]
            DerivedPublicKeyInner::EcdsaSecp256k1(ck) => Some(ck.1.to_vec()),
            #[cfg(feature = "secp256k1")]
            DerivedPublicKeyInner::Bip340Secp256k1(ck) => Some(ck.1.to_vec()),
            #[cfg(feature = "ed25519")]
            DerivedPublicKeyInner::Ed25519(ck) => Some(ck.1.to_vec()),
            #[cfg(feature = "vetkeys")]
            DerivedPublicKeyInner::VetKD(_ck) => None,
        }
    }
}

/// A public key ultimately derived from a master key
pub struct DerivedPublicKey {
    inner: DerivedPublicKeyInner,
}

impl DerivedPublicKey {
    /// Return the serialized encoding of the derived public key
    pub fn serialize(&self) -> Vec<u8> {
        match &self.inner {
            #[cfg(feature = "secp256k1")]
            DerivedPublicKeyInner::EcdsaSecp256k1(ck) => ck.0.serialize_sec1(true),
            #[cfg(feature = "secp256k1")]
            DerivedPublicKeyInner::Bip340Secp256k1(ck) => ck.0.serialize_sec1(true),
            #[cfg(feature = "ed25519")]
            DerivedPublicKeyInner::Ed25519(ck) => ck.0.serialize_raw().to_vec(),
            #[cfg(feature = "vetkeys")]
            DerivedPublicKeyInner::VetKD(ck) => ck.serialize(),
        }
    }

    /// Return the chain code used for further derivation, if relevant
    ///
    /// Returns None if not applicable for this algorithm
    pub fn chain_code(&self) -> Option<Vec<u8>> {
        match &self.inner {
            #[cfg(feature = "secp256k1")]
            DerivedPublicKeyInner::EcdsaSecp256k1(ck) => Some(ck.1.to_vec()),
            #[cfg(feature = "secp256k1")]
            DerivedPublicKeyInner::Bip340Secp256k1(ck) => Some(ck.1.to_vec()),
            #[cfg(feature = "ed25519")]
            DerivedPublicKeyInner::Ed25519(ck) => Some(ck.1.to_vec()),
            #[cfg(feature = "vetkeys")]
            DerivedPublicKeyInner::VetKD(_ck) => None,
        }
    }
}

/// Derive an ECDSA public key
///
/// This is an offline equivalent to the `ecdsa_public_key` management canister call
///
/// As an extension of the management canister call this function also
/// supports the keys that are used (for testing) by PocketIC.
///
/// See [IC method `ecdsa_public_key`](https://internetcomputer.org/docs/references/ic-interface-spec/#ic-ecdsa_public_key).
///
/// # Supported Keys
///
/// The following key IDs are currently supported
///
/// * `key_1`: The production key used on mainnet
/// * `test_key_1`: The test key used on mainnet
/// * `pocketic_key_1`: The key used by PocketIC when a request to the management canister
///   uses `key_1`.
/// * `pocketic_test_key_1`: The key used by PocketIC when a request to the management canister
///   uses `test_key_1`.
/// * `dfx_test_key`: PocketIC specific test key
pub fn derive_ecdsa_key(args: &EcdsaPublicKeyArgs) -> Result<EcdsaPublicKeyResult, Error> {
    let canister_id = args.canister_id.ok_or(Error::CanisterIdMissing)?;

    let dk = MasterPublicKey::try_from(&args.key_id)?
        .derive_canister_key(&canister_id)
        .derive_key(&args.derivation_path)?;

    Ok(EcdsaPublicKeyResult {
        public_key: dk.serialize(),
        chain_code: dk.chain_code().expect("Missing chain code"),
    })
}

/// Derive a Schnorr public key
///
/// This is an offline equivalent to the `schnorr_public_key` management canister call
///
/// See [IC method `schnorr_public_key`](https://internetcomputer.org/docs/references/ic-interface-spec/#ic-schnorr_public_key).
///
/// # Supported Keys
///
/// Currently this function supports both Ed25519 and BIP340 Schnorr key derivation,
/// using any of the following key names:
///
/// * `key_1`: The production key used on mainnet
/// * `test_key_1`: The test key used on mainnet
/// * `pocketic_key_1`: The key used by PocketIC when a request to the management canister
///   uses `key_1`.
/// * `pocketic_test_key_1`: The key used by PocketIC when a request to the management canister
///   uses `test_key_1`.
/// * `dfx_test_key`: PocketIC specific test key
pub fn derive_schnorr_key(args: &SchnorrPublicKeyArgs) -> Result<SchnorrPublicKeyResult, Error> {
    let canister_id = args.canister_id.ok_or(Error::CanisterIdMissing)?;

    let dk = MasterPublicKey::try_from(&args.key_id)?
        .derive_canister_key(&canister_id)
        .derive_key(&args.derivation_path)?;

    Ok(SchnorrPublicKeyResult {
        public_key: dk.serialize(),
        chain_code: dk.chain_code().expect("Missing chain code"),
    })
}

/// Derive a VetKD public key
///
/// This is an offline equivalent to the `vetkd_public_key` management canister call
///
/// See [IC method `vetkd_public_key`](https://internetcomputer.org/docs/references/ic-interface-spec/#ic-vetkd_public_key)
pub fn derive_vetkd_key(args: &VetKDPublicKeyArgs) -> Result<VetKDPublicKeyResult, Error> {
    let canister_id = args.canister_id.ok_or(Error::CanisterIdMissing)?;

    let ck = MasterPublicKey::try_from(&args.key_id)?.derive_canister_key(&canister_id);

    let dk = ck.derive_key_with_context(&args.context);
    Ok(VetKDPublicKeyResult {
        public_key: dk.serialize(),
    })
}
