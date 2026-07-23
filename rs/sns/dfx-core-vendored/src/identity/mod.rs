//! Identity type and module.
//!
//! Wallets are a map of network-identity, but don't have their own types or manager
//! type.
use crate::error::identity::{
    LoadPemIdentityError, LoadPemIdentityError::ReadIdentityFileFailed, NewHardwareIdentityError,
    NewHardwareIdentityError::InstantiateHardwareIdentityFailed, NewIdentityError,
};
use crate::identity::identity_file_locations::IdentityFileLocations;
use candid::Principal;
use ic_agent::Signature;
use ic_agent::agent::EnvelopeContent;
use ic_agent::identity::{
    AnonymousIdentity, BasicIdentity, Delegation, Secp256k1Identity, SignedDelegation,
};
use ic_identity_hsm::HardwareIdentity;
pub use identity_manager::{HardwareIdentityConfiguration, IdentityConfiguration, IdentityManager};
use serde::Serialize;
use slog::Logger;

mod identity_file_locations;
pub mod identity_manager;
pub mod keyring_mock;
pub mod pem_safekeeping;

pub const ANONYMOUS_IDENTITY_NAME: &str = "anonymous";
pub const IDENTITY_JSON: &str = "identity.json";
pub const TEMP_IDENTITY_PREFIX: &str = if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
    "___s_temp___"
} else {
    "___temp___"
};

const HSM_SLOT_INDEX: usize = 0;

pub struct Identity {
    /// The name of this Identity.
    name: String,

    /// Whether this identity is stored in unencrypted form.
    /// False for identities that are not stored at all.
    pub insecure: bool,

    /// Inner implementation of this identity.
    inner: Box<dyn ic_agent::Identity + Sync + Send>,

    identity_type: IdentityType,
}

impl Identity {
    pub fn anonymous() -> Self {
        Self {
            name: ANONYMOUS_IDENTITY_NAME.to_string(),
            inner: Box::new(AnonymousIdentity {}),
            insecure: false,
            identity_type: IdentityType::Anonymous,
        }
    }

    fn basic(
        name: &str,
        pem_content: &[u8],
        identity_type: IdentityType,
    ) -> Result<Self, LoadPemIdentityError> {
        let inner = Box::new(
            BasicIdentity::from_pem(pem_content)
                .map_err(|e| ReadIdentityFileFailed(name.into(), Box::new(e)))?,
        );

        Ok(Self {
            name: name.to_string(),
            inner,
            insecure: identity_type == IdentityType::Plaintext,
            identity_type,
        })
    }

    fn secp256k1(
        name: &str,
        pem_content: &[u8],
        identity_type: IdentityType,
    ) -> Result<Self, LoadPemIdentityError> {
        let inner = Box::new(
            Secp256k1Identity::from_pem(pem_content)
                .map_err(|e| ReadIdentityFileFailed(name.into(), Box::new(e)))?,
        );

        Ok(Self {
            name: name.to_string(),
            inner,
            insecure: identity_type == IdentityType::Plaintext,
            identity_type,
        })
    }

    fn hardware(
        name: &str,
        hsm: HardwareIdentityConfiguration,
    ) -> Result<Self, NewHardwareIdentityError> {
        let inner = Box::new(
            HardwareIdentity::new(
                hsm.pkcs11_lib_path,
                HSM_SLOT_INDEX,
                &hsm.key_id,
                identity_manager::get_dfx_hsm_pin,
            )
            .map_err(|e| InstantiateHardwareIdentityFailed(name.into(), Box::new(e)))?,
        );
        Ok(Self {
            name: name.to_string(),
            inner,
            insecure: false,
            identity_type: IdentityType::Hsm,
        })
    }

    pub(crate) fn new(
        name: &str,
        config: IdentityConfiguration,
        locations: &IdentityFileLocations,
        log: &Logger,
    ) -> Result<Self, NewIdentityError> {
        if let Some(hsm) = config.hsm {
            Identity::hardware(name, hsm).map_err(NewIdentityError::NewHardwareIdentityFailed)
        } else {
            let (pem_content, identity_type) =
                pem_safekeeping::load_pem(log, locations, name, &config)
                    .map_err(NewIdentityError::LoadPemFailed)?;
            Identity::secp256k1(name, &pem_content, identity_type)
                .or_else(|e| Identity::basic(name, &pem_content, identity_type).map_err(|_| e))
                .map_err(NewIdentityError::LoadPemIdentityFailed)
        }
    }

    /// Get the name of this identity.
    #[allow(dead_code)]
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn identity_type(&self) -> IdentityType {
        self.identity_type
    }
}

impl ic_agent::Identity for Identity {
    fn sender(&self) -> Result<Principal, String> {
        self.inner.sender()
    }

    fn public_key(&self) -> Option<Vec<u8>> {
        self.inner.public_key()
    }

    fn delegation_chain(&self) -> Vec<SignedDelegation> {
        self.inner.delegation_chain()
    }

    fn sign(&self, content: &EnvelopeContent) -> Result<Signature, String> {
        self.inner.sign(content)
    }

    fn sign_arbitrary(&self, content: &[u8]) -> Result<Signature, String> {
        self.inner.sign_arbitrary(content)
    }

    fn sign_delegation(&self, content: &Delegation) -> Result<Signature, String> {
        self.inner.sign_delegation(content)
    }
}

impl AsRef<Identity> for Identity {
    fn as_ref(&self) -> &Identity {
        self
    }
}

#[derive(Serialize, Copy, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum IdentityType {
    Keyring,
    Plaintext,
    EncryptedLocal,
    Hsm,
    Anonymous,
}
