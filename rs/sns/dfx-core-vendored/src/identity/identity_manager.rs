use crate::config::directories::get_user_dfx_config_dir;
use crate::error::identity::{
    GetIdentityConfigOrDefaultError,
    GetIdentityConfigOrDefaultError::LoadIdentityConfigurationFailed,
    InstantiateIdentityFromNameError,
    InstantiateIdentityFromNameError::{GetIdentityPrincipalFailed, LoadIdentityFailed},
    LoadIdentityError, NewIdentityManagerError,
    NewIdentityManagerError::LoadIdentityManagerConfigurationFailed,
    RequireIdentityExistsError,
};
use crate::error::structured_file::StructuredFileError;
use crate::identity::identity_file_locations::IdentityFileLocations;
use crate::identity::{
    ANONYMOUS_IDENTITY_NAME, IDENTITY_JSON, Identity as DfxIdentity, TEMP_IDENTITY_PREFIX,
};
use crate::json::load_json_file;
use candid::Principal;
use serde::{Deserialize, Serialize};
use slog::{Logger, trace};
use std::path::{Path, PathBuf};

const DEFAULT_IDENTITY_NAME: &str = "default";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Configuration {
    #[serde(default = "default_identity")]
    pub default: String,
}

fn default_identity() -> String {
    String::from(DEFAULT_IDENTITY_NAME)
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct IdentityConfiguration {
    pub hsm: Option<HardwareIdentityConfiguration>,

    /// If the identity's PEM file is encrypted on disk this contains everything (except the password) to decrypt the file.
    pub encryption: Option<EncryptionConfiguration>,

    /// If the identity's PEM file is stored in the system's keyring, this field contains the identity's name WITHOUT the common prefix.
    pub keyring_identity_suffix: Option<String>,
}

/// The information necessary to de- and encrypt (except the password) the identity's .pem file
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptionConfiguration {
    /// Salt used for deriving the key from the password
    pub pw_salt: String,

    /// 96 bit Nonce used to decrypt the file
    pub file_nonce: Vec<u8>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HardwareIdentityConfiguration {
    #[cfg_attr(
        not(windows),
        doc = r#"The file path to the opensc-pkcs11 library e.g. "/usr/local/lib/opensc-pkcs11.so""#
    )]
    #[cfg_attr(
        windows,
        doc = r#"The file path to the opensc-pkcs11 library e.g. "C:\Program Files (x86)\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"#
    )]
    pub pkcs11_lib_path: String,

    /// A sequence of pairs of hex digits
    pub key_id: String,
}

#[derive(Clone, Debug)]
pub struct IdentityManager {
    file_locations: IdentityFileLocations,
    selected_identity: String,
    selected_identity_principal: Option<Principal>,
}

#[derive(PartialEq)]
pub enum InitializeIdentity {
    Allow,
    Disallow,
}

impl IdentityManager {
    /// Creates an `IdentityManager` from the on-disk dfx identity store.
    ///
    /// Unlike upstream dfx, this vendored subset never auto-creates a default
    /// identity: identity creation is dfx's responsibility. `InitializeIdentity`
    /// is retained for API compatibility, but `Allow` behaves like `Disallow`
    /// (an error is returned when no identity configuration is found).
    pub fn new(
        logger: &Logger,
        identity_override: Option<&str>,
        _initialize_identity: InitializeIdentity,
    ) -> Result<Self, NewIdentityManagerError> {
        let config_dfx_dir_path =
            get_user_dfx_config_dir().map_err(NewIdentityManagerError::GetConfigDirectoryFailed)?;
        let identity_root_path = config_dfx_dir_path.join("identity");
        let identity_json_path = config_dfx_dir_path.join("identity.json");

        let configuration = if identity_json_path.exists() {
            load_configuration(&identity_json_path)
                .map_err(LoadIdentityManagerConfigurationFailed)?
        } else {
            return Err(NewIdentityManagerError::NoIdentityConfigurationFound);
        };

        let selected_identity = identity_override
            .unwrap_or(&configuration.default)
            .to_string();

        let file_locations = IdentityFileLocations::new(identity_root_path);

        let mgr = IdentityManager {
            file_locations,
            selected_identity,
            selected_identity_principal: None,
        };

        if let Some(identity) = identity_override {
            mgr.require_identity_exists(logger, identity)
                .map_err(NewIdentityManagerError::OverrideIdentityMustExist)?;
        }

        Ok(mgr)
    }

    pub fn get_selected_identity_principal(&self) -> Option<Principal> {
        self.selected_identity_principal
    }

    /// Create an Identity instance for use with an Agent
    pub fn instantiate_selected_identity(
        &mut self,
        log: &Logger,
    ) -> Result<Box<DfxIdentity>, InstantiateIdentityFromNameError> {
        let name = self.selected_identity.clone();
        self.instantiate_identity_from_name(name.as_str(), log)
    }

    /// Provide a valid Identity name and create its Identity instance for use with an Agent
    pub fn instantiate_identity_from_name(
        &mut self,
        identity_name: &str,
        log: &Logger,
    ) -> Result<Box<DfxIdentity>, InstantiateIdentityFromNameError> {
        let identity = match identity_name {
            ANONYMOUS_IDENTITY_NAME => Box::new(DfxIdentity::anonymous()),
            identity_name => {
                self.require_identity_exists(log, identity_name)
                    .map_err(InstantiateIdentityFromNameError::RequireIdentityExistsFailed)?;
                Box::new(
                    self.load_identity(identity_name, log)
                        .map_err(LoadIdentityFailed)?,
                )
            }
        };
        use ic_agent::identity::Identity;
        self.selected_identity_principal =
            Some(identity.sender().map_err(GetIdentityPrincipalFailed)?);
        Ok(identity)
    }

    fn load_identity(&self, name: &str, log: &Logger) -> Result<DfxIdentity, LoadIdentityError> {
        let config = self
            .get_identity_config_or_default(name)
            .map_err(LoadIdentityError::GetIdentityConfigOrDefaultFailed)?;
        DfxIdentity::new(name, config, self.file_locations(), log)
            .map_err(LoadIdentityError::NewIdentityFailed)
    }

    pub(crate) fn file_locations(&self) -> &IdentityFileLocations {
        &self.file_locations
    }

    /// Determines if there are enough files present to consider the identity as existing.
    /// Does NOT guarantee that the identity will load correctly.
    pub fn require_identity_exists(
        &self,
        log: &Logger,
        name: &str,
    ) -> Result<(), RequireIdentityExistsError> {
        trace!(log, "Checking if identity '{name}' exists.");
        if name == ANONYMOUS_IDENTITY_NAME {
            return Ok(());
        }

        if name.starts_with(TEMP_IDENTITY_PREFIX) {
            return Err(RequireIdentityExistsError::ReservedIdentityName(
                String::from(name),
            ));
        }

        let json_path = self.get_identity_json_path(name);
        let plaintext_pem_path = self.file_locations.get_plaintext_identity_pem_path(name);
        let encrypted_pem_path = self.file_locations.get_encrypted_identity_pem_path(name);

        if !plaintext_pem_path.exists() && !encrypted_pem_path.exists() && !json_path.exists() {
            Err(RequireIdentityExistsError::IdentityDoesNotExist(
                String::from(name),
                json_path,
            ))
        } else {
            Ok(())
        }
    }

    pub fn get_identity_dir_path(&self, identity: &str) -> PathBuf {
        self.file_locations.get_identity_dir_path(identity)
    }

    /// Returns the path where an identity's `IdentityConfiguration` is stored.
    pub fn get_identity_json_path(&self, identity: &str) -> PathBuf {
        self.get_identity_dir_path(identity).join(IDENTITY_JSON)
    }

    pub fn get_identity_config_or_default(
        &self,
        identity: &str,
    ) -> Result<IdentityConfiguration, GetIdentityConfigOrDefaultError> {
        let json_path = self.get_identity_json_path(identity);
        if json_path.exists() {
            load_json_file(&json_path)
                .map_err(|err| LoadIdentityConfigurationFailed(identity.to_string(), err))
        } else {
            Ok(IdentityConfiguration::default())
        }
    }
}

pub(super) fn get_dfx_hsm_pin() -> Result<String, String> {
    std::env::var("DFX_HSM_PIN")
        .map_err(|_| "There is no DFX_HSM_PIN environment variable.".to_string())
}

fn load_configuration(path: &Path) -> Result<Configuration, StructuredFileError> {
    load_json_file(path)
}
