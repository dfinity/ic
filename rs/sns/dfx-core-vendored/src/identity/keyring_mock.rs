use crate::error::keyring::KeyringError::{
    DecodePemFailed, GetPasswordFailed, LoadMockKeyringFailed, MockKeyNotFound, MockUnavailable,
    NewEntryFailed,
};
use crate::error::keyring::{KeyringError, KeyringMaintenanceError};
use crate::json::load_json_file;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::PathBuf};

pub const KEYRING_SERVICE_NAME: &str = "internet_computer_identities";
pub const KEYRING_IDENTITY_PREFIX: &str = "internet_computer_identity_";
pub const USE_KEYRING_MOCK_ENV_VAR: &str = "DFX_CI_MOCK_KEYRING_LOCATION";
fn keyring_identity_name_from_suffix(suffix: &str) -> String {
    format!("{KEYRING_IDENTITY_PREFIX}{suffix}")
}

enum KeyringMockMode {
    /// Use system keyring
    NoMock,
    /// Simulate keyring where access is granted
    MockAvailable,
    /// Simulate keyring where access is rejected
    MockReject,
}

impl KeyringMockMode {
    fn current_mode() -> Self {
        match std::env::var(USE_KEYRING_MOCK_ENV_VAR) {
            Err(_) => Self::NoMock,
            Ok(location) => match location.as_str() {
                "" => Self::MockReject,
                _ => Self::MockAvailable,
            },
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct KeyringMock {
    pub kv_store: HashMap<String, String>,
}

impl KeyringMock {
    fn get_location() -> Result<PathBuf, KeyringError> {
        match std::env::var(USE_KEYRING_MOCK_ENV_VAR) {
            Ok(filename) => match filename.as_str() {
                "" => Err(MockUnavailable()),
                _ => Ok(PathBuf::from(filename)),
            },
            _ => unreachable!("Mock keyring unavailable."),
        }
    }

    pub fn load() -> Result<Self, KeyringError> {
        let location = Self::get_location()?;
        if location.exists() {
            load_json_file(&location).map_err(LoadMockKeyringFailed)
        } else {
            Ok(Self::default())
        }
    }
}

pub fn load_pem_from_keyring(identity_name_suffix: &str) -> Result<Vec<u8>, KeyringError> {
    let keyring_identity_name = keyring_identity_name_from_suffix(identity_name_suffix);
    match KeyringMockMode::current_mode() {
        KeyringMockMode::NoMock => {
            let entry = keyring::Entry::new(KEYRING_SERVICE_NAME, &keyring_identity_name)
                .map_err(NewEntryFailed)?;
            let encoded_pem = entry
                .get_password()
                .handle_macos_acl_error()?
                .map_err(GetPasswordFailed)?;
            let pem = hex::decode(encoded_pem).map_err(DecodePemFailed)?;
            Ok(pem)
        }
        KeyringMockMode::MockAvailable => {
            let mock = KeyringMock::load()?;
            let encoded_pem = mock
                .kv_store
                .get(&keyring_identity_name)
                .ok_or(MockKeyNotFound(keyring_identity_name))?;
            let pem = hex::decode(encoded_pem).map_err(DecodePemFailed)?;
            Ok(pem)
        }
        KeyringMockMode::MockReject => Err(MockUnavailable()),
    }
}

trait KeyringResultExt: Sized {
    fn handle_macos_acl_error(self) -> Result<Self, KeyringMaintenanceError>;
}

impl<T> KeyringResultExt for Result<T, keyring::Error> {
    fn handle_macos_acl_error(self) -> Result<Self, KeyringMaintenanceError> {
        match self {
            Ok(value) => Ok(Ok(value)),
            #[cfg(target_os = "macos")]
            Err(keyring::Error::PlatformFailure(err))
                if err
                    .downcast_ref::<security_framework::base::Error>()
                    .is_some_and(|err| err.code() == -67671) =>
            {
                Err(KeyringMaintenanceError)
            }
            Err(e) => Ok(Err(e)),
        }
    }
}
