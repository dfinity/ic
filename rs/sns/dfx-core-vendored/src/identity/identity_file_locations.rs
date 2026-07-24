use crate::identity::IdentityConfiguration;
use std::path::PathBuf;

pub const IDENTITY_PEM: &str = "identity.pem";
pub const IDENTITY_PEM_ENCRYPTED: &str = "identity.pem.encrypted";

#[derive(Clone, Debug)]
pub(crate) struct IdentityFileLocations {
    root_dir: PathBuf,
}

impl IdentityFileLocations {
    pub fn new(root_dir: PathBuf) -> Self {
        Self { root_dir }
    }

    /// Determines the path of the (potentially encrypted) PEM file.
    pub fn get_identity_pem_path(
        &self,
        identity_name: &str,
        identity_config: &IdentityConfiguration,
    ) -> PathBuf {
        if identity_config.encryption.is_some() {
            self.get_encrypted_identity_pem_path(identity_name)
        } else {
            self.get_plaintext_identity_pem_path(identity_name)
        }
    }

    /// Determines the path of the clear-text PEM file.
    pub fn get_plaintext_identity_pem_path(&self, identity_name: &str) -> PathBuf {
        self.get_identity_dir_path(identity_name).join(IDENTITY_PEM)
    }

    /// Determines the path of the encrypted PEM file.
    pub fn get_encrypted_identity_pem_path(&self, identity_name: &str) -> PathBuf {
        self.get_identity_dir_path(identity_name)
            .join(IDENTITY_PEM_ENCRYPTED)
    }

    pub fn get_identity_dir_path(&self, identity: &str) -> PathBuf {
        self.root_dir.join(identity)
    }
}
