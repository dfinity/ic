use crate::public_key_store::proto_pubkey_store::ProtoPublicKeyStore;
use crate::public_key_store::PublicKeyAddError;
use crate::public_key_store::{
    PublicKeyGenerationTimestamps, PublicKeySetOnceError, PublicKeyStore,
};
use ic_protobuf::registry::crypto::v1::{PublicKey, X509PublicKeyCert};
use std::fs;
use std::fs::Permissions;
use std::io::Error;
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

/// This store is opened in a newly created temporary directory, which will
/// exist for as long as the object stays in scope. As soon as the object (or
/// rather, the contained tempdir field) goes out of scope, the created
/// temporary directory will automatically be deleted.
pub struct TempPublicKeyStore {
    store: ProtoPublicKeyStore,
    _temp_dir: TempDir,
}

impl TempPublicKeyStore {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let temp_dir = tempfile::Builder::new()
            .prefix("ic_crypto_")
            .tempdir()
            .expect("failed to create temporary crypto directory");
        fs::set_permissions(temp_dir.path(), Permissions::from_mode(0o750)).unwrap_or_else(|_| {
            panic!(
                "failed to set permissions of crypto directory {}",
                temp_dir.path().display()
            )
        });
        let public_key_store_file = "temp_public_keys.pb";
        let store = ProtoPublicKeyStore::open(temp_dir.path(), public_key_store_file);
        TempPublicKeyStore {
            store,
            _temp_dir: temp_dir,
        }
    }
}

impl PublicKeyStore for TempPublicKeyStore {
    fn set_once_node_signing_pubkey(
        &mut self,
        key: PublicKey,
    ) -> Result<(), PublicKeySetOnceError> {
        self.store.set_once_node_signing_pubkey(key)
    }

    fn node_signing_pubkey(&self) -> Option<PublicKey> {
        self.store.node_signing_pubkey()
    }

    fn set_once_committee_signing_pubkey(
        &mut self,
        key: PublicKey,
    ) -> Result<(), PublicKeySetOnceError> {
        self.store.set_once_committee_signing_pubkey(key)
    }

    fn committee_signing_pubkey(&self) -> Option<PublicKey> {
        self.store.committee_signing_pubkey()
    }

    fn set_once_ni_dkg_dealing_encryption_pubkey(
        &mut self,
        key: PublicKey,
    ) -> Result<(), PublicKeySetOnceError> {
        self.store.set_once_ni_dkg_dealing_encryption_pubkey(key)
    }

    fn ni_dkg_dealing_encryption_pubkey(&self) -> Option<PublicKey> {
        self.store.ni_dkg_dealing_encryption_pubkey()
    }

    fn set_once_tls_certificate(
        &mut self,
        cert: X509PublicKeyCert,
    ) -> Result<(), PublicKeySetOnceError> {
        self.store.set_once_tls_certificate(cert)
    }

    fn tls_certificate(&self) -> Option<&X509PublicKeyCert> {
        self.store.tls_certificate()
    }

    fn add_idkg_dealing_encryption_pubkey(
        &mut self,
        key: PublicKey,
    ) -> Result<(), PublicKeyAddError> {
        self.store.add_idkg_dealing_encryption_pubkey(key)
    }

    fn set_idkg_dealing_encryption_pubkeys(&mut self, keys: Vec<PublicKey>) -> Result<(), Error> {
        self.store.set_idkg_dealing_encryption_pubkeys(keys)
    }

    fn idkg_dealing_encryption_pubkeys(&self) -> Vec<PublicKey> {
        self.store.idkg_dealing_encryption_pubkeys()
    }

    fn generation_timestamps(&self) -> PublicKeyGenerationTimestamps {
        self.store.generation_timestamps()
    }
}
