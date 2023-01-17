use crate::public_key_store::PublicKeyAddError;
use crate::public_key_store::{
    PublicKeyGenerationTimestamps, PublicKeySetOnceError, PublicKeyStore,
};
use ic_protobuf::crypto::v1::NodePublicKeys;
use ic_protobuf::registry::crypto::v1::{PublicKey as PublicKeyProto, X509PublicKeyCert};
use ic_types::Time;
use prost::Message;
use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};
use std::{fs, io};

#[cfg(test)]
mod tests;

const CURRENT_PKS_VERSION: u32 = 1;

/// A public key store that persists data to the filesystem using protocol buffers.
pub struct ProtoPublicKeyStore {
    proto_file: PathBuf,
    keys: NodePublicKeys,
}

impl ProtoPublicKeyStore {
    /// Opens a public key store in `dir`/`file_name`.
    ///
    /// If the store does not exist on disk, a new one is created in memory.
    /// This store is then persisted to disk upon the first change of data.
    pub fn open(dir: &Path, file_name: &str) -> Self {
        let proto_file = dir.join(file_name);
        let keys = match Self::read_node_public_keys_proto_from_disk(&proto_file) {
            Some(node_public_keys) => node_public_keys,
            None => NodePublicKeys {
                version: CURRENT_PKS_VERSION,
                ..Default::default()
            },
        };
        ProtoPublicKeyStore { proto_file, keys }
    }

    /// Returns the path to the protobuf file storing the keys.
    pub fn proto_file_path(&self) -> &Path {
        self.proto_file.as_path()
    }

    fn read_node_public_keys_proto_from_disk(path: &Path) -> Option<NodePublicKeys> {
        match fs::read(path) {
            Ok(data) => {
                Some(NodePublicKeys::decode(&*data).expect("error parsing public key store data"))
            }
            Err(err) => match err.kind() {
                ErrorKind::NotFound => None,
                _ => panic!("Failed to read public key store data: {}", err),
            },
        }
    }

    fn write_node_public_keys_proto_to_disk(&mut self) -> Result<(), io::Error> {
        // Setting the version to CURRENT_PKS_VERSION to unify all stores in production.
        self.keys.version = CURRENT_PKS_VERSION;
        ic_utils::fs::write_protobuf_using_tmp_file(&self.proto_file, &self.keys)
    }
}

impl PublicKeyStore for ProtoPublicKeyStore {
    fn set_once_node_signing_pubkey(
        &mut self,
        key: PublicKeyProto,
    ) -> Result<(), PublicKeySetOnceError> {
        if self.keys.node_signing_pk.is_some() {
            return Err(PublicKeySetOnceError::AlreadySet);
        }
        self.keys.node_signing_pk = Some(key);
        self.write_node_public_keys_proto_to_disk()
            .map_err(|io_error| PublicKeySetOnceError::Io(io_error))
    }

    fn node_signing_pubkey(&self) -> Option<PublicKeyProto> {
        self.keys
            .node_signing_pk
            .as_ref()
            .map(|pk| remove_timestamp(pk.clone()))
    }

    fn set_once_committee_signing_pubkey(
        &mut self,
        key: PublicKeyProto,
    ) -> Result<(), PublicKeySetOnceError> {
        if self.keys.committee_signing_pk.is_some() {
            return Err(PublicKeySetOnceError::AlreadySet);
        }
        self.keys.committee_signing_pk = Some(key);
        self.write_node_public_keys_proto_to_disk()
            .map_err(|io_error| PublicKeySetOnceError::Io(io_error))
    }

    fn committee_signing_pubkey(&self) -> Option<PublicKeyProto> {
        self.keys
            .committee_signing_pk
            .as_ref()
            .map(|pk| remove_timestamp(pk.clone()))
    }

    fn set_once_ni_dkg_dealing_encryption_pubkey(
        &mut self,
        key: PublicKeyProto,
    ) -> Result<(), PublicKeySetOnceError> {
        if self.keys.dkg_dealing_encryption_pk.is_some() {
            return Err(PublicKeySetOnceError::AlreadySet);
        }
        self.keys.dkg_dealing_encryption_pk = Some(key);
        self.write_node_public_keys_proto_to_disk()
            .map_err(|io_error| PublicKeySetOnceError::Io(io_error))
    }

    fn ni_dkg_dealing_encryption_pubkey(&self) -> Option<PublicKeyProto> {
        self.keys
            .dkg_dealing_encryption_pk
            .as_ref()
            .map(|pk| remove_timestamp(pk.clone()))
    }

    fn set_once_tls_certificate(
        &mut self,
        cert: X509PublicKeyCert,
    ) -> Result<(), PublicKeySetOnceError> {
        if self.keys.tls_certificate.is_some() {
            return Err(PublicKeySetOnceError::AlreadySet);
        }
        self.keys.tls_certificate = Some(cert);
        self.write_node_public_keys_proto_to_disk()
            .map_err(|io_error| PublicKeySetOnceError::Io(io_error))
    }

    fn tls_certificate(&self) -> Option<&X509PublicKeyCert> {
        self.keys.tls_certificate.as_ref()
    }

    fn add_idkg_dealing_encryption_pubkey(
        &mut self,
        key: PublicKeyProto,
    ) -> Result<(), PublicKeyAddError> {
        self.keys.idkg_dealing_encryption_pks.push(key);
        self.write_node_public_keys_proto_to_disk()
            .map_err(|io_error| PublicKeyAddError::Io(io_error))
    }

    fn set_idkg_dealing_encryption_pubkeys(
        &mut self,
        keys: Vec<PublicKeyProto>,
    ) -> Result<(), Error> {
        self.keys.idkg_dealing_encryption_pks = keys;
        self.write_node_public_keys_proto_to_disk()
    }

    fn idkg_dealing_encryption_pubkeys(&self) -> Vec<PublicKeyProto> {
        self.keys
            .idkg_dealing_encryption_pks
            .iter()
            .map(|pk| remove_timestamp(pk.clone()))
            .collect()
    }

    fn generation_timestamps(&self) -> PublicKeyGenerationTimestamps {
        PublicKeyGenerationTimestamps {
            node_signing_public_key: timestamp(self.keys.node_signing_pk.as_ref()),
            committee_signing_public_key: timestamp(self.keys.committee_signing_pk.as_ref()),
            dkg_dealing_encryption_public_key: timestamp(
                self.keys.dkg_dealing_encryption_pk.as_ref(),
            ),
            last_idkg_dealing_encryption_public_key: timestamp(
                self.keys.idkg_dealing_encryption_pks.last(),
            ),
        }
    }

    fn idkg_dealing_encryption_pubkeys_count(&self) -> usize {
        self.keys.idkg_dealing_encryption_pks.len()
    }
}

fn remove_timestamp(public_key: PublicKeyProto) -> PublicKeyProto {
    PublicKeyProto {
        timestamp: None,
        ..public_key
    }
}

fn timestamp(public_key: Option<&PublicKeyProto>) -> Option<Time> {
    public_key
        .and_then(|pk| pk.timestamp)
        .and_then(|millis| Time::from_millis_since_unix_epoch(millis).ok())
}
