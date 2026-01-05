use ic_crypto_utils_threshold_sig_der::threshold_sig_public_key_to_pem;
use ic_protobuf::registry::crypto::v1::PublicKey as PbPublicKey;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_types::RegistryVersion;
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use prost::Message;
use std::path::{Path, PathBuf};
use std::{convert::TryFrom, fmt};

/// Adds the k/v entry to the given data provider.
pub fn write_registry_entry<P, M>(
    data_provider: &ProtoRegistryDataProvider,
    _path: P,
    key: &str,
    registry_version: RegistryVersion,
    record: M,
) where
    P: AsRef<Path> + fmt::Debug,
    M: Message + std::clone::Clone,
{
    data_provider
        .add(key, registry_version, Some(record))
        .expect("Could not add key to registry data provider.");
}

/// Writes a protobuf registry entry to a file on disk, in the given path.
/// The file name is the key of the entry in the registry.
///
/// # Panics
///
/// Panics if the parent dir doesn't exist, or if the serialization fails.
pub(crate) fn write_proto_to_file_raw<P, M>(key: &str, pb: M, parent_dir: P)
where
    P: AsRef<Path> + fmt::Debug,
    M: Message + std::clone::Clone,
{
    let mut buf = Vec::new();
    pb.encode(&mut buf).expect("Error serializing proto");
    let file_path = PathBuf::from(parent_dir.as_ref()).join(key);
    std::fs::write(file_path, buf).expect("Unable to write pb to file.");
}

pub fn store_threshold_sig_pk<P: AsRef<Path>>(pk: &PbPublicKey, path: P) {
    let pk = ThresholdSigPublicKey::try_from(pk.clone())
        .expect("failed to parse threshold signature PK from protobuf");
    let pem_bytes = threshold_sig_public_key_to_pem(pk)
        .expect("failed to encode threshold signature PK into PEM");

    let path = path.as_ref();
    std::fs::write(path, pem_bytes)
        .unwrap_or_else(|e| panic!("failed to store public key to {}: {}", path.display(), e));
}
