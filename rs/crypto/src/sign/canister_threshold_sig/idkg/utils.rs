//! Utilities useful for implementations of IDkgProtocol
#[cfg(test)]
mod tests;

mod errors;
pub use errors::*;

use ic_crypto_internal_threshold_sig_ecdsa::{EccCurveType, MEGaPublicKey};
use ic_interfaces::registry::RegistryClient;
use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use ic_registry_client::helper::crypto::CryptoRegistry;
use ic_types::crypto::canister_threshold_sig::idkg::IDkgReceivers;
use ic_types::crypto::KeyPurpose;
use ic_types::{NodeId, NodeIndex, RegistryVersion};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Query the registry for the MEGa public keys of all receivers.
///
/// The returned map is keyed by the index of the receiver.
pub fn idkg_encryption_keys_from_registry(
    receivers: &IDkgReceivers,
    registry: &Arc<dyn RegistryClient>,
    registry_version: RegistryVersion,
) -> Result<BTreeMap<NodeIndex, MEGaPublicKey>, MegaKeyFromRegistryError> {
    receivers
        .iter()
        .map(|(index, receiver)| {
            let enc_pubkey = get_mega_pubkey(&receiver, registry, registry_version)?;
            Ok((index, enc_pubkey))
        })
        .collect()
}

/// Query the registry for the MEGa public key of `node_id` receiver.
pub fn get_mega_pubkey(
    node_id: &NodeId,
    registry: &Arc<dyn RegistryClient>,
    registry_version: RegistryVersion,
) -> Result<MEGaPublicKey, MegaKeyFromRegistryError> {
    let maybe_key = registry
        .get_crypto_key_for_node(*node_id, KeyPurpose::IDkgMEGaEncryption, registry_version)
        .map_err(MegaKeyFromRegistryError::RegistryError)?;

    match &maybe_key {
        Some(pk_proto) => mega_public_key_from_proto(pk_proto, node_id),
        None => Err(MegaKeyFromRegistryError::PublicKeyNotFound {
            registry_version,
            node_id: *node_id,
        }),
    }
}

/// Deserialize a Protobuf public key to a MEGaPublicKey.
fn mega_public_key_from_proto(
    proto: &PublicKeyProto,
    node_id: &NodeId,
) -> Result<MEGaPublicKey, MegaKeyFromRegistryError> {
    let curve_type = match AlgorithmIdProto::from_i32(proto.algorithm) {
        Some(AlgorithmIdProto::MegaSecp256k1) => Ok(EccCurveType::K256),
        alg_id => Err(MegaKeyFromRegistryError::UnsupportedAlgorithm {
            algorithm_id: alg_id,
        }),
    }?;

    MEGaPublicKey::deserialize(curve_type, &proto.key_value).map_err(|_| {
        MegaKeyFromRegistryError::MalformedPublicKey {
            node_id: *node_id,
            key_bytes: proto.key_value.clone(),
        }
    })
}
