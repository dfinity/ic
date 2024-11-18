//! Conversion of keys into various formats
use ic_base_types::{NodeId, PrincipalId};
use ic_crypto_ed25519::PublicKey;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;

#[cfg(test)]
mod tests;

#[derive(Clone, Debug)]
pub enum InvalidNodePublicKey {
    MalformedRawBytes { internal_error: String },
}

/// Computes the NodeId associated to the given (Protobuf-serialized) public key
///
/// # Errors
/// * `InvalidNodePublicKey::MalformedRawBytes` if the provided key is not a
///   proper Ed25519 public key
///
/// # Returns
/// * The NodeId associated to the key
pub fn derive_node_id(node_signing_pk: &PublicKeyProto) -> Result<NodeId, InvalidNodePublicKey> {
    let raw_key = &node_signing_pk.key_value;

    let pk = PublicKey::deserialize_raw(&raw_key[..]).map_err(|e| {
        InvalidNodePublicKey::MalformedRawBytes {
            internal_error: format!("{:?}", e),
        }
    })?;
    let der_pk = pk.serialize_rfc8410_der();
    Ok(NodeId::from(PrincipalId::new_self_authenticating(&der_pk)))
}
