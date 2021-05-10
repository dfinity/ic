use ic_crypto_internal_csp::types::CspPop;
use ic_crypto_internal_types::sign::threshold_sig::dkg::encryption_public_key::CspEncryptionPublicKey;
use ic_types::crypto::dkg::EncryptionPublicKeyWithPop;
use ic_types::crypto::{CryptoError, CryptoResult};
use ic_types::NodeId;
use std::collections::BTreeMap;

#[cfg(test)]
mod tests;

pub fn ensure_node_id_has_key(
    node_id: NodeId,
    verified_keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
) -> CryptoResult<()> {
    key_for_node_id(node_id, &verified_keys)?;
    Ok(())
}

pub fn key_for_node_id(
    node_id: NodeId,
    verified_keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
) -> CryptoResult<&EncryptionPublicKeyWithPop> {
    verified_keys
        .get(&node_id)
        .ok_or_else(|| CryptoError::InvalidArgument {
            message: format!("Missing key for node ID \"{:?}\".", node_id),
        })
}

// TODO (CRP-311): Switch 'nodes' to type 'Receivers' once threshold methods use
// new DKG config.
pub fn csp_keys(
    nodes: &[NodeId],
    verified_keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
) -> Vec<Option<(CspEncryptionPublicKey, CspPop)>> {
    let nodes: Vec<Option<_>> = nodes.iter().cloned().map(Some).collect();
    csp_keys_for_optional_node_ids(&nodes, verified_keys)
}

pub fn csp_keys_for_optional_node_ids(
    nodes: &[Option<NodeId>],
    verified_keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
) -> Vec<Option<(CspEncryptionPublicKey, CspPop)>> {
    nodes
        .iter()
        .map(|optional_node_id| {
            optional_node_id
                .clone()
                .map(|node_id| {
                    verified_keys.get(&node_id).map(|pk_with_pop| {
                        let pk = CspEncryptionPublicKey::from(&pk_with_pop.key);
                        let pop = CspPop::from(&pk_with_pop.proof_of_possession);
                        (pk, pop)
                    })
                })
                .flatten()
        })
        .collect()
}
