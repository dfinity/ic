use super::*;
use ic_crypto_internal_types::encrypt::forward_secure::MalformedFsEncryptionPublicKeyError;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::CspFsEncryptionPublicKey;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::Epoch;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use ic_registry_client::helper::crypto::CryptoRegistry;
use ic_types::crypto::threshold_sig::ni_dkg::config::dealers::NiDkgDealers;
use ic_types::crypto::threshold_sig::ni_dkg::config::receivers::NiDkgReceivers;
use ic_types::crypto::threshold_sig::ni_dkg::errors::FsEncryptionPublicKeyNotInRegistryError;
use ic_types::registry::RegistryClientError;

pub fn epoch(registry_version: RegistryVersion) -> Epoch {
    u32::try_from(registry_version.get())
        .map(Epoch::new)
        .unwrap_or_else(|error| panic!("Cannot convert registry version to epoch: {}", error))
}

pub fn index_in_resharing_committee_or_panic(
    node_id: &NodeId,
    committee: &NiDkgReceivers,
) -> NodeIndex {
    committee.position(*node_id).unwrap_or_else(|| {
        panic!(
            "DKG config invariant violated: node {} not in resharing committee ({:?})",
            node_id, committee
        )
    })
}

/// Computes the dealers index in the set of `NiDkgDealers.
///
/// # Panics:
/// * If the dealer is not included in `NiDkgDealers`.
pub fn dealer_index_in_dealers_or_panic(dealers: &NiDkgDealers, dealer: NodeId) -> NodeIndex {
    dealers.position(dealer).unwrap_or_else(|| {
        panic!(
            "This operation requires node ({}) to be a dealer, but it is not.",
            dealer
        )
    })
}

pub fn csp_encryption_pubkey(
    node_id: &NodeId,
    registry: &Arc<dyn RegistryClient>,
    registry_version: RegistryVersion,
) -> Result<CspFsEncryptionPublicKey, DkgEncPubkeyRegistryQueryError> {
    let pk_proto = encryption_pubkey(node_id, registry, registry_version)?;
    CspFsEncryptionPublicKey::try_from(pk_proto)
        .map_err(DkgEncPubkeyRegistryQueryError::MalformedFsEncryptionPublicKey)
}

fn encryption_pubkey(
    node_id: &NodeId,
    registry: &Arc<dyn RegistryClient>,
    registry_version: RegistryVersion,
) -> Result<PublicKeyProto, DkgEncPubkeyRegistryQueryError> {
    match registry.get_crypto_key_for_node(
        *node_id,
        KeyPurpose::DkgDealingEncryption,
        registry_version,
    )? {
        Some(pk_proto) => Ok(pk_proto),
        None => Err(
            DkgEncPubkeyRegistryQueryError::FsEncryptionPublicKeyNotInRegistry(
                FsEncryptionPublicKeyNotInRegistryError {
                    registry_version,
                    node_id: *node_id,
                },
            ),
        ),
    }
}

pub enum DkgEncPubkeyRegistryQueryError {
    FsEncryptionPublicKeyNotInRegistry(FsEncryptionPublicKeyNotInRegistryError),
    MalformedFsEncryptionPublicKey(MalformedFsEncryptionPublicKeyError),
    Registry(RegistryClientError),
}

impl From<RegistryClientError> for DkgEncPubkeyRegistryQueryError {
    fn from(registry_client_error: RegistryClientError) -> Self {
        DkgEncPubkeyRegistryQueryError::Registry(registry_client_error)
    }
}
