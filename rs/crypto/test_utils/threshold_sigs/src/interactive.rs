use crate::common::crypto_for;
use ic_crypto::utils::dkg::{initial_dkg_transcript, InitialDkgConfig};
use ic_crypto::utils::TempCryptoComponent;
use ic_interfaces::crypto::{DkgAlgorithm, Signable, ThresholdSigner};
use ic_types::crypto::threshold_sig::ni_dkg::DkgId;
use ic_types::crypto::{dkg, dkg::Transcript, ThresholdSigShareOf};
use ic_types::{IDkgId, NodeId, SubnetId};
use std::collections::{BTreeMap, BTreeSet};

pub fn initial_idkg_transcript_for_nodes_in_subnet(
    subnet_id: SubnetId,
    nodes: &[NodeId],
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
) -> Transcript {
    let nodes_set: BTreeSet<_> = nodes.iter().cloned().collect();
    assert_eq!(nodes.len(), nodes_set.len(), "duplicate nodes");

    // Create initial DKG config
    let initial_dkg_config = InitialDkgConfig::new(&nodes_set, subnet_id);

    // Collect ephemeral encryption public keys from nodes in subnet
    let keys_collected_from_nodes = idkg_encryption_public_keys(
        &initial_dkg_config.get().receivers,
        &initial_dkg_config.get(),
        &crypto_components,
    );

    // Create initial DKG transcript
    initial_dkg_transcript(initial_dkg_config, &keys_collected_from_nodes)
}

pub fn idkg_encryption_public_keys(
    nodes: &[NodeId],
    dkg_config: &dkg::Config,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
) -> BTreeMap<NodeId, dkg::EncryptionPublicKeyWithPop> {
    nodes
        .iter()
        .map(|node| {
            let key = crypto_for(*node, crypto_components)
                .generate_encryption_keys(dkg_config, *node)
                .unwrap_or_else(|error| {
                    panic!(
                        "failed to generate encryption public key for {:?}: {:?}",
                        node, error
                    )
                });
            (*node, key)
        })
        .collect()
}

pub fn load_idkg_transcript_for_each(
    nodes: &[NodeId],
    transcript: &Transcript,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
) {
    nodes
        .iter()
        .for_each(|node_id| load_idkg_transcript(transcript, crypto_components, *node_id));
}

pub fn load_idkg_transcript(
    transcript: &dkg::Transcript,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    node_id: NodeId,
) {
    if let Err(e) = crypto_for(node_id, crypto_components).load_transcript(transcript, node_id) {
        panic!("{:?}", e);
    }
}

pub fn sign_threshold_for_each<H: Signable>(
    signers: &[NodeId],
    msg: &H,
    dkg_id: IDkgId,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
) -> BTreeMap<NodeId, ThresholdSigShareOf<H>> {
    signers
        .iter()
        .map(|signer| {
            let sig_share = crypto_for(*signer, &crypto_components)
                .sign_threshold(msg, DkgId::IDkgId(dkg_id))
                .unwrap_or_else(|_| panic!("signing by node {:?} failed", signer));
            (*signer, sig_share)
        })
        .collect()
}
