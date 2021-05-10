//! Utilities for interactive Distributed Key Generation (DKG).
use super::*;
use crate::common::utils::dkg::utils::{
    crypto_for, dealer_and_receiver_keys, dealings, encryption_public_keys,
    fake_non_complaining_responses, get_threshold_for_committee_of_size,
};
use ic_crypto_internal_csp::types::conversions::csp_pub_coeffs_from_transcript;
use ic_crypto_internal_csp::types::CspResponse;
use ic_crypto_internal_threshold_sig_bls12381::types::public_coefficients::conversions::pub_key_bytes_from_pub_coeff_bytes;
use ic_crypto_internal_types::sign::threshold_sig::public_coefficients::bls12_381::PublicCoefficientsBytes;
use ic_crypto_internal_types::sign::threshold_sig::public_key::CspThresholdSigPublicKey;
use ic_interfaces::crypto::DkgAlgorithm;
use ic_protobuf::registry::subnet::v1::InitialDkgTranscriptRecord;
use ic_types::consensus::Threshold;
use ic_types::crypto::dkg;
use ic_types::crypto::dkg::EncryptionPublicKeyWithPop;
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use ic_types::IDkgId;
use ic_types::{Height, PrincipalId, SubnetId};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

#[cfg(test)]
mod tests;

/// A config used to create an initial interactive DKG transcript. Such a
/// transcript is used to bootstrap a subnet for testing purposes.
pub struct InitialDkgConfig {
    dkg_config: dkg::Config,
}

impl InitialDkgConfig {
    /// Creates an initial DKG config for a subnet initially containing the
    /// nodes `nodes_in_subnet`.
    ///
    /// The DKG ID contained in the config uses `Height` 0 as instance ID
    /// together with the given `subnet_id`. The receivers in the config are
    /// the `nodes_in_subnet`.
    ///
    /// # Panics
    /// The function panics if `nodes_in_subnet` is empty.
    pub fn new(nodes_in_subnet: &BTreeSet<NodeId>, subnet_id: SubnetId) -> Self {
        Self::ensure_subnet_not_empty(nodes_in_subnet);
        let threshold = get_threshold_for_committee_of_size(nodes_in_subnet.len());
        let dummy_dealers: Vec<NodeId> = (1u64..)
            .map(PrincipalId::new_node_test_id)
            .map(NodeId::from)
            .filter(|node_id| !nodes_in_subnet.contains(node_id))
            .take(threshold)
            .collect();
        let dkg_config = dkg::Config {
            dkg_id: IDkgId {
                instance_id: Height::from(0),
                subnet_id,
            },
            dealers: dummy_dealers,
            receivers: nodes_in_subnet.iter().cloned().collect(),
            threshold,
            resharing_transcript: None,
        };
        Self { dkg_config }
    }

    pub fn get(&self) -> &dkg::Config {
        &self.dkg_config
    }

    fn ensure_subnet_not_empty(nodes_in_subnet: &BTreeSet<NodeId>) {
        if nodes_in_subnet.is_empty() {
            panic!("subnet must not be empty");
        }
    }
}

/// Creates an initial DKG transcript.
///
/// The transcript is created by performing the DKG protocol in a _centralized_
/// manner. This method must only be used for testing purposes since the
/// transcript is generated in a centralized manner.
///
/// # Panics
/// * If the `receiver_keys` don't match the receivers in the
///   `initial_dkg_config`.
pub fn initial_dkg_transcript(
    initial_dkg_config: InitialDkgConfig,
    receiver_keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
) -> dkg::Transcript {
    let dkg_config = initial_dkg_config.get();
    ensure_matching_node_ids(&dkg_config.receivers, receiver_keys);

    let registry_client = FakeRegistryClient::new(Arc::new(ProtoRegistryDataProvider::new()));
    let crypto_comps =
        TempCryptoComponent::multiple_new(&dkg_config.dealers, Arc::new(registry_client));

    let dealer_keys = encryption_public_keys(&dkg_config.dealers, &dkg_config, &crypto_comps);
    let dealer_and_receiver_keys = dealer_and_receiver_keys(&dealer_keys, receiver_keys);
    let dealings = dealings(
        &dkg_config.dealers,
        &dkg_config,
        &dealer_and_receiver_keys,
        &crypto_comps,
    );
    let fake_responses = fake_non_complaining_responses(&dkg_config.receivers);

    let transcript_generator = first_dealer(&dkg_config);
    crypto_for(transcript_generator, &crypto_comps)
        .create_transcript(
            &dkg_config,
            &dealer_and_receiver_keys,
            &dealings,
            &fake_responses,
        )
        .unwrap_or_else(|error| panic!("failed to create transcript: {:?}", error))
}

fn first_dealer(dkg_config: &dkg::Config) -> NodeId {
    *dkg_config
        .dealers
        .iter()
        .next()
        .expect("internal error: expected the initial DKG config to contain dealers")
}

fn ensure_matching_node_ids(
    receivers_in_config: &[NodeId],
    receiver_keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
) {
    let receivers_from_config: BTreeSet<NodeId> = receivers_in_config.iter().cloned().collect();
    let receivers_from_keys: BTreeSet<NodeId> = receiver_keys.keys().cloned().collect();
    assert_eq!(
        receivers_from_keys, receivers_from_config,
        "the config's receivers must match the keys' receivers"
    );
}

/// Converts a DKG transcript into the corresponding protobuf representation.
pub fn initial_dkg_transcript_record_from_transcript(
    transcript: dkg::Transcript,
) -> InitialDkgTranscriptRecord {
    use ic_protobuf::registry::subnet::v1::DkgId;

    InitialDkgTranscriptRecord {
        id: Some(DkgId {
            subnet_id: transcript.dkg_id.subnet_id.get().into_vec(),
            instance_id: transcript.dkg_id.instance_id.get(),
        }),
        committee: transcript
            .committee
            .into_iter()
            .map(|x| x.expect("invalid initial DKG transcript").get().into_vec())
            .collect(),
        transcript_bytes: transcript.transcript_bytes.0,
    }
}

/// Extracts the threshold signature public key from a DKG transcript
pub fn threshold_sig_pubkey_from_transcript(
    dkg_transcript: &dkg::Transcript,
) -> ThresholdSigPublicKey {
    let csp_public_coeffs = csp_pub_coeffs_from_transcript(dkg_transcript);
    let public_coeffs_bytes = PublicCoefficientsBytes::from(csp_public_coeffs);
    let public_key_bytes = pub_key_bytes_from_pub_coeff_bytes(&public_coeffs_bytes);
    let csp_threshold_sig_pubkey = CspThresholdSigPublicKey::from(public_key_bytes);
    ThresholdSigPublicKey::from(csp_threshold_sig_pubkey)
}

mod utils {
    use super::*;
    use ic_types::crypto::dkg::Response;

    pub fn dealer_and_receiver_keys(
        dealer_keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
        receiver_keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
    ) -> BTreeMap<NodeId, EncryptionPublicKeyWithPop> {
        let mut dealer_keys = dealer_keys.clone();
        let mut receiver_keys = receiver_keys.clone();
        dealer_keys.append(&mut receiver_keys);
        dealer_keys
    }

    pub fn encryption_public_keys(
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

    pub fn dealings(
        dealers: &[NodeId],
        dkg_config: &dkg::Config,
        keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
        crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    ) -> BTreeMap<NodeId, dkg::Dealing> {
        dealers
            .iter()
            .map(|node| {
                let dealing = crypto_for(*node, &crypto_components)
                    .create_dealing(dkg_config, keys, *node)
                    .unwrap_or_else(|error| {
                        panic!("failed to create dealing for {:?}: {:?}", node, error)
                    });
                (*node, dealing)
            })
            .collect()
    }

    pub fn fake_non_complaining_responses(receivers: &[NodeId]) -> BTreeMap<NodeId, Response> {
        receivers
            .iter()
            .map(|node| {
                let fake_response = CspResponse::new_without_complaints();
                (*node, Response::from(&fake_response))
            })
            .collect()
    }

    pub fn crypto_for(
        node_id: NodeId,
        crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    ) -> &TempCryptoComponent {
        crypto_components
            .get(&node_id)
            .unwrap_or_else(|| panic!("missing crypto component for {:?}", node_id))
    }

    pub fn get_threshold_for_committee_of_size(group_size: usize) -> Threshold {
        num_integer::div_ceil(group_size, 3)
    }
}
