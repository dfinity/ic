//! Utilities for non-interactive Distributed Key Generation (NI-DKG), and
//! for testing distributed key generation and threshold signing.
use crate::{dummy_transcript_for_tests, dummy_transcript_for_tests_with_params};
use ic_crypto_internal_bls12_381_type::{G1Affine, G2Affine, Scalar};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::CspNiDkgTranscript::Groth20_Bls12_381;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
use ic_crypto_internal_types::NodeIndex;
use ic_crypto_temp_crypto::{CryptoComponentRng, TempCryptoComponent, TempCryptoComponentGeneric};
use ic_interfaces::crypto::NiDkgAlgorithm;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use ic_protobuf::registry::subnet::v1::InitialNiDkgTranscriptRecord;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::make_crypto_node_key;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_types::consensus::get_faults_tolerated;
use ic_types::crypto::threshold_sig::ni_dkg::config::receivers::NiDkgReceivers;
use ic_types::crypto::threshold_sig::ni_dkg::config::{NiDkgConfig, NiDkgConfigData};
use ic_types::crypto::threshold_sig::ni_dkg::{NiDkgDealing, NiDkgTargetId};
use ic_types::crypto::threshold_sig::ni_dkg::{
    NiDkgId, NiDkgTag, NiDkgTargetSubnet, NiDkgTranscript,
};
use ic_types::crypto::KeyPurpose;
use ic_types::{Height, NodeId, SubnetId};
use ic_types::{NumberOfNodes, RegistryVersion};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;
use std::sync::Arc;

#[cfg(test)]
mod tests;

/// A config used to create an initial NI-DKG transcript. Such a transcript is
/// used to bootstrap a subnet for testing purposes.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
pub struct InitialNiDkgConfig {
    dkg_config: NiDkgConfig,
}

impl InitialNiDkgConfig {
    pub const START_BLOCK_HEIGHT: u64 = 0;

    /// Creates an initial DKG config for a subnet initially containing the
    /// nodes `nodes_in_subnet`.
    ///
    /// The DKG ID contained in the config is for start block `Height` 0 (see
    /// the constant `START_BLOCK_HEIGHT`), a _remote_ target subnet with ID
    /// `target_id`, the given `dealer_subnet`, and `dkg_tag`.
    ///
    /// The config uses the node with the smallest ID (as determined by the
    /// `Ord` trait) in `nodes_in_subnet` as dealer, and the `nodes_in_subnet`
    /// as receivers. The config's threshold is set in accordance with the
    /// `dkg_tag` (low/high).
    ///
    /// # Panics
    /// The function panics if `nodes_in_subnet` is empty.
    pub fn new(
        nodes_in_subnet: &BTreeSet<NodeId>,
        dealer_subnet: SubnetId,
        dkg_tag: NiDkgTag,
        target_id: NiDkgTargetId,
        registry_version: RegistryVersion,
    ) -> Self {
        Self::ensure_subnet_not_empty(nodes_in_subnet);
        let threshold = dkg_tag.threshold_for_subnet_of_size(nodes_in_subnet.len());
        let max_corrupt_receivers = get_faults_tolerated(nodes_in_subnet.len());
        let dkg_config_data = NiDkgConfigData {
            dkg_id: NiDkgId {
                start_block_height: Height::from(Self::START_BLOCK_HEIGHT),
                dealer_subnet,
                dkg_tag,
                target_subnet: NiDkgTargetSubnet::Remote(target_id),
            },
            max_corrupt_dealers: NumberOfNodes::new(0),
            dealers: nodes_in_subnet.iter().copied().take(1).collect(),
            max_corrupt_receivers: number_of_nodes_from_usize(max_corrupt_receivers),
            receivers: nodes_in_subnet.clone(),
            threshold: number_of_nodes_from_usize(threshold),
            registry_version,
            resharing_transcript: None,
        };
        let dkg_config = NiDkgConfig::new(dkg_config_data)
            .expect("internal error: config invariant unexpectedly violated");
        Self { dkg_config }
    }

    pub fn get(&self) -> &NiDkgConfig {
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
pub fn initial_dkg_transcript<R: rand::Rng + rand::CryptoRng>(
    initial_dkg_config: InitialNiDkgConfig,
    receiver_keys: &BTreeMap<NodeId, PublicKeyProto>,
    rng: &mut R,
) -> NiDkgTranscript {
    let dkg_config = initial_dkg_config.get();
    ensure_matching_node_ids(dkg_config.receivers(), receiver_keys);

    let dealer_id = first_dealer(dkg_config);
    let registry = fake_registry_with_encryption_keys(receiver_keys, dkg_config.registry_version());
    let dealer_crypto = TempCryptoComponent::builder()
        .with_registry(Arc::new(registry))
        .with_node_id(dealer_id)
        .with_rng(ChaCha20Rng::from_seed(rng.gen()))
        .build();

    transcript_with_single_dealing(dkg_config, dealer_crypto, dealer_id)
}

#[derive(Copy, Clone, Debug)]
pub struct SecretKeyBytes {
    val: [u8; 32],
}

impl AsRef<[u8]> for SecretKeyBytes {
    fn as_ref(&self) -> &[u8] {
        &self.val
    }
}

/// Return a fake transcript and the master secret associated with it
///
/// The transcript is not valid and cannot be used by NIDKG
pub fn initial_dkg_transcript_and_master_key<R: rand::Rng + rand::CryptoRng>(
    initial_dkg_config: InitialNiDkgConfig,
    receiver_keys: &BTreeMap<NodeId, PublicKeyProto>,
    rng: &mut R,
) -> (NiDkgTranscript, SecretKeyBytes) {
    let mut transcript = initial_dkg_transcript(initial_dkg_config, receiver_keys, rng);

    let master_secret = Scalar::random(rng);

    let public_key_bytes = G2Affine::from(G2Affine::generator() * &master_secret).serialize();

    let master_secret_bytes = SecretKeyBytes {
        val: master_secret.serialize(),
    };

    transcript.internal_csp_transcript = match transcript.internal_csp_transcript {
        Groth20_Bls12_381(transcript) => {
            let mut mod_transcript = transcript.clone();
            mod_transcript.public_coefficients.coefficients[0] = PublicKeyBytes(public_key_bytes);
            Groth20_Bls12_381(mod_transcript)
        }
    };

    (transcript, master_secret_bytes)
}

/// Return a fake transcript and the master secret associated with it
///
/// The transcript is not valid and cannot be used by NIDKG
pub fn dummy_initial_dkg_transcript_with_master_key<R: rand::Rng + rand::CryptoRng>(
    rng: &mut R,
) -> (NiDkgTranscript, SecretKeyBytes) {
    let mut transcript = dummy_transcript_for_tests();

    let master_secret = Scalar::random(rng);

    let public_key_bytes = G2Affine::from(G2Affine::generator() * &master_secret).serialize();

    let master_secret_bytes = SecretKeyBytes {
        val: master_secret.serialize(),
    };

    transcript.internal_csp_transcript = match transcript.internal_csp_transcript {
        Groth20_Bls12_381(transcript) => {
            let mut mod_transcript = transcript.clone();
            mod_transcript.public_coefficients.coefficients[0] = PublicKeyBytes(public_key_bytes);
            Groth20_Bls12_381(mod_transcript)
        }
    };

    (transcript, master_secret_bytes)
}

#[derive(Copy, Clone, Debug)]
pub struct CombinedSignatureBytes {
    val: [u8; 48],
}

impl AsRef<[u8]> for CombinedSignatureBytes {
    fn as_ref(&self) -> &[u8] {
        &self.val
    }
}

pub fn sign_message(message: &[u8], secret_key: &SecretKeyBytes) -> CombinedSignatureBytes {
    let dst = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
    let secret = Scalar::deserialize(&secret_key.val).expect("Invalid SecretKeyBytes");
    let message = G1Affine::hash(dst, message);
    let signature = message * secret;

    CombinedSignatureBytes {
        val: signature.serialize(),
    }
}

fn number_of_nodes_from_usize(count: usize) -> NumberOfNodes {
    let count = NodeIndex::try_from(count).expect("node index overflow");
    NumberOfNodes::from(count)
}

fn ensure_matching_node_ids(
    receivers_in_config: &NiDkgReceivers,
    receiver_keys: &BTreeMap<NodeId, PublicKeyProto>,
) {
    let receivers_from_config: &BTreeSet<NodeId> = receivers_in_config.get();
    let receivers_from_keys: &BTreeSet<NodeId> = &receiver_keys.keys().cloned().collect();
    assert_eq!(
        receivers_from_keys, receivers_from_config,
        "the config's receivers must match the keys' receivers"
    );
}

fn first_dealer(dkg_config: &NiDkgConfig) -> NodeId {
    *dkg_config
        .dealers()
        .get()
        .iter()
        .next()
        .expect("internal error: expected the initial DKG config to contain a dealer")
}

fn fake_registry_with_encryption_keys(
    keys: &BTreeMap<NodeId, PublicKeyProto>,
    registry_version: RegistryVersion,
) -> FakeRegistryClient {
    let registry_data = Arc::new(ProtoRegistryDataProvider::new());
    for (node, key) in keys {
        registry_data
            .add(
                &make_crypto_node_key(*node, KeyPurpose::DkgDealingEncryption),
                registry_version,
                Some(key.clone()),
            )
            .expect("internal error: failed to add DKG dealing encryption key to fake registry");
    }
    let registry = FakeRegistryClient::new(registry_data);
    registry.update_to_latest_version();
    registry
}

fn map_with(dealer: NodeId, dealing: NiDkgDealing) -> BTreeMap<NodeId, NiDkgDealing> {
    let mut map = BTreeMap::new();
    map.insert(dealer, dealing);
    map
}

fn transcript_with_single_dealing<R: CryptoComponentRng>(
    dkg_config: &NiDkgConfig,
    dealer_crypto: TempCryptoComponentGeneric<R>,
    dealer_id: NodeId,
) -> NiDkgTranscript {
    let dealing = dealer_crypto
        .create_dealing(dkg_config)
        .expect("internal error: failed to create dealing");
    dealer_crypto
        .create_transcript(dkg_config, &map_with(dealer_id, dealing))
        .expect("internal error: failed to create transcript")
}

pub fn dummy_initial_dkg_transcript(
    committee: Vec<NodeId>,
    tag: NiDkgTag,
) -> InitialNiDkgTranscriptRecord {
    let threshold = committee.len() as u32 / 3 + 1;
    let transcript = dummy_transcript_for_tests_with_params(committee, tag, threshold, 0);
    InitialNiDkgTranscriptRecord {
        id: Some(transcript.dkg_id.into()),
        threshold: transcript.threshold.get().get(),
        committee: transcript
            .committee
            .iter()
            .map(|(_, c)| c.get().to_vec())
            .collect(),
        registry_version: 1,
        internal_csp_transcript: serde_cbor::to_vec(&transcript.internal_csp_transcript).unwrap(),
    }
}
