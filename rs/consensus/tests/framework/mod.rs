#![allow(dead_code)]
#![allow(unused_imports)]
mod delivery;
mod driver;
mod execution;
pub mod malicious;
mod runner;
mod types;

pub use runner::ConsensusRunner;
pub use types::{
    ComponentModifier, ConsensusDependencies, ConsensusDriver, ConsensusInstance,
    ConsensusRunnerConfig, StopPredicate,
};

use ic_crypto_temp_crypto::{NodeKeysToGenerate, TempCryptoComponent, TempCryptoComponentGeneric};
use ic_crypto_test_utils_ni_dkg::{initial_dkg_transcript, InitialNiDkgConfig};
use ic_interfaces_registry::RegistryClient;
use ic_management_canister_types::{
    EcdsaCurve, EcdsaKeyId, MasterPublicKeyId, SchnorrAlgorithm, SchnorrKeyId,
};
use ic_protobuf::registry::subnet::v1::{CatchUpPackageContents, InitialNiDkgTranscriptRecord};
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_client_helpers::crypto::CryptoRegistry;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_registry_subnet_features::{ChainKeyConfig, EcdsaConfig, KeyConfig};
use ic_test_utilities_consensus::make_genesis;
use ic_test_utilities_registry::SubnetRecordBuilder;
use ic_types::{
    consensus::CatchUpPackage,
    crypto::{
        threshold_sig::ni_dkg::{NiDkgTag, NiDkgTargetId},
        KeyPurpose,
    },
    subnet_id_into_protobuf, NodeId, RegistryVersion, SubnetId,
};
use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Setup a subnet of the given subnet_id and node_ids by creating an initial registry
/// with required records, including subnet record, node record, node public keys,
/// catch-up package (with proper NiDKG transcripts).
///
/// Return the registry client, catch-up package, and a list of crypto components, one
/// for each node.
pub fn setup_subnet<R: Rng + CryptoRng>(
    subnet_id: SubnetId,
    node_ids: &[NodeId],
    rng: &mut R,
) -> (
    Arc<dyn RegistryClient>,
    CatchUpPackage,
    Vec<Arc<TempCryptoComponentGeneric<ChaCha20Rng>>>,
) {
    let initial_version = 1;
    let registry_version = RegistryVersion::from(initial_version);
    let data_provider = Arc::new(ProtoRegistryDataProvider::new());
    let registry_client = Arc::new(FakeRegistryClient::new(Arc::clone(&data_provider) as Arc<_>));

    let subnet_record = SubnetRecordBuilder::from(node_ids)
        .with_dkg_interval_length(19)
        .with_chain_key_config(ChainKeyConfig {
            key_configs: test_threshold_key_ids()
                .iter()
                .map(|key_id| KeyConfig {
                    key_id: key_id.clone(),
                    pre_signatures_to_create_in_advance: 4,
                    max_queue_size: 40,
                })
                .collect(),
            ..ChainKeyConfig::default()
        })
        .build();
    data_provider
        .add(
            &ic_registry_keys::make_subnet_record_key(subnet_id),
            registry_version,
            Some(subnet_record),
        )
        .expect("Could not add node record.");
    let cryptos: Vec<_> = node_ids
        .iter()
        .map(|node_id| {
            TempCryptoComponent::builder()
                .with_node_id(*node_id)
                .with_registry_client_and_data(registry_client.clone(), data_provider.clone())
                .with_keys(NodeKeysToGenerate::all())
                .with_rng(ChaCha20Rng::from_seed(rng.gen()))
                .build_arc()
        })
        .collect();

    // This is required by the XNet payload builder.
    for node in node_ids.iter() {
        data_provider
            .add(
                &ic_registry_keys::make_node_record_key(*node),
                registry_version,
                Some(ic_protobuf::registry::node::v1::NodeRecord::default()),
            )
            .expect("Could not add node record.");
    }

    // Make CUPContent from initial DKG
    registry_client.reload();
    let version = registry_client.get_latest_version();
    let dkg_dealing_encryption_pubkeys: BTreeMap<_, _> = node_ids
        .iter()
        .map(|node_id| {
            (
                *node_id,
                registry_client
                    .get_crypto_key_for_node(*node_id, KeyPurpose::DkgDealingEncryption, version)
                    .unwrap()
                    .unwrap(),
            )
        })
        .collect();
    let random_ni_dkg_target_id = NiDkgTargetId::new(rng.gen());
    let node_ids = node_ids.iter().copied().collect::<BTreeSet<_>>();
    let ni_dkg_transcript_low_threshold = initial_dkg_transcript(
        InitialNiDkgConfig::new(
            &node_ids,
            subnet_id,
            NiDkgTag::LowThreshold,
            random_ni_dkg_target_id,
            registry_version,
        ),
        &dkg_dealing_encryption_pubkeys,
        rng,
    );
    let ni_dkg_transcript_high_threshold = initial_dkg_transcript(
        InitialNiDkgConfig::new(
            &node_ids,
            subnet_id,
            NiDkgTag::HighThreshold,
            random_ni_dkg_target_id,
            registry_version,
        ),
        &dkg_dealing_encryption_pubkeys,
        rng,
    );
    /*
            let subnet_threshold_signing_public_key = PublicKey::from(ThresholdSigPublicKey::from(
                &ni_dkg_transcript_high_threshold,
            ));
    */
    let ni_transcripts: BTreeMap<_, _> = vec![
        (
            NiDkgTag::LowThreshold,
            ni_dkg_transcript_low_threshold.clone(),
        ),
        (
            NiDkgTag::HighThreshold,
            ni_dkg_transcript_high_threshold.clone(),
        ),
    ]
    .into_iter()
    .collect();

    let subnet_dkg = CatchUpPackageContents {
        initial_ni_dkg_transcript_low_threshold: Some(InitialNiDkgTranscriptRecord::from(
            ni_dkg_transcript_low_threshold,
        )),
        initial_ni_dkg_transcript_high_threshold: Some(InitialNiDkgTranscriptRecord::from(
            ni_dkg_transcript_high_threshold,
        )),
        ..Default::default()
    };

    data_provider
        .add(
            &ic_registry_keys::make_catch_up_package_contents_key(subnet_id),
            registry_version,
            Some(subnet_dkg),
        )
        .expect("Could not add node record.");

    // Add threshold signing subnet to registry
    for key_id in test_threshold_key_ids() {
        data_provider
            .add(
                &ic_registry_keys::make_chain_key_signing_subnet_list_key(&key_id),
                registry_version,
                Some(
                    ic_protobuf::registry::crypto::v1::ChainKeySigningSubnetList {
                        subnets: vec![subnet_id_into_protobuf(subnet_id)],
                    },
                ),
            )
            .expect("Could not add chain key signing subnet list");
    }
    registry_client.reload();
    registry_client.update_to_latest_version();

    let summary = ic_consensus::dkg::make_genesis_summary(
        &*registry_client,
        subnet_id,
        Option::from(version),
    )
    .with_current_transcripts(ni_transcripts);
    let cup = make_genesis(summary);
    (registry_client, cup, cryptos)
}

pub(crate) fn test_threshold_key_ids() -> Vec<MasterPublicKeyId> {
    vec![
        MasterPublicKeyId::Ecdsa(EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "ecdsa_test_key".to_string(),
        }),
        MasterPublicKeyId::Schnorr(SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Ed25519,
            name: "ed25519_test_key".to_string(),
        }),
        MasterPublicKeyId::Schnorr(SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Bip340Secp256k1,
            name: "bip340_test_key".to_string(),
        }),
    ]
}
