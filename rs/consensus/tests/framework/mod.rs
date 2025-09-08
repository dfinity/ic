#![allow(dead_code)]
#![allow(unused_imports)]
mod delivery;
mod driver;
mod execution;
pub mod malicious;
mod runner;
mod types;

use ic_consensus_dkg::get_dkg_summary_from_cup_contents;
pub use runner::ConsensusRunner;
pub use types::{
    ComponentModifier, ConsensusDependencies, ConsensusDriver, ConsensusInstance,
    ConsensusRunnerConfig, StopPredicate,
};

use ic_crypto_temp_crypto::{NodeKeysToGenerate, TempCryptoComponent, TempCryptoComponentGeneric};
use ic_crypto_test_utils_ni_dkg::{InitialNiDkgConfig, initial_dkg_transcript};
use ic_interfaces_registry::RegistryClient;
use ic_management_canister_types_private::{
    EcdsaCurve, EcdsaKeyId, MasterPublicKeyId, SchnorrAlgorithm, SchnorrKeyId, VetKdCurve,
    VetKdKeyId,
};
use ic_protobuf::registry::subnet::v1::{CatchUpPackageContents, InitialNiDkgTranscriptRecord};
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_client_helpers::{crypto::CryptoRegistry, subnet::SubnetRegistry};
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_registry_subnet_features::{ChainKeyConfig, KeyConfig};
use ic_test_utilities_consensus::make_genesis;
use ic_test_utilities_registry::SubnetRecordBuilder;
use ic_types::{
    NodeId, RegistryVersion, SubnetId,
    consensus::CatchUpPackage,
    crypto::{
        KeyPurpose,
        threshold_sig::ni_dkg::{NiDkgTag, NiDkgTargetId},
    },
    subnet_id_into_protobuf,
};
use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

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
            key_configs: test_master_public_key_ids()
                .iter()
                .map(|key_id| KeyConfig {
                    key_id: key_id.clone(),
                    pre_signatures_to_create_in_advance: if key_id.requires_pre_signatures() {
                        4
                    } else {
                        0
                    },
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
                .with_rng(ChaCha20Rng::from_seed(rng.r#gen()))
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
    let random_ni_dkg_target_id = NiDkgTargetId::new(rng.r#gen());
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

    // Add chain-key enabled subnet to registry
    for key_id in test_master_public_key_ids() {
        data_provider
            .add(
                &ic_registry_keys::make_chain_key_enabled_subnet_list_key(&key_id),
                registry_version,
                Some(
                    ic_protobuf::registry::crypto::v1::ChainKeyEnabledSubnetList {
                        subnets: vec![subnet_id_into_protobuf(subnet_id)],
                    },
                ),
            )
            .expect("Could not add chain-key enabled subnet list");
    }
    registry_client.reload();
    registry_client.update_to_latest_version();

    let cup_contents = registry_client
        .get_cup_contents(subnet_id, registry_client.get_latest_version())
        .expect("Failed to retreive the DKG transcripts from registry");
    let summary = get_dkg_summary_from_cup_contents(
        cup_contents.value.expect("Missing CUP contents"),
        subnet_id,
        &*registry_client,
        version,
    )
    .expect("Failed to get DKG summary from CUP contents")
    .with_current_transcripts(ni_transcripts);

    let cup = make_genesis(summary);
    (registry_client, cup, cryptos)
}

pub(crate) fn test_master_public_key_ids() -> Vec<MasterPublicKeyId> {
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
        MasterPublicKeyId::VetKd(VetKdKeyId {
            curve: VetKdCurve::Bls12_381_G2,
            name: "vetkd_test_key".to_string(),
        }),
    ]
}
