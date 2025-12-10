use ic_crypto_test_utils_ni_dkg::dummy_transcript_for_tests_with_params;
use ic_limits::INITIAL_NOTARY_DELAY;
use ic_management_canister_types_private::VetKdKeyId;
use ic_protobuf::registry::crypto::v1::AlgorithmId;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use ic_protobuf::registry::subnet::v1::ChainKeyInitialization;
use ic_protobuf::registry::subnet::v1::chain_key_initialization::Initialization;
use ic_protobuf::registry::subnet::v1::{
    CanisterCyclesCostSchedule, CatchUpPackageContents, InitialNiDkgTranscriptRecord,
    SubnetListRecord, SubnetRecord,
};
use ic_protobuf::types::v1::master_public_key_id::KeyId;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::{
    make_catch_up_package_contents_key, make_crypto_threshold_signing_pubkey_key,
    make_subnet_list_record_key, make_subnet_record_key,
};
use ic_registry_local_store::{LocalStoreImpl, compact_delta_to_changelog};
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_registry_subnet_features::ChainKeyConfig;
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use ic_types::crypto::threshold_sig::ni_dkg::NiDkgMasterPublicKeyId;
use ic_types::{
    NodeId, PrincipalId, RegistryVersion, ReplicaVersion, SubnetId,
    crypto::threshold_sig::ni_dkg::{NiDkgTag, NiDkgTranscript},
};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

fn empty_ni_dkg_transcript_with_committee(
    committee: &[NodeId],
    registry_version: u64,
    tag: NiDkgTag,
) -> NiDkgTranscript {
    dummy_transcript_for_tests_with_params(
        committee.to_vec(),
        tag.clone(),
        tag.threshold_for_subnet_of_size(committee.len()) as u32,
        registry_version,
    )
}

/// Returns the registry with provided subnet records.
pub fn setup_registry(
    subnet_id: SubnetId,
    versions: Vec<(u64, SubnetRecord)>,
) -> Arc<FakeRegistryClient> {
    let registry = setup_registry_non_final(subnet_id, versions).1;
    registry.update_to_latest_version();
    registry
}

/// Returns the registry with provided subnet records and the corresponding data
/// provider, which can be used for further registry updates. Note that the
/// returned registry is _NOT UPDATED_ to the latest version, as the data
/// provider can be used externally to add records corresponding to the latest
/// version.
pub fn setup_registry_non_final(
    subnet_id: SubnetId,
    versions: Vec<(u64, SubnetRecord)>,
) -> (Arc<ProtoRegistryDataProvider>, Arc<FakeRegistryClient>) {
    let registry_data_provider = Arc::new(ProtoRegistryDataProvider::new());
    assert!(
        !versions.is_empty(),
        "Cannot setup a registry without records."
    );
    let (version, record) = &versions[0];

    insert_initial_dkg_transcript(*version, subnet_id, record, &registry_data_provider);

    for (version, record) in versions {
        add_subnet_record(&registry_data_provider, version, subnet_id, record);
    }
    let registry = Arc::new(FakeRegistryClient::new(
        Arc::clone(&registry_data_provider) as Arc<_>
    ));
    (registry_data_provider, registry)
}

pub fn insert_initial_dkg_transcript(
    version: u64,
    subnet_id: SubnetId,
    record: &SubnetRecord,
    registry_data_provider: &Arc<ProtoRegistryDataProvider>,
) {
    let committee = record
        .membership
        .iter()
        .map(|n| NodeId::from(PrincipalId::try_from(&n[..]).unwrap()))
        .collect::<Vec<_>>();

    let high_threshold_transcript = InitialNiDkgTranscriptRecord::from(
        empty_ni_dkg_transcript_with_committee(&committee, version, NiDkgTag::HighThreshold),
    );
    let low_threshold_transcript = InitialNiDkgTranscriptRecord::from(
        empty_ni_dkg_transcript_with_committee(&committee, version, NiDkgTag::LowThreshold),
    );

    let chain_key_initializations = record
        .chain_key_config
        .iter()
        .flat_map(|config| config.key_configs.iter())
        .filter_map(|config| config.key_id.clone())
        .filter_map(|key_id| match key_id.key_id {
            Some(KeyId::Vetkd(ref vet_key_id)) => Some((
                key_id.clone(),
                empty_ni_dkg_transcript_with_committee(
                    &committee,
                    version,
                    NiDkgTag::HighThresholdForKey(NiDkgMasterPublicKeyId::VetKd(
                        VetKdKeyId::try_from(vet_key_id.clone()).unwrap(),
                    )),
                ),
            )),
            _ => None,
        })
        .map(|(key_id, transcript)| ChainKeyInitialization {
            key_id: Some(key_id),
            initialization: Some(Initialization::TranscriptRecord(
                InitialNiDkgTranscriptRecord::from(transcript),
            )),
        })
        .collect::<Vec<_>>();

    let cup_contents = CatchUpPackageContents {
        initial_ni_dkg_transcript_high_threshold: Some(high_threshold_transcript),
        initial_ni_dkg_transcript_low_threshold: Some(low_threshold_transcript),
        chain_key_initializations,
        ..Default::default()
    };

    // Insert initial DKG transcripts
    registry_data_provider
        .add(
            &make_catch_up_package_contents_key(subnet_id),
            RegistryVersion::from(version),
            Some(cup_contents),
        )
        .expect("Failed to add subnet record.");
}

pub fn add_single_subnet_record(
    registry_data_provider: &Arc<ProtoRegistryDataProvider>,
    version: u64,
    subnet_id: SubnetId,
    record: SubnetRecord,
) {
    let registry_version = RegistryVersion::from(version);
    registry_data_provider
        .add(
            &make_subnet_record_key(subnet_id),
            registry_version,
            Some(record),
        )
        .expect("Failed to add subnet record.");
}

pub fn add_subnet_key_record(
    registry_data_provider: &Arc<ProtoRegistryDataProvider>,
    version: u64,
    subnet_id: SubnetId,
    subnet_pubkey: ThresholdSigPublicKey,
) {
    let registry_version = RegistryVersion::from(version);
    let record = PublicKeyProto {
        algorithm: AlgorithmId::ThresBls12381 as i32,
        key_value: subnet_pubkey.into_bytes().to_vec(),
        version: 0,
        proof_data: None,
        timestamp: None,
    };
    registry_data_provider
        .add(
            &make_crypto_threshold_signing_pubkey_key(subnet_id),
            registry_version,
            Some(record),
        )
        .expect("Failed to add subnet threshold signing pubkey record.");
}

pub fn add_subnet_list_record(
    registry_data_provider: &Arc<ProtoRegistryDataProvider>,
    version: u64,
    subnet_ids: Vec<SubnetId>,
) {
    let registry_version = RegistryVersion::from(version);
    let subnet_list_record = SubnetListRecord {
        subnets: subnet_ids
            .into_iter()
            .map(|subnet_id| subnet_id.get().into_vec())
            .collect(),
    };
    registry_data_provider
        .add(
            make_subnet_list_record_key().as_str(),
            registry_version,
            Some(subnet_list_record),
        )
        .unwrap();
}

pub fn add_subnet_record(
    registry_data_provider: &Arc<ProtoRegistryDataProvider>,
    version: u64,
    subnet_id: SubnetId,
    record: SubnetRecord,
) {
    add_single_subnet_record(registry_data_provider, version, subnet_id, record);
    add_subnet_list_record(registry_data_provider, version, vec![subnet_id]);
}

/// Provides a `SubnetRecord` to unit tests
pub fn test_subnet_record() -> SubnetRecord {
    SubnetRecord {
        membership: vec![],
        max_ingress_bytes_per_message: 2 * 1024 * 1024,
        max_ingress_messages_per_block: 1000,
        max_block_payload_size: 4 * 1024 * 1024,
        unit_delay_millis: 500,
        initial_notary_delay_millis: INITIAL_NOTARY_DELAY.as_millis() as u64,
        replica_version_id: ReplicaVersion::default().into(),
        dkg_interval_length: 59,
        dkg_dealings_per_block: 1,
        start_as_nns: false,
        subnet_type: SubnetType::Application.into(),
        is_halted: false,
        halt_at_cup_height: false,
        features: Some(Default::default()),
        max_number_of_canisters: 0,
        ssh_readonly_access: vec![],
        ssh_backup_access: vec![],
        chain_key_config: None,
        canister_cycles_cost_schedule: CanisterCyclesCostSchedule::Normal as i32,
        recalled_replica_version_ids: vec![],
    }
}

pub struct SubnetRecordBuilder {
    record: SubnetRecord,
}

impl Default for SubnetRecordBuilder {
    fn default() -> Self {
        Self {
            record: test_subnet_record(),
        }
    }
}

impl SubnetRecordBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn with_max_ingress_bytes_per_message(
        mut self,
        max_ingress_bytes_per_message: u64,
    ) -> Self {
        self.record.max_ingress_bytes_per_message = max_ingress_bytes_per_message;
        self
    }

    pub fn with_max_ingress_messages_per_block(
        mut self,
        max_ingress_messages_per_block: u64,
    ) -> Self {
        self.record.max_ingress_messages_per_block = max_ingress_messages_per_block;
        self
    }

    pub fn with_max_block_payload_size(mut self, max_block_payload_size: u64) -> Self {
        self.record.max_block_payload_size = max_block_payload_size;
        self
    }

    pub fn from(committee: &[NodeId]) -> Self {
        Self::new().with_committee(committee)
    }

    pub fn with_replica_version(mut self, version: &str) -> Self {
        self.record.replica_version_id = version.into();
        self
    }

    pub fn with_dkg_interval_length(mut self, len: u64) -> Self {
        self.record.dkg_interval_length = len;
        self
    }

    pub fn with_committee(mut self, committee: &[NodeId]) -> Self {
        let raw_node_ids: Vec<Vec<u8>> = committee
            .iter()
            .cloned()
            .map(|n| n.get().into_vec())
            .collect();
        self.record.membership = raw_node_ids;
        self
    }

    pub fn with_is_halted(mut self, is_halted: bool) -> Self {
        self.record.is_halted = is_halted;
        self
    }

    pub fn with_halt_at_cup_height(mut self, halt_at_cup_height: bool) -> Self {
        self.record.halt_at_cup_height = halt_at_cup_height;
        self
    }

    pub fn with_subnet_type(mut self, subnet_type: SubnetType) -> Self {
        self.record.subnet_type = subnet_type.into();
        self
    }

    pub fn with_features(mut self, features: SubnetFeatures) -> Self {
        self.record.features = Some(features.into());
        self
    }

    pub fn with_chain_key_config(mut self, chain_key_config: ChainKeyConfig) -> Self {
        self.record.chain_key_config = Some(chain_key_config.into());
        self
    }

    pub fn with_unit_delay(mut self, unit_delay: Duration) -> Self {
        self.record.unit_delay_millis = unit_delay.as_millis() as u64;
        self
    }

    pub fn with_membership(mut self, node_ids: &[NodeId]) -> Self {
        self.record.membership = node_ids
            .iter()
            .map(|node_id| node_id.get().as_slice().to_vec())
            .collect();
        self
    }

    pub fn with_max_number_of_canisters(mut self, max_number_of_canisters: u64) -> Self {
        self.record.max_number_of_canisters = max_number_of_canisters;
        self
    }

    pub fn with_dkg_dealings_per_block(mut self, dkg_dealings_per_block: u64) -> Self {
        self.record.dkg_dealings_per_block = dkg_dealings_per_block;
        self
    }

    pub fn build(self) -> SubnetRecord {
        self.record
    }
}

/// Gets a `LocalStore` holding mainnet registry snapshot from around jan. 2022.
pub fn get_mainnet_delta_00_6d_c1() -> (TempDir, LocalStoreImpl) {
    let tempdir = TempDir::new().unwrap();

    let changelog =
        compact_delta_to_changelog(ic_registry_local_store_artifacts::MAINNET_DELTA_00_6D_C1)
            .expect("")
            .1;
    let store = LocalStoreImpl::from_changelog(changelog, tempdir.path()).unwrap();

    (tempdir, store)
}
