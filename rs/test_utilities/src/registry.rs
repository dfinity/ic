use crate::crypto::empty_ni_dkg_transcripts_with_committee;
use ic_crypto::utils::ni_dkg::initial_ni_dkg_transcript_record_from_transcript;
use ic_interfaces::registry::{
    LocalStoreCertifiedTimeReader, RegistryClient, RegistryClientResult,
    RegistryClientVersionedResult,
};
use ic_interfaces::time_source::TimeSource;
use ic_protobuf::registry::subnet::v1::{CatchUpPackageContents, SubnetListRecord, SubnetRecord};
use ic_registry_client::fake::FakeRegistryClient;
use ic_registry_common::proto_registry_data_provider::ProtoRegistryDataProvider;
use ic_registry_keys::{
    make_catch_up_package_contents_key, make_subnet_list_record_key, make_subnet_record_key,
};
use ic_registry_subnet_type::SubnetType;
use ic_types::crypto::threshold_sig::ni_dkg::NiDkgTag;
use ic_types::{registry::RegistryClientError, PrincipalId, Time};
use ic_types::{NodeId, RegistryVersion, ReplicaVersion, SubnetId};
use mockall::predicate::*;
use mockall::*;
use std::sync::Arc;

mock! {
    pub RegistryClient {}

    pub trait RegistryClient: Send + Sync {
        fn get_value(&self, key: &str, version: RegistryVersion) -> RegistryClientResult<Vec<u8>>;
        fn get_versioned_value(
            &self,
            key: &str,
            version: RegistryVersion,
        ) -> RegistryClientVersionedResult<Vec<u8>>;

        fn get_key_family(&self,
            key_prefix: &str,
            version: RegistryVersion
        ) -> Result<Vec<String>, RegistryClientError>;

        fn get_latest_version(&self) -> RegistryVersion;

        fn get_version_timestamp(&self, registry_version: RegistryVersion) -> Option<Time>;
    }
}

/// Returns the registry with provided subnet records.
pub fn setup_registry(
    subnet_id: SubnetId,
    versions: Vec<(u64, SubnetRecord)>,
) -> Arc<dyn RegistryClient> {
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
    mut versions: Vec<(u64, SubnetRecord)>,
) -> (Arc<ProtoRegistryDataProvider>, Arc<FakeRegistryClient>) {
    let registry_data_provider = Arc::new(ProtoRegistryDataProvider::new());
    assert!(
        !versions.is_empty(),
        "Cannot setup a registry without records."
    );
    let (version, record) = &mut versions[0];

    insert_initial_dkg_transcript(*version, subnet_id, record, &registry_data_provider);

    for (version, record) in versions.iter().cloned() {
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
    use std::convert::TryFrom;
    let committee = record
        .membership
        .iter()
        .map(|n| NodeId::from(PrincipalId::try_from(&n[..]).unwrap()))
        .collect();
    let mut transcripts = empty_ni_dkg_transcripts_with_committee(committee, version);
    let high_threshold_transcript = initial_ni_dkg_transcript_record_from_transcript(
        transcripts
            .remove(&NiDkgTag::HighThreshold)
            .expect("Missing HighThreshold Transcript"),
    );
    let low_threshold_transcript = initial_ni_dkg_transcript_record_from_transcript(
        transcripts
            .remove(&NiDkgTag::LowThreshold)
            .expect("Missing LowThreshold Transcript"),
    );

    let cup_contents = CatchUpPackageContents {
        initial_ni_dkg_transcript_high_threshold: Some(high_threshold_transcript),
        initial_ni_dkg_transcript_low_threshold: Some(low_threshold_transcript),
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

pub fn add_subnet_record(
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
    let subnet_list_record = SubnetListRecord {
        subnets: vec![subnet_id.get().into_vec()],
    };
    // Set subnetwork list
    registry_data_provider
        .add(
            make_subnet_list_record_key().as_str(),
            registry_version,
            Some(subnet_list_record),
        )
        .unwrap();
}

/// Provides a `SubnetRecord` to unit tests
pub fn test_subnet_record() -> SubnetRecord {
    SubnetRecord {
        membership: vec![],
        ingress_bytes_per_block_soft_cap: 1024 * 1024,
        max_ingress_bytes_per_message: 60 * 1024 * 1024,
        max_ingress_messages_per_block: 1000,
        max_block_payload_size: 2 * 1024 * 1024,
        unit_delay_millis: 500,
        initial_notary_delay_millis: 1500,
        replica_version_id: ReplicaVersion::default().into(),
        dkg_interval_length: 59,
        dkg_dealings_per_block: 1,
        gossip_config: None,
        start_as_nns: false,
        subnet_type: SubnetType::Application.into(),
        is_halted: false,
        max_instructions_per_message: 5_000_000_000,
        max_instructions_per_round: 7_000_000_000,
        max_instructions_per_install_code: 200_000_000_000,
        features: None,
        max_number_of_canisters: 0,
        ssh_readonly_access: vec![],
        ssh_backup_access: vec![],
        ecdsa_config: None,
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

    pub fn with_subnet_type(mut self, subnet_type: SubnetType) -> Self {
        self.record.subnet_type = subnet_type.into();
        self
    }

    pub fn build(self) -> SubnetRecord {
        self.record
    }
}

pub struct FakeLocalStoreCertifiedTimeReader {
    time_source: Arc<dyn TimeSource>,
}
impl FakeLocalStoreCertifiedTimeReader {
    pub fn new(time_source: Arc<dyn TimeSource>) -> Self {
        Self { time_source }
    }
}
impl LocalStoreCertifiedTimeReader for FakeLocalStoreCertifiedTimeReader {
    fn read_certified_time(&self) -> Time {
        self.time_source.get_relative_time()
    }
}
