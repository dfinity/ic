use super::*;
use assert_matches::assert_matches;
use ic_ic00_types::{EcdsaCurve, EcdsaKeyId};
use ic_interfaces_registry::RegistryValue;
use ic_interfaces_state_manager::StateReader;
use ic_interfaces_state_manager_mocks::MockStateManager;
use ic_protobuf::registry::subnet::v1::SubnetRecord as SubnetRecordProto;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_proto_data_provider::{ProtoRegistryDataProvider, ProtoRegistryDataProviderError};
use ic_registry_routing_table::{routing_table_insert_subnet, CanisterMigrations, RoutingTable};
use ic_registry_subnet_features::{EcdsaConfig, SevFeatureStatus};
use ic_test_utilities::state_manager::FakeStateManager;
use ic_test_utilities::{
    notification::{Notification, WaitResult},
    types::{
        batch::BatchBuilder,
        ids::{node_test_id, subnet_test_id},
    },
};
use ic_test_utilities_logger::with_test_replica_logger;
use ic_test_utilities_metrics::{fetch_int_counter_vec, metric_vec};
use ic_test_utilities_registry::SubnetRecordBuilder;
use ic_types::{
    batch::{Batch, BatchMessages},
    crypto::threshold_sig::ni_dkg::{NiDkgTag, NiDkgTranscript},
    time::Time,
    NodeId, PrincipalId, Randomness,
};
use maplit::{btreemap, btreeset};
use std::{fmt::Debug, sync::Arc, time::Duration};

/// Helper function for testing the values of the
/// `METRIC_DELIVER_BATCH_COUNT` metric.
fn assert_deliver_batch_count_eq(
    ignored: u64,
    queue_full: u64,
    success: u64,
    metrics_registry: &MetricsRegistry,
) {
    assert_eq!(
        metric_vec(&[
            (&[(LABEL_STATUS, STATUS_IGNORED)], ignored),
            (&[(LABEL_STATUS, STATUS_QUEUE_FULL)], queue_full),
            (&[(LABEL_STATUS, STATUS_SUCCESS)], success),
        ]),
        fetch_int_counter_vec(metrics_registry, METRIC_DELIVER_BATCH_COUNT)
    );
}

#[test]
fn message_routing_does_not_block() {
    with_test_replica_logger(|log| {
        let timeout = Duration::from_secs(10);

        let mut mock = MockBatchProcessor::new();
        let started_notification = Arc::new(Notification::new());
        let notification = Arc::new(Notification::new());
        mock.expect_process_batch().returning({
            let notification = Arc::clone(&notification);
            let started_notification = Arc::clone(&started_notification);
            move |_| {
                started_notification.notify(());
                assert_eq!(
                    notification.wait_with_timeout(timeout),
                    WaitResult::Notified(())
                );
            }
        });

        let mock_box = Box::new(mock);
        let mut state_manager = MockStateManager::new();
        state_manager
            .expect_latest_state_height()
            .return_const(Height::from(0));

        let state_manager = Arc::new(state_manager);
        let metrics_registry = MetricsRegistry::new();
        let metrics = Arc::new(MessageRoutingMetrics::new(&metrics_registry));
        let mr =
            MessageRoutingImpl::from_batch_processor(state_manager, mock_box, metrics, log.clone());
        // We need to submit one extra batch because the very first one
        // is removed from the queue by the background worker.
        for batch_number in 1..BATCH_QUEUE_BUFFER_SIZE + 2 {
            let batch_number = Height::from(batch_number as u64);
            info!(log, "Delivering batch {}", batch_number);
            assert_eq!(batch_number, mr.expected_batch_height());
            mr.deliver_batch(BatchBuilder::default().batch_number(batch_number).build())
                .unwrap();
            assert_eq!(
                started_notification.wait_with_timeout(timeout),
                WaitResult::Notified(())
            );
            assert_deliver_batch_count_eq(0, 0, batch_number.get(), &metrics_registry);
        }

        let last_batch = Height::from(BATCH_QUEUE_BUFFER_SIZE as u64 + 2);
        assert_eq!(last_batch, mr.expected_batch_height());
        assert_eq!(
            mr.deliver_batch(BatchBuilder::default().batch_number(last_batch).build()),
            Err(MessageRoutingError::QueueIsFull)
        );
        assert_deliver_batch_count_eq(0, 1, 1 + BATCH_QUEUE_BUFFER_SIZE as u64, &metrics_registry);
        notification.notify(());
    });
}

/// Readable version of `SubnetRecordProto` holding only the relevant entries for
/// `BatchProcessorImpl::try_to_read_registry()`.
#[derive(Default, Debug, Clone)]
struct SubnetRecord<'a> {
    membership: &'a [NodeId],
    subnet_type: SubnetType,
    features: SubnetFeatures,
    ecdsa_config: EcdsaConfig,
    max_number_of_canisters: u64,
}

impl<'a> From<SubnetRecord<'a>> for SubnetRecordProto {
    fn from(record: SubnetRecord) -> SubnetRecordProto {
        SubnetRecordBuilder::new()
            .with_membership(record.membership)
            .with_subnet_type(record.subnet_type)
            .with_features(record.features.into())
            .with_ecdsa_config(record.ecdsa_config)
            .with_max_number_of_canisters(record.max_number_of_canisters)
            .build()
    }
}

/// Wrapper around data to be written to the registry. `Valid(_)` represents data that can be
/// written to the registry as is. `Corrupted` represents a registry record with corrupted data in
/// it and `Missing` represents data that is missing.
#[derive(Clone, Debug, PartialEq)]
enum Integrity<T: Clone> {
    Valid(T),
    Corrupted,
    Missing,
}

impl<T: Copy + Clone> Copy for Integrity<T> {}

impl<T: Clone + Debug> Integrity<T> {
    /// Maps an `Integrity<T>` to `Integrity<U>` by applying a function to a contained
    /// value (if `Valid`) or returns `Corrupted` (if `Corrupted`) or `Missing` (if `Missing`).
    fn map<U, F>(self, f: F) -> Integrity<U>
    where
        U: Clone + Debug,
        F: FnOnce(T) -> U,
    {
        match self {
            Self::Valid(value) => Integrity::<U>::Valid(f(value)),
            Self::Corrupted => Integrity::<U>::Corrupted,
            Self::Missing => Integrity::<U>::Missing,
        }
    }

    /// Converts from &Integrity<T> to Integrity<&T>.
    fn as_ref<'a>(&'a self) -> Integrity<&'a T> {
        match self {
            Self::Valid(value) => Integrity::<&'a T>::Valid(value),
            Self::Corrupted => Integrity::<&'a T>::Corrupted,
            Self::Missing => Integrity::<&'a T>::Missing,
        }
    }
}

/// Helper struct for `write_test_records()`.
#[derive(Clone)]
struct TestRecords<'a, const N: usize> {
    subnet_ids: Integrity<[SubnetId; N]>,
    subnet_records: [Integrity<&'a SubnetRecord<'a>>; N],
    ni_dkg_transcripts: [Integrity<Option<&'a NiDkgTranscript>>; N],
    nns_subnet_id: Integrity<SubnetId>,
    // EcdsaKeyId is used to make a key for the record. An empty `BTreeMap` therefore means no
    // recrods in the registry and wrapping it in `Integrity` would be redundant.
    ecdsa_signing_subnets: &'a BTreeMap<EcdsaKeyId, Integrity<Vec<SubnetId>>>,
    provisional_whitelist: Integrity<&'a ProvisionalWhitelist>,
    routing_table: Integrity<&'a RoutingTable>,
    canister_migrations: Integrity<&'a CanisterMigrations>,
}

/// Writes records into the registry using the `FakeRegistryClient`.
struct RegistryFixture {
    pub data_provider: Arc<ProtoRegistryDataProvider>,
    pub registry: Arc<FakeRegistryClient>,
}

impl RegistryFixture {
    fn new() -> Self {
        let data_provider = Arc::new(ProtoRegistryDataProvider::new());
        let registry = Arc::new(FakeRegistryClient::new(data_provider.clone()));
        Self {
            data_provider,
            registry,
        }
    }

    /// Writes a record into the registry using the provided key.
    /// - If `value` is `Valid(_)`, is is written to the registry as is.
    /// - If `value` is `Corrupted` a list of prime numbers is written instead. Reading this from
    ///   the registry will cause an error just as corrupted data would.
    /// - If `value` is `Missing` no record is written at all. Note that both a record with no data
    ///   in it and a record missing altogether results in the same behavior when reading the
    ///   registry.
    fn write_record<T: Clone + RegistryValue>(
        &self,
        key: &str,
        value: Integrity<T>,
    ) -> Result<(), ProtoRegistryDataProviderError> {
        match value {
            Integrity::Valid(value) => self.data_provider.add(
                key,
                self.registry.get_latest_version().increment(),
                Some(value),
            ),
            Integrity::Corrupted => {
                let corrupted_data: Vec<u8> = vec![
                    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 71, 73, 79,
                    83, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167,
                    173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
                ];
                self.data_provider.add(
                    key,
                    self.registry.get_latest_version().increment(),
                    Some(corrupted_data),
                )
            }
            Integrity::Missing => Ok(()),
        }
    }

    /// Writes the Ni DKG transcript corresponding to a subnet id into the registry.
    fn write_ni_dkg_transcripts(
        &self,
        subnet_id: SubnetId,
        transcript: Integrity<Option<&NiDkgTranscript>>,
    ) -> Result<(), ProtoRegistryDataProviderError> {
        use ic_protobuf::registry::subnet::v1::{
            CatchUpPackageContents, InitialNiDkgTranscriptRecord,
        };
        use ic_registry_keys::make_catch_up_package_contents_key;

        self.write_record(
            &make_catch_up_package_contents_key(subnet_id),
            transcript.map(|transcript| CatchUpPackageContents {
                initial_ni_dkg_transcript_low_threshold: transcript
                    .map(|transcript| InitialNiDkgTranscriptRecord::from(transcript.clone())),
                initial_ni_dkg_transcript_high_threshold: transcript
                    .map(|transcript| InitialNiDkgTranscriptRecord::from(transcript.clone())),
                ..Default::default()
            }),
        )
    }

    /// Writes the subnet record corresponding to a subnet id into the registry.
    fn write_subnet_record(
        &self,
        subnet_id: SubnetId,
        subnet_record: Integrity<&SubnetRecord>,
    ) -> Result<(), ProtoRegistryDataProviderError> {
        use ic_registry_keys::make_subnet_record_key;

        self.write_record(
            &make_subnet_record_key(subnet_id),
            subnet_record.map(|sr| SubnetRecordProto::from(sr.clone())),
        )
    }

    /// Writes the routing table into the registry.
    fn write_routing_table(
        &self,
        routing_table: Integrity<&RoutingTable>,
    ) -> Result<(), ProtoRegistryDataProviderError> {
        use ic_protobuf::registry::routing_table::v1::RoutingTable as RoutingTableProto;
        use ic_registry_keys::make_routing_table_record_key;

        self.write_record(
            &make_routing_table_record_key(),
            routing_table.map(|rt| RoutingTableProto::from(rt)),
        )
    }

    /// Writes the canister migrations list into the registry.
    fn write_canister_migrations(
        &self,
        canister_migrations: Integrity<&CanisterMigrations>,
    ) -> Result<(), ProtoRegistryDataProviderError> {
        use ic_protobuf::registry::routing_table::v1::CanisterMigrations as CanisterMigrationsProto;
        use ic_registry_keys::make_canister_migrations_record_key;

        self.write_record(
            &make_canister_migrations_record_key(),
            canister_migrations.map(|cm| CanisterMigrationsProto::from(cm)),
        )
    }

    /// Writes the the root (NNS) subnet id into the registry.
    fn write_root_subnet_id(
        &self,
        nns_subnet_id: Integrity<SubnetId>,
    ) -> Result<(), ProtoRegistryDataProviderError> {
        use ic_registry_keys::ROOT_SUBNET_ID_KEY;
        use ic_types::subnet_id_into_protobuf;

        self.write_record(
            ROOT_SUBNET_ID_KEY,
            nns_subnet_id.map(|id| subnet_id_into_protobuf(id)),
        )
    }

    /// Writes the ECDSA signing subnets into the registry.
    fn write_ecdsa_signing_subnets(
        &self,
        ecdsa_signing_subnets: &BTreeMap<EcdsaKeyId, Integrity<Vec<SubnetId>>>,
    ) -> Result<(), ProtoRegistryDataProviderError> {
        use ic_protobuf::registry::crypto::v1::EcdsaSigningSubnetList;
        use ic_registry_keys::make_ecdsa_signing_subnet_list_key;
        use ic_types::subnet_id_into_protobuf;

        for (ecdsa_key, subnet_ids) in ecdsa_signing_subnets.iter() {
            self.write_record(
                &make_ecdsa_signing_subnet_list_key(ecdsa_key),
                subnet_ids
                    .as_ref()
                    .map(|subnet_ids| EcdsaSigningSubnetList {
                        subnets: subnet_ids
                            .iter()
                            .map(|subnet_id| subnet_id_into_protobuf(*subnet_id))
                            .collect::<Vec<_>>(),
                    }),
            )?;
        }
        Ok(())
    }

    /// Writes the subnet list into the registry.
    fn write_subnet_list<const N: usize>(
        &self,
        subnet_ids: &Integrity<[SubnetId; N]>,
    ) -> Result<(), ProtoRegistryDataProviderError> {
        use ic_protobuf::registry::subnet::v1::SubnetListRecord;
        use ic_registry_keys::make_subnet_list_record_key;

        self.write_record(
            &make_subnet_list_record_key(),
            subnet_ids.as_ref().map(|subnet_ids| SubnetListRecord {
                subnets: subnet_ids
                    .iter()
                    .map(|subnet_id| subnet_id.get().as_slice().to_vec())
                    .collect(),
            }),
        )
    }

    /// Writes the provisional whitelist into the registry.
    fn write_provisional_whitelist(
        &self,
        provisional_whitelist: Integrity<&ProvisionalWhitelist>,
    ) -> Result<(), ProtoRegistryDataProviderError> {
        use ic_protobuf::registry::provisional_whitelist::v1::ProvisionalWhitelist as ProvisionalWhitelistProto;
        use ic_registry_keys::make_provisional_whitelist_record_key;

        self.write_record(
            &make_provisional_whitelist_record_key(),
            provisional_whitelist.map(|wl| ProvisionalWhitelistProto::from(wl.clone())),
        )
    }

    /// Writes the relevant records into the registry for testing
    /// `BatchProcessorImpl::try_to_read_registry()`.
    /// `subnet_ids` is used to write
    /// - the list subnet ids.
    /// - as the subnet id for each provided subnet record.
    /// - as the subnet id for each provided Ni DKG transcript.
    ///
    /// Note that a record in the registry can have no value. If an argument is `Option<_>`, a
    /// record will be created but no value will be written.
    /// If `subnet_ids` is `None`, no subnet records and no DKG transcripts are written since a
    /// subnet id is required for the corresponding keys.
    fn write_test_records<const N: usize>(
        &self,
        input: &TestRecords<N>,
    ) -> Result<(), ProtoRegistryDataProviderError> {
        self.write_subnet_list::<N>(&input.subnet_ids)?;
        if let Integrity::Valid(subnet_ids) = input.subnet_ids {
            for (subnet_id, subnet_record) in subnet_ids.iter().zip(input.subnet_records.iter()) {
                self.write_subnet_record(*subnet_id, *subnet_record)?;
            }
            for (subnet_id, transcripts) in subnet_ids.iter().zip(input.ni_dkg_transcripts.iter()) {
                self.write_ni_dkg_transcripts(*subnet_id, *transcripts)?;
            }
        }
        self.write_routing_table(input.routing_table)?;
        self.write_canister_migrations(input.canister_migrations)?;
        self.write_root_subnet_id(input.nns_subnet_id)?;
        self.write_ecdsa_signing_subnets(input.ecdsa_signing_subnets)?;
        self.write_provisional_whitelist(input.provisional_whitelist)?;
        self.registry.update_to_latest_version();
        Ok(())
    }
}

/// Fake state machine implementation used to instantiate a batch processor.
/// This enables direct testing of `BatchProcessorImpl::try_to_read_registry()`
/// and `BatchProcessorImpl::process_batch()`.
/// The implementation of the trait `StateMachine` below maps the `network_topology`
/// and the `subnet_record` into the state (just like the real one does); this allows
/// checking that these quantities are passed on to the state machine correctly.
///
/// Additionally the state machine itself holds an `Arc` for the execution registry
/// settings, which allows to check those are passed correctly as well.
/// `Arc<Mutex<_>>` is because `execute_round(&self, ..)` does not take a mutable
/// reference and because `BatchProcessorImpl` insists on the fake state machine in a
/// `Box` (rather than an `Arc` which we need to check the contents from the outside).
struct FakeStateMachine(Arc<Mutex<RegistryExecutionSettings>>);

impl StateMachine for FakeStateMachine {
    fn execute_round(
        &self,
        mut state: ReplicatedState,
        network_topology: NetworkTopology,
        _batch: Batch,
        subnet_features: SubnetFeatures,
        registry_settings: &RegistryExecutionSettings,
    ) -> ReplicatedState {
        state.metadata.network_topology = network_topology;
        state.metadata.own_subnet_features = subnet_features;
        *self.0.lock().unwrap() = registry_settings.clone();
        state
    }
}

/// Generates an instance of `BatchProcessorImpl` along with an `Arc` to its metrics;
/// an `Arc` to the underlying state manager; and an `Arc` to the registry settings
/// which are stored by the fake state machine.
fn make_batch_processor(
    registry: Arc<FakeRegistryClient>,
    log: ReplicaLogger,
) -> (
    BatchProcessorImpl,
    Arc<MessageRoutingMetrics>,
    Arc<FakeStateManager>,
    Arc<Mutex<RegistryExecutionSettings>>,
) {
    let metrics = Arc::new(MessageRoutingMetrics::new(&MetricsRegistry::default()));
    let state_manager = Arc::new(FakeStateManager::default());
    let registry_settings = Arc::new(Mutex::new(RegistryExecutionSettings {
        max_number_of_canisters: 0,
        provisional_whitelist: ProvisionalWhitelist::All,
        max_ecdsa_queue_size: 0,
        subnet_size: 0,
    }));
    let batch_processor = BatchProcessorImpl {
        state_manager: state_manager.clone(),
        state_machine: Box::new(FakeStateMachine(registry_settings.clone())),
        registry,
        bitcoin_config: BitcoinConfig::default(),
        metrics: metrics.clone(),
        log,
        malicious_flags: MaliciousFlags::default(),
    };
    (batch_processor, metrics, state_manager, registry_settings)
}

/// Convenience wrapper for `BatchProcessorImpl::try_to_read_registry()`.
fn try_to_read_registry(
    registry: Arc<FakeRegistryClient>,
    log: ReplicaLogger,
    own_subnet_id: SubnetId,
) -> Result<(NetworkTopology, SubnetFeatures, RegistryExecutionSettings), String> {
    let (batch_processor, _, _, _) = make_batch_processor(registry.clone(), log);
    batch_processor.try_to_read_registry(registry.get_latest_version(), own_subnet_id)
}

/// Tests that `BatchProcessorImpl::try_to_read_registry()` returns `Ok(_)`; and checks that the
/// records entered into the registry are read from the registry correctly.
///
/// Two subnets are used for this, one considered the 'own subnet'.
/// The subnet records are fully specified for 'own subnet' only, whereas the other subnet uses
/// default values whereever possible. This setup ensures records are parsed correctly and also
/// that different records are returned for different subnets.
///
/// Finally `BatchProcessorImpl::process_batch()` is called directly to check the
/// `network_topology`, the `subnet_record` and the `registry_execution_settings` sare handed
/// over to the state machine as intended.
#[test]
fn try_read_registry_succeeds_with_fully_specified_registry_records() {
    with_test_replica_logger(|log| {
        use Integrity::*;

        // Own subnet characteristics.
        let own_subnet_id = subnet_test_id(13);
        let own_subnet_record = SubnetRecord {
            membership: &[node_test_id(1), node_test_id(2)],
            subnet_type: SubnetType::Application,
            features: SubnetFeatures {
                canister_sandboxing: true,
                http_requests: true,
                sev_status: Some(SevFeatureStatus::Disabled),
                onchain_observability: Some(true),
            },
            ecdsa_config: EcdsaConfig {
                key_ids: vec![
                    EcdsaKeyId {
                        curve: EcdsaCurve::Secp256k1,
                        name: "ecdsa key 1".to_string(),
                    },
                    EcdsaKeyId {
                        curve: EcdsaCurve::Secp256k1,
                        name: "ecdsa key 2".to_string(),
                    },
                ],
                max_queue_size: Some(891),
                ..Default::default()
            },
            max_number_of_canisters: 387,
        };

        let own_transcript = NiDkgTranscript::dummy_transcript_for_tests_with_params(
            vec![node_test_id(123)], // committee
            NiDkgTag::HighThreshold, // dkg_tag
            2,                       // threshold
            3,                       // registry_version
        );

        // Other subnet characteristics.
        let other_subnet_id = subnet_test_id(17);
        let other_subnet_record = SubnetRecord::default();
        let other_transcript = NiDkgTranscript::dummy_transcript_for_tests();

        // General parameters.
        let nns_subnet_id = subnet_test_id(42);
        let provisional_whitelist = ProvisionalWhitelist::Set(btreeset! {
            PrincipalId::new_user_test_id(101),
            PrincipalId::new_node_test_id(103),
            PrincipalId::new_subnet_test_id(107)
        });
        let ecdsa_signing_subnets = btreemap! {
            EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: "key 1".to_string(),
            }
            => Valid(vec![subnet_test_id(1009), subnet_test_id(1013)]),
            EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: "key 2".to_string(),
            }
            => Valid(vec![subnet_test_id(1019)]),
        };
        let mut routing_table = RoutingTable::new();
        routing_table_insert_subnet(&mut routing_table, own_subnet_id).unwrap();
        routing_table_insert_subnet(&mut routing_table, other_subnet_id).unwrap();
        let mut canister_migrations = CanisterMigrations::new();
        canister_migrations
            .insert_ranges(
                routing_table.ranges(own_subnet_id),
                own_subnet_id,
                other_subnet_id,
            )
            .unwrap();

        let fixture = RegistryFixture::new();
        fixture
            .write_test_records(&TestRecords {
                subnet_ids: Valid([own_subnet_id, other_subnet_id]),
                subnet_records: [Valid(&own_subnet_record), Valid(&other_subnet_record)],
                ni_dkg_transcripts: [Valid(Some(&own_transcript)), Valid(Some(&other_transcript))],
                nns_subnet_id: Valid(nns_subnet_id),
                ecdsa_signing_subnets: &ecdsa_signing_subnets,
                provisional_whitelist: Valid(&provisional_whitelist),
                routing_table: Valid(&routing_table),
                canister_migrations: Valid(&canister_migrations),
            })
            .unwrap();

        // Reading from the registry must succeed for fully specified records.
        let (batch_processor, metrics, state_manager, registry_settings) =
            make_batch_processor(fixture.registry.clone(), log);
        let (network_topology, own_subnet_features, registry_execution_settings) = batch_processor
            .try_to_read_registry(fixture.registry.get_latest_version(), own_subnet_id)
            .unwrap();

        // Full specification includes the subnet size of `own_subnet_id`. Check the corresponding
        // critical error counter is untouched.
        assert_eq!(metrics.critical_error_missing_subnet_size.get(), 0);

        // Check network topology.
        assert_eq!(network_topology.subnets.len(), 2);
        for (subnet_id, subnet_record, transcript) in [
            (own_subnet_id, &own_subnet_record, &own_transcript),
            (other_subnet_id, &other_subnet_record, &other_transcript),
        ] {
            let subnet_topology = network_topology.subnets.get(&subnet_id).unwrap();
            assert_eq!(
                ic_crypto_utils_threshold_sig_der::public_key_to_der(
                    &transcript.public_key().into_bytes()
                )
                .unwrap(),
                subnet_topology.public_key,
            );
            assert_eq!(
                subnet_record
                    .membership
                    .iter()
                    .cloned()
                    .collect::<BTreeSet<_>>(),
                subnet_topology.nodes
            );
            assert_eq!(subnet_record.subnet_type, subnet_topology.subnet_type);
            assert_eq!(subnet_record.features, subnet_topology.subnet_features);
            assert_eq!(
                subnet_record
                    .ecdsa_config
                    .key_ids
                    .iter()
                    .cloned()
                    .collect::<BTreeSet<_>>(),
                subnet_topology.ecdsa_keys_held
            );
        }
        assert_eq!(nns_subnet_id, network_topology.nns_subnet_id);
        assert_eq!(
            ecdsa_signing_subnets,
            network_topology
                .ecdsa_signing_subnets
                .iter()
                .map(|(key, val)| (key.clone(), Valid(val.clone())))
                .collect::<BTreeMap<_, _>>()
        );
        assert_eq!(routing_table, *network_topology.routing_table);
        assert_eq!(canister_migrations, *network_topology.canister_migrations);

        // Check registry execution settings.
        assert_eq!(
            own_subnet_record.max_number_of_canisters,
            registry_execution_settings.max_number_of_canisters,
        );
        assert_eq!(
            provisional_whitelist,
            registry_execution_settings.provisional_whitelist,
        );
        assert_eq!(
            own_subnet_record.ecdsa_config.max_queue_size,
            Some(registry_execution_settings.max_ecdsa_queue_size),
        );
        assert_eq!(
            own_subnet_record.membership.len(),
            registry_execution_settings.subnet_size,
        );

        // Commit a state with `own_subnet_id` in its metadata to ensure the latest
        // state corresponds to the registry records written above.
        let (height, mut state) = state_manager.take_tip();
        state.metadata.own_subnet_id = own_subnet_id;
        state_manager.commit_and_certify(state, height.increment(), CertificationScope::Metadata);

        // Check `network_topology` and `subnet_features` are mapped into the new state correctly
        // by calling `BatchProcessorImpl::process_batch()` which will pass the `network_topology` and
        // the `subnet_features` on to `execute_round()` (in this case `FakeStateMachine::execute_round()`
        // defined above). Additionally check the `registry_execution_settings` are also passed
        // correctly (they are stored in the internal `Arc` of the fake state machine itself).
        let latest_state = state_manager.get_latest_state().take();
        assert_ne!(network_topology, latest_state.metadata.network_topology);
        assert_ne!(
            own_subnet_features,
            latest_state.metadata.own_subnet_features
        );
        assert_ne!(
            *registry_settings.lock().unwrap(),
            registry_execution_settings,
        );
        batch_processor.process_batch(Batch {
            batch_number: height.increment().increment(),
            requires_full_state_hash: false,
            messages: BatchMessages::default(),
            randomness: Randomness::new([123; 32]),
            ecdsa_subnet_public_keys: BTreeMap::default(),
            registry_version: fixture.registry.get_latest_version(),
            time: Time::from_nanos_since_unix_epoch(0),
            consensus_responses: Vec::new(),
        });
        let latest_state = state_manager.get_latest_state().take();
        assert_eq!(network_topology, latest_state.metadata.network_topology);
        assert_eq!(
            own_subnet_features,
            latest_state.metadata.own_subnet_features
        );
        assert_eq!(
            *registry_settings.lock().unwrap(),
            registry_execution_settings,
        );
    });
}

/// Tests that `BatchProcessorImpl::try_to_read_registry()` returns `Ok(_)` with the minimum amount
/// of records explicitly specified; and checks that the it returns `Err(_)` if any of those
/// records are missing.
#[test]
fn try_read_registry_succeeds_with_minimal_registry_records() {
    with_test_replica_logger(|log| {
        use Integrity::*;

        let own_subnet_id = subnet_test_id(13);
        let own_subnet_record = SubnetRecord {
            max_number_of_canisters: 784,
            ..Default::default()
        };
        let own_transcript = NiDkgTranscript::dummy_transcript_for_tests();
        let nns_subnet_id = subnet_test_id(42);

        let minimal_input = TestRecords {
            subnet_ids: Valid([own_subnet_id]),
            subnet_records: [Valid(&own_subnet_record)],
            ni_dkg_transcripts: [Valid(Some(&own_transcript))],
            nns_subnet_id: Valid(nns_subnet_id),
            ecdsa_signing_subnets: &BTreeMap::default(),
            provisional_whitelist: Missing,
            routing_table: Missing,
            canister_migrations: Missing,
        };

        let fixture = RegistryFixture::new();
        fixture.write_test_records(&minimal_input).unwrap();

        // Check that minimal specification returns `Ok(_)`.
        let (batch_processor, metrics, _, _) =
            make_batch_processor(fixture.registry.clone(), log.clone());
        let result = batch_processor
            .try_to_read_registry(fixture.registry.get_latest_version(), own_subnet_id);
        assert_matches!(result, Ok(_));

        // Minimal specification contains an empty `membership` for `own_subnet_id`. Check the
        // critical error for `subnet_size` has incremented.
        assert_eq!(metrics.critical_error_missing_subnet_size.get(), 1);
        // Check the subnet size was set to the maximum for a small app subnet.
        let (_, _, registry_execution_settings) = result.unwrap();
        assert_eq!(
            registry_execution_settings.subnet_size,
            SMALL_APP_SUBNET_MAX_SIZE
        );

        // Check that omitting any of these arguments returns `Err(_)`.
        let fixture = RegistryFixture::new();
        fixture
            .write_test_records(&TestRecords {
                subnet_ids: Missing,
                ..minimal_input
            })
            .unwrap();
        assert_matches!(
            try_to_read_registry(fixture.registry, log.clone(), own_subnet_id),
            Err(err) if err.ends_with("not found")
        );
        let fixture = RegistryFixture::new();
        fixture
            .write_test_records(&TestRecords {
                subnet_records: [Missing],
                ..minimal_input
            })
            .unwrap();
        assert_matches!(
            try_to_read_registry(fixture.registry, log.clone(), own_subnet_id),
            Err(err) if err.ends_with("not found")
        );
        let fixture = RegistryFixture::new();
        fixture
            .write_test_records(&TestRecords {
                ni_dkg_transcripts: [Missing],
                ..minimal_input
            })
            .unwrap();
        assert_matches!(
            try_to_read_registry(fixture.registry, log.clone(), own_subnet_id),
            Err(err) if err.ends_with("not found")
        );
        let fixture = RegistryFixture::new();
        fixture
            .write_test_records(&TestRecords {
                nns_subnet_id: Missing,
                ..minimal_input
            })
            .unwrap();
        assert_matches!(
            try_to_read_registry(fixture.registry, log, own_subnet_id),
            Err(err) if err.ends_with("not found")
        );
    });
}

/// Tests that `BatchProcessorImpl::try_to_read_registry()` returns `Err(_)` if records in the
/// registry hold corrupted data. Corrupted data is simulated by writing a string of prime numbers
/// (almost anything would do) rather than an actual struct into registry.
///
/// Note that Subnet Ids can be parsed from any string of u8, making this approach difficult for
/// them. A faulty Subnet Id can however have consequences elsewhere, which can be tested.
#[test]
fn try_to_read_registry_returns_errors_for_corrupted_records() {
    with_test_replica_logger(|log| {
        use Integrity::*;

        let own_subnet_id = subnet_test_id(13);
        let own_subnet_record = SubnetRecord {
            max_number_of_canisters: 784,
            ..Default::default()
        };
        let own_transcript = NiDkgTranscript::dummy_transcript_for_tests();
        let nns_subnet_id = subnet_test_id(42);

        let minimal_input = TestRecords {
            subnet_ids: Valid([own_subnet_id]),
            subnet_records: [Valid(&own_subnet_record)],
            ni_dkg_transcripts: [Valid(Some(&own_transcript))],
            nns_subnet_id: Valid(nns_subnet_id),
            ecdsa_signing_subnets: &BTreeMap::default(),
            provisional_whitelist: Missing,
            routing_table: Missing,
            canister_migrations: Missing,
        };

        // Corrupted Subnet Ids.
        // Any string of u8 can be successfully parsed into a Subnet Id.
        // However, reading a subnet record for a faulty Subnet Id triggers an error.
        let fixture = RegistryFixture::new();
        fixture
            .write_test_records(&TestRecords {
                subnet_ids: Corrupted,
                ..minimal_input
            })
            .unwrap();
        assert_matches!(
            try_to_read_registry(fixture.registry, log.clone(), own_subnet_id),
            Err(err) if err.starts_with("'subnet record") && err.ends_with("not found")
        );

        // Corrupted DKG transcripts.
        let fixture = RegistryFixture::new();
        fixture
            .write_test_records(&TestRecords {
                ni_dkg_transcripts: [Corrupted],
                ..minimal_input
            })
            .unwrap();
        assert_matches!(
            try_to_read_registry(fixture.registry, log.clone(), own_subnet_id),
            Err(err) if err.starts_with("Failed to read")
        );

        // Missing DKG transcript (as in `None` in the catch up package contents).
        let fixture = RegistryFixture::new();
        fixture
            .write_test_records(&TestRecords {
                ni_dkg_transcripts: [Valid(None)],
                ..minimal_input
            })
            .unwrap();
        assert_matches!(
            try_to_read_registry(fixture.registry, log.clone(), own_subnet_id),
            Err(err) if err.starts_with("Failed to read")
        );

        // Corrupted subnet record.
        let fixture = RegistryFixture::new();
        fixture
            .write_test_records(&TestRecords {
                subnet_records: [Corrupted],
                ..minimal_input
            })
            .unwrap();
        assert_matches!(
            try_to_read_registry(fixture.registry, log.clone(), own_subnet_id),
            Err(err) if err.starts_with("Failed to read")
        );

        // Corrupted NNS Subnet Id.
        let fixture = RegistryFixture::new();
        fixture
            .write_test_records(&TestRecords {
                nns_subnet_id: Corrupted,
                ..minimal_input
            })
            .unwrap();
        assert_matches!(
            try_to_read_registry(fixture.registry, log.clone(), own_subnet_id),
            Err(err) if err.starts_with("Failed to read")
        );

        // ECDSA signing subnets succeeds with everything. Writing random bytes will therefore not
        // trigger an error in `BatchProcessorImpl::try_read_registry()`.

        // Corrupted provisional whitelist.
        let fixture = RegistryFixture::new();
        fixture
            .write_test_records(&TestRecords {
                provisional_whitelist: Corrupted,
                ..minimal_input
            })
            .unwrap();
        assert_matches!(
            try_to_read_registry(fixture.registry, log.clone(), own_subnet_id),
            Err(err) if err.starts_with("Failed to read")
        );

        // Corrupted routing table.
        let fixture = RegistryFixture::new();
        fixture
            .write_test_records(&TestRecords {
                routing_table: Corrupted,
                ..minimal_input
            })
            .unwrap();
        assert_matches!(
            try_to_read_registry(fixture.registry, log.clone(), own_subnet_id),
            Err(err) if err.starts_with("Failed to read")
        );

        // Corrupted canister migrations.
        let fixture = RegistryFixture::new();
        fixture
            .write_test_records(&TestRecords {
                canister_migrations: Corrupted,
                ..minimal_input
            })
            .unwrap();
        assert_matches!(
            try_to_read_registry(fixture.registry, log, own_subnet_id),
            Err(err) if err.starts_with("Failed to read")
        );
    });
}

/// Checks the critical error counter for 'read from the registry failed' is incremented in
/// `BatchProcessorImpl::try_registry()` due to an error underneath.
///
/// This is done by spawning a thread that attempts to read from an empty registry using the next
/// current registry version (after an update). This will fail and thus get stuck and retry every
/// 100ms until it succeeds. Each cycle the critical error counter must be incremented.
///
/// After waiting 150ms, the registry is updated with minimal input which causes the read to
/// succeed (after at least one failed attempt) thus the future can be joined and the critical
/// error counter should be non-zero.
#[test]
fn check_critical_error_counter_is_incremented_for_read_failure() {
    with_test_replica_logger(|log| {
        use Integrity::*;

        let own_subnet_id = subnet_test_id(13);
        let own_subnet_record = SubnetRecord {
            max_number_of_canisters: 784,
            ..Default::default()
        };
        let own_transcript = NiDkgTranscript::dummy_transcript_for_tests();
        let nns_subnet_id = subnet_test_id(42);

        let minimal_input = TestRecords {
            subnet_ids: Valid([own_subnet_id]),
            subnet_records: [Valid(&own_subnet_record)],
            ni_dkg_transcripts: [Valid(Some(&own_transcript))],
            nns_subnet_id: Valid(nns_subnet_id),
            ecdsa_signing_subnets: &BTreeMap::default(),
            provisional_whitelist: Missing,
            routing_table: Missing,
            canister_migrations: Missing,
        };

        let fixture = RegistryFixture::new();
        let next_registry_version = fixture.registry.get_latest_version().increment();
        let (batch_processor, _, _, _) =
            make_batch_processor(fixture.registry.clone(), log.clone());

        // Try reading the registry at the next version; should return `Err(_)`.
        assert_matches!(
            batch_processor.try_to_read_registry(next_registry_version, own_subnet_id),
            Err(err) if err.contains("the requested version is not available locally")
        );
        // Write minimal records to the registry, reading the registry should now work.
        fixture.write_test_records(&minimal_input).unwrap();
        assert_matches!(
            batch_processor.try_to_read_registry(next_registry_version, own_subnet_id),
            Ok(_)
        );

        let fixture = RegistryFixture::new();
        let next_registry_version = fixture.registry.get_latest_version().increment();
        let (batch_processor, metrics, _, _) = make_batch_processor(fixture.registry.clone(), log);

        // Spawn a thread trying to read from the registry at the next version; this will fail
        // until we update the registry.
        let handle = std::thread::spawn(move || {
            batch_processor.read_registry(next_registry_version, own_subnet_id)
        });
        // Wait 150ms, then update the registry and join the thread above.
        std::thread::sleep(Duration::from_millis(150));
        fixture.write_test_records(&minimal_input).unwrap();
        handle.join().unwrap();

        // The critical error counter must have been incremented at least once.
        assert_ne!(metrics.critical_error_failed_to_read_registry.get(), 0);
    });
}
