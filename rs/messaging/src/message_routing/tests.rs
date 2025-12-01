use self::routing::demux::Demux;
use self::routing::stream_handler::StreamHandler;
use self::scheduling::valid_set_rule::ValidSetRule;
use crate::routing::demux::DemuxImpl;

use super::*;
use assert_matches::assert_matches;
use ic_crypto_test_utils_ni_dkg::{
    dummy_transcript_for_tests, dummy_transcript_for_tests_with_params,
};
use ic_interfaces_registry::RegistryValue;
use ic_interfaces_state_manager::StateReader;
use ic_interfaces_state_manager_mocks::MockStateManager;
use ic_management_canister_types_private::{EcdsaCurve, EcdsaKeyId, MasterPublicKeyId};
use ic_protobuf::registry::crypto::v1::{ChainKeyEnabledSubnetList, PublicKey as PublicKeyProto};
use ic_protobuf::registry::subnet::v1::SubnetRecord as SubnetRecordProto;
use ic_protobuf::registry::{
    api_boundary_node::v1::ApiBoundaryNodeRecord, node::v1::IPv4InterfaceConfig,
    node::v1::NodeRecord,
};
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::{make_canister_ranges_key, make_chain_key_enabled_subnet_list_key};
use ic_registry_local_registry::LocalRegistry;
use ic_registry_proto_data_provider::{ProtoRegistryDataProvider, ProtoRegistryDataProviderError};
use ic_registry_routing_table::{CanisterMigrations, RoutingTable, routing_table_insert_subnet};
use ic_registry_subnet_features::{ChainKeyConfig, KeyConfig};
use ic_replicated_state::Stream;
use ic_test_utilities::state_manager::FakeStateManager;
use ic_test_utilities_logger::with_test_replica_logger;
use ic_test_utilities_metrics::{fetch_int_counter_vec, fetch_int_gauge_vec, metric_vec};
use ic_test_utilities_registry::{SubnetRecordBuilder, get_mainnet_delta_00_6d_c1};
use ic_test_utilities_state::CanisterStateBuilder;
use ic_test_utilities_types::{
    batch::BatchBuilder,
    ids::{canister_test_id, node_test_id, subnet_test_id},
};
use ic_types::batch::BlockmakerMetrics;
use ic_types::xnet::{StreamIndexedQueue, StreamSlice};
use ic_types::{CanisterId, ReplicaVersion};
use ic_types::{
    NodeId, PrincipalId, Randomness,
    batch::{Batch, BatchMessages},
    crypto::AlgorithmId,
    crypto::threshold_sig::ni_dkg::{NiDkgTag, NiDkgTranscript},
    time::Time,
};
use maplit::{btreemap, btreeset};
use std::{fmt::Debug, str::FromStr, sync::Arc, time::Duration};

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

mod notification {
    use std::sync::{Condvar, Mutex};
    use std::time::Duration;

    /// One-off notification that can be used to synchronize two threads.
    ///
    /// ```no_run
    /// use notification::{Notification, WaitResult};
    /// use std::sync::Arc;
    /// use std::thread;
    /// use std::time::Duration;
    ///
    /// let notification = Arc::new(Notification::new());
    /// let handle = thread::spawn({
    ///     let notification = Arc::clone(&notification);
    ///     move || {
    ///         assert_eq!(
    ///             notification.wait_with_timeout(Duration::from_secs(10)),
    ///             WaitResult::Notified(()),
    ///         );
    ///     }
    /// });
    /// notification.notify(());
    /// handle.join().unwrap();
    /// ```
    pub struct Notification<T> {
        mutex: Mutex<Option<T>>,
        condvar: Condvar,
    }

    /// The result of the `wait_with_timeout` call.
    #[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
    pub enum WaitResult<T> {
        Notified(T),
        TimedOut,
    }

    impl<T> Default for Notification<T> {
        fn default() -> Self {
            Self {
                mutex: Mutex::new(None),
                condvar: Condvar::new(),
            }
        }
    }

    impl<T> Notification<T>
    where
        T: Clone + std::fmt::Debug + PartialEq,
    {
        /// Create a new notification that is not raised.
        pub fn new() -> Self {
            Self::default()
        }

        /// Set the notification to the raised state. Once notification is
        /// saturated, it stays saturated forever, there is no way to reset it.
        ///
        /// # Panics
        ///
        /// Panics if `notify` is called twice with different values.
        pub fn notify(&self, value: T) {
            {
                let mut guard = self.mutex.lock().unwrap();
                if let Some(ref old_value) = *guard {
                    if value != *old_value {
                        panic!(
                            "Notified twice with different values: first {old_value:?}, then {value:?}"
                        );
                    } else {
                        return;
                    }
                }
                *guard = Some(value);
            }
            self.condvar.notify_all();
        }

        /// Wait for another thread to call `notify`, but no longer than
        /// `duration`.
        ///
        /// Returns `WaitResult::Notified(T)` if the notification was raised and
        /// `WaitResult::TimedOut` if it didn't happen within `duration`.
        pub fn wait_with_timeout(&self, duration: Duration) -> WaitResult<T> {
            let guard = self.mutex.lock().unwrap();

            if let Some(ref value) = *guard {
                return WaitResult::Notified(value.clone());
            }

            let (guard, _result) = self.condvar.wait_timeout(guard, duration).unwrap();
            match *guard {
                Some(ref value) => WaitResult::Notified(value.clone()),
                None => WaitResult::TimedOut,
            }
        }
    }

    #[test]
    fn test_single_threaded_notification() {
        let notification = Notification::<i32>::new();
        assert_eq!(
            notification.wait_with_timeout(Duration::from_millis(0)),
            WaitResult::TimedOut
        );

        notification.notify(1);
        assert_eq!(
            notification.wait_with_timeout(Duration::from_millis(0)),
            WaitResult::Notified(1)
        );
    }

    #[test]
    #[should_panic(expected = "first 1, then 2")]
    fn test_panics_on_incompatible_notify() {
        let notification = Notification::<i32>::new();
        notification.notify(1);
        notification.notify(2);
    }

    #[test]
    fn test_notify_same_value_twice_does_not_panic() {
        let notification = Notification::<i32>::new();
        notification.notify(1);
        notification.notify(1);
        assert_eq!(
            notification.wait_with_timeout(Duration::from_millis(0)),
            WaitResult::Notified(1)
        );
    }
}

#[test]
fn message_routing_does_not_block() {
    use notification::{Notification, WaitResult};

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
        let metrics = MessageRoutingMetrics::new(&metrics_registry);
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
#[derive(Clone, Debug, Default)]
struct SubnetRecord<'a> {
    membership: &'a [NodeId],
    subnet_type: SubnetType,
    features: SubnetFeatures,
    chain_key_config: ChainKeyConfig,
    max_number_of_canisters: u64,
}

impl From<SubnetRecord<'_>> for SubnetRecordProto {
    fn from(record: SubnetRecord) -> SubnetRecordProto {
        SubnetRecordBuilder::new()
            .with_membership(record.membership)
            .with_subnet_type(record.subnet_type)
            .with_features(record.features)
            .with_chain_key_config(record.chain_key_config)
            .with_max_number_of_canisters(record.max_number_of_canisters)
            .build()
    }
}

/// Wrapper around data to be written to the registry. `Valid(_)` represents data that can be
/// written to the registry as is. `Corrupted` represents a registry record with corrupted data in
/// it and `Missing` represents data that is missing.
#[derive(Clone, PartialEq, Debug)]
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
    // MasterPublicKeyId is used to make a key for the record. An empty `BTreeMap` therefore means no
    // records in the registry and wrapping it in `Integrity` would be redundant.
    chain_key_enabled_subnets: &'a BTreeMap<MasterPublicKeyId, Integrity<Vec<SubnetId>>>,
    provisional_whitelist: Integrity<&'a ProvisionalWhitelist>,
    routing_table: Integrity<&'a RoutingTable>,
    canister_migrations: Integrity<&'a CanisterMigrations>,
    node_public_keys: &'a BTreeMap<NodeId, Integrity<PublicKeyProto>>,
    api_boundary_node_records: &'a BTreeMap<NodeId, Integrity<ApiBoundaryNodeRecord>>,
    node_records: &'a BTreeMap<NodeId, Integrity<NodeRecord>>,
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
        use ic_registry_transport::pb::v1::{RegistryMutation, registry_mutation::Type};
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
                self.data_provider.add_mutations(vec![RegistryMutation {
                    mutation_type: Type::Insert as i32,
                    key: key.as_bytes().to_vec(),
                    value: corrupted_data,
                }])
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

        self.write_record(
            &make_canister_ranges_key(CanisterId::from_u64(0)),
            routing_table.map(RoutingTableProto::from),
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
            canister_migrations.map(CanisterMigrationsProto::from),
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
            nns_subnet_id.map(subnet_id_into_protobuf),
        )
    }

    /// Writes the chain key enabled subnets into the registry.
    fn write_chain_key_enabled_subnets(
        &self,
        chain_key_enabled_subnets: &BTreeMap<MasterPublicKeyId, Integrity<Vec<SubnetId>>>,
    ) -> Result<(), ProtoRegistryDataProviderError> {
        use ic_types::subnet_id_into_protobuf;

        for (key_id, subnet_ids) in chain_key_enabled_subnets.iter() {
            self.write_record(
                &make_chain_key_enabled_subnet_list_key(key_id),
                subnet_ids
                    .as_ref()
                    .map(|subnet_ids| ChainKeyEnabledSubnetList {
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

    // Writes node public keys into the registry.
    fn write_node_public_keys(
        &self,
        node_public_keys: &BTreeMap<NodeId, Integrity<PublicKeyProto>>,
    ) -> Result<(), ProtoRegistryDataProviderError> {
        use ic_registry_keys::make_crypto_node_key;

        for (node_id, public_key) in node_public_keys.iter() {
            self.write_record(
                &make_crypto_node_key(*node_id, KeyPurpose::NodeSigning),
                public_key.clone(),
            )?;
        }
        Ok(())
    }

    // Writes API Boundary Node records into the registry.
    fn write_api_boundary_nodes_records(
        &self,
        api_boundary_node_records: &BTreeMap<NodeId, Integrity<ApiBoundaryNodeRecord>>,
    ) -> Result<(), ProtoRegistryDataProviderError> {
        use ic_registry_keys::make_api_boundary_node_record_key;

        for (node_id, record) in api_boundary_node_records.iter() {
            self.write_record(&make_api_boundary_node_record_key(*node_id), record.clone())?;
        }
        Ok(())
    }

    // Writes node records into the registry.
    fn write_node_records(
        &self,
        node_records: &BTreeMap<NodeId, Integrity<NodeRecord>>,
    ) -> Result<(), ProtoRegistryDataProviderError> {
        use ic_registry_keys::make_node_record_key;

        for (node_id, record) in node_records.iter() {
            self.write_record(&make_node_record_key(*node_id), record.clone())?;
        }
        Ok(())
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
        self.write_chain_key_enabled_subnets(input.chain_key_enabled_subnets)?;
        self.write_provisional_whitelist(input.provisional_whitelist)?;
        self.write_node_public_keys(input.node_public_keys)?;
        self.write_api_boundary_nodes_records(input.api_boundary_node_records)?;
        self.write_node_records(input.node_records)?;
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
        node_public_keys: NodePublicKeys,
        api_boundary_nodes: ApiBoundaryNodes,
    ) -> ReplicatedState {
        state.metadata.network_topology = network_topology;
        state.metadata.own_subnet_features = subnet_features;
        state.metadata.node_public_keys = node_public_keys;
        state.metadata.api_boundary_nodes = api_boundary_nodes;
        let mut canister_states = BTreeMap::new();
        canister_states.insert(
            canister_test_id(1),
            CanisterStateBuilder::new()
                .with_wasm(vec![2; 1024 * 1024]) // 1MiB wasm
                .build(),
        );
        canister_states.insert(
            canister_test_id(2),
            CanisterStateBuilder::new()
                .with_wasm(vec![5; 10 * 1024]) // 10 KiB wasm
                .build(),
        );
        state.put_canister_states(canister_states);
        *self.0.lock().unwrap() = registry_settings.clone();
        state
    }
}

/// Generates an instance of `BatchProcessorImpl` along with an `Arc` to its metrics;
/// an `Arc` to the underlying state manager; and an `Arc` to the registry settings
/// which are stored by the fake state machine.
fn make_batch_processor<RegistryClient_: RegistryClient + 'static>(
    registry: Arc<RegistryClient_>,
    log: ReplicaLogger,
) -> (
    BatchProcessorImpl<RegistryClient_>,
    MessageRoutingMetrics,
    Arc<FakeStateManager>,
    Arc<Mutex<RegistryExecutionSettings>>,
) {
    let metrics = MessageRoutingMetrics::new(&MetricsRegistry::default());
    let state_manager = Arc::new(FakeStateManager::default());
    let registry_settings = Arc::new(Mutex::new(RegistryExecutionSettings {
        max_number_of_canisters: 0,
        provisional_whitelist: ProvisionalWhitelist::All,
        chain_key_settings: BTreeMap::new(),
        subnet_size: 0,
        node_ids: BTreeSet::new(),
        registry_version: RegistryVersion::default(),
        canister_cycles_cost_schedule: ic_types::batch::CanisterCyclesCostSchedule::Normal,
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
) -> Result<
    (
        NetworkTopology,
        SubnetFeatures,
        RegistryExecutionSettings,
        NodePublicKeys,
        ApiBoundaryNodes,
    ),
    ReadRegistryError,
> {
    let (batch_processor, _, _, _) = make_batch_processor(registry.clone(), log);
    batch_processor.try_to_read_registry(registry.get_latest_version(), own_subnet_id)
}

/// Tests that `BatchProcessorImpl::try_to_read_registry()` returns `Ok(_)`; and checks that the
/// records entered into the registry are read from the registry correctly.
///
/// Two subnets are used for this, one considered the 'own subnet'.
/// The subnet records are fully specified for 'own subnet' only, whereas the other subnet uses
/// default values wherever possible. This setup ensures records are parsed correctly and also
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
                ..Default::default()
            },
            chain_key_config: ChainKeyConfig {
                key_configs: vec![
                    KeyConfig {
                        key_id: MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                            curve: EcdsaCurve::Secp256k1,
                            name: "ecdsa key 1".to_string(),
                        }),
                        pre_signatures_to_create_in_advance: 891,
                        max_queue_size: 891,
                    },
                    KeyConfig {
                        key_id: MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                            curve: EcdsaCurve::Secp256k1,
                            name: "ecdsa key 2".to_string(),
                        }),
                        pre_signatures_to_create_in_advance: 891,
                        max_queue_size: 891,
                    },
                ],
                ..ChainKeyConfig::default()
            },

            max_number_of_canisters: 387,
        };

        let own_transcript = dummy_transcript_for_tests_with_params(
            vec![node_test_id(123)], // committee
            NiDkgTag::HighThreshold, // dkg_tag
            2,                       // threshold
            3,                       // registry_version
        );

        // Other subnet characteristics.
        let other_subnet_id = subnet_test_id(17);
        let other_subnet_record = SubnetRecord::default();
        let other_transcript = dummy_transcript_for_tests();

        // General parameters.
        let nns_subnet_id = subnet_test_id(42);
        let provisional_whitelist = ProvisionalWhitelist::Set(btreeset! {
            PrincipalId::new_user_test_id(101),
            PrincipalId::new_node_test_id(103),
            PrincipalId::new_subnet_test_id(107)
        });
        let chain_key_enabled_subnets = btreemap! {
            MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: "key 1".to_string(),
            })
            => Valid(vec![subnet_test_id(1009), subnet_test_id(1013)]),
            MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: "key 2".to_string(),
            })
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

        let dummy_node_key_1 = PublicKeyProto {
            version: 0,
            algorithm: AlgorithmId::Ed25519 as i32,
            key_value: vec![
                194, 4, 63, 12, 39, 41, 96, 171, 151, 5, 92, 5, 93, 46, 7, 29, 26, 73, 51, 85, 118,
                76, 74, 0, 82, 39, 82, 75, 0, 45, 238, 3,
            ],
            proof_data: None,
            timestamp: None,
        };
        let dummy_node_key_2 = PublicKeyProto {
            version: 0,
            algorithm: AlgorithmId::Ed25519 as i32,
            key_value: vec![
                85, 122, 95, 50, 59, 92, 34, 104, 48, 6, 2, 64, 1, 8, 116, 27, 56, 8, 62, 96, 92,
                28, 26, 52, 12, 45, 64, 17, 6, 20, 104, 8,
            ],
            proof_data: None,
            timestamp: None,
        };
        let node_public_keys = btreemap! {
            node_test_id(1) => Valid(dummy_node_key_1.clone()),
            node_test_id(2) => Valid(dummy_node_key_2.clone()),
        };

        let api_boundary_node_records = btreemap! {
            node_test_id(11) => Valid(ApiBoundaryNodeRecord {
                version: "some_version".to_string(),
            }),
            node_test_id(12) => Valid(ApiBoundaryNodeRecord {
                version: "some_version".to_string(),
            }),
        };

        let node_records = btreemap! {
            node_test_id(11) => Valid(NodeRecord {
                http : Some(
                    ic_registry_client_helpers::node_operator::ConnectionEndpoint {
                        ip_addr: "2001:0db8:85a3:0000:0000:8a2e:0370:7334".to_string(),
                        port: 1,
                    },
                ),
                public_ipv4_config: Some(IPv4InterfaceConfig {
                    ip_addr: "127.0.0.1".to_string(),
                    ..Default::default()
                }),
                domain: Some("api-bn11.example.org".to_string()),
                ..Default::default()
            }),
            node_test_id(12) => Valid(NodeRecord {
                http : Some(
                    ic_registry_client_helpers::node_operator::ConnectionEndpoint {
                        ip_addr: "2001:0db8:85a3:0000:0000:8a2e:0370:7335".to_string(),
                        port: 1,
                    },
                ),
                domain: Some("api-bn12.example.org".to_string()),
                ..Default::default()
            }),
        };

        let fixture = RegistryFixture::new();
        fixture
            .write_test_records(&TestRecords {
                subnet_ids: Valid([own_subnet_id, other_subnet_id]),
                subnet_records: [Valid(&own_subnet_record), Valid(&other_subnet_record)],
                ni_dkg_transcripts: [Valid(Some(&own_transcript)), Valid(Some(&other_transcript))],
                nns_subnet_id: Valid(nns_subnet_id),
                chain_key_enabled_subnets: &chain_key_enabled_subnets,
                provisional_whitelist: Valid(&provisional_whitelist),
                routing_table: Valid(&routing_table),
                canister_migrations: Valid(&canister_migrations),
                node_public_keys: &node_public_keys,
                api_boundary_node_records: &api_boundary_node_records,
                node_records: &node_records,
            })
            .unwrap();

        // Reading from the registry must succeed for fully specified records.
        let (batch_processor, metrics, state_manager, registry_settings) =
            make_batch_processor(fixture.registry.clone(), log);
        let (
            network_topology,
            own_subnet_features,
            registry_execution_settings,
            node_public_keys,
            api_boundary_nodes,
        ) = batch_processor
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
                    &ThresholdSigPublicKey::try_from(transcript)
                        .expect("should extract public key from high threshold transcript")
                        .into_bytes()
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
                    .chain_key_config
                    .key_configs
                    .iter()
                    .map(|key_config| key_config.key_id.clone())
                    .collect::<BTreeSet<_>>(),
                subnet_topology.chain_keys_held
            );
        }
        assert_eq!(nns_subnet_id, network_topology.nns_subnet_id);
        assert_eq!(
            chain_key_enabled_subnets,
            network_topology
                .chain_key_enabled_subnets
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
        for key_config in own_subnet_record.chain_key_config.key_configs {
            assert_eq!(
                key_config.max_queue_size,
                registry_execution_settings
                    .chain_key_settings
                    .get(&key_config.key_id)
                    .unwrap()
                    .max_queue_size
            );
        }

        assert_eq!(
            own_subnet_record.membership.len(),
            registry_execution_settings.subnet_size,
        );

        // Check node public keys.
        assert_eq!(node_public_keys.len(), 2);
        for (node_id, public_key) in [
            (node_test_id(1), &dummy_node_key_1),
            (node_test_id(2), &dummy_node_key_2),
        ] {
            assert_eq!(
                ic_ed25519::PublicKey::deserialize_raw(&public_key.key_value)
                    .expect("invalid public key")
                    .serialize_rfc8410_der(),
                *node_public_keys.get(&node_id).unwrap(),
            );
        }

        // Check API Boundary Nodes.
        assert_eq!(api_boundary_nodes.len(), 2);
        let entry_1 = api_boundary_nodes.get(&node_test_id(11)).unwrap();
        assert_eq!(
            entry_1,
            &ApiBoundaryNodeEntry {
                domain: "api-bn11.example.org".to_string(),
                ipv4_address: Some("127.0.0.1".to_string()),
                ipv6_address: "2001:0db8:85a3:0000:0000:8a2e:0370:7334".to_string(),
                pubkey: None,
            }
        );
        let entry_2 = api_boundary_nodes.get(&node_test_id(12)).unwrap();
        assert_eq!(
            entry_2,
            &ApiBoundaryNodeEntry {
                domain: "api-bn12.example.org".to_string(),
                ipv4_address: None,
                ipv6_address: "2001:0db8:85a3:0000:0000:8a2e:0370:7335".to_string(),
                pubkey: None,
            }
        );

        // Commit a state with `own_subnet_id` in its metadata to ensure the latest
        // state corresponds to the registry records written above.
        let (height, mut state) = state_manager.take_tip();
        state.metadata.own_subnet_id = own_subnet_id;
        state_manager.commit_and_certify(
            state,
            height.increment(),
            CertificationScope::Metadata,
            None,
        );

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
            batch_summary: None,
            requires_full_state_hash: false,
            content: BatchContent::Data {
                batch_messages: BatchMessages::default(),
                consensus_responses: Vec::new(),
                chain_key_data: Default::default(),
            },
            randomness: Randomness::new([123; 32]),
            registry_version: fixture.registry.get_latest_version(),
            time: Time::from_nanos_since_unix_epoch(0),
            blockmaker_metrics: BlockmakerMetrics::new_for_test(),
            replica_version: ReplicaVersion::default(),
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
        use ReadRegistryError::*;

        let own_subnet_id = subnet_test_id(13);
        let own_subnet_record = SubnetRecord {
            max_number_of_canisters: 784,
            ..Default::default()
        };
        let own_transcript = dummy_transcript_for_tests();
        let nns_subnet_id = subnet_test_id(42);

        let minimal_input = TestRecords {
            subnet_ids: Valid([own_subnet_id]),
            subnet_records: [Valid(&own_subnet_record)],
            ni_dkg_transcripts: [Valid(Some(&own_transcript))],
            nns_subnet_id: Valid(nns_subnet_id),
            chain_key_enabled_subnets: &BTreeMap::default(),
            provisional_whitelist: Missing,
            routing_table: Missing,
            canister_migrations: Missing,
            node_public_keys: &BTreeMap::default(),
            api_boundary_node_records: &BTreeMap::default(),
            node_records: &BTreeMap::default(),
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
        let (_, _, registry_execution_settings, _, _) = result.unwrap();
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
            Err(Persistent(err)) if err.contains(&own_subnet_id.to_string()) && err.ends_with("not found")
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
            Err(Persistent(err)) if err.contains(&own_subnet_id.to_string()) && err.ends_with("not found")
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
            Err(Persistent(err)) if err.contains(&own_subnet_id.to_string()) && err.ends_with("not found")
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
            Err(Persistent(err)) if err.ends_with("not found")
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
        let own_transcript = dummy_transcript_for_tests();
        let nns_subnet_id = subnet_test_id(42);

        let minimal_input = TestRecords {
            subnet_ids: Valid([own_subnet_id]),
            subnet_records: [Valid(&own_subnet_record)],
            ni_dkg_transcripts: [Valid(Some(&own_transcript))],
            nns_subnet_id: Valid(nns_subnet_id),
            chain_key_enabled_subnets: &BTreeMap::default(),
            provisional_whitelist: Missing,
            routing_table: Missing,
            canister_migrations: Missing,
            node_public_keys: &BTreeMap::default(),
            api_boundary_node_records: &BTreeMap::default(),
            node_records: &BTreeMap::default(),
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
            Err(ReadRegistryError::Persistent(err)) if err.contains("subnet IDs") && err.contains("failed to decode")
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
            Err(ReadRegistryError::Persistent(err)) if err.contains(&own_subnet_id.to_string()) && err.contains("RegistryClientError")
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
            Err(ReadRegistryError::Persistent(err)) if err.contains(&own_subnet_id.to_string()) && err.contains("RegistryClientError")
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
            Err(ReadRegistryError::Persistent(err)) if err.contains(&own_subnet_id.to_string()) && err.contains("failed to decode")
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
            Err(ReadRegistryError::Persistent(err)) if err.contains("RegistryClientError")
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
            Err(ReadRegistryError::Persistent(err)) if err.contains("RegistryClientError")
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
            Err(ReadRegistryError::Persistent(err)) if err.contains("RegistryClientError")
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
            try_to_read_registry(fixture.registry, log.clone(), own_subnet_id),
            Err(ReadRegistryError::Persistent(err)) if err.contains("RegistryClientError")
        );

        // Corrupted node public keys.
        // Note a corrupted node public key here means the registry data cannot be converted into `PublicKeyProto`.
        let fixture = RegistryFixture::new();
        fixture
            .write_test_records(&TestRecords {
                node_public_keys: &btreemap! {
                    node_test_id(1) => Corrupted,
                    node_test_id(2) => Corrupted,
                },
                // The membership for the own subnet cannot be empty otherwise public keys won't be read at all.
                subnet_records: [Valid(&SubnetRecord {
                    membership: &[node_test_id(1)],
                    ..own_subnet_record.clone()
                })],
                ..minimal_input
            })
            .unwrap();
        assert_matches!(
            try_to_read_registry(fixture.registry, log.clone(), own_subnet_id),
            Err(ReadRegistryError::Persistent(err)) if err.contains("RegistryClientError")
        );

        // Corrupted node records.
        let fixture = RegistryFixture::new();
        fixture
            .write_test_records(&TestRecords {
                api_boundary_node_records: &btreemap! {
                    node_test_id(11) => Valid(ApiBoundaryNodeRecord {
                        version: "some_version".to_string(),
                    }),
                },
                node_records: &btreemap! {
                    node_test_id(11) => Corrupted,
                },
                ..minimal_input
            })
            .unwrap();
        assert_matches!(
            try_to_read_registry(fixture.registry, log, own_subnet_id),
            Err(ReadRegistryError::Persistent(err)) if err.contains("RegistryClientError")
        );
    });
}

/// Tests that `BatchProcessorImpl::try_to_read_registry()` can skip missing or invalid node public keys.
#[test]
fn try_read_registry_can_skip_missing_or_invalid_node_public_keys() {
    with_test_replica_logger(|log| {
        use Integrity::*;

        let own_subnet_id = subnet_test_id(13);
        let own_subnet_record = SubnetRecord {
            max_number_of_canisters: 784,
            // The node IDs need to be set here otherwise public keys won't be read at all.
            membership: &[node_test_id(1), node_test_id(2), node_test_id(3)],
            ..Default::default()
        };
        let own_transcript = dummy_transcript_for_tests();
        let nns_subnet_id = subnet_test_id(42);

        let input = TestRecords {
            subnet_ids: Valid([own_subnet_id]),
            subnet_records: [Valid(&own_subnet_record)],
            ni_dkg_transcripts: [Valid(Some(&own_transcript))],
            nns_subnet_id: Valid(nns_subnet_id),
            chain_key_enabled_subnets: &BTreeMap::default(),
            provisional_whitelist: Missing,
            routing_table: Missing,
            canister_migrations: Missing,
            node_public_keys: &BTreeMap::default(),
            api_boundary_node_records: &BTreeMap::default(),
            node_records: &BTreeMap::default(),
        };

        // An invalid node public key.
        // An invalid key here refers to the fact that the content of PublicKeyProto does not constitute a valid Ed25519 public key.
        let invalid_node_key = PublicKeyProto {
            version: 0,
            algorithm: AlgorithmId::MultiBls12_381 as i32,
            key_value: [0; 96].to_vec(),
            proof_data: None,
            timestamp: None,
        };

        let valid_node_key = PublicKeyProto {
            version: 0,
            algorithm: AlgorithmId::Ed25519 as i32,
            key_value: vec![
                5, 33, 1, 58, 103, 6, 147, 39, 52, 223, 50, 129, 91, 4, 116, 88, 204, 9, 15, 8, 0,
                86, 1, 18, 53, 51, 73, 136, 89, 73, 171, 53,
            ],
            proof_data: None,
            timestamp: None,
        };

        let fixture = RegistryFixture::new();
        fixture
            .write_test_records(&TestRecords {
                node_public_keys: &btreemap! {
                    node_test_id(1) => Missing,
                    node_test_id(2) => Valid(invalid_node_key),
                    // Note that the key does not match the node ID but it does not matter for the purposes of this test.
                    node_test_id(3) => Valid(valid_node_key.clone()),
                },
                subnet_records: [Valid(&own_subnet_record)],
                ..input
            })
            .unwrap();

        let (batch_processor, metrics, _, _) =
            make_batch_processor(fixture.registry.clone(), log.clone());
        let res = batch_processor
            .try_to_read_registry(fixture.registry.get_latest_version(), own_subnet_id);
        assert_matches!(res, Ok(_));

        // check that critical error counter is incremented both for missing and invalid keys.
        assert_eq!(
            metrics
                .critical_error_missing_or_invalid_node_public_keys
                .get(),
            2
        );

        let (_, _, _, node_public_keys, _) = res.unwrap();
        assert_eq!(node_public_keys.len(), 1);
        assert!(!node_public_keys.contains_key(&node_test_id(1)));
        assert!(!node_public_keys.contains_key(&node_test_id(2)));
        assert_eq!(
            ic_ed25519::PublicKey::deserialize_raw(&valid_node_key.key_value)
                .expect("invalid public key")
                .serialize_rfc8410_der(),
            *node_public_keys.get(&node_test_id(3)).unwrap(),
        );
    });
}

#[test]
fn try_read_registry_can_skip_missing_or_invalid_fields_of_api_boundary_nodes() {
    with_test_replica_logger(|log| {
        use Integrity::*;

        let own_subnet_id = subnet_test_id(13);
        let own_subnet_record = SubnetRecord {
            max_number_of_canisters: 784,
            ..Default::default()
        };
        let own_transcript = dummy_transcript_for_tests();
        let nns_subnet_id = subnet_test_id(42);

        let input = TestRecords {
            subnet_ids: Valid([own_subnet_id]),
            subnet_records: [Valid(&own_subnet_record)],
            ni_dkg_transcripts: [Valid(Some(&own_transcript))],
            nns_subnet_id: Valid(nns_subnet_id),
            chain_key_enabled_subnets: &BTreeMap::default(),
            provisional_whitelist: Missing,
            routing_table: Missing,
            canister_migrations: Missing,
            node_public_keys: &BTreeMap::default(),
            api_boundary_node_records: &BTreeMap::default(),
            node_records: &BTreeMap::default(),
        };

        let api_boundary_node_records = &btreemap! {
            node_test_id(11) => Valid(ApiBoundaryNodeRecord {
                version: "some_version".to_string(),
            }),
            node_test_id(12) => Valid(ApiBoundaryNodeRecord {
                version: "some_version".to_string(),
            }),
            node_test_id(13) => Valid(ApiBoundaryNodeRecord {
                version: "some_version".to_string(),
            }),
            node_test_id(14) => Valid(ApiBoundaryNodeRecord {
                version: "some_version".to_string(),
            }),
            node_test_id(15) => Valid(ApiBoundaryNodeRecord {
                version: "some_version".to_string(),
            }),
            node_test_id(16) => Valid(ApiBoundaryNodeRecord {
                version: "some_version".to_string(),
            }),
        };

        let node_records = &btreemap! {
            node_test_id(11) => Valid(NodeRecord {
                http: Some(
                    ic_registry_client_helpers::node_operator::ConnectionEndpoint {
                        ip_addr: "2001:0db8:85a3:0000:0000:8a2e:0370:7335".to_string(),
                        port: 1,
                    },
                ),
                domain: Some("api-bn12.example.org".to_string()),
                ..Default::default()
            }),
            // The NodeRecord is missing.
            node_test_id(12) => Missing,
            // This NodeRecord does not have a domain field.
            node_test_id(13) => Valid(NodeRecord {
                http: Some(
                    ic_registry_client_helpers::node_operator::ConnectionEndpoint {
                        ip_addr: "2001:0db8:85a3:0000:0000:8a2e:0370:7336".to_string(),
                        port: 1,
                    },
                ),
                domain: None,
                ..Default::default()
            }),
            // This NodeRecord does not have a http field.
            node_test_id(14) => Valid(NodeRecord {
                http: None,
                domain: Some("api-bn14.example.org".to_string()),
                ..Default::default()
            }),
            // This NodeRecord has an invalid ipv6 address.
            node_test_id(15) => Valid(NodeRecord {
                http: Some(
                    ic_registry_client_helpers::node_operator::ConnectionEndpoint {
                        ip_addr: "corrupted_ipv6_address".to_string(),
                        port: 1,
                    },
                ),
                domain: Some("api-bn15.example.org".to_string()),
                ..Default::default()
            }),
            // This NodeRecord has an invalid ipv4 address.
            node_test_id(16) => Valid(NodeRecord {
                http: Some(
                    ic_registry_client_helpers::node_operator::ConnectionEndpoint {
                        ip_addr: "2001:0db8:85a3:0000:0000:8a2e:0370:7337".to_string(),
                        port: 1,
                    },
                ),
                public_ipv4_config: Some(
                    IPv4InterfaceConfig {
                        ip_addr: "corrupted_ipv4_address".to_string(),
                        ..Default::default()
                    }
                ),
                domain: Some("api-bn15.example.org".to_string()),
                ..Default::default()
            }),
        };

        let fixture = RegistryFixture::new();
        fixture
            .write_test_records(&TestRecords {
                api_boundary_node_records,
                node_records,
                subnet_records: [Valid(&own_subnet_record)],
                ..input
            })
            .unwrap();

        let (batch_processor, metrics, _, _) =
            make_batch_processor(fixture.registry.clone(), log.clone());
        let res = batch_processor
            .try_to_read_registry(fixture.registry.get_latest_version(), own_subnet_id);
        assert_matches!(res, Ok(_));

        // There are six API BNs in the registry. However, five nodes have missing or invalid fields of NodeRecord.
        // Hence, only one nodes are retrieved.
        let (_, _, _, _, api_boundary_nodes) = res.unwrap();
        assert_eq!(api_boundary_nodes.len(), 1);
        assert!(api_boundary_nodes.contains_key(&node_test_id(11)));

        assert_eq!(
            metrics
                .critical_error_missing_or_invalid_api_boundary_nodes
                .get(),
            5
        );
    });
}

/// Checks the critical error counter for 'read from the registry failed' is not incremented in
/// `BatchProcessorImpl::try_registry()` due to a transient error underneath.
///
/// This is done by spawning a thread that attempts to read from an empty registry using the next
/// current registry version (after an update). This will fail and thus get stuck and retry every
/// 100ms until it succeeds.
///
/// After waiting 150ms, the registry is updated with minimal input which causes the read to
/// succeed (after at least one failed attempt) thus the future can be joined but the critical
/// error counter should still be zero.
#[test]
fn check_critical_error_counter_is_not_incremented_for_transient_error() {
    with_test_replica_logger(|log| {
        use Integrity::*;

        let own_subnet_id = subnet_test_id(13);
        let own_subnet_record = SubnetRecord {
            max_number_of_canisters: 784,
            ..Default::default()
        };
        let own_transcript = dummy_transcript_for_tests();
        let nns_subnet_id = subnet_test_id(42);

        let minimal_input = TestRecords {
            subnet_ids: Valid([own_subnet_id]),
            subnet_records: [Valid(&own_subnet_record)],
            ni_dkg_transcripts: [Valid(Some(&own_transcript))],
            nns_subnet_id: Valid(nns_subnet_id),
            chain_key_enabled_subnets: &BTreeMap::default(),
            provisional_whitelist: Missing,
            routing_table: Missing,
            canister_migrations: Missing,
            node_public_keys: &BTreeMap::default(),
            api_boundary_node_records: &BTreeMap::default(),
            node_records: &BTreeMap::default(),
        };

        let fixture = RegistryFixture::new();
        let next_registry_version = fixture.registry.get_latest_version().increment();
        let (batch_processor, _, _, _) =
            make_batch_processor(fixture.registry.clone(), log.clone());

        // Try reading the registry at the next version; should return `Err(_)`.
        assert_matches!(
            batch_processor.try_to_read_registry(next_registry_version, own_subnet_id),
            Err(ReadRegistryError::Transient(_))
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

        assert_eq!(metrics.critical_error_failed_to_read_registry.get(), 0);
    });
}

pub fn mainnet_nns_subnet() -> SubnetId {
    SubnetId::new(
        PrincipalId::from_str("tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe")
            .unwrap(),
    )
}

pub fn mainnet_app_subnet() -> SubnetId {
    SubnetId::new(
        PrincipalId::from_str("6pbhf-qzpdk-kuqbr-pklfa-5ehhf-jfjps-zsj6q-57nrl-kzhpd-mu7hc-vae")
            .unwrap(),
    )
}

/// Tests `BatchProcessorImpl::try_to_read_registry()` successfully reads a snapshot of the mainnet
/// registry.
#[test]
fn reading_mainnet_registry_succeeds() {
    with_test_replica_logger(|log| {
        let (tmp, _local_store) = get_mainnet_delta_00_6d_c1();
        let registry =
            Arc::new(LocalRegistry::new(tmp.path(), Duration::from_millis(500)).unwrap());

        let registry_version = registry.get_latest_version();

        let (batch_processor, _, _, _) = make_batch_processor(registry, log);
        assert_matches!(
            batch_processor.try_to_read_registry(registry_version, mainnet_nns_subnet()),
            Ok(_)
        );
        assert_matches!(
            batch_processor.try_to_read_registry(registry_version, mainnet_app_subnet()),
            Ok(_)
        );
    });
}

#[test]
fn process_batch_updates_subnet_metrics() {
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
                ..Default::default()
            },
            max_number_of_canisters: 387,
            chain_key_config: ChainKeyConfig {
                key_configs: vec![
                    KeyConfig {
                        key_id: MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                            curve: EcdsaCurve::Secp256k1,
                            name: "ecdsa key 1".to_string(),
                        }),
                        max_queue_size: 891,
                        pre_signatures_to_create_in_advance: 891,
                    },
                    KeyConfig {
                        key_id: MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                            curve: EcdsaCurve::Secp256k1,
                            name: "ecdsa key 2".to_string(),
                        }),
                        max_queue_size: 891,
                        pre_signatures_to_create_in_advance: 891,
                    },
                ],
                ..Default::default()
            },
        };

        let own_transcript = dummy_transcript_for_tests_with_params(
            vec![node_test_id(123)], // committee
            NiDkgTag::HighThreshold, // dkg_tag
            2,                       // threshold
            3,                       // registry_version
        );

        // Other subnet characteristics.
        let other_subnet_id = subnet_test_id(17);
        let other_subnet_record = SubnetRecord::default();
        let other_transcript = dummy_transcript_for_tests();

        // General parameters.
        let nns_subnet_id = subnet_test_id(42);
        let provisional_whitelist = ProvisionalWhitelist::Set(btreeset! {
            PrincipalId::new_user_test_id(101),
            PrincipalId::new_node_test_id(103),
            PrincipalId::new_subnet_test_id(107)
        });
        let chain_key_enabled_subnets = btreemap! {
            MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: "key 1".to_string(),
            })
            => Valid(vec![subnet_test_id(1009), subnet_test_id(1013)]),
            MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: "key 2".to_string(),
            })
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

        let dummy_node_key_1 = PublicKeyProto {
            version: 0,
            algorithm: AlgorithmId::Ed25519 as i32,
            key_value: vec![
                14, 52, 33, 2, 5, 208, 188, 227, 25, 91, 30, 79, 70, 187, 95, 199, 50, 5, 99, 11,
                66, 19, 2, 94, 30, 40, 3, 51, 32, 79, 197, 9,
            ],
            proof_data: None,
            timestamp: None,
        };
        let dummy_node_key_2 = PublicKeyProto {
            version: 0,
            algorithm: AlgorithmId::Ed25519 as i32,
            key_value: vec![
                5, 33, 1, 58, 103, 6, 147, 39, 52, 223, 50, 129, 91, 4, 116, 88, 204, 9, 15, 8, 0,
                86, 1, 18, 53, 51, 73, 136, 89, 73, 171, 53,
            ],
            proof_data: None,
            timestamp: None,
        };
        let node_public_keys = btreemap! {
            node_test_id(1) => Valid(dummy_node_key_1.clone()),
            node_test_id(2) => Valid(dummy_node_key_2.clone()),
        };

        let fixture = RegistryFixture::new();
        fixture
            .write_test_records(&TestRecords {
                subnet_ids: Valid([own_subnet_id, other_subnet_id]),
                subnet_records: [Valid(&own_subnet_record), Valid(&other_subnet_record)],
                ni_dkg_transcripts: [Valid(Some(&own_transcript)), Valid(Some(&other_transcript))],
                nns_subnet_id: Valid(nns_subnet_id),
                chain_key_enabled_subnets: &chain_key_enabled_subnets,
                provisional_whitelist: Valid(&provisional_whitelist),
                routing_table: Valid(&routing_table),
                canister_migrations: Valid(&canister_migrations),
                node_public_keys: &node_public_keys,
                api_boundary_node_records: &BTreeMap::default(),
                node_records: &BTreeMap::default(),
            })
            .unwrap();

        // Reading from the registry must succeed for fully specified records.
        let (batch_processor, _metrics, state_manager, _registry_settings) =
            make_batch_processor(fixture.registry.clone(), log);
        let (height, mut state) = state_manager.take_tip();
        state.metadata.own_subnet_id = own_subnet_id;
        state_manager.commit_and_certify(
            state,
            height.increment(),
            CertificationScope::Metadata,
            None,
        );

        batch_processor.process_batch(Batch {
            batch_number: height.increment().increment(),
            batch_summary: None,
            requires_full_state_hash: false,
            content: BatchContent::Data {
                batch_messages: BatchMessages::default(),
                consensus_responses: Vec::new(),
                chain_key_data: Default::default(),
            },
            randomness: Randomness::new([123; 32]),
            registry_version: fixture.registry.get_latest_version(),
            time: Time::from_nanos_since_unix_epoch(0),
            blockmaker_metrics: BlockmakerMetrics::new_for_test(),
            replica_version: ReplicaVersion::default(),
        });

        let latest_state = state_manager.get_latest_state().take();
        let canister_state = latest_state
            .canister_states
            .values()
            .map(|canister| canister.memory_usage())
            .sum();
        assert_eq!(
            latest_state.metadata.subnet_metrics.canister_state_bytes,
            canister_state
        );
    });
}

#[test]
fn test_demux_delivers_certified_stream_slices() {
    struct FakeValidSetRule;
    impl ValidSetRule for FakeValidSetRule {
        fn induct_messages(
            &self,
            _: &mut ReplicatedState,
            _: Vec<ic_types::messages::SignedIngress>,
        ) {
            // do nothing
        }
    }

    struct FakeStreamHandler {
        expected_slices: BTreeMap<SubnetId, StreamSlice>,
    }

    impl FakeStreamHandler {
        fn new(expected_slices: BTreeMap<SubnetId, StreamSlice>) -> FakeStreamHandler {
            FakeStreamHandler { expected_slices }
        }
    }

    impl StreamHandler for FakeStreamHandler {
        fn process_stream_slices(
            &self,
            state: ReplicatedState,
            stream_slices: BTreeMap<SubnetId, StreamSlice>,
        ) -> ReplicatedState {
            assert_eq!(self.expected_slices, stream_slices);
            state
        }
    }

    with_test_replica_logger(|log| {
        let src_subnet_id = subnet_test_id(42);
        let dst_subnet_id = subnet_test_id(43);
        let other_subnet_id = subnet_test_id(44);

        // Obtain a certified stream slice.
        let certified_stream_slice = {
            // Set up state manager.
            let src_state_manager = FakeStateManager::new();

            // Obtain tip...
            let (mut height, mut state) = src_state_manager.take_tip();
            // ... and use testing function to put stream to encode as certified slice
            use ic_replicated_state::testing::ReplicatedStateTesting;
            state.modify_streams(|streams| {
                streams.insert(
                    dst_subnet_id,
                    Stream::new(
                        StreamIndexedQueue::with_begin(StreamIndex::new(0)),
                        StreamIndex::new(42),
                    ),
                );
            });

            // Commit state with modified streams.
            height.inc_assign();
            src_state_manager.commit_and_certify(state, height, CertificationScope::Metadata, None);

            // Encode slice.
            src_state_manager
                .encode_certified_stream_slice(dst_subnet_id, None, None, None, None)
                .unwrap()
        };

        // Set up destination state manager.
        let dst_metrics = MetricsRegistry::new();
        let dst_state_manager = Arc::new(FakeStateManager::new());

        // Make up a second slice with a different height.
        let other_height = Height::new(99);
        let mut certified_stream_slice_other_height = certified_stream_slice.clone();
        certified_stream_slice_other_height.certification.height = other_height;

        // Create messages to be provided as part of `BatchMessages`.
        let certified_stream_slices = btreemap![src_subnet_id => certified_stream_slice, other_subnet_id => certified_stream_slice_other_height];

        let expected_slices = certified_stream_slices
            .clone()
            .into_iter()
            .map(|(subnet, slice)| {
                (
                    subnet,
                    dst_state_manager
                        .decode_valid_certified_stream_slice(&slice)
                        .unwrap(),
                )
            })
            .collect::<BTreeMap<_, _>>();

        let demux: Box<dyn Demux> = Box::new(DemuxImpl::new(
            Box::new(FakeValidSetRule),
            Box::new(FakeStreamHandler::new(expected_slices)),
            dst_state_manager.clone(),
            MessageRoutingMetrics::new(&dst_metrics),
            log,
        ));

        let (_, dst_state) = dst_state_manager.take_tip();

        demux.process_payload(
            dst_state,
            BatchMessages {
                certified_stream_slices,
                ..Default::default()
            },
        );

        assert_eq!(
            metric_vec(&[
                (&[(LABEL_REMOTE, &src_subnet_id.to_string())], 1),
                (&[(LABEL_REMOTE, &other_subnet_id.to_string())], 99)
            ]),
            fetch_int_gauge_vec(&dst_metrics, METRIC_REMOTE_CERTIFIED_HEIGHTS)
        );
    });
}
