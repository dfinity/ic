use super::*;
use crate::test_fixtures::*;
use crate::{ExpectedIndices, STATUS_SUCCESS};
use assert_matches::assert_matches;
use ic_crypto_tree_hash::{Digest, Witness};
use ic_interfaces_certified_stream_store::DecodeStreamError;
use ic_interfaces_certified_stream_store_mocks::MockCertifiedStreamStore;
use ic_interfaces_state_manager::StateReader;
use ic_replicated_state::Stream;
use ic_replicated_state::metadata_state::StreamMap;
use ic_test_utilities::state_manager::FakeStateManager;
use ic_test_utilities_consensus::fake::Fake;
use ic_test_utilities_logger::with_test_replica_logger;
use ic_test_utilities_metrics::{
    fetch_histogram_vec_count, fetch_int_counter_vec, fetch_int_gauge, metric_vec,
};
use ic_test_utilities_types::ids::{NODE_42, SUBNET_1, SUBNET_2, SUBNET_3, SUBNET_4, SUBNET_5};
use ic_types::CryptoHashOfPartialState;
use ic_types::consensus::certification::{Certification, CertificationContent};
use ic_types::crypto::{CryptoHash, Signed};
use ic_types::signature::ThresholdSignature;
use ic_types::xnet::RejectReason;
use maplit::btreemap;
use std::sync::{Arc, Mutex};

/// Creates an `XNetEndpointResolver` around a `ProximityMap` that resolves to
/// the remote node of the given index; and calls `xnet_stream_url()` on it.
fn resolve_xnet_stream_endpoint(remote_node_index: u64, log: ReplicaLogger) -> EndpointLocator {
    let registry = get_node_selection_registry_for_test();
    let metrics = MetricsRegistry::new();

    let proximity_map = Arc::new(ProximityMap::with_rng(
        mock_gen_range_low(remote_node_index, 3),
        LOCAL_NODE_1_OPERATOR_1,
        registry.clone(),
        &metrics,
        log.clone(),
    ));
    let endpoint_resolver = XNetEndpointResolver::new(
        registry,
        LOCAL_NODE_1_OPERATOR_1,
        LOCAL_SUBNET,
        proximity_map,
        log,
    );

    endpoint_resolver
        .xnet_stream_url(REMOTE_SUBNET, 1.into(), 2.into(), 1000)
        .unwrap()
}

#[tokio::test]
async fn xnet_stream_url_node_same_operator() {
    with_test_replica_logger(|log| {
        assert_eq!(
            EndpointLocator {
                node_id: REMOTE_NODE_1_OPERATOR_1,
                url: "http://gfvbo-licaa-aaaaa-aaaap-2ai.169@192.168.1.1:2197/api/v1/stream/fscpm-uiaaa-aaaaa-aaaap-yai?msg_begin=2&witness_begin=1&byte_limit=1000"
                    .parse::<Uri>()
                    .unwrap(),
                proximity: PeerLocation::Local
            },
            resolve_xnet_stream_endpoint(0, log)
        );
    });
}

#[tokio::test]
async fn xnet_stream_url_node_other_operator() {
    with_test_replica_logger(|log| {
        assert_eq!(
            EndpointLocator {
                node_id: REMOTE_NODE_3_OPERATOR_2,
                url: "http://hr2go-2qeaa-aaaaa-aaaap-2ai.169@192.168.1.3:2197/api/v1/stream/fscpm-uiaaa-aaaaa-aaaap-yai?msg_begin=2&witness_begin=1&byte_limit=1000"
                    .parse::<Uri>()
                    .unwrap(),
                proximity: PeerLocation::Remote
            },
            resolve_xnet_stream_endpoint(2, log)
        );
    });
}

/// Our outgoing stream to `REMOTE_SUBNET` across the advert tests: we have
/// inducted its messages up to `OWN_SIGNALS_END`; it has signalled ours up to
/// `OWN_MESSAGES_BEGIN`, where the messages we still hold for it begin.
///
/// An advert is thus new to us iff it ends past `OWN_SIGNALS_END`, signals past
/// `OWN_MESSAGES_BEGIN`, or begins past a reject signal of ours.
const OWN_SIGNALS_END: u64 = 3;
const OWN_MESSAGES_BEGIN: u64 = 5;
const OWN_MESSAGES_END: u64 = 10;

fn own_stream_for_advert_tests() -> Stream {
    generate_stream(&StreamConfig {
        message_begin: OWN_MESSAGES_BEGIN,
        message_end: OWN_MESSAGES_END,
        signal_end: OWN_SIGNALS_END,
    })
}

/// `REMOTE_SUBNET`'s stream to us, as advertised in the advert tests, having
/// both new messages and new signals.
fn peer_stream_for_advert_tests() -> Stream {
    generate_stream(&StreamConfig {
        message_begin: OWN_SIGNALS_END,
        message_end: OWN_SIGNALS_END + 4,
        signal_end: OWN_MESSAGES_END,
    })
}

/// An `XNetAdvertHandlerImpl` under test, with the pool it shares and the
/// receiving end of the pull requests it sends.
struct AdvertHandlerFixture {
    handler: Arc<XNetAdvertHandlerImpl>,
    pool: Arc<Mutex<CertifiedSlicePool>>,
    pull_requests: mpsc::Receiver<SubnetId>,
}

impl AdvertHandlerFixture {
    /// Builds an `XNetAdvertHandlerImpl` around `certified_stream_store`, with a
    /// registry that only knows `REMOTE_SUBNET` and a pool that records headers.
    fn new(certified_stream_store: MockCertifiedStreamStore, log: ReplicaLogger) -> Self {
        Self::with_streams(
            btreemap! { REMOTE_SUBNET => own_stream_for_advert_tests() },
            certified_stream_store,
            log,
        )
    }

    /// Like `new()`, but with the given outgoing streams.
    fn with_streams(
        streams: StreamMap,
        certified_stream_store: MockCertifiedStreamStore,
        log: ReplicaLogger,
    ) -> Self {
        let state_manager = Arc::new(FakeStateManager::new());
        put_replicated_state_for_testing(state_manager.as_ref(), streams);
        // `FakeStateManager` only reports a height as certified once a certification
        // for it has been delivered.
        state_manager.deliver_state_certification(Certification {
            height: CERTIFIED_HEIGHT,
            height_witness: Witness::new_for_testing(Digest([0; 32])),
            signed: Signed {
                content: CertificationContent::new(CryptoHashOfPartialState::from(CryptoHash(
                    vec![],
                ))),
                signature: ThresholdSignature::fake(),
            },
        });
        let registry = get_registry_for_test(&[REMOTE_SUBNET]);

        let pool = Arc::new(Mutex::new(CertifiedSlicePool::new(
            &MetricsRegistry::new(),
            log.clone(),
        )));
        let (pull_task, _, pull_requests) = PullTaskHandle::new();
        let handler = Arc::new(XNetAdvertHandlerImpl::new(
            state_manager as Arc<_>,
            Arc::new(certified_stream_store) as Arc<_>,
            registry as Arc<_>,
            Arc::clone(&pool),
            pull_task,
            log,
        ));

        Self {
            handler,
            pool,
            pull_requests,
        }
    }

    /// Handles `advert`, as posted by `REMOTE_SUBNET`.
    fn handle_advert(
        &self,
        advert: CertifiedStreamSlice,
    ) -> Result<XNetAdvertOutcome, XNetAdvertError> {
        self.handler.handle_advert(REMOTE_SUBNET, advert)
    }

    /// Records `header` as `REMOTE_SUBNET`'s.
    fn record_peer_header(&self, header: &StreamHeader) {
        self.pool
            .lock()
            .unwrap()
            .record_peer_header(REMOTE_SUBNET, header);
    }

    /// The recorded header for `REMOTE_SUBNET`, if any.
    fn recorded_peer_header(&self) -> Option<Arc<StreamHeader>> {
        self.pool
            .lock()
            .unwrap()
            .peer_header(REMOTE_SUBNET)
            .cloned()
    }

    /// Takes the pull requests sent since the last call.
    fn take_pull_requests(&mut self) -> Vec<SubnetId> {
        std::iter::from_fn(|| self.pull_requests.try_recv().ok()).collect()
    }
}

/// A mock store expecting exactly `count` verifying decodes of an advert
/// carrying `advertised`'s header. Only adverts classified as `NothingNew` or
/// `Actionable` are verified, so the count is what we're really asserting.
fn store_expecting_decodes(advertised: &Stream, count: usize) -> MockCertifiedStreamStore {
    let decoded = advertised.slice(advertised.messages_begin(), Some(0));
    let mut store = MockCertifiedStreamStore::new();
    store
        .expect_decode_certified_stream_slice()
        .times(count)
        .returning(move |_, _, _| Ok(decoded.clone()));
    store
}

/// An advert offering messages we have not inducted is actionable: its header is
/// recorded and a pull requested.
#[tokio::test]
async fn handle_advert_actionable() {
    with_test_replica_logger(|log| {
        let advertised = peer_stream_for_advert_tests();
        let header = advertised.header();
        let mut fixture = AdvertHandlerFixture::new(store_expecting_decodes(&advertised, 1), log);

        assert_matches!(
            fixture.handle_advert(make_advert(&advertised)),
            Ok(XNetAdvertOutcome::Actionable)
        );
        assert_eq!(Some(Arc::new(header)), fixture.recorded_peer_header());
        assert_eq!(vec![REMOTE_SUBNET], fixture.take_pull_requests());

        // Redundant copies of the same advert are classified as duplicates
        // and not verified again; but each requests a pull.
        for _ in 0..2 {
            assert_matches!(
                fixture.handle_advert(make_advert(&advertised)),
                Ok(XNetAdvertOutcome::Duplicate)
            );
        }
        assert_eq!(vec![REMOTE_SUBNET; 2], fixture.take_pull_requests());
    });
}

/// An advert offering only content already accounted for by the cached stream
/// position, i.e. included into blocks, is dropped without being verified.
#[tokio::test]
async fn handle_advert_in_payload() {
    with_test_replica_logger(|log| {
        let advertised = peer_stream_for_advert_tests();
        let mut fixture = AdvertHandlerFixture::new(store_expecting_decodes(&advertised, 0), log);

        // A past payload already covers all of it.
        fixture.pool.lock().unwrap().garbage_collect(btreemap! {
            REMOTE_SUBNET => ExpectedIndices {
                message_index: advertised.messages_end(),
                signal_index: advertised.signals_end(),
                ..Default::default()
            }
        });

        assert_matches!(
            fixture.handle_advert(make_advert(&advertised)),
            Ok(XNetAdvertOutcome::InPayload)
        );
        // The advertised header was not (verified and) recorded; nor a pull requested.
        assert_eq!(None, fixture.recorded_peer_header());
        assert!(fixture.take_pull_requests().is_empty());
    });
}

/// An advert bringing signals we have not acted on is actionable even with no
/// messages we have not inducted: only those signals let us garbage collect the
/// messages we hold for `REMOTE_SUBNET`.
#[tokio::test]
async fn handle_advert_new_signals() {
    with_test_replica_logger(|log| {
        // Nothing we have not inducted, but signals past those we have acted on.
        let advertised = generate_stream(&StreamConfig {
            message_begin: 0,
            message_end: OWN_SIGNALS_END,
            signal_end: OWN_MESSAGES_BEGIN + 2,
        });
        let header = advertised.header();
        let mut fixture = AdvertHandlerFixture::new(store_expecting_decodes(&advertised, 1), log);

        // A recorded header covering everything except the new signals.
        let recorded = generate_stream(&StreamConfig {
            message_begin: 0,
            message_end: OWN_SIGNALS_END,
            signal_end: OWN_MESSAGES_BEGIN,
        });
        fixture.record_peer_header(&recorded.header());

        assert_matches!(
            fixture.handle_advert(make_advert(&advertised)),
            Ok(XNetAdvertOutcome::Actionable)
        );
        assert_eq!(Some(Arc::new(header)), fixture.recorded_peer_header());
        assert_eq!(vec![REMOTE_SUBNET], fixture.take_pull_requests());
    });
}

/// An advert whose content we have already recorded is classified as a
/// duplicate without being verified; and a pull is requested, in case the
/// earlier one failed.
#[tokio::test]
async fn handle_advert_duplicate_content() {
    with_test_replica_logger(|log| {
        let advertised = peer_stream_for_advert_tests();
        let header = advertised.header();
        let mut fixture = AdvertHandlerFixture::new(store_expecting_decodes(&advertised, 0), log);

        fixture.record_peer_header(&header);

        assert_matches!(
            fixture.handle_advert(make_advert(&advertised)),
            Ok(XNetAdvertOutcome::Duplicate)
        );
        assert_eq!(vec![REMOTE_SUBNET], fixture.take_pull_requests());
    });
}

/// An advert offering nothing we do not already have is answered with our own
/// certified header, so its sender can observe our stream's `begin`. It is only
/// verified if it advances the recorded header.
#[tokio::test]
async fn handle_advert_nothing_new() {
    with_test_replica_logger(|log| {
        let advertised = generate_stream(&StreamConfig {
            message_begin: 0,
            message_end: OWN_SIGNALS_END,
            signal_end: OWN_MESSAGES_BEGIN,
        });
        // The header-only reply, as encoded from our own stream.
        let own_header = make_certified_stream_slice(
            LOCAL_SUBNET,
            StreamConfig {
                message_begin: OWN_MESSAGES_BEGIN,
                message_end: OWN_MESSAGES_BEGIN,
                signal_end: OWN_SIGNALS_END,
            },
        );

        // Two copies, as from two nodes of the source subnet at the same certified
        // height: each is answered, or only one of the peer's nodes would learn our
        // header per height. Only the first one advances the recorded header, so only
        // it is verified.
        let mut store = store_expecting_decodes(&advertised, 1);
        let expected_reply = own_header.clone();
        store
            .expect_encode_certified_stream_slice()
            .times(2)
            .returning(move |_, _, _, msg_limit, _| {
                assert_eq!(msg_limit, Some(0));
                Ok(own_header.clone())
            });
        let mut fixture = AdvertHandlerFixture::new(store, log);

        for _ in 0..2 {
            assert_matches!(
                fixture.handle_advert(make_advert(&advertised)),
                Ok(XNetAdvertOutcome::NothingNew)
            );
            // Recorded from the first copy.
            assert_eq!(
                Some(Arc::new(advertised.header())),
                fixture.recorded_peer_header()
            );
            assert_eq!(
                Some(expected_reply.clone()),
                fixture.handler.certified_header(REMOTE_SUBNET)
            );
        }
        // Nothing to pull.
        assert!(fixture.take_pull_requests().is_empty());
    });
}

/// An advert whose `begin` is past a reject signal of ours brings something even
/// when all of its messages and signals are accounted for: inducting it lets us
/// garbage collect that signal.
#[tokio::test]
async fn handle_advert_collecting_reject_signal() {
    with_test_replica_logger(|log| {
        // As `own_stream_for_advert_tests()`, except that we rejected the last message
        // we inducted, leaving a reject signal at `REJECT_SIGNAL`.
        const REJECT_SIGNAL: u64 = OWN_SIGNALS_END - 1;
        let mut own_stream = generate_stream(&StreamConfig {
            message_begin: OWN_MESSAGES_BEGIN,
            message_end: OWN_MESSAGES_END,
            signal_end: REJECT_SIGNAL,
        });
        own_stream.push_reject_signal(RejectReason::CanisterMigrating);

        // A stream whose messages and signals we've inducted; only its `begin` differs.
        let advertised = |begin| {
            generate_stream(&StreamConfig {
                message_begin: begin,
                message_end: OWN_SIGNALS_END,
                signal_end: OWN_MESSAGES_BEGIN,
            })
        };

        // A `begin` at the reject signal leaves it uncollected.
        let fixture = AdvertHandlerFixture::with_streams(
            btreemap! { REMOTE_SUBNET => own_stream.clone() },
            store_expecting_decodes(&advertised(REJECT_SIGNAL), 1),
            log.clone(),
        );
        assert_matches!(
            fixture.handle_advert(make_advert(&advertised(REJECT_SIGNAL))),
            Ok(XNetAdvertOutcome::NothingNew)
        );

        // One past it collects it, so there is something to fetch after all.
        let fixture = AdvertHandlerFixture::with_streams(
            btreemap! { REMOTE_SUBNET => own_stream },
            store_expecting_decodes(&advertised(REJECT_SIGNAL + 1), 1),
            log,
        );
        assert_matches!(
            fixture.handle_advert(make_advert(&advertised(REJECT_SIGNAL + 1))),
            Ok(XNetAdvertOutcome::Actionable)
        );
    });
}

/// An advert whose payload is not a canonical stream slice is rejected out of
/// hand, before any verification.
#[tokio::test]
async fn handle_advert_decode_error() {
    with_test_replica_logger(|log| {
        // No expectations: verifying an advert we cannot even decode would panic.
        let store = MockCertifiedStreamStore::new();
        let fixture = AdvertHandlerFixture::new(store, log);

        let advert = CertifiedStreamSlice {
            payload: b"garbage".to_vec(),
            ..make_advert(&peer_stream_for_advert_tests())
        };

        assert_matches!(
            fixture.handle_advert(advert),
            Err(XNetAdvertError::DecodeError(_))
        );
        assert_eq!(None, fixture.recorded_peer_header());
    });
}

/// An advert offering new content whose certification does not verify is
/// rejected and not recorded.
#[tokio::test]
async fn handle_advert_invalid_signature() {
    with_test_replica_logger(|log| {
        let advertised = peer_stream_for_advert_tests();
        let mut store = MockCertifiedStreamStore::new();
        store
            .expect_decode_certified_stream_slice()
            .times(1)
            .return_once(|_, _, _| Err(DecodeStreamError::InvalidSignature(REMOTE_SUBNET)));
        let mut fixture = AdvertHandlerFixture::new(store, log);

        assert_matches!(
            fixture.handle_advert(make_advert(&advertised)),
            Err(XNetAdvertError::InvalidSignature)
        );
        assert_eq!(None, fixture.recorded_peer_header());
        assert!(fixture.take_pull_requests().is_empty());
    });
}

/// A subnet is scheduled at most once, however many pulls from it are requested:
/// including while its pull is in flight, after it was taken off the queue; until
/// it is removed.
#[test]
fn pull_schedule_push_pop_and_remove() {
    let mut schedule = PullSchedule::default();
    schedule.push(SUBNET_1);
    schedule.push(SUBNET_2);
    schedule.push(SUBNET_1);
    assert_eq!(VecDeque::from([SUBNET_1, SUBNET_2]), schedule.queue);

    // In flight, so still scheduled.
    assert_eq!(Some(SUBNET_1), schedule.pop());
    schedule.push(SUBNET_1);
    assert_eq!(VecDeque::from([SUBNET_2]), schedule.queue);

    // Removing a queued subnet takes it off the queue.
    schedule.remove(SUBNET_2);
    assert_eq!(None, schedule.pop());

    schedule.remove(SUBNET_1);
    schedule.push(SUBNET_1);
    assert_eq!(Some(SUBNET_1), schedule.pop());
}

/// A `XNetClient` that replies to every advert with the same canned response,
/// recording what was posted where.
struct FakeAdvertClient {
    /// `Err(())` stands for `XNetClientError::Timeout`, as `XNetClientError` is not
    /// `Clone`.
    reply: Result<Option<CertifiedStreamSlice>, ()>,

    posted: Mutex<Vec<(NodeId, CertifiedStreamSlice)>>,

    /// The `AdvertTask` metrics, to check the outstanding count while in flight.
    metrics: MetricsRegistry,
}

impl FakeAdvertClient {
    fn new(reply: Result<Option<CertifiedStreamSlice>, ()>, metrics: &MetricsRegistry) -> Self {
        Self {
            reply,
            posted: Mutex::new(Vec::new()),
            metrics: metrics.clone(),
        }
    }

    fn posted(&self) -> Vec<(NodeId, CertifiedStreamSlice)> {
        self.posted.lock().unwrap().clone()
    }
}

#[async_trait]
impl XNetClient for FakeAdvertClient {
    async fn query(
        &self,
        _endpoint: &EndpointLocator,
    ) -> Result<CertifiedStreamSlice, XNetClientError> {
        unimplemented!("no querying in these tests")
    }

    async fn post_advert(
        &self,
        endpoint: &EndpointLocator,
        advert: CertifiedStreamSlice,
    ) -> Result<Option<CertifiedStreamSlice>, XNetClientError> {
        assert_eq!(
            Some(1),
            fetch_int_gauge(&self.metrics, METRIC_OUTSTANDING_ADVERTS)
        );
        self.posted.lock().unwrap().push((endpoint.node_id, advert));
        match &self.reply {
            Ok(reply) => Ok(reply.clone()),
            Err(()) => Err(XNetClientError::Timeout),
        }
    }
}

/// A `XNetEndpointResolver` for `LOCAL_NODE` on `LOCAL_SUBNET`, using the
/// registry from `get_node_selection_registry_for_test()`. Its node selection
/// always picks the first candidates, so advert targets are deterministic.
fn endpoint_resolver(metrics: &MetricsRegistry, log: ReplicaLogger) -> XNetEndpointResolver {
    let registry = get_node_selection_registry_for_test();
    let proximity_map = Arc::new(ProximityMap::with_rng(
        mock_gen_range_low(0, 1),
        LOCAL_NODE,
        registry.clone(),
        metrics,
        log.clone(),
    ));
    XNetEndpointResolver::new(registry, LOCAL_NODE, LOCAL_SUBNET, proximity_map, log)
}

/// A `PullTask` for `LOCAL_SUBNET`, populating `pool`, with no certified state.
/// Its client cannot query, so its pulls must never run.
fn pull_task(pool: &Arc<Mutex<CertifiedSlicePool>>, log: ReplicaLogger) -> Arc<PullTask> {
    let metrics = MetricsRegistry::new();
    Arc::new(PullTask {
        pool: Arc::clone(pool),
        endpoint_resolver: Arc::new(endpoint_resolver(&metrics, log.clone())),
        xnet_client: Arc::new(FakeAdvertClient::new(Ok(None), &metrics)),
        certified_stream_store: Arc::new(MockCertifiedStreamStore::new()),
        state_manager: Arc::new(FakeStateManager::new()),
        registry: get_node_selection_registry_for_test(),
        metrics: PullTaskMetrics::new(&metrics),
        log,
    })
}

/// `start_pulls()` starts a pull from every queued subnet that still has
/// something to pull, keeping it scheduled meanwhile; and unschedules the rest.
/// `end_pull()` requeues a subnet only if its pull pooled something and there is
/// more to pull.
#[tokio::test]
async fn pull_task_start_and_end_pulls() {
    with_test_replica_logger(|log| {
        let pool = Arc::new(Mutex::new(CertifiedSlicePool::new(
            &MetricsRegistry::new(),
            log.clone(),
        )));
        let header = generate_stream(&StreamConfig {
            message_begin: 0,
            message_end: 5,
            signal_end: 0,
        })
        .header();
        let covering_header = ExpectedIndices {
            message_index: header.end(),
            signal_index: header.signals_end(),
            max_no_gc_header_begin: header.begin(),
        };
        // Something to pull from `REMOTE_SUBNET`; nothing left to pull from `SUBNET_2`;
        // and no stream position to pull from for `SUBNET_3`.
        {
            let mut pool = pool.lock().unwrap();
            pool.garbage_collect(btreemap! {
                REMOTE_SUBNET => ExpectedIndices::default(),
                SUBNET_2 => covering_header.clone(),
            });
            for subnet_id in [REMOTE_SUBNET, SUBNET_2, SUBNET_3] {
                pool.record_peer_header(subnet_id, &header);
            }
        }
        let task = pull_task(&pool, log);
        let mut schedule = PullSchedule::default();
        let mut in_flight = InFlightPulls::default();

        for subnet_id in [REMOTE_SUBNET, SUBNET_2, SUBNET_3] {
            schedule.push(subnet_id);
        }
        // Spawns a pull that never runs, because the test runs on a single-threaded
        // runtime and the test body never awaits.
        task.start_pulls(&mut schedule, &mut in_flight);
        assert_eq!(
            vec![REMOTE_SUBNET],
            in_flight.subnets.values().copied().collect::<Vec<_>>()
        );
        assert_eq!(BTreeSet::from([REMOTE_SUBNET]), schedule.scheduled);
        assert!(schedule.queue.is_empty());

        // A pull that pooled something, with more left to pull, is requeued.
        task.end_pull(&mut schedule, REMOTE_SUBNET, true);
        assert_eq!(VecDeque::from([REMOTE_SUBNET]), schedule.queue);

        // One that pooled nothing is not.
        assert_eq!(Some(REMOTE_SUBNET), schedule.pop());
        task.end_pull(&mut schedule, REMOTE_SUBNET, false);
        assert!(schedule.scheduled.is_empty());

        // Nor is one with nothing left to pull.
        schedule.push(REMOTE_SUBNET);
        assert_eq!(Some(REMOTE_SUBNET), schedule.pop());
        pool.lock().unwrap().garbage_collect(btreemap! {
            REMOTE_SUBNET => covering_header,
        });
        task.end_pull(&mut schedule, REMOTE_SUBNET, true);
        assert!(schedule.scheduled.is_empty());
    });
}

/// On a refill trigger, the pull task schedules every peer whose recorded header
/// offers something left to pull; and no other.
#[tokio::test]
async fn pull_task_schedules_pending_pulls() {
    with_test_replica_logger(|log| {
        let pool = Arc::new(Mutex::new(CertifiedSlicePool::new(
            &MetricsRegistry::new(),
            log.clone(),
        )));
        let header = generate_stream(&StreamConfig {
            message_begin: 0,
            message_end: 5,
            signal_end: 0,
        })
        .header();
        // Something to pull from `REMOTE_SUBNET`; nothing left to pull from `SUBNET_2`;
        // and no recorded header for `SUBNET_3`.
        {
            let mut pool = pool.lock().unwrap();
            pool.garbage_collect(btreemap! {
                REMOTE_SUBNET => ExpectedIndices::default(),
                SUBNET_2 => ExpectedIndices {
                    message_index: header.end(),
                    signal_index: header.signals_end(),
                    max_no_gc_header_begin: header.begin(),
                },
                SUBNET_3 => ExpectedIndices::default(),
            });
            for subnet_id in [REMOTE_SUBNET, SUBNET_2] {
                pool.record_peer_header(subnet_id, &header);
            }
        }
        let task = pull_task(&pool, log);
        let mut schedule = PullSchedule::default();

        task.schedule_pending_pulls(&mut schedule);
        assert_eq!(VecDeque::from([REMOTE_SUBNET]), schedule.queue);
    });
}

/// The pull task never schedules our own subnet: the loopback stream is inducted
/// separately.
#[tokio::test]
async fn pull_task_skips_own_subnet() {
    with_test_replica_logger(|log| {
        let pool = Arc::new(Mutex::new(CertifiedSlicePool::new(
            &MetricsRegistry::new(),
            log.clone(),
        )));
        // Recorded headers offering something to pull.
        let header = generate_stream(&StreamConfig {
            message_begin: 0,
            message_end: 1,
            signal_end: 0,
        })
        .header();
        for subnet_id in [LOCAL_SUBNET, REMOTE_SUBNET] {
            pool.lock().unwrap().record_peer_header(subnet_id, &header);
        }
        let task = pull_task(&pool, log);
        let mut schedule = PullSchedule::default();

        // Neither on request, nor on refill.
        task.schedule_pull(&mut schedule, LOCAL_SUBNET);
        task.schedule_pending_pulls(&mut schedule);
        assert_eq!(VecDeque::from([REMOTE_SUBNET]), schedule.queue);
    });
}

/// An `AdvertTask` posting through `xnet_client`, with `fixture`'s handler
/// deciding what to advertise and handling the replies; and using the registry
/// from `get_node_selection_registry_for_test()`.
fn advert_task(
    xnet_client: Arc<dyn XNetClient>,
    fixture: &AdvertHandlerFixture,
    metrics: &MetricsRegistry,
    log: ReplicaLogger,
) -> AdvertTask {
    AdvertTask::new(
        Arc::clone(&fixture.handler),
        Arc::new(endpoint_resolver(metrics, log.clone())),
        xnet_client,
        metrics,
        log,
    )
}

/// Our certified header, as advertised: that of `own_stream_for_advert_tests()`.
fn own_advert() -> CertifiedStreamSlice {
    make_advert_for(LOCAL_SUBNET, REMOTE_SUBNET, &own_stream_for_advert_tests())
}

/// Makes `store` encode `own_advert()` as our certified header.
fn with_own_header(mut store: MockCertifiedStreamStore) -> MockCertifiedStreamStore {
    store
        .expect_encode_certified_stream_slice()
        .returning(|_, _, _, _, _| Ok(own_advert()));
    store
}

/// Asserts that `metrics` record exactly one advert, sent to `REMOTE_SUBNET` with
/// the given `status`; and none outstanding.
fn assert_one_advert_sent(metrics: &MetricsRegistry, status: &str) {
    assert_eq!(
        metric_vec(&[(
            &[
                (LABEL_REMOTE, REMOTE_SUBNET.to_string()),
                (LABEL_STATUS, status.to_string()),
            ],
            1,
        )]),
        fetch_int_counter_vec(metrics, METRIC_ADVERTS_SENT)
    );
    assert_eq!(
        metric_vec(&[(&[(LABEL_STATUS, status)], 1)]),
        fetch_histogram_vec_count(metrics, METRIC_SEND_ADVERT_DURATION)
    );
    assert_eq!(
        Some(0),
        fetch_int_gauge(metrics, METRIC_OUTSTANDING_ADVERTS)
    );
}

/// An advert the peer accepted but did not reply to leaves us with no recorded
/// header.
#[tokio::test]
async fn advertise_to_without_reply() {
    with_test_replica_logger(|log| async {
        let metrics = MetricsRegistry::new();
        let xnet_client = Arc::new(FakeAdvertClient::new(Ok(None), &metrics));

        let fixture = AdvertHandlerFixture::new(MockCertifiedStreamStore::new(), log.clone());

        advert_task(xnet_client.clone(), &fixture, &metrics, log)
            .advertise_to(REMOTE_SUBNET, REMOTE_NODE_2_OPERATOR_1, own_advert())
            .await;

        assert_eq!(
            vec![(REMOTE_NODE_2_OPERATOR_1, own_advert())],
            xnet_client.posted()
        );
        assert_eq!(None, fixture.recorded_peer_header());
        assert_one_advert_sent(&metrics, STATUS_SUCCESS);
    })
    .await;
}

/// A reply to an advert is a header from the peer, so it goes back through the
/// receive path and is recorded like any other.
#[tokio::test]
async fn advertise_to_records_the_reply() {
    with_test_replica_logger(|log| async {
        let metrics = MetricsRegistry::new();
        // A remote stream with all our messages inducted and our signals acted on.
        let remote_stream = generate_stream(&StreamConfig {
            message_begin: OWN_SIGNALS_END,
            message_end: OWN_SIGNALS_END,
            signal_end: OWN_MESSAGES_END,
        });
        let xnet_client = Arc::new(FakeAdvertClient::new(
            Ok(Some(make_advert(&remote_stream))),
            &metrics,
        ));

        // Expect to have to verify the reply.
        let fixture =
            AdvertHandlerFixture::new(store_expecting_decodes(&remote_stream, 1), log.clone());

        advert_task(xnet_client.clone(), &fixture, &metrics, log)
            .advertise_to(REMOTE_SUBNET, REMOTE_NODE_1_OPERATOR_1, own_advert())
            .await;

        assert_eq!(1, xnet_client.posted().len());
        assert_eq!(
            Some(Arc::new(remote_stream.header())),
            fixture.recorded_peer_header()
        );
        // Reply is actionable because it has signals for all our messages.
        assert_one_advert_sent(&metrics, "actionable");
    })
    .await;
}

/// A reply whose certification does not verify is an error, and is not
/// recorded by the pool.
#[tokio::test]
async fn advertise_to_invalid_reply() {
    with_test_replica_logger(|log| async {
        let metrics = MetricsRegistry::new();
        let remote_stream = generate_stream(&StreamConfig {
            message_begin: OWN_SIGNALS_END,
            message_end: OWN_SIGNALS_END,
            signal_end: OWN_MESSAGES_END,
        });
        let xnet_client = Arc::new(FakeAdvertClient::new(
            Ok(Some(make_advert(&remote_stream))),
            &metrics,
        ));

        let mut store = MockCertifiedStreamStore::new();
        store
            .expect_decode_certified_stream_slice()
            .times(1)
            .return_once(|_, _, _| Err(DecodeStreamError::InvalidSignature(REMOTE_SUBNET)));
        let fixture = AdvertHandlerFixture::new(store, log.clone());

        advert_task(xnet_client.clone(), &fixture, &metrics, log)
            .advertise_to(REMOTE_SUBNET, REMOTE_NODE_1_OPERATOR_1, own_advert())
            .await;

        assert_eq!(1, xnet_client.posted().len());
        assert_eq!(None, fixture.recorded_peer_header());
        assert_one_advert_sent(&metrics, "invalid_signature");
    })
    .await;
}

/// A post that fails is an error, and no longer outstanding.
#[tokio::test]
async fn advertise_to_post_failure() {
    with_test_replica_logger(|log| async {
        let metrics = MetricsRegistry::new();
        let xnet_client = Arc::new(FakeAdvertClient::new(Err(()), &metrics));

        let fixture = AdvertHandlerFixture::new(MockCertifiedStreamStore::new(), log.clone());

        advert_task(xnet_client.clone(), &fixture, &metrics, log)
            .advertise_to(REMOTE_SUBNET, REMOTE_NODE_1_OPERATOR_1, own_advert())
            .await;

        assert_eq!(1, xnet_client.posted().len());
        assert_one_advert_sent(&metrics, "Timeout");
    })
    .await;
}

/// A node we cannot resolve to an `XNetEndpoint` is not advertised to.
#[tokio::test]
async fn advertise_to_unknown_node() {
    with_test_replica_logger(|log| async {
        let metrics = MetricsRegistry::new();
        let xnet_client = Arc::new(FakeAdvertClient::new(Ok(None), &metrics));

        let fixture = AdvertHandlerFixture::new(MockCertifiedStreamStore::new(), log.clone());

        advert_task(xnet_client.clone(), &fixture, &metrics, log)
            .advertise_to(REMOTE_SUBNET, NODE_42, own_advert())
            .await;

        assert!(xnet_client.posted().is_empty());
        assert_one_advert_sent(&metrics, "MissingXNetEndpoint");
    })
    .await;
}

#[test]
fn advert_target_count_scales_with_subnet_sizes() {
    assert_eq!(3, advert_target_count(13, 13));
    // Enough targets for `ADVERTS_PER_NODE` adverts per node of a larger subnet.
    assert_eq!(10, advert_target_count(13, 40));
    // At least one target.
    assert_eq!(1, advert_target_count(40, 13));
    // No more targets than the peer has nodes.
    assert_eq!(3, advert_target_count(1, 3));
}

/// We owe an advert to every peer whose stream holds messages; or that has not
/// seen our latest signals, as far as its recorded header tells. Never to
/// ourselves.
#[test]
fn subnets_owed_adverts() {
    with_test_replica_logger(|log| {
        let stream = |message_count: u64, signal_end: u64| {
            generate_stream(&StreamConfig {
                message_begin: 10,
                message_end: 10 + message_count,
                signal_end,
            })
        };
        let peer_header = |begin: u64| {
            generate_stream(&StreamConfig {
                message_begin: begin,
                message_end: begin,
                signal_end: 0,
            })
            .header()
        };
        // The loopback stream is the one to `FakeStateManager`'s own subnet.
        let own_subnet_id = FakeStateManager::new()
            .get_latest_state()
            .get_ref()
            .metadata
            .own_subnet_id;
        let fixture = AdvertHandlerFixture::with_streams(
            btreemap! {
                own_subnet_id => stream(2, 0),
                SUBNET_1 => stream(2, 0),
                SUBNET_2 => stream(0, 5),
                SUBNET_3 => stream(0, 5),
                SUBNET_4 => stream(0, 5),
                SUBNET_5 => stream(0, 0),
            },
            MockCertifiedStreamStore::new(),
            log,
        );
        {
            let mut pool = fixture.pool.lock().unwrap();
            // Has seen our signals.
            pool.record_peer_header(SUBNET_2, &peer_header(5));
            // Has not.
            pool.record_peer_header(SUBNET_3, &peer_header(3));
        }

        // `SUBNET_1` for its messages, `SUBNET_3` and `SUBNET_4` for our signals.
        assert_eq!(
            vec![SUBNET_1, SUBNET_3, SUBNET_4],
            fixture.handler.subnets_owed_adverts()
        );
    });
}

/// A stream gone by the time we encode its header is not advertised.
#[test]
fn adverts_owed_without_stream() {
    with_test_replica_logger(|log| {
        let mut store = MockCertifiedStreamStore::new();
        store
            .expect_encode_certified_stream_slice()
            .returning(|subnet_id, _, _, _, _| {
                Err(EncodeStreamError::NoStreamForSubnet(subnet_id))
            });
        let fixture = AdvertHandlerFixture::new(store, log);

        assert!(fixture.handler.adverts_owed().is_empty());
    });
}

/// Advert targets are `advert_target_count()` nodes of the peer subnet: healthy
/// ones only, as long as there are enough of those.
#[test]
fn advert_targets() {
    with_test_replica_logger(|log| {
        let resolver = endpoint_resolver(&MetricsRegistry::new(), log);
        let targets = || resolver.advert_targets(REMOTE_SUBNET).unwrap();

        // 6 local nodes and 3 remote ones make for 2 targets.
        assert_eq!(
            vec![REMOTE_NODE_1_OPERATOR_1, REMOTE_NODE_2_OPERATOR_1],
            targets()
        );

        // Two healthy nodes are enough.
        resolver
            .proximity_map
            .observe_failure(REMOTE_NODE_1_OPERATOR_1);
        assert_eq!(
            vec![REMOTE_NODE_2_OPERATOR_1, REMOTE_NODE_3_OPERATOR_2],
            targets()
        );

        // One is not, so unhealthy nodes are picked too.
        resolver
            .proximity_map
            .observe_failure(REMOTE_NODE_2_OPERATOR_1);
        assert_eq!(
            vec![REMOTE_NODE_1_OPERATOR_1, REMOTE_NODE_2_OPERATOR_1],
            targets()
        );

        assert_matches!(
            resolver.advert_targets(SUBNET_5),
            Err(Error::MissingSubnet(subnet)) if subnet == SUBNET_5
        );
    });
}

/// Every subnet we owe an advert to gets our certified header, to all of its
/// targets; one whose targets cannot be picked, none.
#[test]
fn adverts_to_send() {
    with_test_replica_logger(|log| {
        let metrics = MetricsRegistry::new();
        // `SUBNET_5` is unknown to the registry.
        let fixture = AdvertHandlerFixture::with_streams(
            btreemap! {
                REMOTE_SUBNET => own_stream_for_advert_tests(),
                SUBNET_5 => own_stream_for_advert_tests(),
            },
            with_own_header(MockCertifiedStreamStore::new()),
            log.clone(),
        );
        let task = advert_task(
            Arc::new(FakeAdvertClient::new(Ok(None), &metrics)),
            &fixture,
            &metrics,
            log,
        );

        // 6 local nodes and 3 remote ones make for 2 targets.
        assert_eq!(
            vec![(
                REMOTE_SUBNET,
                own_advert(),
                vec![REMOTE_NODE_1_OPERATOR_1, REMOTE_NODE_2_OPERATOR_1]
            )],
            task.adverts_to_send()
        );
        assert_eq!(
            metric_vec(&[(
                &[
                    (LABEL_REMOTE, SUBNET_5.to_string()),
                    (LABEL_STATUS, "MissingSubnet".to_string()),
                ],
                1,
            )]),
            fetch_int_counter_vec(&metrics, METRIC_ADVERTS_SENT)
        );
    });
}

/// A newly certified height sets off the adverts; and the task ends once the
/// sender is dropped.
#[tokio::test]
async fn advertises_on_newly_certified_height() {
    with_test_replica_logger(|log| async {
        let metrics = MetricsRegistry::new();
        let xnet_client = Arc::new(FakeAdvertClient::new(Ok(None), &metrics));
        let fixture = AdvertHandlerFixture::new(
            with_own_header(MockCertifiedStreamStore::new()),
            log.clone(),
        );

        let (height_tx, height_rx) = watch::channel(Height::new(0));
        advert_task(xnet_client.clone(), &fixture, &metrics, log)
            .start(height_rx, &tokio::runtime::Handle::current());
        height_tx.send(CERTIFIED_HEIGHT).unwrap();

        // 6 local nodes and 3 remote ones make for 2 targets.
        let expected_sent = metric_vec(&[(
            &[
                (LABEL_REMOTE, REMOTE_SUBNET.to_string()),
                (LABEL_STATUS, STATUS_SUCCESS.to_string()),
            ],
            2,
        )]);
        tokio::time::timeout(Duration::from_secs(10), async {
            while fetch_int_counter_vec(&metrics, METRIC_ADVERTS_SENT) != expected_sent {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("Timed out waiting for adverts");

        // Posted in whichever order the spawned tasks ran.
        let mut posted = xnet_client.posted();
        posted.sort_by_key(|(node, _)| *node);
        assert_eq!(
            vec![
                (REMOTE_NODE_1_OPERATOR_1, own_advert()),
                (REMOTE_NODE_2_OPERATOR_1, own_advert()),
            ],
            posted
        );

        // Once the sender is dropped, the task ends, dropping its reference to the
        // client.
        drop(height_tx);
        tokio::time::timeout(Duration::from_secs(10), async {
            while Arc::strong_count(&xnet_client) > 1 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("Timed out waiting for the advert task to end");
    })
    .await;
}
