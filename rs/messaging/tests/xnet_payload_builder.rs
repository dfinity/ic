use async_trait::async_trait;
use ic_interfaces::{
    certified_stream_store::CertifiedStreamStore, messaging::XNetPayloadBuilder,
    registry::RegistryClient,
};
use ic_logger::ReplicaLogger;
use ic_messaging::{
    certified_slice_pool::{CertifiedSlicePool, UnpackedStreamSlice},
    xnet_payload_builder_testing::*,
    ExpectedIndices, XNetPayloadBuilderImpl,
};
use ic_metrics::MetricsRegistry;
use ic_protobuf::registry::{
    node::v1::connection_endpoint::Protocol, subnet::v1::SubnetListRecord,
};
use ic_registry_client::{
    client::RegistryClientImpl,
    helper::node::{ConnectionEndpoint, NodeRecord},
};
use ic_registry_common::proto_registry_data_provider::ProtoRegistryDataProvider;
use ic_registry_keys::{make_node_record_key, make_subnet_list_record_key, make_subnet_record_key};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::metadata_state::Stream;
use ic_state_manager::StateManagerImpl;
use ic_test_utilities::{
    crypto::fake_tls_handshake::FakeTlsHandshake,
    metrics::{
        fetch_histogram_stats, fetch_histogram_vec_count, metric_vec, HistogramStats, MetricVec,
    },
    mock_time,
    registry::SubnetRecordBuilder,
    state::arb_stream,
    types::ids::{
        NODE_1, NODE_2, NODE_3, NODE_4, NODE_42, NODE_5, SUBNET_1, SUBNET_2, SUBNET_3, SUBNET_4,
        SUBNET_5,
    },
    with_test_replica_logger,
};
use ic_types::{
    batch::ValidationContext,
    xnet::{CertifiedStreamSlice, StreamIndex, StreamIndexedQueue, StreamSlice},
    CountBytes, Height, NodeId, RegistryVersion, SubnetId,
};
use maplit::btreemap;
use proptest::prelude::*;
use std::{
    collections::BTreeMap,
    convert::TryFrom,
    sync::{Arc, Mutex},
};
use tempfile::TempDir;
use tokio::{runtime::Handle, time::Duration};

mod common;
use common::*;

pub const OWN_NODE: NodeId = NODE_42;
pub const REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(169);

/// Test fixture around a `XNetPayloadBuilderImpl` for use in payload building
/// tests.
struct XNetPayloadBuilderFixture {
    pub xnet_payload_builder: XNetPayloadBuilderImpl,
    pub state_manager: Arc<StateManagerImpl>,
    pub certified_height: Height,
    pub metrics: MetricsRegistry,
    pub _temp_dir: TempDir,
}

impl XNetPayloadBuilderFixture {
    fn new(fixture: StateManagerFixture) -> Self {
        let state_manager = Arc::new(fixture.state_manager);
        let tls_handshake = Arc::new(FakeTlsHandshake::new());

        // Throwaway runtime, we don't need registry polling or pool refill.
        let runtime_handle = tokio::runtime::Runtime::new().unwrap().handle().clone();
        let registry = get_registry_for_test(runtime_handle.clone());

        let xnet_payload_builder = XNetPayloadBuilderImpl::new(
            Arc::clone(&state_manager) as Arc<_>,
            Arc::clone(&state_manager) as Arc<_>,
            tls_handshake as Arc<_>,
            registry,
            runtime_handle,
            OWN_NODE,
            OWN_SUBNET,
            &fixture.metrics,
            fixture.log,
        );

        Self {
            xnet_payload_builder,
            state_manager,
            certified_height: fixture.certified_height,
            metrics: fixture.metrics,
            _temp_dir: fixture.temp_dir,
        }
    }

    /// Calls `get_xnet_payload()` on the wrapped `XNetPayloadBuilder` and
    /// decodes all slices in the payload.
    fn get_xnet_payload(&self, byte_limit: usize) -> BTreeMap<SubnetId, StreamSlice> {
        let time = mock_time();
        let validation_context = ValidationContext {
            registry_version: REGISTRY_VERSION,
            certified_height: self.certified_height,
            time,
        };

        self.xnet_payload_builder
            .get_xnet_payload(&validation_context, &[], (byte_limit as u64).into())
            .stream_slices
            .into_iter()
            .map(|(k, v)| {
                (
                    k,
                    self.state_manager
                        .decode_certified_stream_slice(k, REGISTRY_VERSION, &v)
                        .unwrap(),
                )
            })
            .collect()
    }

    /// Pools the provided slice coming from a given subnet and returns its byte
    /// size, as evaluated by `UnpackedStreamSlice::count_bytes()`.
    fn pool_slice(
        &self,
        subnet_id: SubnetId,
        stream: &Stream,
        from: StreamIndex,
        msg_count: usize,
        log: &ReplicaLogger,
    ) -> usize {
        let certified_slice = in_slice(stream, from, from, msg_count, log);
        let slice_size_bytes = UnpackedStreamSlice::try_from(certified_slice.clone())
            .unwrap()
            .count_bytes();
        pool_slice(&self.xnet_payload_builder, subnet_id, certified_slice);
        slice_size_bytes
    }

    /// Fetches the values of the `METRIC_BUILD_PAYLOAD_DURATION` histograms'
    /// `_count` fields for all label value combinations.
    fn build_payload_counts(&self) -> MetricVec<u64> {
        fetch_histogram_vec_count(&self.metrics, METRIC_BUILD_PAYLOAD_DURATION)
    }

    /// Fetches the `METRIC_SLICE_MESSAGES` histogram's stats.
    fn slice_messages_stats(&self) -> HistogramStats {
        fetch_histogram_stats(&self.metrics, METRIC_SLICE_MESSAGES).unwrap()
    }

    /// Fetches the `METRIC_SLICE_PAYLOAD_SIZE` histogram's stats.
    fn slice_payload_size_stats(&self) -> HistogramStats {
        fetch_histogram_stats(&self.metrics, METRIC_SLICE_PAYLOAD_SIZE).unwrap()
    }
}

/// Generates a `RegistryClient` with an own node record (the minimum necessary
/// to boot up an `XNetPayloadBuilderImpl`), subnet records for `SUBNET_1`
/// through `SUBNET_5` (each consisting of one node, with a corresponding node
/// record) and a subnet list record covering `SUBNET_1` through `SUBNET_5` (so
/// they're considered for payload building).
fn get_registry_for_test(runtime_handle: Handle) -> Arc<dyn RegistryClient> {
    let data_provider = ProtoRegistryDataProvider::new();

    for (i, node) in [OWN_NODE, NODE_1, NODE_2, NODE_3, NODE_4, NODE_5]
        .iter()
        .enumerate()
    {
        data_provider
            .add(
                &make_node_record_key(*node),
                REGISTRY_VERSION,
                Some(NodeRecord {
                    xnet: Some(ConnectionEndpoint {
                        ip_addr: "127.0.0.1".to_string(),
                        port: i as u32,
                        protocol: Protocol::Http1 as i32,
                    }),
                    ..Default::default()
                }),
            )
            .unwrap();
    }

    for (subnet, node) in &[
        (SUBNET_1, NODE_1),
        (SUBNET_2, NODE_2),
        (SUBNET_3, NODE_3),
        (SUBNET_4, NODE_4),
        (SUBNET_5, NODE_5),
    ] {
        let subnet_record = SubnetRecordBuilder::from(&[*node]).build();
        data_provider
            .add(
                &make_subnet_record_key(*subnet),
                REGISTRY_VERSION,
                Some(subnet_record),
            )
            .unwrap();
    }

    let subnet_list_record = SubnetListRecord {
        subnets: vec![
            SUBNET_1.get().to_vec(),
            SUBNET_2.get().to_vec(),
            SUBNET_3.get().to_vec(),
            SUBNET_4.get().to_vec(),
            SUBNET_5.get().to_vec(),
        ],
    };
    data_provider
        .add(
            make_subnet_list_record_key().as_str(),
            REGISTRY_VERSION,
            Some(subnet_list_record),
        )
        .unwrap();

    let registry_client = RegistryClientImpl::new(Arc::new(data_provider), None);
    runtime_handle.block_on(async { registry_client.fetch_and_start_polling().unwrap() });
    Arc::new(registry_client)
}

/// Creates an incoming `CertifiedStreamSlice` containing `msg_count` messages
/// beginning at `msg_from` and witness beginning at `witness_from`.
fn in_slice(
    stream: &Stream,
    witness_from: StreamIndex,
    msg_from: StreamIndex,
    msg_count: usize,
    log: &ReplicaLogger,
) -> CertifiedStreamSlice {
    let remote_state_manager =
        StateManagerFixture::new(log.clone()).with_stream(OWN_SUBNET, stream.clone());
    remote_state_manager.get_partial_slice(OWN_SUBNET, witness_from, msg_from, msg_count)
}

/// Creates a matching outgoing stream for the given stream and slice begin
/// index.
fn out_stream(in_stream: &Stream, messages_begin: StreamIndex) -> Stream {
    Stream::new(
        StreamIndexedQueue::with_begin(in_stream.signals_end()),
        messages_begin,
    )
}

proptest! {
    /// Tests payload building with various alignments of expected indices to
    /// slice: just before the pooled slice, within the pooled slice, just
    /// after the pooled slice.
    #[test]
    fn get_xnet_payload_slice_alignment(
        (stream, from, msg_count) in arb_stream_slice(5, 10),
    ) {
        // Bump `from` (and adjust `msg_count` accordingly) so we can decrement it later
        // on.
        let from = from.increment();
        let msg_count = msg_count - 1;

        with_test_replica_logger(|log| {
            let mut state_manager =
                StateManagerFixture::with_subnet_type(SubnetType::Application, log.clone());

            // We will be creating 3 identical copies of the slice, each coming from a
            // different subnet.
            //
            // Create 3 reverse streams within `state_manager`:
            //  * One with `signals_end` just before `from` (so there's a missing message).
            //  * One with `signals_end` just after `from` (so there's an extra message).
            //  * One with `signals_end` just after `from + msg_count` (so we've already
            //    seen all messages).
            state_manager =
                state_manager.with_stream(SUBNET_1, out_stream(&stream, from.decrement()));
            state_manager =
                state_manager.with_stream(SUBNET_2, out_stream(&stream, from.increment()));
            state_manager = state_manager.with_stream(
                SUBNET_3,
                out_stream(&stream, from + (msg_count as u64 + 1).into()),
            );

            // Create payload builder with the 3 slices pooled.
            let xnet_payload_builder = XNetPayloadBuilderFixture::new(state_manager);
            xnet_payload_builder.pool_slice(SUBNET_1, &stream, from, msg_count, &log);
            xnet_payload_builder.pool_slice(SUBNET_2, &stream, from, msg_count, &log);
            xnet_payload_builder.pool_slice(SUBNET_3, &stream, from, msg_count, &log);

            // Build the payload.
            let payload = xnet_payload_builder
                .get_xnet_payload(std::usize::MAX);

            // Payload should contain 1 slice...
            assert_eq!(
                1,
                payload.len(),
                "Expecting 1 slice in payload, got {}",
                payload.len()
            );
            // ...from SUBNET_2...
            if let Some(slice) = payload.get(&SUBNET_2) {
                assert_eq!(stream.messages_begin(), slice.header().begin);
                assert_eq!(stream.messages_end(), slice.header().end);
                assert_eq!(stream.signals_end(), slice.header().signals_end);

                // ...with non-empty messages...
                if let Some(messages) = slice.messages() {
                    // ...between (from + 1) and stream.end.
                    assert_eq!(from.increment(), messages.begin());
                    assert_eq!(from + (msg_count as u64).into(), messages.end());
                } else {
                    panic!("Expected a non-empty slice from SUBNET_2");
                }
            } else {
                panic!(
                    "Expected a slice from SUBNET_2, got {:?}",
                    payload.keys().next()
                );
            }

            assert_eq!(
                metric_vec(&[(&[(LABEL_STATUS, STATUS_SUCCESS)], 1)]),
                xnet_payload_builder.build_payload_counts()
            );
            assert_eq!(
                HistogramStats {
                    count: 1,
                    sum: (msg_count - 1) as f64
                },
                xnet_payload_builder.slice_messages_stats()
            );
            assert_eq!(1, xnet_payload_builder.slice_payload_size_stats().count);
        });
    }

    /// Tests payload building with a byte limit just under the total slice
    /// size.
    #[test]
    fn get_xnet_payload_byte_limit_exceeded(
        (stream1, from1, msg_count1) in arb_stream_slice(10, 15),
        (stream2, from2, msg_count2) in arb_stream_slice(10, 15),
    ) {
        with_test_replica_logger(|log| {
            let mut state_manager =
                StateManagerFixture::with_subnet_type(SubnetType::Application, log.clone());

            // Create a matching outgoing stream within `state_manager` for each slice.
            state_manager = state_manager.with_stream(SUBNET_1, out_stream(&stream1, from1));
            state_manager = state_manager.with_stream(SUBNET_2, out_stream(&stream2, from2));

            // Create payload builder with the 2 slices pooled.
            let xnet_payload_builder = XNetPayloadBuilderFixture::new(state_manager);
            let mut slice_bytes_sum = 0;
            slice_bytes_sum += xnet_payload_builder.pool_slice(SUBNET_1, &stream1, from1, msg_count1, &log);
            slice_bytes_sum += xnet_payload_builder.pool_slice(SUBNET_2, &stream2, from2, msg_count2, &log);

            // Build a payload with a byte limit just under the total size of the 2 slices.
            let payload = xnet_payload_builder
                .get_xnet_payload(slice_bytes_sum - 1);

            // Payload should contain 2 slices.
            assert_eq!(
                2,
                payload.len(),
                "Expecting 2 slices in payload, got {}",
                payload.len()
            );
            // And exactly one message should be missing.
            let msg_count: usize = payload
                .values()
                .map(|slice| slice.messages().map(|m| m.len()).unwrap_or(0))
                .sum();
            assert_eq!(msg_count1 + msg_count2 - 1, msg_count);

            assert_eq!(
                metric_vec(&[(&[(LABEL_STATUS, STATUS_SUCCESS)], 1)]),
                xnet_payload_builder.build_payload_counts()
            );
            assert_eq!(
                HistogramStats {
                    count: 2,
                    sum: (msg_count1 + msg_count2 - 1) as f64
                },
                xnet_payload_builder.slice_messages_stats()
            );
            assert_eq!(2, xnet_payload_builder.slice_payload_size_stats().count);
        });
    }

    /// Tests payload building with a byte limit too small even for an empty
    /// slice.
    #[test]
    fn get_xnet_payload_byte_limit_too_small(
        (stream, from, msg_count) in arb_stream_slice(10, 15),
    ) {
        with_test_replica_logger(|log| {
            let mut state_manager =
                StateManagerFixture::with_subnet_type(SubnetType::Application, log.clone());

            // Create a matching outgoing stream within `state_manager` for each slice.
            state_manager = state_manager.with_stream(REMOTE_SUBNET, out_stream(&stream, from));

            // Create payload builder with the slice pooled.
            let xnet_payload_builder = XNetPayloadBuilderFixture::new(state_manager);
            xnet_payload_builder.pool_slice(REMOTE_SUBNET, &stream, from, msg_count, &log);

            // Build a payload with a byte limit too small even for an empty slice.
            let payload = xnet_payload_builder.get_xnet_payload(1);

            // Payload should contain no slices.
            assert!(
                payload.is_empty(),
                "Expecting empty payload, got payload of length {}",
                payload.len()
            );

            assert_eq!(
                metric_vec(&[(&[(LABEL_STATUS, STATUS_SUCCESS)], 1)]),
                xnet_payload_builder.build_payload_counts()
            );
            assert_eq!(
                HistogramStats {
                    count: 0,
                    sum: 0.0
                },
                xnet_payload_builder.slice_messages_stats()
            );
            assert_eq!(0, xnet_payload_builder.slice_payload_size_stats().count);
        });
    }

    /// Tests payload building from a pool containing an empty slice only.
    #[test]
    fn get_xnet_payload_empty_slice(
        out_stream in arb_stream(1, 1),
    ) {
        // Empty incoming stream.
        let from = out_stream.signals_end();
        let stream = Stream::new(
            StreamIndexedQueue::with_begin(from),
            out_stream.header().begin,
        );

        with_test_replica_logger(|log| {
            let mut state_manager =
                StateManagerFixture::with_subnet_type(SubnetType::Application, log.clone());

            // Place outgoing stream into `state_manager`.
            state_manager = state_manager.with_stream(REMOTE_SUBNET, out_stream);

            // Create payload builder with empty slice pooled.
            let xnet_payload_builder = XNetPayloadBuilderFixture::new(state_manager);
            xnet_payload_builder.pool_slice(REMOTE_SUBNET, &stream, from, 0, &log);

            // Build a payload.
            let payload = xnet_payload_builder
                .get_xnet_payload(std::usize::MAX);

            // Payload should be empty (we already have all signals in the slice).
            assert!(payload.is_empty(), "Expecting empty in payload, got a slice");

            // Bump `stream.signals_end` and pool an empty slice again.
            let mut updated_stream = stream.clone();
            updated_stream.increment_signals_end();
            xnet_payload_builder.pool_slice(REMOTE_SUBNET, &updated_stream, from, 0, &log);

            // Build a payload again.
            let payload = xnet_payload_builder
                .get_xnet_payload(std::usize::MAX);

            // Payload should now contain 1 empty slice from REMOTE_SUBNET.
            assert_eq!(
                1,
                payload.len(),
                "Expecting 1 slice in payload, got {}",
                payload.len()
            );
            if let Some(slice) = payload.get(&REMOTE_SUBNET) {
                assert_eq!(stream.messages_begin(), slice.header().begin);
                assert_eq!(stream.messages_end(), slice.header().end);
                assert_eq!(updated_stream.signals_end(), slice.header().signals_end);
                assert!(slice.messages().is_none());
            } else {
                panic!(
                    "Expected a slice from REMOTE_SUBNET, got {:?}",
                    payload.keys().next()
                );
            }

            assert_eq!(
                metric_vec(&[(&[(LABEL_STATUS, STATUS_SUCCESS)], 2)]),
                xnet_payload_builder.build_payload_counts()
            );
            assert_eq!(
                HistogramStats {
                    count: 1,
                    sum: 0.
                },
                xnet_payload_builder.slice_messages_stats()
            );
            assert_eq!(1, xnet_payload_builder.slice_payload_size_stats().count);
        });
    }

    /// Tests payload building on a system subnet when the combined sizes of the
    /// incoming stream slice and outgoing stream exceed the system subnet
    /// stream throttling limit.
    #[test]
    fn system_subnet_stream_throttling(
        out_stream in arb_stream(SYSTEM_SUBNET_STREAM_MSG_LIMIT / 2 + 1, SYSTEM_SUBNET_STREAM_MSG_LIMIT + 10),
        (stream, from, msg_count) in arb_stream_slice(SYSTEM_SUBNET_STREAM_MSG_LIMIT / 2 + 1, SYSTEM_SUBNET_STREAM_MSG_LIMIT),
    ) {
        // Set the outgoing stream's signals_end to the slice begin.
        let out_stream = Stream::new(out_stream.messages().clone(), from);
        // And the incoming stream's signals_end just beyond the outgoing stream's
        // start, so we always get a slice, even empty.
        let stream = Stream::new(stream.messages().clone(), out_stream.messages_begin().increment());

        with_test_replica_logger(|log| {
            // Fixtures.
            let state_manager =
                StateManagerFixture::with_subnet_type(SubnetType::System, log.clone())
                    .with_stream(REMOTE_SUBNET, out_stream.clone());
            let xnet_payload_builder = XNetPayloadBuilderFixture::new(state_manager);

            // Populate payload builder pool with the REMOTE_SUBNET -> OWN_SUBNET slice.
            let slice = in_slice(&stream, from, from, msg_count, &log);
            pool_slice(
                &xnet_payload_builder.xnet_payload_builder,
                REMOTE_SUBNET,
                slice,
            );

            let payload = xnet_payload_builder
                .get_xnet_payload(std::usize::MAX);

            assert_eq!(1, payload.len());
            if let Some(slice) = payload.get(&REMOTE_SUBNET) {
                let max_slice_len =
                    SYSTEM_SUBNET_STREAM_MSG_LIMIT.saturating_sub(out_stream.messages().len());
                let expected_slice_len = msg_count.min(max_slice_len);

                if expected_slice_len == 0 {
                    assert!(slice.messages().is_none());
                } else if let Some(messages) = slice.messages() {
                    assert_eq!(
                        expected_slice_len,
                        messages.len(),
                        "Expecting a slice of length min({}, {}), got {}",
                        msg_count,
                        max_slice_len,
                        messages.len()
                    );
                } else {
                    panic!(
                        "Expecting a slice of length min({}, {}), got an empty slice",
                        msg_count, max_slice_len
                    );
                }

                assert_eq!(
                metric_vec(&[(&[(LABEL_STATUS, STATUS_SUCCESS)], 1)]),
                    xnet_payload_builder.build_payload_counts()
                );
                assert_eq!(
                    HistogramStats {
                        count: 1,
                        sum: expected_slice_len as f64
                    },
                    xnet_payload_builder.slice_messages_stats()
                );
                assert_eq!(1, xnet_payload_builder.slice_payload_size_stats().count);
            } else {
                panic!(
                    "Expecting payload with a single slice, from {}",
                    REMOTE_SUBNET
                );
            }
        });
    }
}

/// A fake `XNetClient` that returns the results matching the respective
/// query URLs and panics on all other URLs.
///
/// `mockall` does not interact nicely with `async_trait` so we use a fake
/// instead.
struct FakeXNetClient {
    results: BTreeMap<String, Result<CertifiedStreamSlice, FakeXNetClientError>>,
}

#[async_trait]
impl XNetClient for FakeXNetClient {
    async fn query(
        &self,
        endpoint: &EndpointLocator,
    ) -> Result<CertifiedStreamSlice, XNetClientError> {
        let url = url::Url::parse(&endpoint.url.to_string()).unwrap();

        self.results
            .get(url.as_str())
            .unwrap_or_else(|| {
                panic!(
                    "Unexpected URL {}. Expecting one of {:?}",
                    url, self.results
                )
            })
            .clone()
            .map_err(|e| match e {
                FakeXNetClientError::ErrorResponse => {
                    XNetClientError::ErrorResponse(hyper::StatusCode::NOT_FOUND, "Oops".to_string())
                }
                FakeXNetClientError::NoContent => XNetClientError::NoContent,
            })
    }
}

/// A replacement for `XNetClientError` because `XNetClientError` is not `Clone`
/// and thus can't be used directly by `FakeXNetClient`.
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
enum FakeXNetClientError {
    ErrorResponse,
    NoContent,
}

proptest! {
    /// Tests refilling an empty pool.
    #[test]
    fn refill_pool_empty(
        (stream, from, msg_count) in arb_stream_slice(10, 15),
    ) {
        with_test_replica_logger(|log| {
            let runtime = tokio::runtime::Runtime::new().unwrap();

            let stream_position = ExpectedIndices {
                message_index: from,
                signal_index: stream.signals_end(),
            };

            let metrics_registry = MetricsRegistry::new();
            let pool = Arc::new(Mutex::new(CertifiedSlicePool::new(&metrics_registry)));
            pool.lock()
                .unwrap()
                .garbage_collect(btreemap! [REMOTE_SUBNET => stream_position.clone()]);

            let registry = get_registry_for_test(runtime.handle().clone());
            let proximity_map = Arc::new(ProximityMap::new(OWN_NODE, registry.clone(), &metrics_registry, log.clone()));
            let endpoint_resolver =
                XNetEndpointResolver::new(registry, OWN_NODE, OWN_SUBNET, proximity_map, log.clone());
            let byte_limit = (POOL_SLICE_BYTE_SIZE_MAX - 350) * 98 / 100;
            let url = endpoint_resolver
                .xnet_endpoint_url(REMOTE_SUBNET, from, from, byte_limit)
                .unwrap()
                .url
                .to_string();

            let slice = in_slice(&stream, from, from, msg_count, &log);

            let xnet_client = Arc::new(FakeXNetClient {
                results: btreemap![
                    url => Ok(slice.clone()),
                ],
            });

            let refill_handle = PoolRefillTask::start(
                Arc::clone(&pool),
                endpoint_resolver,
                xnet_client,
                runtime.handle().clone(),
                Arc::new(XNetPayloadBuilderMetrics::new(&metrics_registry)),
                log,
            );
            refill_handle.trigger_refill();

            runtime.block_on(async {
                let mut count: u64 = 0;
                // Keep polling until a slice is present in the pool.
                loop {
                    if let (_, Some(_), _, _) = pool.lock().unwrap().slice_stats(REMOTE_SUBNET)
                    {
                        break;
                    }
                    count += 1;
                    if count > 50 {
                        panic!("refill task failed to complete within 5 seconds");
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            });

            assert_opt_slices_eq(
                Some(slice),
                pool.lock()
                    .unwrap()
                    .take_slice(REMOTE_SUBNET, Some(&stream_position), None, None)
                    .unwrap()
                    .map(|(slice, _)| slice),
            );
        });
    }

    /// Tests refilling a pool with an already existing slice, requiring an
    /// append.
    #[test]
    fn refill_pool_append(
        (stream, from, msg_count) in arb_stream_slice(10, 15),
    ) {
        // Bump `from` so we always get a non-empty prefix.
        let from = from.increment();
        let msg_count = msg_count - 1;

        with_test_replica_logger(|log| {
            let runtime = tokio::runtime::Runtime::new().unwrap();

            let stream_begin = stream.messages_begin();
            let stream_position = ExpectedIndices {
                message_index: stream_begin,
                signal_index: stream.signals_end(),
            };

            let remote_state_manager =
                StateManagerFixture::new(log.clone()).with_stream(OWN_SUBNET, stream.clone());
            let in_slice = |witness_from, msg_from, msg_count| {
                remote_state_manager.get_partial_slice(
                    OWN_SUBNET,
                    witness_from,
                    msg_from,
                    msg_count,
                )
            };

            let metrics_registry = MetricsRegistry::new();
            let pool = Arc::new(Mutex::new(CertifiedSlicePool::new(&metrics_registry)));
            let prefix_msg_count = (from - stream_begin).get() as usize;
            let prefix = in_slice(stream_begin, stream_begin, prefix_msg_count);
            let prefix_size_bytes = UnpackedStreamSlice::try_from(prefix.clone()).unwrap().count_bytes();
            {
                let mut pool = pool.lock().unwrap();
                pool.put(REMOTE_SUBNET, prefix).unwrap();
                pool.garbage_collect(btreemap! [REMOTE_SUBNET => stream_position.clone()]);
            }

            let registry = get_registry_for_test(runtime.handle().clone());
            let proximity_map = Arc::new(ProximityMap::new(OWN_NODE, registry.clone(), &metrics_registry, log.clone()));
            let endpoint_resolver =
                XNetEndpointResolver::new(registry, OWN_NODE, OWN_SUBNET, proximity_map, log.clone());
            let byte_limit = (POOL_SLICE_BYTE_SIZE_MAX - prefix_size_bytes - 350) * 98 / 100;
            let url = endpoint_resolver
                .xnet_endpoint_url(REMOTE_SUBNET, stream_begin, from, byte_limit)
                .unwrap()
                .url
                .to_string();

            let suffix = in_slice(stream_begin, from, msg_count);
            let xnet_client = Arc::new(FakeXNetClient {
                results: btreemap![
                    url => Ok(suffix),
                ],
            });

            let refill_handle = PoolRefillTask::start(
                Arc::clone(&pool),
                endpoint_resolver,
                xnet_client,
                runtime.handle().clone(),
                Arc::new(XNetPayloadBuilderMetrics::new(&metrics_registry)),
                log ,
            );
            refill_handle.trigger_refill();

            let expected_msg_count = prefix_msg_count + msg_count;
            runtime.block_on(async {
                let mut count: u64 = 0;
                // Keep polling until the pooled slice has `expected_msg_count` messages.
                loop {
                    let (_, _, msg_count, _) = pool.lock().unwrap().slice_stats(REMOTE_SUBNET);
                    if msg_count == expected_msg_count {
                        break;
                    }
                    count += 1;
                    if count > 50 {
                        panic!("refill task failed to complete within 5 seconds");
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            });

            let slice = in_slice(stream_begin, stream_begin, expected_msg_count);
            assert_opt_slices_eq(
                Some(slice),
                pool.lock()
                    .unwrap()
                    .take_slice(REMOTE_SUBNET, Some(&stream_position), None, None)
                    .unwrap()
                    .map(|(slice, _)| slice),
            );
        });
    }
}
