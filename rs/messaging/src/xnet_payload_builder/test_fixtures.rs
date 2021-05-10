//! Common test fixtures for `XNetPayloadBuilder` tests.

use super::*;
use ic_interfaces::state_manager::CertificationScope;
use ic_protobuf::registry::{
    node::v1::{connection_endpoint::Protocol, ConnectionEndpoint, NodeRecord},
    subnet::v1::SubnetListRecord,
};
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_common::proto_registry_data_provider::ProtoRegistryDataProvider;
use ic_registry_keys::{make_node_record_key, make_subnet_record_key, SUBNET_LIST_KEY};
use ic_replicated_state::{ReplicatedState, Stream};
use ic_test_utilities::{
    mock_time,
    registry::test_subnet_record,
    state_manager::FakeStateManager,
    types::{
        ids::{
            canister_test_id, node_test_id, subnet_test_id, NODE_1, NODE_2, NODE_3, NODE_4, NODE_5,
            NODE_6, NODE_7, SUBNET_0, SUBNET_1, SUBNET_2, SUBNET_3, SUBNET_4, SUBNET_5,
        },
        messages::RequestBuilder,
    },
};
use ic_types::{
    messages::CallbackId,
    xnet::{CertifiedStreamSlice, StreamIndex, StreamIndexedQueue},
    Height, NumBytes, RegistryVersion, SubnetId,
};
use maplit::btreemap;
use std::collections::BTreeMap;

pub(crate) const CERTIFIED_HEIGHT: Height = Height::new(13);
pub(crate) const REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(169);

pub(crate) const LOCAL_SUBNET: SubnetId = SUBNET_0;
pub(crate) const LOCAL_NODE: NodeId = NODE_1;

pub(crate) const SRC_CANISTER: u64 = 2;
pub(crate) const DST_CANISTER: u64 = 3;
pub(crate) const CALLBACK_ID: u64 = 4;

pub(crate) const PAYLOAD_BYTES_LIMIT: NumBytes = NumBytes::new(POOL_SLICE_BYTE_SIZE_MAX as u64);

pub(crate) const REMOTE_NODE_1_NO_1: NodeId = NODE_1;
pub(crate) const REMOTE_NODE_2_NO_1: NodeId = NODE_2;
pub(crate) const REMOTE_NODE_3_NO_2: NodeId = NODE_3;
pub(crate) const REMOTE_NODE_4_NO_2: NodeId = NODE_4;
pub(crate) const LOCAL_NODE_NO_1: NodeId = NODE_5;
pub(crate) const LOCAL_NODE_NO_2: NodeId = NODE_6;
pub(crate) const LOCAL_NODE_NO_3: NodeId = NODE_7;

/// Generates a valid combination of `ReplicatedState` and `XNetPayloads` and
/// the expected message and signal indices for each subnet.
///
/// The state contains streams for `SUBNET_1` and `SUBNET_2`. The payloads
/// contain slices for `SUBNET_1` through `SUBNET_4`.
///
/// Both the state and the payloads include a stream/non-empty stream slice for
/// `SUBNET_1`, so duplicating any payload; or removing any payload except the
/// last; will result in an invalid combination.
pub(crate) fn get_xnet_state_for_testing(
    state_manager: &FakeStateManager,
) -> (Vec<XNetPayload>, BTreeMap<SubnetId, ExpectedIndices>) {
    // A `ReplicatedState` with existing streams for `SUBNET_1` and `SUBNET_2`.
    let stream_1 = generate_stream(&StreamConfig {
        message_begin: 10,
        message_end: 17,
        signal_end: 17,
    });

    let stream_2 = generate_stream(&StreamConfig {
        message_begin: 2,
        message_end: 4,
        signal_end: 5,
    });

    put_replicated_state_for_testing(
        state_manager,
        btreemap![SUBNET_1 => stream_1, SUBNET_2 => stream_2],
    );

    // An `XNetPayload` with `CertifiedStreamSlices` from `SUBNET_1` and `SUBNET_3`.
    let slice_1_1 = make_certified_stream_slice(
        SUBNET_1,
        StreamConfig {
            message_begin: 17,
            message_end: 19,
            signal_end: 10,
        },
    );
    let slice_1_3 = make_certified_stream_slice(
        SUBNET_3,
        StreamConfig {
            message_begin: 0,
            message_end: 2,
            signal_end: 0,
        },
    );
    let payload_1 = XNetPayload {
        stream_slices: btreemap![SUBNET_1 => slice_1_1, SUBNET_3 => slice_1_3],
    };

    // An `XNetPayload` with `CertifiedStreamSlices` from `SUBNET_1` and `SUBNET_2`.
    let slice_2_1 = make_certified_stream_slice(
        SUBNET_1,
        // A slice with no messages but containing signals that if ignored would lead the
        // validation logic to conclude there is a gap even though there is none.
        StreamConfig {
            message_begin: 19,
            message_end: 19,
            signal_end: 12,
        },
    );
    let slice_2_2 = make_certified_stream_slice(
        SUBNET_2,
        StreamConfig {
            message_begin: 5,
            message_end: 7,
            signal_end: 3,
        },
    );
    let payload_2 = XNetPayload {
        stream_slices: btreemap![SUBNET_1 => slice_2_1, SUBNET_2 => slice_2_2],
    };

    // An `XNetPayload` with `CertifiedStreamSlices` from `SUBNET_1` and `SUBNET_2`.
    let slice_3_1 = make_certified_stream_slice(
        SUBNET_1,
        StreamConfig {
            message_begin: 19,
            message_end: 21,
            signal_end: 16,
        },
    );
    let slice_3_4 = make_certified_stream_slice(
        SUBNET_4,
        StreamConfig {
            message_begin: 0,
            message_end: 1,
            signal_end: 0,
        },
    );

    let payload_3 = XNetPayload {
        stream_slices: btreemap![SUBNET_1 => slice_3_1, SUBNET_4 => slice_3_4],
    };

    (
        vec![payload_3, payload_2, payload_1],
        btreemap![
            SUBNET_1 => ExpectedIndices {message_index:StreamIndex::new(21), signal_index:StreamIndex::new(16)},
            SUBNET_2 => ExpectedIndices {message_index:StreamIndex::new(7), signal_index:StreamIndex::new(3)},
            SUBNET_3 => ExpectedIndices {message_index:StreamIndex::new(2), signal_index:StreamIndex::new(0)},
            SUBNET_4 => ExpectedIndices {message_index:StreamIndex::new(1), signal_index:StreamIndex::new(0)},
            SUBNET_5 => ExpectedIndices {message_index:StreamIndex::new(0), signal_index:StreamIndex::new(0)},
        ],
    )
}

/// Commits a `ReplicatedState` containing the given streams.
pub(crate) fn put_replicated_state_for_testing(
    state_manager: &dyn StateManager<State = ReplicatedState>,
    streams: BTreeMap<SubnetId, Stream>,
) {
    let (_height, mut state) = state_manager.take_tip();
    state.put_streams(streams);
    state_manager.commit_and_certify(state, CERTIFIED_HEIGHT, CertificationScope::Metadata);
}

/// Creates a `CertifiedStreamSlice` from the given subnet, containing a stream
/// slice with the given configuration.
pub(crate) fn make_certified_stream_slice(
    from: SubnetId,
    config: StreamConfig,
) -> CertifiedStreamSlice {
    let state_manager = FakeStateManager::new();
    let (_height, mut state) = state_manager.take_tip();
    let stream = generate_stream(&config);
    state.put_streams(btreemap![from => stream]);
    state_manager.commit_and_certify(state, CERTIFIED_HEIGHT, CertificationScope::Metadata);
    state_manager
        .encode_certified_stream_slice(
            from,
            Some(StreamIndex::new(config.message_begin)),
            Some(StreamIndex::new(config.message_begin)),
            Some((config.message_end - config.message_begin) as usize),
            None,
        )
        .unwrap()
}

/// Configuration for generating a stream: begin/end indices for messages; and
/// end index for signals.
pub(crate) struct StreamConfig {
    pub(crate) message_begin: u64,
    pub(crate) message_end: u64,
    pub(crate) signal_end: u64,
}

/// Generates a stream based on the given configuration.
pub(crate) fn generate_stream(config: &StreamConfig) -> Stream {
    let message = RequestBuilder::default()
        .sender(canister_test_id(SRC_CANISTER))
        .receiver(canister_test_id(DST_CANISTER))
        .method_name("test_method".to_string())
        .sender_reply_callback(CallbackId::from(CALLBACK_ID))
        .build();

    let mut messages = StreamIndexedQueue::with_begin(StreamIndex::from(config.message_begin));
    for _ in config.message_begin..config.message_end {
        messages.push(message.clone().into());
    }

    Stream {
        messages,
        signals_end: config.signal_end.into(),
    }
}

/// Generates a `ValidationContext` at `REGISTRY_VERSION` and
/// `CERTIFIED_HEIGHT`.
pub(crate) fn get_validation_context_for_test() -> ValidationContext {
    let time = mock_time();
    ValidationContext {
        registry_version: REGISTRY_VERSION,
        certified_height: CERTIFIED_HEIGHT,
        time,
    }
}

/// Generates a registry data_provider containing `subnet_count` subnets with a
/// single node each (starting with subnet 1) at `REGISTRY_VERSION`; and
/// matching`XNetEndpoint` URLs for each node (beginning at the respective
/// expected index or else 0).
pub(crate) fn get_registry_and_urls_for_test(
    subnet_count: u8,
    mut expected_indices: BTreeMap<SubnetId, ExpectedIndices>,
) -> (Arc<RegistryClientImpl>, Vec<String>) {
    let mut urls = vec![];
    let mut subnets: Vec<Vec<u8>> = vec![];

    let data_provider = ProtoRegistryDataProvider::new();

    data_provider
        .add(
            &make_node_record_key(LOCAL_NODE),
            REGISTRY_VERSION,
            Some(NodeRecord::default()),
        )
        .expect("Could not add node record for local node");

    for i in 0..subnet_count {
        let subnet_id = subnet_test_id(1 + i as u64);
        let node_id = node_test_id(1001 + i as u64);
        let node_ip = format!("192.168.0.{}", 1 + i);
        let xnet_port = 2197 + i as u16;
        let expected_index = expected_indices
            .remove(&subnet_id)
            .unwrap_or_else(Default::default)
            .message_index;

        subnets.push(subnet_id.get().into_vec());

        let mut subnet_record = test_subnet_record();
        subnet_record.membership = vec![node_id.clone().get().into_vec()];

        // Set node to subnet assignment.
        data_provider
            .add(
                &make_subnet_record_key(subnet_id),
                REGISTRY_VERSION,
                Some(subnet_record),
            )
            .expect("Could not add subnet record.");

        // Set connection information for node.
        let xnet_endpoint = ConnectionEndpoint {
            ip_addr: node_ip.clone(),
            port: xnet_port as u32,
            protocol: Protocol::Http1 as i32,
        };
        data_provider
            .add(
                &make_node_record_key(node_id),
                REGISTRY_VERSION,
                Some(NodeRecord {
                    xnet: Some(xnet_endpoint.clone()),
                    xnet_api: vec![xnet_endpoint.clone()],
                    ..Default::default()
                }),
            )
            .expect("Could not add node record.");

        urls.push(format!(
            "http://{}:{}/api/v1/stream/{}?msg_begin={}&witness_begin={}&byte_limit={}",
            node_ip,
            xnet_port,
            LOCAL_SUBNET,
            expected_index,
            expected_index,
            (POOL_SLICE_BYTE_SIZE_MAX - 350) * 98 / 100
        ));
    }

    // Add lists of subnets.
    data_provider
        .add(
            SUBNET_LIST_KEY,
            REGISTRY_VERSION,
            Some(SubnetListRecord { subnets }),
        )
        .expect("Coult not add subnet list record.");

    let registry_client = RegistryClientImpl::new(Arc::new(data_provider), None);
    registry_client.fetch_and_start_polling().unwrap();
    (Arc::new(registry_client), urls)
}

/// Generates a `RegistryClient` at version zero, i.e. with no records.
pub fn get_empty_registry_for_test() -> Arc<dyn RegistryClient> {
    let data_provider = ProtoRegistryDataProvider::new();
    // We add a node record for the local node as this is required for the
    // XNetPayloadBuilder to start.
    data_provider
        .add(
            &make_node_record_key(LOCAL_NODE),
            REGISTRY_VERSION,
            Some(NodeRecord::default()),
        )
        .expect("Could not add node record.");
    let registry_client = RegistryClientImpl::new(Arc::new(data_provider), None);
    registry_client.fetch_and_start_polling().unwrap();
    Arc::new(registry_client)
}

/// Adds a node record with the given values to the given data provider.
fn add_node_record_with_node_operator_id(
    data_provider: &ProtoRegistryDataProvider,
    node_id: NodeId,
    node_ip: String,
    node_operator_id: Vec<u8>,
) {
    let xnet_endpoint = ConnectionEndpoint {
        ip_addr: node_ip,
        port: 2197,
        protocol: Protocol::Http1 as i32,
    };

    data_provider
        .add(
            &make_node_record_key(node_id),
            REGISTRY_VERSION,
            Some(NodeRecord {
                xnet: Some(xnet_endpoint.clone()),
                xnet_api: vec![xnet_endpoint],
                node_operator_id,
                ..Default::default()
            }),
        )
        .expect("Could not add node record.");
}

/// Adds a subnet record with the given values to the given data provider.
fn add_subnet_record(
    data_provider: &ProtoRegistryDataProvider,
    subnet_id: SubnetId,
    members: Vec<NodeId>,
) {
    let mut subnet_record = test_subnet_record();
    subnet_record.membership = members.iter().map(|id| id.get().into_vec()).collect();
    data_provider
        .add(
            &make_subnet_record_key(subnet_id),
            REGISTRY_VERSION,
            Some(subnet_record),
        )
        .expect("Could not add subnet record.");
}

/// Creates a registry to be used with the `xnet_endpoint_url` tests. The
/// setting is the following. There is one subnet with `subnet_test_id(1)` with
/// three nodes `LOCAL_NODE_NO_1`, `LOCAL_NODE_NO_2`, `LOCAL_NODE_NO_3` and one
/// subnet with `subnet_test_id(2)` with four nodes: `REMOTE_NODE_1_NO_1`,
/// `REMOTE_NODE_2_NO_1`, `REMOTE_NODE_3_NO_2`, `REMOTE_NODE_4_NO_2`, where the
/// `NO_X` postfix indicates in which node operator they are under.
pub(crate) fn create_xnet_endpoint_url_test_fixture() -> Arc<RegistryClientImpl> {
    let data_provider = ProtoRegistryDataProvider::new();

    add_node_record_with_node_operator_id(
        &data_provider,
        LOCAL_NODE_NO_1,
        "192.168.0.1".to_string(),
        vec![1],
    );
    add_node_record_with_node_operator_id(
        &data_provider,
        LOCAL_NODE_NO_2,
        "192.168.0.2".to_string(),
        vec![2],
    );
    add_node_record_with_node_operator_id(
        &data_provider,
        LOCAL_NODE_NO_3,
        "192.168.0.3".to_string(),
        vec![3],
    );
    add_subnet_record(
        &data_provider,
        subnet_test_id(1),
        vec![LOCAL_NODE_NO_1, LOCAL_NODE_NO_2, LOCAL_NODE_NO_3],
    );

    add_node_record_with_node_operator_id(
        &data_provider,
        REMOTE_NODE_1_NO_1,
        "192.168.0.4".to_string(),
        vec![1],
    );

    add_node_record_with_node_operator_id(
        &data_provider,
        REMOTE_NODE_2_NO_1,
        "192.168.0.5".to_string(),
        vec![1],
    );

    add_node_record_with_node_operator_id(
        &data_provider,
        REMOTE_NODE_3_NO_2,
        "192.168.0.6".to_string(),
        vec![2],
    );

    add_node_record_with_node_operator_id(
        &data_provider,
        REMOTE_NODE_4_NO_2,
        "192.168.0.7".to_string(),
        vec![2],
    );

    add_subnet_record(
        &data_provider,
        subnet_test_id(2),
        vec![
            REMOTE_NODE_1_NO_1,
            REMOTE_NODE_2_NO_1,
            REMOTE_NODE_3_NO_2,
            REMOTE_NODE_4_NO_2,
        ],
    );

    let registry_client = RegistryClientImpl::new(Arc::new(data_provider), None);
    registry_client.fetch_and_start_polling().unwrap();
    Arc::new(registry_client)
}
