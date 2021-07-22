//! Transport client implementation for testing.

use async_trait::async_trait;
///
/// The test client instantiates the transport object and goes through the
/// sequence, expected to be followed by transport clients like P2P:
///   - Register a client (of type P2P)
///   - Adds valid peers
///
/// The topology:
///   - Node 1 is the source, Node 2 and 3 are relays
///   - These are connected in a ring. The message flow: 1 -> 2 -> 3 -> 1
///   - Node 1 generates a message, other nodes relay it to next node in the
///     ring, until Node 1 gets it back
///  - There are two flows/connections between each pair: 1 <-> 2, 2 <-> 3, 3
///    <-> 1 (total 6 flows/connections)
///
/// To run (repeat this for nodes {1, 2, 3}):
/// cargo run --bin transport_client --
///     --node <node_id>
///     --message_count <count>
///
/// If not specified, message_count = 100 (default, applies only for the source
/// node)
use clap::{App, Arg, ArgMatches};
use crossbeam_channel::{self, Receiver, RecvTimeoutError, Sender};
use rand::Rng;
use std::collections::HashSet;
use std::convert::TryFrom;
use std::sync::{Arc, Mutex};
use std::time;

pub mod test_utils;

use ic_config::logger::Config as LoggerConfig;
use ic_config::logger::LogTarget;
use ic_interfaces::transport::{AsyncTransportEventHandler, SendError, Transport};
use ic_logger::{error, info, warn, LoggerImpl, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_protobuf::registry::node::v1::{
    connection_endpoint::Protocol, ConnectionEndpoint, FlowEndpoint, NodeRecord,
};
use ic_transport::transport::create_transport;
// use ic_transport::transport::TransportImpl;
use ic_types::transport::TransportErrorCode;
use ic_types::{
    transport::{
        FlowId, FlowTag, TransportClientType, TransportConfig, TransportFlowConfig,
        TransportFlowInfo, TransportPayload, TransportStateChange,
    },
    NodeId, PrincipalId, RegistryVersion, SubnetId,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use test_utils::{create_crypto, to_node_id};
use tokio::time::Duration;

// From the on_message() handler
struct TestMessage {
    flow_id: FlowId,
    payload: TransportPayload,
}

type MpscSender = Sender<TestMessage>;
type MpscReceiver = Receiver<TestMessage>;

const ARG_NODE_ID: &str = "node";
const ARG_MSG_COUNT: &str = "count";

const REG_V1: RegistryVersion = RegistryVersion::new(1);
const SUBNET_ID: u8 = 100;
const FLOW_TAG_1: u32 = 1234;
const FLOW_TAG_2: u32 = 5678;

const TEST_MESSAGE_LEN: usize = 1_000_000;

const RECV_TIMEOUT_MS: u64 = 40000;

#[derive(Debug)]
enum Role {
    Source,
    Relay,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TestClientErrorCode {
    TransportError(TransportErrorCode),
    MessageMismatch,
    NotAllFlowsUp,
    Timeout,
    UnknownFailure,
}

struct TestClient {
    transport: Arc<dyn Transport>,
    client_type: TransportClientType,
    _event_handler: Arc<TestClientEventHandler>,
    prev: NodeId,
    next: NodeId,
    prev_node_record: NodeRecord,
    next_node_record: NodeRecord,
    receiver: MpscReceiver,
    active_flows: Arc<Mutex<HashSet<TransportFlowInfo>>>,
    registry_version: RegistryVersion,
    log: ReplicaLogger,
    active: Arc<AtomicBool>,
}

impl TestClient {
    fn new(
        transport: Arc<dyn Transport>,
        registry_node_list: &[(NodeId, NodeRecord)],
        prev: &NodeId,
        next: &NodeId,
        registry_version: RegistryVersion,
        log: ReplicaLogger,
        active_flag: Arc<AtomicBool>,
    ) -> Self {
        let (sender, receiver) = crossbeam_channel::unbounded();
        let active_flows = Arc::new(Mutex::new(HashSet::new()));
        let event_handler = Arc::new(TestClientEventHandler {
            sender,
            active_flows: active_flows.clone(),
            log: log.clone(),
        });
        let client_type = TransportClientType::P2P;
        if let Err(e) = transport.register_client(client_type, event_handler.clone()) {
            panic!("Failed to register client: {:?}", e);
        };

        let prev_node_record = match registry_node_list.iter().position(|n| n.0 == *prev) {
            Some(pos) => registry_node_list[pos].1.clone(),
            None => panic!("Failed to find prev record"),
        };
        let next_node_record = match registry_node_list.iter().position(|n| n.0 == *next) {
            Some(pos) => registry_node_list[pos].1.clone(),
            None => panic!("Failed to find next record"),
        };

        TestClient {
            transport,
            client_type,
            _event_handler: event_handler,
            prev: *prev,
            next: *next,
            prev_node_record,
            next_node_record,
            receiver,
            active_flows,
            registry_version,
            log,
            active: active_flag,
        }
    }

    fn start_connections(&self) -> Result<(), TransportErrorCode> {
        self.transport
            .start_connections(
                self.client_type,
                &self.prev,
                &self.prev_node_record,
                self.registry_version,
            )
            .map_err(|e| {
                warn!(
                    self.log,
                    "Failed to start_connections(): peer = {:?} err = {:?}", self.prev, e
                );
                e
            })?;
        self.transport
            .start_connections(
                self.client_type,
                &self.next,
                &self.next_node_record,
                self.registry_version,
            )
            .map_err(|e| {
                warn!(
                    self.log,
                    "Failed to start_connections(): peer = {:?} err = {:?}", self.next, e
                );
                e
            })?;
        Ok(())
    }

    fn stop_connections(&self) -> Result<(), TransportErrorCode> {
        self.transport
            .stop_connections(self.client_type, &self.prev, self.registry_version)
            .map_err(|e| {
                warn!(
                    self.log,
                    "Failed to stop_connections(): peer = {:?} err = {:?}", self.prev, e
                );
                e
            })?;
        self.transport
            .stop_connections(self.client_type, &self.next, self.registry_version)
            .map_err(|e| {
                warn!(
                    self.log,
                    "Failed to stop_connections(): peer = {:?} err = {:?}", self.next, e
                );
                e
            })?;
        Ok(())
    }

    // Waits for the flows/connections to be up
    async fn wait_for_flow_up(&self) -> Result<(), TestClientErrorCode> {
        let expected_flows = 4;
        for _ in 0..10 {
            let num_flows = self.active_flows.lock().unwrap().len();
            if num_flows == expected_flows {
                info!(self.log, "Expected flows up: {}", expected_flows);
                return Ok(());
            }
            info!(
                self.log,
                "Flows up: {}/{}, to wait ...", num_flows, expected_flows
            );
            tokio::time::sleep(Duration::from_secs(3)).await;
        }

        warn!(self.log, "All flows not up, exiting");
        Err(TestClientErrorCode::NotAllFlowsUp)
    }

    // Relay processing. Receives the messages and relays it to next peer.
    fn relay_loop(&self) -> Result<(), TransportErrorCode> {
        loop {
            if !self.active.load(Ordering::Relaxed) {
                info!(self.log, "Relay thread exiting");
                println!("Relay thread exiting (1)");
                return Ok(());
            }
            let msg;
            loop {
                let msg_res = self.receive();
                match msg_res {
                    Err(_e) => {
                        if !self.active.load(Ordering::Relaxed) {
                            // Channel is down, stop thread
                            info!(self.log, "Relay thread exiting");
                            return Ok(());
                        };
                    }
                    Ok(message) => {
                        msg = message;
                        break;
                    }
                };
            }

            if msg.flow_id.peer_id != self.prev {
                warn!(self.log, "relay(): unexpected flow id: {:?}", msg.flow_id);
                return Err(TransportErrorCode::FlowNotFound);
            }

            let flow_id = msg.flow_id;
            let msg_len = msg.payload.0.len();
            self.transport
                .send(self.client_type, &self.next, flow_id.flow_tag, msg.payload)
                .map_err(|e| {
                    warn!(
                        self.log,
                        "relay(): Failed to send(): peer = {:?}, flow = {:?}, err = {:?}",
                        self.next,
                        flow_id,
                        e
                    );
                    e
                })?;
            info!(
                self.log,
                "relay(): relayed from {:?} -> peer {:?}, msg_len = {}",
                flow_id,
                self.next,
                msg_len
            );
        }
    }

    // Source mode: send the  message, receive the echoed the message, compare them
    fn send_receive_compare(
        &self,
        count: usize,
        flow_tag: FlowTag,
    ) -> Result<(), TestClientErrorCode> {
        let send_flow = FlowId::new(TransportClientType::P2P, self.next, flow_tag);
        let receive_flow = FlowId::new(TransportClientType::P2P, self.prev, flow_tag);
        let send_msg = TestClient::build_message();
        let send_copy = send_msg.clone();
        self.transport
            .send(
                self.client_type,
                &send_flow.peer_id,
                send_flow.flow_tag,
                send_msg,
            )
            .map_err(|e| {
                warn!(
                    self.log,
                    "send_receive_compare(): failed to send(): flow = {:?} err = {:?}",
                    send_flow,
                    e
                );
                TestClientErrorCode::TransportError(e)
            })?;
        info!(
            self.log,
            "send_receive_compare([{}]): sent message: flow = {:?}, msg_len = {}",
            count,
            send_flow,
            send_copy.0.len(),
        );

        let rcv_msg = match self.receive() {
            Ok(msg) => msg,
            Err(e) => return Err(e),
        };
        info!(
            self.log,
            "send_receive_compare([{}]): received response: flow = {:?}, msg_len = {}",
            count,
            rcv_msg.flow_id,
            rcv_msg.payload.0.len()
        );

        if !self.compare(receive_flow, send_copy, rcv_msg) {
            return Err(TestClientErrorCode::MessageMismatch);
        }
        Ok(())
    }

    // Reads the next message from the channel
    fn receive(&self) -> Result<TestMessage, TestClientErrorCode> {
        match tokio::task::block_in_place(move || {
            self.receiver
                .recv_timeout(time::Duration::from_millis(RECV_TIMEOUT_MS))
        }) {
            Ok(msg) => Ok(msg),
            Err(RecvTimeoutError::Timeout) => {
                warn!(self.log, "Message receive timed out");
                Err(TestClientErrorCode::Timeout)
            }
            Err(e) => {
                warn!(self.log, "Failed to receive message: {:?}", e);
                Err(TestClientErrorCode::UnknownFailure)
            }
        }
    }

    // Builds the transport message with the given client/message types, and
    // randomized payload
    fn build_message() -> TransportPayload {
        let mut rng = rand::thread_rng();
        let mut v: Vec<u8> = Vec::new();
        for _ in 0..TEST_MESSAGE_LEN {
            v.push(rng.gen::<u8>());
        }

        TransportPayload(v)
    }

    // Compares the two messages(hdr and payload parts)
    fn compare(&self, flow_id: FlowId, payload: TransportPayload, rcv_msg: TestMessage) -> bool {
        if rcv_msg.flow_id != flow_id {
            warn!(self.log, "compare(): FlowTag mismatch");
            return false;
        }

        if payload.0.len() != rcv_msg.payload.0.len() {
            warn!(self.log, "compare(): Length mismatch");
            return false;
        }

        for i in 0..payload.0.len() {
            if payload.0[i] != rcv_msg.payload.0[i] {
                warn!(self.log, "Payload mismatch");
                return false;
            }
        }

        true
    }
}

struct TestClientEventHandler {
    sender: MpscSender,
    active_flows: Arc<Mutex<HashSet<TransportFlowInfo>>>,
    log: ReplicaLogger,
}

impl TestClientEventHandler {
    fn on_message(&self, flow_id: FlowId, message: TransportPayload) -> Option<TransportPayload> {
        tokio::task::block_in_place(move || {
            self.sender
                .send(TestMessage {
                    flow_id,
                    payload: message,
                })
                .expect("on_message(): failed to send")
        });

        None
    }

    fn on_error(&self, flow: FlowId, error: TransportErrorCode) {
        error!(self.log, "on_error(): Flow: {:?}, error: {:?}", flow, error);
    }

    fn on_state_change(&self, change: TransportStateChange) {
        info!(self.log, "on_state_change(): {:?}", change);
        match change {
            TransportStateChange::PeerFlowUp(flow) => {
                self.active_flows.lock().unwrap().insert(flow);
            }
            TransportStateChange::PeerFlowDown(flow) => {
                self.active_flows.lock().unwrap().remove(&flow);
            }
        }
    }
}

#[async_trait]
impl AsyncTransportEventHandler for TestClientEventHandler {
    async fn send_message(&self, flow: FlowId, message: TransportPayload) -> Result<(), SendError> {
        self.on_message(flow, message);
        Ok(())
    }

    async fn state_changed(&self, state_change: TransportStateChange) {
        self.on_state_change(state_change)
    }

    async fn error(&self, flow: FlowId, error: TransportErrorCode) {
        self.on_error(flow, error);
    }
}

// Returns the command line argument matcher.
fn cmd_line_matches() -> ArgMatches<'static> {
    App::new("Test Transport Client")
        .about("Test program to test the transport layer")
        .arg(
            Arg::with_name(ARG_NODE_ID)
                .long("node")
                .help("node id [1..3]")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name(ARG_MSG_COUNT)
                .long("message_count")
                .help("Message Count")
                .default_value("100")
                .takes_value(true),
        )
        .get_matches()
}

#[derive(Debug)]
struct ConfigAndRecords {
    config: TransportConfig,
    node_records: Vec<(NodeId, NodeRecord)>,
}

// Generates the config and the registry node records for the three nodes
// Returns a map of NodeId -> (TransportConfig, NodeRecord)
// TODO: P2P-517 read from a config file
fn generate_config_and_registry(node_id: &NodeId) -> ConfigAndRecords {
    // Tuples: (NodeId, IP, server port 1, server port 2)
    let node_info = vec![
        (to_node_id(1), "127.0.0.1".to_string(), 4100, 4101),
        (to_node_id(2), "127.0.0.1".to_string(), 4102, 4103),
        (to_node_id(3), "127.0.0.1".to_string(), 4104, 4105),
    ];

    let mut config = None;
    let mut node_records = Vec::new();
    for n in node_info.iter() {
        if *node_id == n.0 {
            config = Some(TransportConfig {
                node_ip: n.1.clone(),
                p2p_flows: vec![
                    TransportFlowConfig {
                        flow_tag: FLOW_TAG_1,
                        server_port: n.2,
                        queue_size: 1024,
                    },
                    TransportFlowConfig {
                        flow_tag: FLOW_TAG_2,
                        server_port: n.3,
                        queue_size: 1024,
                    },
                ],
            });
        }

        let mut node_record: NodeRecord = Default::default();
        node_record.p2p_flow_endpoints.push(FlowEndpoint {
            flow_tag: FLOW_TAG_1,
            endpoint: Some(ConnectionEndpoint {
                ip_addr: n.1.clone(),
                port: n.2 as u32,
                protocol: Protocol::P2p1Tls13 as i32,
            }),
        });
        node_record.p2p_flow_endpoints.push(FlowEndpoint {
            flow_tag: FLOW_TAG_2,
            endpoint: Some(ConnectionEndpoint {
                ip_addr: n.1.clone(),
                port: n.3 as u32,
                protocol: Protocol::P2p1Tls13 as i32,
            }),
        });

        node_records.push((n.0, node_record));
    }

    ConfigAndRecords {
        config: config.unwrap(),
        node_records,
    }
}

// Returns the peers: prev/next in the ring.
fn parse_topology(
    registry_node_list: &[(NodeId, NodeRecord)],
    node_id: &NodeId,
) -> (NodeId, NodeId, Role) {
    let node_ids: Vec<NodeId> = registry_node_list.iter().map(|n| n.0).collect();
    assert_eq!(node_ids.contains(&node_id), true);

    let l = node_ids.len();
    assert_eq!(l >= 3, true);
    let role = if *node_id == node_ids[0] {
        Role::Source
    } else {
        Role::Relay
    };
    match registry_node_list.iter().position(|n| n.0 == *node_id) {
        Some(pos) => {
            let prev = if pos == 0 { l - 1 } else { pos - 1 };
            let next = (pos + 1) % l;
            (node_ids[prev], node_ids[next], role)
        }
        None => panic!("Node not found in registry.json"),
    }
}

async fn do_work_source(
    test_client: &TestClient,
    message_count: usize,
) -> Result<(), TestClientErrorCode> {
    test_client.wait_for_flow_up().await?;

    for i in 1..=message_count {
        test_client
            .send_receive_compare(i, FlowTag::from(FLOW_TAG_1))
            .map_err(|e| println!("send_receive_compare(): failed with error: {:?}", e))
            .unwrap();
        test_client
            .send_receive_compare(i, FlowTag::from(FLOW_TAG_2))
            .map_err(|e| println!("send_receive_compare(): failed with error: {:?}", e))
            .unwrap();
    }
    Ok(())
}

async fn task_main(
    node_id_val: u8,
    message_count: usize,
    active_flag: Arc<AtomicBool>,
) -> Result<(), TestClientErrorCode> {
    let v: Vec<u8> = vec![SUBNET_ID];
    let subnet_id = SubnetId::from(PrincipalId::try_from(v.as_slice()).unwrap());
    let node_id = to_node_id(node_id_val);
    let node_number = node_id_val as usize;

    let logger_config = LoggerConfig {
        target: LogTarget::File(PathBuf::from(format!(
            "./transport_test_{}.log",
            node_id_val
        ))),
        ..Default::default()
    };
    let logger = LoggerImpl::new(
        &logger_config,
        format!("transport_test_client [node {}]", node_id_val),
    );
    let log = ReplicaLogger::new(logger.root.clone().into());
    let config_and_records = generate_config_and_registry(&node_id);

    let (prev, next, role) = parse_topology(config_and_records.node_records.as_slice(), &node_id);
    info!(log, "subnet_id = {:?} node_id = {:?}", subnet_id, node_id,);
    info!(
        log,
        "prev = {:?}, next = {:?}, role = {:?}", prev, next, role
    );

    println!("creating crypto... [Node: {}]", node_id_val);
    let registry_version = REG_V1;
    let crypto = match tokio::task::block_in_place(|| {
        create_crypto(node_number, 3, node_id, registry_version)
    }) {
        Ok(crypto) => crypto,
        Err(_) => {
            panic!("unable to create crypto");
        }
    };

    println!("starting transport...");
    println!("starting transport... [Node: {}]", node_id_val);
    let transport = create_transport(
        // let transport = TransportImpl::new(
        node_id,
        config_and_records.config.clone(),
        registry_version,
        MetricsRegistry::new(),
        crypto,
        tokio::runtime::Handle::current(),
        log.clone(),
    );

    println!("starting test client... [Node: {}]", node_id_val);
    let test_client = TestClient::new(
        transport,
        config_and_records.node_records.as_slice(),
        &prev,
        &next,
        registry_version,
        log.clone(),
        active_flag.clone(),
    );
    println!("starting connections... [Node: {}]", node_id_val);
    test_client
        .start_connections()
        .map_err(TestClientErrorCode::TransportError)?;

    println!("starting test... [Node: {}]", node_id_val);
    match role {
        Role::Source => {
            let res = do_work_source(&test_client, message_count).await;
            active_flag.store(false, Ordering::Relaxed);
            if let Err(e) = res {
                info!(log, "Source thread failed, attempting to stop connections");
                let _x = test_client.stop_connections();
                Err(e)
            } else {
                test_client
                    .stop_connections()
                    .map_err(TestClientErrorCode::TransportError)?;
                info!(log, "Test successful");
                Ok(())
            }
        }
        Role::Relay => {
            let res = test_client.relay_loop();
            let _x = test_client.stop_connections();
            res.map_err(TestClientErrorCode::TransportError)
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), TestClientErrorCode> {
    // Cmd line params.
    let matches = cmd_line_matches();
    let node_id_val = matches
        .value_of(ARG_NODE_ID)
        .unwrap()
        .parse::<u8>()
        .unwrap();
    let message_count = matches
        .value_of(ARG_MSG_COUNT)
        .unwrap()
        .parse::<usize>()
        .unwrap();
    task_main(node_id_val, message_count, Arc::new(AtomicBool::new(true))).await
}

#[cfg(test)]
const TEST_NODE_COUNT: u8 = 3;
#[cfg(test)]
const TEST_MESSAGE_COUNT: usize = 10;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_transport_spawn_tasks() {
    let active_flag = Arc::new(AtomicBool::new(true));
    let mut handles = Vec::new();

    // Spawn tokio tasks
    for node_id in 1..(TEST_NODE_COUNT + 1) {
        let flag = active_flag.clone();
        let handle =
            tokio::spawn(async move { task_main(node_id, TEST_MESSAGE_COUNT, flag).await });
        handles.push(handle);
    }

    let res = futures::future::join_all(handles).await;
    let results = res.iter().map(|x| x.as_ref().unwrap());

    results.for_each(|x| assert!(x.is_ok()));
}
