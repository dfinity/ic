//! Transport client implementation for testing.
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
use clap::{Arg, ArgMatches, Command};
use crossbeam_channel::{self, Receiver, RecvTimeoutError, Sender};
use rand::Rng;
use std::collections::HashSet;
use std::convert::Infallible;
use std::convert::TryFrom;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time;

mod utils;

use ic_config::{
    logger::{Config as LoggerConfig, LogTarget},
    transport::TransportConfig,
};
use ic_interfaces_transport::{
    FlowTag, Transport, TransportErrorCode, TransportEvent, TransportPayload,
};
use ic_logger::{info, warn, LoggerImpl, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_transport::transport::create_transport;
use ic_types::{NodeId, PrincipalId, RegistryVersion, SubnetId};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::time::Duration;
use tower::util::BoxCloneService;
use tower::Service;
use utils::{create_crypto, to_node_id};

// From the on_message() handler
struct TestMessage {
    peer_id: NodeId,
    payload: TransportPayload,
}

type MpscSender = Sender<TestMessage>;
type MpscReceiver = Receiver<TestMessage>;

const ARG_NODE_ID: &str = "node";
const ARG_MSG_COUNT: &str = "count";

const REG_V1: RegistryVersion = RegistryVersion::new(1);
const SUBNET_ID: u8 = 100;
const FLOW_TAG: u32 = 1234;

const TEST_MESSAGE_LEN: usize = 1_000_000;

const RECV_TIMEOUT_MS: u64 = 40000;

#[derive(Debug)]
enum Role {
    Source,
    Relay,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum TestClientErrorCode {
    TransportError(TransportErrorCode),
    MessageMismatch,
    NotAllFlowsUp,
    Timeout,
    UnknownFailure,
}

struct TestClient {
    transport: Arc<dyn Transport>,
    prev: NodeId,
    next: NodeId,
    prev_node_record: SocketAddr,
    next_node_record: SocketAddr,
    receiver: MpscReceiver,
    active_flows: Arc<Mutex<HashSet<NodeId>>>,
    registry_version: RegistryVersion,
    log: ReplicaLogger,
    active: Arc<AtomicBool>,
}

impl TestClient {
    fn new(
        transport: Arc<dyn Transport>,
        node_socket_list: &[(NodeId, SocketAddr)],
        prev: &NodeId,
        next: &NodeId,
        registry_version: RegistryVersion,
        log: ReplicaLogger,
        active_flag: Arc<AtomicBool>,
    ) -> Self {
        let (sender, receiver) = crossbeam_channel::unbounded();
        let active_flows = Arc::new(Mutex::new(HashSet::new()));
        let event_handler = BoxCloneService::new(TestClientEventHandler {
            sender,
            active_flows: active_flows.clone(),
        });
        transport.set_event_handler(event_handler);

        let prev_node_record = match node_socket_list.iter().position(|n| n.0 == *prev) {
            Some(pos) => node_socket_list[pos].1,
            None => panic!("Failed to find prev record"),
        };
        let next_node_record = match node_socket_list.iter().position(|n| n.0 == *next) {
            Some(pos) => node_socket_list[pos].1,
            None => panic!("Failed to find next record"),
        };

        TestClient {
            transport,
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

    fn start_connection(&self) -> Result<(), TransportErrorCode> {
        self.transport
            .start_connection(&self.prev, self.prev_node_record, self.registry_version)
            .map_err(|e| {
                warn!(
                    self.log,
                    "Failed to start_connection(): peer = {:?} err = {:?}", self.prev, e
                );
                e
            })?;
        self.transport
            .start_connection(&self.next, self.next_node_record, self.registry_version)
            .map_err(|e| {
                warn!(
                    self.log,
                    "Failed to start_connection(): peer = {:?} err = {:?}", self.next, e
                );
                e
            })?;
        Ok(())
    }

    fn stop_connection(&self) {
        self.transport.stop_connection(&self.prev);
        self.transport.stop_connection(&self.next);
    }

    // Waits for the flows/connections to be up
    fn wait_for_flow_up(&self) -> Result<(), TestClientErrorCode> {
        let expected_flows = 2;
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
            std::thread::sleep(Duration::from_secs(3));
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

            if msg.peer_id != self.prev {
                return Err(TransportErrorCode::NotFound);
            }

            let msg_len = msg.payload.0.len();
            self.transport
                .send(&self.next, FlowTag::from(FLOW_TAG), msg.payload)
                .map_err(|e| {
                    warn!(
                        self.log,
                        "relay(): Failed to send(): peer = {:?},  err = {:?}", self.next, e
                    );
                    e
                })?;
            info!(
                self.log,
                "relay(): relayed from peer {:?}, msg_len = {}", self.next, msg_len
            );
        }
    }

    // Source mode: send the  message, receive the echoed the message, compare them
    fn send_receive_compare(
        &self,
        count: usize,
        flow_tag: FlowTag,
    ) -> Result<(), TestClientErrorCode> {
        let send_peer_id = self.next;
        let receive_peer_id = self.prev;
        let send_msg = TestClient::build_message();
        let send_copy = send_msg.clone();
        self.transport
            .send(&send_peer_id, flow_tag, send_msg)
            .map_err(|e| {
                warn!(
                    self.log,
                    "send_receive_compare(): failed to send(): peer_id = {:?} err = {:?}",
                    send_peer_id,
                    e
                );
                TestClientErrorCode::TransportError(e)
            })?;
        info!(
            self.log,
            "send_receive_compare([{}]): sent message: peer_id = {:?}, msg_len = {}",
            count,
            send_peer_id,
            send_copy.0.len(),
        );

        let rcv_msg = match self.receive() {
            Ok(msg) => msg,
            Err(e) => return Err(e),
        };
        info!(
            self.log,
            "send_receive_compare([{}]): received response: peer_id = {:?}, msg_len = {}",
            count,
            rcv_msg.peer_id,
            rcv_msg.payload.0.len()
        );

        if !self.compare(receive_peer_id, send_copy, rcv_msg) {
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
    fn compare(&self, peer_id: NodeId, payload: TransportPayload, rcv_msg: TestMessage) -> bool {
        if rcv_msg.peer_id != peer_id {
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

#[derive(Clone)]
struct TestClientEventHandler {
    sender: MpscSender,
    active_flows: Arc<Mutex<HashSet<NodeId>>>,
}

impl TestClientEventHandler {
    fn on_message(
        sender: MpscSender,
        peer_id: NodeId,
        message: TransportPayload,
    ) -> Option<TransportPayload> {
        tokio::task::block_in_place(move || {
            sender
                .send(TestMessage {
                    peer_id,
                    payload: message,
                })
                .expect("on_message(): failed to send")
        });
        None
    }
}

impl Service<TransportEvent> for TestClientEventHandler {
    type Response = ();
    type Error = Infallible;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + Sync>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, event: TransportEvent) -> Self::Future {
        let active_flows = self.active_flows.clone();
        let sender = self.sender.clone();
        Box::pin(async move {
            match event {
                TransportEvent::Message(msg) => {
                    Self::on_message(sender, msg.peer_id, msg.payload);
                }
                TransportEvent::PeerFlowUp(peer_id) => {
                    active_flows.lock().unwrap().insert(peer_id);
                }
                TransportEvent::PeerFlowDown(peer_id) => {
                    active_flows.lock().unwrap().remove(&peer_id);
                }
            }
            Ok(())
        })
    }
}

// Returns the command line argument matcher.
fn cmd_line_matches() -> ArgMatches {
    Command::new("Test Transport Client")
        .about("Test program to test the transport layer")
        .arg(
            Arg::new(ARG_NODE_ID)
                .long("node")
                .help("node id [1..3]")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::new(ARG_MSG_COUNT)
                .long("message_count")
                .help("Message Count")
                .default_value("100")
                .takes_value(true),
        )
        .get_matches()
}

#[derive(Debug)]
struct ConfigAndPeerSockets {
    config: TransportConfig,
    peer_sockets: Vec<(NodeId, SocketAddr)>,
}

// Generates the config and the registry node records for the three nodes
// Returns a map of NodeId -> (TransportConfig, NodeRecord)
// TODO: P2P-517 read from a config file
fn generate_config_and_registry(node_id: &NodeId) -> ConfigAndPeerSockets {
    // Tuples: (NodeId, IP, server port 1, server port 2)
    let node_info = vec![
        (to_node_id(1), "127.0.0.1".to_string(), 4100),
        (to_node_id(2), "127.0.0.1".to_string(), 4102),
        (to_node_id(3), "127.0.0.1".to_string(), 4104),
    ];

    let mut config = None;
    let mut peer_sockets = Vec::new();
    for n in node_info.iter() {
        if *node_id == n.0 {
            config = Some(TransportConfig {
                node_ip: n.1.clone(),
                legacy_flow_tag: FLOW_TAG,
                listening_port: n.2,
                send_queue_size: 1024,
            });
        }

        let peer_socket = SocketAddr::from_str(&format!("{}:{}", n.1.clone(), n.2)).unwrap();
        peer_sockets.push((n.0, peer_socket));
    }

    ConfigAndPeerSockets {
        config: config.unwrap(),
        peer_sockets,
    }
}

// Returns the peers: prev/next in the ring.
fn parse_topology(
    node_socket_list: &[(NodeId, SocketAddr)],
    node_id: &NodeId,
) -> (NodeId, NodeId, Role) {
    let node_ids: Vec<NodeId> = node_socket_list.iter().map(|n| n.0).collect();
    assert!(node_ids.contains(node_id));

    let l = node_ids.len();
    assert!(l >= 3);
    let role = if *node_id == node_ids[0] {
        Role::Source
    } else {
        Role::Relay
    };
    match node_socket_list.iter().position(|n| n.0 == *node_id) {
        Some(pos) => {
            let prev = if pos == 0 { l - 1 } else { pos - 1 };
            let next = (pos + 1) % l;
            (node_ids[prev], node_ids[next], role)
        }
        None => panic!("Node not found in registry.json"),
    }
}

fn do_work_source(
    test_client: &TestClient,
    message_count: usize,
) -> Result<(), TestClientErrorCode> {
    test_client.wait_for_flow_up()?;

    for i in 1..=message_count {
        test_client
            .send_receive_compare(i, FlowTag::from(FLOW_TAG))
            .map_err(|e| println!("send_receive_compare(): failed with error: {:?}", e))
            .unwrap();
    }
    Ok(())
}

fn task_main(
    node_id_val: u8,
    message_count: usize,
    active_flag: Arc<AtomicBool>,
) -> Result<(), TestClientErrorCode> {
    let v: Vec<u8> = vec![SUBNET_ID];
    let subnet_id = SubnetId::from(PrincipalId::try_from(v.as_slice()).unwrap());
    let node_id = to_node_id(node_id_val);
    let node_number = node_id_val as usize;
    let rt = tokio::runtime::Runtime::new().unwrap();

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

    let (prev, next, role) = parse_topology(config_and_records.peer_sockets.as_slice(), &node_id);
    info!(log, "subnet_id = {:?} node_id = {:?}", subnet_id, node_id,);
    info!(
        log,
        "prev = {:?}, next = {:?}, role = {:?}", prev, next, role
    );

    println!("creating crypto... [Node: {}]", node_id_val);
    let registry_version = REG_V1;
    let crypto = match create_crypto(node_number, 3, node_id, registry_version) {
        Ok(crypto) => crypto,
        Err(_) => {
            panic!("unable to create crypto");
        }
    };

    println!("starting transport...");
    println!("starting transport... [Node: {}]", node_id_val);
    let transport = create_transport(
        node_id,
        config_and_records.config.clone(),
        registry_version,
        MetricsRegistry::new(),
        crypto,
        rt.handle().clone(),
        log.clone(),
    );

    println!("starting test client... [Node: {}]", node_id_val);
    let test_client = TestClient::new(
        transport,
        config_and_records.peer_sockets.as_slice(),
        &prev,
        &next,
        registry_version,
        log.clone(),
        active_flag.clone(),
    );
    println!("starting connections... [Node: {}]", node_id_val);
    test_client
        .start_connection()
        .map_err(TestClientErrorCode::TransportError)?;

    println!("starting test... [Node: {}]", node_id_val);
    match role {
        Role::Source => {
            let res = do_work_source(&test_client, message_count);
            active_flag.store(false, Ordering::Relaxed);
            if let Err(e) = res {
                info!(log, "Source thread failed, attempting to stop connections");
                test_client.stop_connection();
                Err(e)
            } else {
                test_client.stop_connection();
                info!(log, "Test successful");
                Ok(())
            }
        }
        Role::Relay => {
            let res = test_client.relay_loop();
            test_client.stop_connection();
            res.map_err(TestClientErrorCode::TransportError)
        }
    }
}

fn main() {
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
    task_main(node_id_val, message_count, Arc::new(AtomicBool::new(true))).unwrap()
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
        let handle = std::thread::spawn(move || task_main(node_id, TEST_MESSAGE_COUNT, flag));
        handles.push(handle);
    }

    for x in handles {
        let res = x.join().unwrap();
        assert!(res.is_ok());
    }
}
