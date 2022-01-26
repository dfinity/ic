//! Load test for stand alone transport
//!
//! How this works:
//!  - Client sends requests to the server. The request specifies a message size
//!  - Server responds with a message of the requested size
//! This simulates the P2P chunk request/chunk response exchange
//!
//! Usage:
//!  - This example runs the server on host 10.12.35.1, and client on
//!    10.11.35.15
//!
//! On both nodes:
//! # cargo build --release --bin tperf
//! # cd target/x86_64-unknown-linux-gnu/release
//! # export TPERF=target/x86_64-unknown-linux-gnu/release/tperf
//!
//! On the server node:
//! # $TPERF --node_id 1 --node_ip 10.12.35.1
//!          --peer_node_id 2 --peer_node_ip 10.11.35.15
//!          --role server
//!
//! Copy the resulting tls_pubkey_cert.1 to the client machine.
//!
//! On the client node:
//! # $TPERF --node_id 2 --node_ip 10.11.35.15
//!          --peer_node_id 1 --peer_node_ip 10.12.35.1
//!          --role client
//!          --message_count 1000
//!          --message_size 1M
//!          --rps 10
//!
//! Copy the resulting tls_pubkey_cert.2 to the server machine.
//!
//!  Params on client side:
//!  --message_count: number of  messages to exchange (default: 1000)
//!  --message_size: size of the exchanged messages (default: 1K)
//!  --rps: number of requests/sec (default: off, no rate limit)

mod test_utils;

use async_trait::async_trait;
use bincode::{deserialize, serialize};
use byte_unit::{Byte, ByteUnit};
use clap::{App, Arg, ArgMatches};
use crossbeam_channel::{self, Receiver, Sender};
use histogram::Histogram;
use ic_interfaces::transport::{AsyncTransportEventHandler, SendError, Transport};
use ic_logger::{error, info, warn, LoggerImpl, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_protobuf::registry::node::v1::{
    connection_endpoint::Protocol, ConnectionEndpoint, FlowEndpoint, NodeRecord,
};
use ic_transport::transport::create_transport;
use ic_types::{
    transport::{
        FlowId, FlowTag, TransportConfig, TransportErrorCode, TransportFlowConfig,
        TransportFlowInfo, TransportPayload, TransportStateChange,
    },
    NodeId, RegistryVersion,
};
use ratelimit::{Builder, Limiter};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::process::exit;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use test_utils::{create_crypto, to_node_id};

const REG_V1: RegistryVersion = RegistryVersion::new(1);
const ARG_NODE_ID: &str = "node_id";
const ARG_PEER_NODE_ID: &str = "peer_node_id";
const ARG_NODE_IP: &str = "node_ip";
const ARG_PEER_NODE_IP: &str = "peer_node_ip";
const ARG_ROLE: &str = "role";
const ARG_MSG_SIZE: &str = "message_size";
const ARG_MSG_COUNT: &str = "message_count";
const ARG_RPS: &str = "rps";

const FLOW_TAG: u32 = 1234;
const FLOW_PORT: u32 = 4200;

const QFULL_DELAY_USEC: u64 = 10;
const STATUS_UPDATE_SEC: u64 = 10;
const LATENCY_SCALE: u64 = 100;

#[derive(Debug)]
enum Role {
    Client,
    Server,
}

#[derive(Debug)]
struct ConfigAndRecords {
    config: TransportConfig,
    node_records: Vec<(NodeId, NodeRecord)>,
}

// The messages exchanged between client/server
#[derive(Debug, Serialize, Deserialize)]
enum TestMessage {
    Request(Request),
    Response(Response),
}

#[derive(Debug, Serialize, Deserialize)]
struct Request {
    // Request Id
    id: u64,

    // Requested payload size
    payload_size: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct Response {
    // Request Id
    id: u64,

    // Requested payload
    payload: Vec<u8>,
}

// Message from the event handler
struct EventMessage {
    // Time when the event handler got it from transport
    received_ts: Instant,

    // The received message
    message: TestMessage,
}

type MpscSender = Sender<EventMessage>;
type MpscReceiver = Receiver<EventMessage>;
type RequestMap = Arc<Mutex<HashMap<u64, Instant>>>;

trait RateLimiter {
    // Wait for next next token
    fn wait(&mut self);
}

struct RateLimiterImpl {
    limiter: Limiter,
}

impl RateLimiterImpl {
    fn new(rps: u32) -> Self {
        let limiter = Builder::new()
            .capacity(1)
            .quantum(1)
            .frequency(rps) //add quantum tokens every 1 second
            .build();
        Self { limiter }
    }
}

impl RateLimiter for RateLimiterImpl {
    fn wait(&mut self) {
        self.limiter.wait();
    }
}

struct NoopRateLimiter {}
impl RateLimiter for NoopRateLimiter {
    fn wait(&mut self) {}
}

struct TestClient {
    transport: Arc<dyn Transport>,
    _event_handler: Arc<TestClientEventHandler>,
    peer: NodeId,
    peer_node_record: NodeRecord,
    active_flows: Arc<Mutex<HashSet<TransportFlowInfo>>>,
    receiver: MpscReceiver,
    registry_version: RegistryVersion,
    log: ReplicaLogger,
}

impl TestClient {
    fn new(
        transport: Arc<dyn Transport>,
        registry_node_list: &[(NodeId, NodeRecord)],
        peer: &NodeId,
        registry_version: RegistryVersion,
        log: ReplicaLogger,
    ) -> Self {
        let (sender, receiver) = crossbeam_channel::unbounded();
        let active_flows = Arc::new(Mutex::new(HashSet::new()));
        let event_handler = Arc::new(TestClientEventHandler {
            sender,
            active_flows: active_flows.clone(),
            log: log.clone(),
        });
        if let Err(e) = transport.register_client(event_handler.clone()) {
            warn!(log, "Failed to register client: {:?}", e);
            exit(1);
        };
        let peer_node_record = match registry_node_list.iter().position(|n| n.0 == *peer) {
            Some(pos) => registry_node_list[pos].1.clone(),
            None => panic!("Failed to find peer record"),
        };

        TestClient {
            transport,
            _event_handler: event_handler,
            peer: *peer,
            peer_node_record,
            active_flows,
            receiver,
            registry_version,
            log,
        }
    }

    fn start_connections(&self) {
        if let Err(e) = self.transport.start_connections(
            &self.peer,
            &self.peer_node_record,
            self.registry_version,
        ) {
            warn!(
                self.log,
                "Failed to start_connections(): peer = {:?} err = {:?}", self.peer, e
            );
            exit(1);
        }
    }

    // Waits for the flows/connections to be up
    fn wait_for_flow_up(&self) {
        let expected_flows = 1;
        loop {
            let num_flows = self.active_flows.lock().unwrap().len();
            if num_flows == expected_flows {
                info!(self.log, "All expected {} flows up", expected_flows);
                return;
            }
            info!(
                self.log,
                "Flows up: {} out of {}, to wait ...", num_flows, expected_flows
            );
            thread::sleep(Duration::from_secs(3));
        }
    }

    // Sends the given message to the peer, with retries on qfull. Returns the
    // number of qfulls.
    fn send_message(&self, message: TestMessage) -> usize {
        let mut payload = TransportPayload(serialize(&message).unwrap());
        let mut qfull = 0;
        loop {
            match self
                .transport
                .send(&self.peer, FlowTag::from(FLOW_TAG), payload)
            {
                Ok(()) => return qfull,
                Err(TransportErrorCode::TransportBusy(unsent)) => {
                    qfull += 1;
                    payload = unsent;
                    thread::sleep(Duration::from_micros(QFULL_DELAY_USEC));
                }
                Err(e) => {
                    warn!(
                        self.log,
                        "client(): failed to send message: peer = {:?} \
                            err = {:?}",
                        self.peer,
                        e
                    );
                    exit(1);
                }
            }
        }
    }

    // Reads the next message from the channel
    fn receive_message(receiver: &MpscReceiver) -> EventMessage {
        match receiver.recv() {
            Ok(msg) => msg,
            Err(e) => {
                panic!("Failed to receive message: {:?}", e);
            }
        }
    }

    // The client side to send the messages
    fn client(&self, message_size: Byte, message_count: usize, rps: Option<u32>) {
        // Spawn the response handler thread
        let request_map = Arc::new(Mutex::new(HashMap::new()));
        let request_map_cl = request_map.clone();
        let receiver_cl = self.receiver.clone();
        let log_cl = self.log.clone();
        let handle = std::thread::spawn(move || {
            Self::client_response_handler(
                message_size,
                message_count,
                request_map_cl,
                receiver_cl,
                log_cl,
            );
        });

        let mut rate_limiter: Box<dyn RateLimiter> = match rps {
            Some(r) => Box::new(RateLimiterImpl::new(r)),
            None => Box::new(NoopRateLimiter {}),
        };

        // Send the requests
        let start = Instant::now();
        let mut qfull = 0;
        let mut last_update = Instant::now();
        for i in 1..=message_count {
            rate_limiter.wait();
            let id = i as u64;
            let request = TestMessage::Request(Request {
                id,
                payload_size: message_size.get_bytes() as usize,
            });

            request_map.lock().unwrap().insert(id, Instant::now());
            qfull += self.send_message(request);
            if last_update.elapsed().as_secs() > STATUS_UPDATE_SEC || (i % 1000) == 0 {
                info!(
                    self.log,
                    "Client: sent request[{}/{}], qfull = {}", i, message_count, qfull
                );
                last_update = Instant::now();
            }
        }
        info!(
            self.log,
            "Client: requests done, sent {} requests (message size {}, total {}) in {:?}",
            message_count,
            Self::format_bytes(message_size.get_bytes() as usize),
            Self::format_bytes(message_count * (message_size.get_bytes() as usize)),
            start.elapsed(),
        );
        info!(
            self.log,
            "Client: requested bandwidth = {}/sec, rps = {:?}, qfull = {}",
            Self::bandwidth(
                message_count * (message_size.get_bytes() as usize),
                start.elapsed()
            ),
            rps,
            qfull,
        );

        // Wait for all the responses
        handle.join().unwrap();
    }

    fn client_response_handler(
        message_size: Byte,
        message_count: usize,
        request_map: RequestMap,
        receiver: MpscReceiver,
        log: ReplicaLogger,
    ) {
        // Collect the responses
        let mut response_time_histogram = Histogram::new();
        let start = Instant::now();
        let mut received = 0;
        let mut last_update = Instant::now();
        for i in 1..=message_count {
            let event_msg = Self::receive_message(&receiver);
            let response = match event_msg.message {
                TestMessage::Response(r) => r,
                _ => panic!("Unexpected message"),
            };
            assert!(response.id == i as u64);
            assert!(response.payload.len() == message_size.get_bytes() as usize);
            received += message_size.get_bytes() as usize;

            let request_ts = {
                let map = request_map.lock().unwrap();
                *map.get(&response.id).unwrap()
            };

            // Record the latency
            let response_time = event_msg.received_ts.duration_since(request_ts).as_millis()
                / (LATENCY_SCALE as u128);
            response_time_histogram
                .increment(response_time as u64)
                .expect("Failed to update histogram");

            if last_update.elapsed().as_secs() > STATUS_UPDATE_SEC || (i % 1000) == 0 {
                info!(
                    log,
                    "Client: received response[{}]: {}, {:?}, bandwidth = {}/sec",
                    i,
                    Self::format_bytes(received),
                    start.elapsed(),
                    Self::bandwidth(received, start.elapsed())
                );
                info!(
                    log,
                    "    Latency: min = {} msec, max = {} msec, average = {} msec",
                    response_time_histogram.minimum().unwrap() * LATENCY_SCALE,
                    response_time_histogram.maximum().unwrap() * LATENCY_SCALE,
                    response_time_histogram.mean().unwrap() * LATENCY_SCALE
                );
                last_update = Instant::now();
            }
        }
        info!(
            log,
            "Bandwidth summary : {} transferred in {:?}, average = {}/sec",
            Self::format_bytes(received),
            start.elapsed(),
            Self::bandwidth(received, start.elapsed())
        );
        assert!(response_time_histogram.entries() == message_count as u64);
        Self::show_latency_distribution(response_time_histogram, message_count, &log);
    }

    // The server side to process the requests
    fn server(&self) {
        let mut processed = 0;
        let mut sent = 0;
        let mut qfull = 0;
        let start = Instant::now();
        let mut last_update = Instant::now();
        loop {
            let event_msg = Self::receive_message(&self.receiver);
            let request = match event_msg.message {
                TestMessage::Request(r) => r,
                _ => panic!("Unexpected message"),
            };

            let response = TestMessage::Response(Response {
                id: request.id,
                payload: vec![0u8; request.payload_size],
            });

            qfull += self.send_message(response);
            processed += 1;
            sent += request.payload_size;

            if last_update.elapsed().as_secs() > STATUS_UPDATE_SEC || (processed % 1000) == 0 {
                info!(
                    self.log,
                    "Server: processed request[{}]: sent {}, qfull = {}, {:?}, bandwidth = {}/sec",
                    processed,
                    Self::format_bytes(sent),
                    qfull,
                    start.elapsed(),
                    Self::bandwidth(sent, start.elapsed())
                );
                last_update = Instant::now();
            }
        }
    }

    fn show_latency_distribution(
        histogram: Histogram,
        expected_entries: usize,
        log: &ReplicaLogger,
    ) {
        let mut total = 0;
        let mut buckets = 0;
        for bucket in &histogram {
            if bucket.count() > 0 {
                total += bucket.count();
                buckets += 1;
            }
        }
        assert!(total == expected_entries as u64);

        info!(
            log,
            "Latency summary   : min = {} msec, max = {} msec, average = {} msec, \
             histogram_buckets = {}",
            histogram.minimum().unwrap() * LATENCY_SCALE,
            histogram.maximum().unwrap() * LATENCY_SCALE,
            histogram.mean().unwrap() * LATENCY_SCALE,
            buckets
        );
    }

    fn bandwidth(bytes: usize, duration: Duration) -> String {
        let usecs = duration.as_micros();
        let bw = ((bytes as f64) / (usecs as f64)) * 1000000_f64;
        let bw = Byte::from_unit(bw, ByteUnit::B).unwrap();
        Self::format_bytes(bw.get_bytes() as usize)
    }

    fn format_bytes(bytes: usize) -> String {
        let unit = if bytes >= 1_000_000_000_000 {
            ByteUnit::TB
        } else if bytes >= 1_000_000_000 {
            ByteUnit::GB
        } else if bytes >= 1_000_000 {
            ByteUnit::MB
        } else if bytes >= 1_000 {
            ByteUnit::KB
        } else {
            ByteUnit::B
        };
        let bytes = Byte::from_bytes(bytes as u128);
        let adjusted = bytes.get_adjusted_unit(unit);
        adjusted.to_string()
    }
}

struct TestClientEventHandler {
    sender: MpscSender,
    active_flows: Arc<Mutex<HashSet<TransportFlowInfo>>>,
    log: ReplicaLogger,
}

impl TestClientEventHandler {
    fn on_message(&self, _flow_id: FlowId, message: TransportPayload) -> Option<TransportPayload> {
        let received_ts = Instant::now();
        let message: TestMessage = deserialize(&message.0).unwrap();
        let event_message = EventMessage {
            received_ts,
            message,
        };
        self.sender
            .send(event_message)
            .expect("on_message(): failed to send");
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
            TransportStateChange::PeerFlowDown(_) => {
                exit(1);
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
    App::new("tperf")
        .about("Load test for the transport layer")
        .arg(
            Arg::with_name(ARG_NODE_ID)
                .long("node_id")
                .help("Self NodeId")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name(ARG_PEER_NODE_ID)
                .long("peer_node_id")
                .help("Peer NodeId")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name(ARG_NODE_IP)
                .long("node_ip")
                .help("Self IP address")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name(ARG_PEER_NODE_IP)
                .long("peer_node_ip")
                .help("Peer IP address")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name(ARG_ROLE)
                .long("role")
                .help("Client or server")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name(ARG_MSG_SIZE)
                .long("message_size")
                .help("Message size")
                .default_value("1024")
                .takes_value(true),
        )
        .arg(
            Arg::with_name(ARG_MSG_COUNT)
                .long("message_count")
                .help("Message count")
                .default_value("1000")
                .takes_value(true),
        )
        .arg(
            Arg::with_name(ARG_RPS)
                .long("rps")
                .help(
                    "requests/sec to send. If not specified, the client requests will be \
                       submitted with no throttling",
                )
                .takes_value(true),
        )
        .get_matches()
}

fn generate_config_and_registry(
    node_id: &NodeId,
    peer_node_id: &NodeId,
    node_ip: &str,
    peer_ip: &str,
) -> ConfigAndRecords {
    let config = TransportConfig {
        node_ip: node_ip.to_string(),
        p2p_flows: vec![TransportFlowConfig {
            flow_tag: FLOW_TAG,
            server_port: FLOW_PORT as u16,
            queue_size: 8192,
        }],
    };

    let mut node_records = Vec::new();
    let mut node_record: NodeRecord = Default::default();
    node_record.p2p_flow_endpoints.push(FlowEndpoint {
        flow_tag: FLOW_TAG,
        endpoint: Some(ConnectionEndpoint {
            ip_addr: node_ip.to_string(),
            port: FLOW_PORT as u32,
            protocol: Protocol::P2p1Tls13 as i32,
        }),
    });
    node_records.push((*node_id, node_record));

    let mut node_record: NodeRecord = Default::default();
    node_record.p2p_flow_endpoints.push(FlowEndpoint {
        flow_tag: FLOW_TAG,
        endpoint: Some(ConnectionEndpoint {
            ip_addr: peer_ip.to_string(),
            port: FLOW_PORT as u32,
            protocol: Protocol::P2p1Tls13 as i32,
        }),
    });
    node_records.push((*peer_node_id, node_record));

    ConfigAndRecords {
        config,
        node_records,
    }
}

#[tokio::main]
async fn main() {
    let matches = cmd_line_matches();
    let node_id_val = matches
        .value_of(ARG_NODE_ID)
        .unwrap()
        .parse::<u8>()
        .unwrap();
    let peer_node_id_val = matches
        .value_of(ARG_PEER_NODE_ID)
        .unwrap()
        .parse::<u8>()
        .unwrap();
    let node_number = node_id_val as usize;
    let node_ip = matches.value_of(ARG_NODE_IP).unwrap();
    let peer_ip = matches.value_of(ARG_PEER_NODE_IP).unwrap();
    let role = matches.value_of(ARG_ROLE).unwrap();
    let message_size =
        Byte::from_str(matches.value_of(ARG_MSG_SIZE).unwrap().trim().to_string()).unwrap();
    let message_count = matches
        .value_of(ARG_MSG_COUNT)
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let mut rps = None;
    if let Some(s) = matches.value_of(ARG_RPS) {
        rps = Some(s.parse::<u32>().unwrap());
    }
    let role = if role == "client" {
        Role::Client
    } else {
        Role::Server
    };

    let node_id = to_node_id(node_id_val);
    let peer_node_id = to_node_id(peer_node_id_val);

    let metrics_registry = MetricsRegistry::global();
    let logger = LoggerImpl::new(&Default::default(), "transport_test_client".to_string());
    let log = ReplicaLogger::new(logger.root.clone().into());
    let config_and_records =
        generate_config_and_registry(&node_id, &peer_node_id, node_ip, peer_ip);
    info!(
        log,
        "node_id: {} => {:?}, => {:?}", node_id_val, node_id, peer_node_id,
    );
    info!(
        log,
        "node_ip = {}, peer_ip = {}, role = {:?}", node_ip, peer_ip, role
    );
    info!(
        log,
        "Message size = {:?}, message count = {:?}", message_size, message_count
    );

    let registry_version = REG_V1;
    let crypto = match create_crypto(node_number, 3, node_id, registry_version) {
        Ok(crypto) => crypto,
        Err(_) => {
            panic!("unable to create crypto");
        }
    };

    let transport = create_transport(
        node_id,
        config_and_records.config.clone(),
        registry_version,
        metrics_registry,
        crypto,
        tokio::runtime::Handle::current(),
        log.clone(),
    );

    let test_client = TestClient::new(
        transport,
        config_and_records.node_records.as_slice(),
        &peer_node_id,
        registry_version,
        log,
    );
    test_client.start_connections();
    test_client.wait_for_flow_up();

    match role {
        Role::Server => {
            test_client.server();
        }
        Role::Client => {
            test_client.client(message_size, message_count, rps);
        }
    }
}
