use std::{
    fmt,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Error;
use async_trait::async_trait;
use bytes::Buf;
use http::Method;
use ic_bn_lib::http::Client;
use ic_types::messages::{HttpStatusResponse, ReplicaHealthStatus};
use mockall::automock;
use simple_moving_average::{SumTreeSMA, SMA};
use tokio::{
    select,
    sync::{mpsc, watch},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{debug, warn};
use url::Url;

use crate::{
    core::Run,
    metrics::{MetricParamsCheck, WithMetricsCheck},
    persist::Persist,
    snapshot::RegistrySnapshot,
    snapshot::{Node, Subnet},
};

#[derive(Debug, PartialEq, Clone)]
pub enum CheckError {
    Generic(String),
    Network(String),  // Unable to make HTTP request
    Http(u16),        // Got non-200 status code
    ReadBody(String), // Cannot read response body
    Cbor(String),     // Cannot parse CBOR payload
    Health,           // Node reported itself as un-healthy
}

impl CheckError {
    pub fn short(&self) -> &str {
        match self {
            Self::Generic(_) => "generic",
            Self::Network(_) => "network",
            Self::Http(_) => "http",
            Self::ReadBody(_) => "read_body",
            Self::Cbor(_) => "cbor",
            Self::Health => "health",
        }
    }
}

impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Generic(e) => write!(f, "Error: {e}"),
            Self::Network(e) => write!(f, "Network error: {e}"),
            Self::Http(code) => write!(f, "Got non-2xx response code: {code}"),
            Self::ReadBody(e) => write!(f, "Unable to read body: {e}"),
            Self::Cbor(e) => write!(f, "Unable to decode CBOR: {e}"),
            Self::Health => write!(f, "Node reported itself as unhealthy"),
        }
    }
}

const WINDOW_SIZE: usize = 10;
type LatencyMovAvg = SumTreeSMA<f64, f64, WINDOW_SIZE>;

#[derive(Clone, Copy, Debug, PartialEq)]
struct NodeState {
    healthy: bool,
    height: u64,
    avg_latency_secs: f64,
}

// Send node's state message to the SubnetActor after this number of health checks have passed.
const CHECKS_MSG_PERIODICITY: usize = 10;
// Send node's state message to the SubnetActor, if node's latency has deviated from the average by more than this threshold value.
const LATENCY_CHANGE_THRESHOLD: f64 = 0.15;

// NodeActor periodically runs the health checking with given interval and sends the NodeState down to
// SubnetActor when it changes
struct NodeActor {
    idx: usize,
    node: Arc<Node>,
    channel: mpsc::Sender<(usize, NodeState)>,
    token: CancellationToken,
    checker: Arc<dyn Check>,
    state: Option<NodeState>,
    avg_mov_latency: LatencyMovAvg,
    checks_counter: usize,
}

impl NodeActor {
    fn new(
        idx: usize,
        node: Arc<Node>,
        channel: mpsc::Sender<(usize, NodeState)>,
        token: CancellationToken,
        checker: Arc<dyn Check>,
    ) -> Self {
        Self {
            idx,
            node,
            channel,
            token,
            checker,
            state: None,
            avg_mov_latency: LatencyMovAvg::new(),
            checks_counter: 0,
        }
    }

    // Perform the health check
    async fn check(&mut self) {
        self.checks_counter += 1;

        let start = Instant::now();
        let res = self.checker.check(&self.node).await;

        let (healthy, height, latency_change) = match &res {
            Ok(res) => {
                let latency = start.elapsed().as_secs_f64();
                let current_avg = self.avg_mov_latency.get_average();
                self.avg_mov_latency.add_sample(latency);
                let latency_change = (latency - current_avg).abs() / current_avg;
                (true, res.height, latency_change)
            }
            // Note: we don't add latency to the moving average in case of an error.
            Err(_) => (false, 0, 0.0),
        };

        // Note: initially we update only the health field. height and avg latency are updated conditionally.
        let mut new_state = self.state.unwrap_or_else(|| NodeState {
            healthy,
            height,
            avg_latency_secs: self.avg_mov_latency.get_average(),
        });
        new_state.healthy = healthy;

        // Update height and avg latency based on conditions.
        if self.checks_counter >= CHECKS_MSG_PERIODICITY
            || latency_change > LATENCY_CHANGE_THRESHOLD
        {
            // reset the counter
            self.checks_counter = 0;
            new_state.avg_latency_secs = self.avg_mov_latency.get_average();
            new_state.height = height;
        }

        // Send the state down the line if either:
        // - health has changed
        // - conditionally updated height has changed
        // - conditionally updated avg latency has changed
        if Some(new_state) != self.state {
            self.state = Some(new_state);
            // It can never fail in our case
            let _ = self.channel.send((self.idx, new_state)).await;
        }
    }

    async fn run(&mut self, check_interval: Duration) {
        debug!("Healthcheck actor for node {} started", self.node);

        let mut interval = tokio::time::interval(check_interval);
        loop {
            select! {
                // Check if we need to shut down
                _ = self.token.cancelled() => {
                    debug!("Healthcheck actor for node {} stopped", self.node);
                    return;
                }

                // Run the check with given interval
                _ = interval.tick() => self.check().await,
            }
        }
    }
}

// SubnetActor spawns NodeActors, receives their state, computes minimum height for the subnet and sends the
// Subnet with healthy nodes down to GlobalActor when the health state changes
struct SubnetActor {
    idx: usize,
    subnet: Subnet,
    token: CancellationToken,
    token_nodes: CancellationToken,
    tracker: TaskTracker,
    channel_recv: mpsc::Receiver<(usize, NodeState)>,
    channel_out: mpsc::Sender<(usize, Subnet)>,
    states: Vec<Option<NodeState>>,
    max_height_lag: u64,
    healthy_nodes: Option<Vec<Arc<Node>>>,
    state_changed: bool,
    init_done: bool,
}

impl SubnetActor {
    fn new(
        idx: usize,
        subnet: Subnet,
        check_interval: Duration,
        token: CancellationToken,
        checker: Arc<dyn Check>,
        channel_out: mpsc::Sender<(usize, Subnet)>,
        max_height_lag: u64,
    ) -> Self {
        let (channel_send, channel_recv) = mpsc::channel(128);
        let tracker = TaskTracker::new();
        let token_nodes = CancellationToken::new();

        for (idx, node) in subnet.nodes.iter().enumerate() {
            let mut actor = NodeActor::new(
                idx,
                node.clone(),
                channel_send.clone(),
                token_nodes.child_token(),
                checker.clone(),
            );

            tracker.spawn(async move {
                actor.run(check_interval).await;
            });
        }

        Self {
            idx,
            states: vec![None; subnet.nodes.len()],
            subnet,
            token,
            token_nodes,
            tracker,
            channel_recv,
            channel_out,
            max_height_lag,
            healthy_nodes: None,
            state_changed: false,
            init_done: false,
        }
    }

    fn calc_min_height(&self) -> u64 {
        let mut heights = self
            .states
            .iter()
            // calc_min_height is called only when all states are Some()
            .map(|x| x.as_ref().unwrap())
            .filter(|x| x.healthy)
            .map(|x| x.height)
            .collect::<Vec<_>>();

        // Calculate the minimum block height requirement for given subnet
        match heights.len() {
            0 => 0,
            _ => {
                heights.sort();
                let mid_height_0 = heights[(heights.len() - 1) / 2];
                let mid_height_1 = heights[heights.len() / 2];
                // We use the median because it's a good approximation of
                // the "consensus" and keeps us resilient to malicious replicas
                // sending an artificially high height to DoS the BNs
                let median_height = (mid_height_0 + mid_height_1) / 2;
                median_height.saturating_sub(self.max_height_lag)
            }
        }
    }

    // This remembers if we have passed the init state so that we don't have to iterate each time
    fn init_done(&mut self) -> bool {
        if !self.init_done {
            self.init_done = !self.states.iter().any(|x| x.is_none());
        }

        self.init_done
    }

    async fn update(&mut self) {
        // Don't do anything unless we already got initial iteration of states from all node actors
        if !self.init_done() {
            return;
        }

        // Calc the minimum height
        let min_height = self.calc_min_height();

        // Generate a list of healthy nodes
        let nodes = self
            .states
            .iter()
            // All states are Some() - it's checked above
            .map(|x| x.as_ref().unwrap())
            .enumerate()
            // Map from idx to a node
            .map(|(idx, state)| (self.subnet.nodes[idx].clone(), state))
            // Discard unhealthy & lagging behind
            .filter(|(_, state)| state.healthy && state.height >= min_height)
            .map(|(node, state)| {
                let mut node = (*node).clone();
                node.avg_latency_secs = state.avg_latency_secs;
                Arc::new(node)
            })
            .collect::<Vec<_>>();

        // See if the healthy nodes set changed
        if self.healthy_nodes.is_none() || &nodes != self.healthy_nodes.as_ref().unwrap() {
            self.healthy_nodes = Some(nodes.clone());

            // Publish the new subnet
            let subnet = Subnet {
                id: self.subnet.id,
                subnet_type: self.subnet.subnet_type,
                ranges: self.subnet.ranges.clone(),
                nodes,
                replica_version: self.subnet.replica_version.clone(),
            };

            // It can never fail in our case
            let _ = self.channel_out.send((self.idx, subnet)).await;
        }
    }

    async fn run(&mut self, update_interval: Duration) {
        debug!("Healthcheck actor for subnet {} started", self.subnet);

        let mut interval = tokio::time::interval(update_interval);
        loop {
            select! {
                // Check if we need to shut down
                _ = self.token.cancelled() => {
                    // Cancel the node actors token
                    self.token_nodes.cancel();
                    // Wait for all node actors to exit
                    self.tracker.close();
                    self.tracker.wait().await;
                    self.channel_recv.close();
                    debug!("Healthcheck actor for subnet {} stopped", self.subnet);
                    return;
                }

                // Read messages from node actors
                msg = self.channel_recv.recv() => {
                    let (idx, state) = match msg {
                        Some(v) => v,
                        None => return,
                    };

                    let old_state = self.states[idx];
                    self.states[idx] = Some(state);

                    // Trigger an immediate refresh if the node's health state has changed
                    if Some(state.healthy) != old_state.map(|x| x.healthy) {
                        self.update().await;
                    } else {
                        // Otherwise it'll be handled by a periodic job
                        self.state_changed = true;
                    }
                }

                // Periodically recalculate the healthy nodes list
                _ = interval.tick() => {
                    // Check if we've received some new states from node actors
                    if self.state_changed {
                        self.update().await;
                        self.state_changed = false;
                    }
                }
            }
        }
    }
}

// GlobalActor spawns SubnetActors, receives & aggregates their state and persists the new routing table snapshots
struct GlobalActor {
    subnets: Vec<Option<Subnet>>,
    token: CancellationToken,
    token_subnets: CancellationToken,
    tracker: TaskTracker,
    channel_recv: mpsc::Receiver<(usize, Subnet)>,
    persister: Arc<dyn Persist>,
    init_done: bool,
}

impl GlobalActor {
    fn new(
        subnets: Vec<Subnet>,
        check_interval: Duration,
        update_interval: Duration,
        max_height_lag: u64,
        checker: Arc<dyn Check>,
        persister: Arc<dyn Persist>,
        token: CancellationToken,
    ) -> Self {
        let tracker = TaskTracker::new();
        let token_subnets = CancellationToken::new();
        let (channel_send, channel_recv) = mpsc::channel(128);

        // Create & start per-subnet actors
        for (idx, subnet) in subnets.iter().enumerate() {
            let mut actor = SubnetActor::new(
                idx,
                subnet.clone(),
                check_interval,
                token_subnets.child_token(),
                checker.clone(),
                channel_send.clone(),
                max_height_lag,
            );

            tracker.spawn(async move {
                actor.run(update_interval).await;
            });
        }

        Self {
            subnets: vec![None; subnets.len()],
            token,
            token_subnets,
            tracker,
            channel_recv,
            persister,
            init_done: false,
        }
    }

    // This remembers if we have passed the init state so that we don't have to iterate each time
    fn init_done(&mut self) -> bool {
        if !self.init_done {
            self.init_done = !self.subnets.iter().any(|x| x.is_none());
        }

        self.init_done
    }

    // Persist the current health state in a routing table
    fn persist(&mut self) {
        // Don't do anything unless we already got an initial iteration of states from all subnet actors
        if !self.init_done() {
            return;
        }

        let subnets = self
            .subnets
            .clone()
            .into_iter()
            // Subnets are Some() at this stage - this is checked above
            .map(|x| x.unwrap())
            .collect::<Vec<_>>();

        self.persister.persist(subnets);
    }

    async fn run(&mut self) {
        debug!("Healthcheck global actor started");

        loop {
            select! {
                // Check if we need to shut down
                _ = self.token.cancelled() => {
                    // Cancel the node actors token
                    self.token_subnets.cancel();
                    // Wait for all subnet actors to exit
                    self.tracker.close();
                    self.tracker.wait().await;
                    self.channel_recv.close();
                    debug!("Healthcheck global actor stopped");
                    return;
                }

                // Read messages from subnet actors
                msg = self.channel_recv.recv() => {
                    let (idx, subnet) = match msg {
                        Some(v) => v,
                        None => return,
                    };

                    self.subnets[idx] = Some(subnet);
                    self.persist();
                }
            }
        }
    }
}

// Runner receives new registry snapshots and restarts GlobalActor
pub struct Runner {
    max_height_lag: u64,
    check_interval: Duration,
    update_interval: Duration,
    tracker: TaskTracker,
    token: CancellationToken,
    checker: Arc<dyn Check>,
    persister: Arc<dyn Persist>,
    channel_snapshot: watch::Receiver<Option<Arc<RegistrySnapshot>>>,
}

impl Runner {
    pub fn new(
        channel_snapshot: watch::Receiver<Option<Arc<RegistrySnapshot>>>,
        max_height_lag: u64,
        persister: Arc<dyn Persist>,
        checker: Arc<dyn Check>,
        check_interval: Duration,
        update_interval: Duration,
    ) -> Self {
        Self {
            max_height_lag,
            tracker: TaskTracker::new(),
            token: CancellationToken::new(),
            persister,
            checker,
            check_interval,
            update_interval,
            channel_snapshot,
        }
    }

    // Start global actor
    fn start(&mut self) {
        self.tracker = TaskTracker::new();
        self.token = CancellationToken::new();

        // Read the latest snapshot, if it was updated then it's always Some()
        let snapshot = self.channel_snapshot.borrow_and_update().clone().unwrap();

        // Create & spawn new global actor
        let mut actor = GlobalActor::new(
            snapshot.subnets.clone(),
            self.check_interval,
            self.update_interval,
            self.max_height_lag,
            self.checker.clone(),
            self.persister.clone(),
            self.token.child_token(),
        );

        self.tracker.spawn(async move {
            actor.run().await;
        });
    }

    // Stop global actor
    async fn stop(&mut self) {
        self.token.cancel();
        self.tracker.close();
        self.tracker.wait().await;
    }
}

#[async_trait]
impl Run for Runner {
    async fn run(&mut self) -> Result<(), Error> {
        // Watch for snapshot updates and restart global actor
        while self.channel_snapshot.changed().await.is_ok() {
            warn!("New registry snapshot - restarting health check actors");
            self.stop().await;
            self.start();
            warn!("Health check actors restarted");
        }

        Ok(())
    }
}

pub struct CheckResult {
    pub height: u64,
    pub replica_version: String,
}

#[automock]
#[async_trait]
pub trait Check: Send + Sync {
    async fn check(&self, node: &Node) -> Result<CheckResult, CheckError>;
}

pub struct Checker {
    http_client: Arc<dyn Client>,
    timeout: Duration,
}

impl Checker {
    pub fn new(http_client: Arc<dyn Client>, timeout: Duration) -> Self {
        Self {
            http_client,
            timeout,
        }
    }
}

#[async_trait]
impl Check for Checker {
    async fn check(&self, node: &Node) -> Result<CheckResult, CheckError> {
        // Create request
        let u = Url::from_str(&format!("https://{}:{}/api/v2/status", node.id, node.port))
            .map_err(|err| CheckError::Generic(err.to_string()))?;

        let mut request = reqwest::Request::new(Method::GET, u);
        *request.timeout_mut() = Some(self.timeout);

        // Execute request
        let response = self
            .http_client
            .execute(request)
            .await
            .map_err(|err| CheckError::Network(err.to_string()))?;

        if response.status() != reqwest::StatusCode::OK {
            return Err(CheckError::Http(response.status().into()));
        }

        let response_reader = match response.bytes().await {
            Ok(v) => v.reader(),
            Err(e) => return Err(CheckError::ReadBody(e.to_string())),
        };

        let HttpStatusResponse {
            replica_health_status,
            certified_height,
            impl_version,
            ..
        } = match serde_cbor::from_reader(response_reader) {
            Ok(v) => v,
            Err(e) => return Err(CheckError::Cbor(e.to_string())),
        };

        if replica_health_status != Some(ReplicaHealthStatus::Healthy) {
            return Err(CheckError::Health);
        }

        if impl_version.is_none() {
            return Err(CheckError::Generic("No replica version available".into()));
        }

        Ok(CheckResult {
            height: certified_height.map_or(0, |v| v.get()),
            replica_version: impl_version.unwrap(),
        })
    }
}

#[async_trait]
impl<T: Check> Check for WithMetricsCheck<T> {
    async fn check(&self, node: &Node) -> Result<CheckResult, CheckError> {
        let start_time = Instant::now();
        let out = self.0.check(node).await;
        let duration = start_time.elapsed().as_secs_f64();

        let result = match &out {
            Ok(_) => "ok".to_string(),
            Err(e) => format!("error_{}", e.short()),
        };

        let (block_height, replica_version) = out.as_ref().map_or((-1, "unknown"), |out| {
            (out.height as i64, out.replica_version.as_str())
        });

        let MetricParamsCheck {
            counter,
            recorder,
            status,
        } = &self.1;

        let subnet_id = node.subnet_id.to_string();
        let node_id = node.id.to_string();
        let node_addr = node.addr.to_string();

        let labels = &[
            result.as_str(),
            node_id.as_str(),
            subnet_id.as_str(),
            node_addr.as_str(),
        ];

        counter.with_label_values(labels).inc();
        recorder.with_label_values(labels).observe(duration);
        status
            .with_label_values(&labels[1..4])
            .set(out.is_ok().into());

        if let Err(e) = &out {
            warn!(
                action = "check",
                result,
                duration,
                block_height,
                replica_version,
                subnet_id,
                node_id,
                node_addr,
                error = e.to_string(),
            );
        }

        out
    }
}

#[cfg(test)]
pub mod test;
