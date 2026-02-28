use std::{
    collections::HashSet,
    fmt::Display,
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};

use anyhow::Error;
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use bytes::Buf;
use candid::Principal;
use derive_new::new;
use http::Method;
use ic_agent::Agent;
use ic_agent::hash_tree::{HashTree, HashTreeNode, Label, SubtreeLookupResult};
use ic_bn_lib_common::traits::{Run, http::Client};
use ic_types::messages::{HttpStatusResponse, ReplicaHealthStatus};
use mockall::automock;
use simple_moving_average::{SMA, SumTreeSMA};
use strum::IntoStaticStr;
#[allow(clippy::disallowed_types)]
use tokio::sync::Mutex;
use tokio::{
    select,
    sync::{mpsc, watch},
    time::MissedTickBehavior,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{debug, info, warn};

use crate::{
    metrics::{MetricParamsCheck, WithMetricsCheck},
    persist::Persist,
    snapshot::RegistrySnapshot,
    snapshot::{Node, Subnet},
};

/// An error that can occur during check
#[derive(Clone, PartialEq, Debug, IntoStaticStr, thiserror::Error)]
#[strum(serialize_all = "snake_case")]
pub enum CheckError {
    /// Generic error
    #[error("Generic error: {0}")]
    Generic(String),
    /// Unable to make HTTP request
    #[error("Network error: {0}")]
    Network(String),
    /// Got non-200 status code
    #[error("Got non-2xx response code: {0}")]
    Http(u16),
    /// Cannot read response body
    #[error("Unable to read body: {0}")]
    ReadBody(String),
    /// Cannot parse CBOR payload
    #[error("Unable to decode CBOR: {0}")]
    Cbor(String),
    /// Node reported itself as un-healthy
    #[error("Node reported itself as unhealthy")]
    Health,
}

const WINDOW_SIZE: usize = 10;
type LatencyMovAvg = SumTreeSMA<u64, u64, WINDOW_SIZE>;

#[derive(Copy, Clone, PartialEq, Debug)]
struct NodeState {
    healthy: bool,
    height: u64,
    avg_latency_us: u64,
}

/// Send node's state message to the SubnetActor after this number of health checks have passed.
const CHECKS_MSG_PERIODICITY: usize = 10;
/// Send node's state message to the SubnetActor, if node's latency has deviated from the average by more than this threshold value.
const LATENCY_CHANGE_THRESHOLD: f64 = 0.15;

/// NodeActor periodically runs the health checking with given interval and sends the NodeState down to
/// SubnetActor when it changes
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

impl Display for NodeActor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NodeActor({})", self.node)
    }
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

    /// Perform the health check
    async fn check(&mut self) {
        self.checks_counter += 1;

        let start = Instant::now();
        let res = self.checker.check(&self.node).await;

        let (healthy, height, latency_change) = match &res {
            Ok(res) => {
                let latency = start.elapsed().as_micros() as u64;
                let current_avg = self.avg_mov_latency.get_average();
                self.avg_mov_latency.add_sample(latency);
                let latency_change = (latency.abs_diff(current_avg) as f64) / (current_avg as f64);
                (true, res.height, latency_change)
            }

            // Note: we don't add latency to the moving average in case of an error.
            Err(_) => (false, 0, 0.0),
        };

        // Note: initially we update only the health field. height and avg latency are updated conditionally.
        let mut new_state = self.state.unwrap_or_else(|| NodeState {
            healthy,
            height,
            avg_latency_us: self.avg_mov_latency.get_average(),
        });
        new_state.healthy = healthy;

        // Update height and avg latency based on conditions.
        if self.checks_counter >= CHECKS_MSG_PERIODICITY
            || latency_change > LATENCY_CHANGE_THRESHOLD
        {
            // reset the counter
            self.checks_counter = 0;
            new_state.avg_latency_us = self.avg_mov_latency.get_average();
            new_state.height = height;
        }

        // Send the state down the line if either:
        // - health has changed
        // - conditionally updated height has changed
        // - conditionally updated avg latency has changed
        if Some(new_state) != self.state {
            debug!("{self}: new state: {new_state:?}");

            self.state = Some(new_state);
            // It can never fail in our case
            let _ = self.channel.send((self.idx, new_state)).await;
        }
    }

    async fn run(&mut self, check_interval: Duration) {
        debug!("{self}: started");

        let mut interval = tokio::time::interval(check_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            select! {
                // Check if we need to shut down
                _ = self.token.cancelled() => {
                    debug!("{self}: stopped");
                    return;
                }

                // Run the check with given interval
                _ = interval.tick() => self.check().await,
            }
        }
    }
}

type SharedMembership = Arc<ArcSwapOption<HashSet<Principal>>>;

/// MembershipActor periodically fetches the certified membership set for a subnet
/// via the IC Agent and stores the result in shared state.
struct MembershipActor {
    subnet_id: Principal,
    subnet_name: String,
    membership_fetcher: Arc<dyn CertifiedMembershipFetcher>,
    certified_members: SharedMembership,
    token: CancellationToken,
}

impl Display for MembershipActor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MembershipActor({})", self.subnet_name)
    }
}

impl MembershipActor {
    async fn fetch(&self) {
        match self
            .membership_fetcher
            .fetch_certified_members(self.subnet_id)
            .await
        {
            Ok(members) => {
                debug!("{self}: certified membership: {} nodes", members.len());
                self.certified_members.store(Some(Arc::new(members)));
            }
            Err(e) => {
                warn!("{self}: certified membership fetch failed: {e}");
                self.certified_members.store(None);
            }
        }
    }

    async fn run(&self, fetch_interval: Duration) {
        debug!("{self}: started");

        let mut interval = tokio::time::interval(fetch_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            select! {
                _ = self.token.cancelled() => {
                    debug!("{self}: stopped");
                    return;
                }

                _ = interval.tick() => self.fetch().await,
            }
        }
    }
}

/// SubnetActor spawns NodeActors, receives their state, computes minimum height for the subnet and sends the
/// Subnet with healthy nodes down to GlobalActor when the health state changes
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
    certified_members: SharedMembership,
}

impl Display for SubnetActor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SubnetActor({})", self.subnet)
    }
}

impl SubnetActor {
    fn new(
        idx: usize,
        subnet: Subnet,
        check_interval: Duration,
        membership_fetch_interval: Duration,
        token: CancellationToken,
        checker: Arc<dyn Check>,
        channel_out: mpsc::Sender<(usize, Subnet)>,
        max_height_lag: u64,
        membership_fetcher: Arc<dyn CertifiedMembershipFetcher>,
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

        let certified_members: SharedMembership = Arc::new(ArcSwapOption::empty());

        let membership_actor = MembershipActor {
            subnet_id: subnet.id,
            subnet_name: subnet.to_string(),
            membership_fetcher,
            certified_members: certified_members.clone(),
            token: token_nodes.child_token(),
        };

        let interval = membership_fetch_interval;
        tracker.spawn(async move {
            membership_actor.run(interval).await;
        });

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
            certified_members,
        }
    }

    /// Calculate the minimum height across all nodes in this subnet
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

    /// This remembers if we have passed the init state so that we don't have to iterate each time
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

        // Calculate the minimum height across this subnet
        let min_height = self.calc_min_height();

        // Build preliminary healthy list based on health status and height.
        let preliminary_healthy: Vec<(Arc<Node>, NodeState)> = self
            .states
            .iter()
            // All states are Some() - it's checked above in self.init_done()
            .map(|x| *x.as_ref().unwrap())
            .enumerate()
            // Map from idx to a node
            .map(|(idx, state)| (self.subnet.nodes[idx].clone(), state))
            // Discard unhealthy & lagging behind
            .filter(|(_, state)| state.healthy && state.height >= min_height)
            // Update the latency on the node
            .collect();

        // Read the latest certified membership from the background MembershipActor.
        // Ignore the certified set if it covers fewer than 2/3 of the subnet's nodes,
        // since the subnet cannot make progress below that threshold anyway.
        let certified_members = self.certified_members.load();
        let min_members = (self.subnet.nodes.len() * 2).div_ceil(3);
        let certified_set_sufficient = certified_members
            .as_deref()
            .is_some_and(|m| m.len() >= min_members);

        let healthy_nodes: Vec<Arc<Node>> = preliminary_healthy
            .into_iter()
            .filter(|(node, _)| {
                if let Some(members) = certified_members.as_deref()
                    && certified_set_sufficient
                {
                    return members.contains(&node.id);
                }
                true
            })
            .map(|(node, state)| {
                node.avg_latency_us
                    .store(state.avg_latency_us, Ordering::SeqCst);
                node
            })
            .collect();

        // See if the healthy nodes set changed
        if self.healthy_nodes.is_none() || &healthy_nodes != self.healthy_nodes.as_ref().unwrap() {
            warn!(
                "{self}: healthy nodes now {}/{}",
                healthy_nodes.len(),
                self.subnet.nodes.len()
            );

            self.healthy_nodes = Some(healthy_nodes.clone());

            // Publish the new subnet
            let subnet = Subnet {
                id: self.subnet.id,
                subnet_type: self.subnet.subnet_type,
                ranges: self.subnet.ranges.clone(),
                nodes: healthy_nodes,
                replica_version: self.subnet.replica_version.clone(),
            };

            // It can never fail in our case
            let _ = self.channel_out.send((self.idx, subnet)).await;
        }
    }

    async fn run(&mut self, update_interval: Duration) {
        debug!("{self}: started");

        let mut interval = tokio::time::interval(update_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

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
                    debug!("{self}: stopped");
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

/// GlobalActor spawns SubnetActors, receives & aggregates their state and persists the new routing table snapshots
struct GlobalActor {
    subnets: Vec<Option<Subnet>>,
    token: CancellationToken,
    token_subnets: CancellationToken,
    tracker: TaskTracker,
    channel_recv: mpsc::Receiver<(usize, Subnet)>,
    persister: Arc<dyn Persist>,
    init_done: bool,
}

impl Display for GlobalActor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GlobalActor")
    }
}

impl GlobalActor {
    fn new(
        subnets: Vec<Subnet>,
        check_interval: Duration,
        update_interval: Duration,
        membership_fetch_interval: Duration,
        max_height_lag: u64,
        checker: Arc<dyn Check>,
        persister: Arc<dyn Persist>,
        token: CancellationToken,
        membership_fetcher: Arc<dyn CertifiedMembershipFetcher>,
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
                membership_fetch_interval,
                token_subnets.child_token(),
                checker.clone(),
                channel_send.clone(),
                max_height_lag,
                membership_fetcher.clone(),
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

    /// This remembers if we have passed the init state so that we don't have to iterate each time
    fn init_done(&mut self) -> bool {
        if !self.init_done {
            self.init_done = !self.subnets.iter().any(|x| x.is_none());
        }

        self.init_done
    }

    /// Persist the current health state in a routing table
    fn persist(&mut self) {
        // Don't do anything unless we already got an initial iteration of states from all subnet actors
        if !self.init_done() {
            return;
        }

        let subnets = self
            .subnets
            .clone()
            .into_iter()
            // Subnets are Some() at this stage - this is checked above in self.init_done()
            .map(|x| x.unwrap())
            .collect::<Vec<_>>();

        self.persister.persist(subnets);
    }

    async fn run(&mut self) {
        debug!("{self}: started");

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
                    debug!("{self}: stopped");
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

/// Runner receives new registry snapshots and restarts GlobalActor
#[derive(derive_new::new)]
#[allow(clippy::disallowed_types)]
pub struct Runner {
    max_height_lag: u64,
    check_interval: Duration,
    update_interval: Duration,
    membership_fetch_interval: Duration,
    checker: Arc<dyn Check>,
    persister: Arc<dyn Persist>,
    // Tokio mutex is used because its MutexGuard is Send
    channel_snapshot: Mutex<watch::Receiver<Option<Arc<RegistrySnapshot>>>>,
    membership_fetcher: Arc<dyn CertifiedMembershipFetcher>,
}

impl Runner {
    /// Start global actor
    fn start(&self, tracker: &TaskTracker, token: &CancellationToken, subnets: Vec<Subnet>) {
        // Create & spawn new global actor
        let mut actor = GlobalActor::new(
            subnets,
            self.check_interval,
            self.update_interval,
            self.membership_fetch_interval,
            self.max_height_lag,
            self.checker.clone(),
            self.persister.clone(),
            token.child_token(),
            self.membership_fetcher.clone(),
        );

        tracker.spawn(async move {
            actor.run().await;
        });
    }
}

#[async_trait]
impl Run for Runner {
    async fn run(&self, token: CancellationToken) -> Result<(), Error> {
        let mut tracker = TaskTracker::new();
        let mut actor_token = CancellationToken::new();
        let mut snapshot_lock = self.channel_snapshot.lock().await;

        // Watch for snapshot updates and restart global actor
        loop {
            select! {
                _ = token.cancelled() => {
                    return Ok(());
                }

                Ok(_) = snapshot_lock.changed() => {
                    warn!("New registry snapshot - restarting health check actors");

                    // Read the latest snapshot, if it was updated then it's always Some()
                    let snapshot = snapshot_lock
                        .borrow_and_update()
                        .clone()
                        .unwrap();

                    // Stop the current actor
                    actor_token.cancel();
                    tracker.close();
                    tracker.wait().await;

                    // Start the new one
                    tracker = TaskTracker::new();
                    actor_token = CancellationToken::new();
                    self.start(&tracker, &actor_token, snapshot.subnets.clone());
                    warn!("Health check actors restarted");
                }
            }
        }
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

/// Checks the node's health
#[derive(new)]
pub struct Checker {
    http_client: Arc<dyn Client>,
    timeout: Duration,
}

#[async_trait]
impl Check for Checker {
    async fn check(&self, node: &Node) -> Result<CheckResult, CheckError> {
        let mut request = reqwest::Request::new(Method::GET, node.health_check_url.clone());
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
            Err(e) => {
                let error_str: &'static str = e.into();
                format!("error_{error_str}")
            }
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

/// Fetches the certified subnet membership via the IC Agent's read_state API.
#[automock]
#[async_trait]
pub trait CertifiedMembershipFetcher: Send + Sync {
    async fn fetch_certified_members(
        &self,
        subnet_id: Principal,
    ) -> Result<HashSet<Principal>, CheckError>;
}

/// Implementation that uses the IC Agent to query the subnet's read_state endpoint
/// and extracts the set of node Principals from the certified state tree.
pub struct CertifiedMembershipFetcherImpl {
    agent: Agent,
}

impl CertifiedMembershipFetcherImpl {
    pub fn new(agent: Agent) -> Self {
        Self { agent }
    }
}

#[async_trait]
impl CertifiedMembershipFetcher for CertifiedMembershipFetcherImpl {
    async fn fetch_certified_members(
        &self,
        subnet_id: Principal,
    ) -> Result<HashSet<Principal>, CheckError> {
        let paths: Vec<Vec<Label<Vec<u8>>>> = vec![vec![
            Label::from("subnet"),
            Label::from(subnet_id.as_slice()),
            Label::from("node"),
        ]];

        let certificate = self
            .agent
            .read_subnet_state_raw(paths, subnet_id)
            .await
            .map_err(|e| CheckError::Generic(format!("read_state failed: {e}")))?;

        extract_node_ids_from_tree(&certificate.tree, subnet_id)
    }
}

fn extract_node_ids_from_tree(
    tree: &HashTree<Vec<u8>>,
    subnet_id: Principal,
) -> Result<HashSet<Principal>, CheckError> {
    let node_subtree =
        match tree.lookup_subtree(&[b"subnet" as &[u8], subnet_id.as_slice(), b"node"]) {
            SubtreeLookupResult::Found(subtree) => subtree,
            SubtreeLookupResult::Absent => {
                return Err(CheckError::Generic(
                    "Node subtree absent in certificate".into(),
                ));
            }
            SubtreeLookupResult::Unknown => {
                return Err(CheckError::Generic(
                    "Node subtree unknown/pruned in certificate".into(),
                ));
            }
        };

    let mut members = HashSet::new();
    collect_node_ids(node_subtree.as_ref(), &mut members);

    if members.is_empty() {
        return Err(CheckError::Generic(
            "Certificate contained no node members".into(),
        ));
    }

    Ok(members)
}

/// Recursively walk the tree collecting top-level Labeled keys as node Principals.
fn collect_node_ids(tree: &HashTreeNode<Vec<u8>>, members: &mut HashSet<Principal>) {
    match tree {
        HashTreeNode::Labeled(label, _) => match Principal::try_from_slice(label.as_bytes()) {
            Ok(id) => {
                members.insert(id);
            }
            Err(e) => {
                warn!("Unexpected label in node subtree: {e}");
            }
        },
        HashTreeNode::Fork(lr) => {
            collect_node_ids(&lr.0, members);
            collect_node_ids(&lr.1, members);
        }
        _ => {}
    }
}

#[cfg(test)]
pub(crate) mod test {
    use std::{
        collections::HashMap,
        net::{IpAddr, Ipv4Addr},
        sync::Arc,
    };

    use arc_swap::ArcSwapOption;
    use candid::Principal;
    use ic_agent::hash_tree::{Label, empty, fork, label, leaf};
    use ic_registry_subnet_type::SubnetType;

    use super::*;
    use crate::{
        persist::{Persister, Routes},
        snapshot::{CanisterRange, Node, RegistrySnapshot, Subnet, node_test_id, subnet_test_id},
        test_utils::valid_tls_certificate_and_validation_time,
    };

    const NODE_ID_OFFSET: u64 = 1000;

    impl Routes {
        // Check if given node exists in the lookup table
        pub fn node_exists(&self, node_id: Principal) -> bool {
            for s in self.subnet_map.values() {
                for n in s.nodes.iter() {
                    if n.id == node_id {
                        return true;
                    }
                }
            }

            false
        }
    }

    pub fn generate_custom_registry_snapshot(
        subnet_count: u64,
        nodes_per_subnet: u64,
        offset: u64,
    ) -> RegistrySnapshot {
        let mut subnets = Vec::new();
        let mut nodes_hash = HashMap::new();

        for i in 0..subnet_count {
            let subnet_id = subnet_test_id(offset + i).get().0;

            let mut nodes = Vec::new();
            for j in 0..nodes_per_subnet {
                let node = Node::new(
                    node_test_id(NODE_ID_OFFSET + offset + i * 100 + j).get().0,
                    subnet_id,
                    SubnetType::Application,
                    IpAddr::V4(Ipv4Addr::new(192, 168, i as u8, j as u8)),
                    8080,
                    valid_tls_certificate_and_validation_time()
                        .0
                        .certificate_der,
                )
                .unwrap();
                let node = Arc::new(node);

                nodes.push(node.clone());
                nodes_hash.insert(node.id.to_string(), node);
            }

            subnets.push(Subnet {
                id: subnet_id,
                subnet_type: SubnetType::Application,
                ranges: vec![CanisterRange {
                    start: node_test_id(NODE_ID_OFFSET + offset + i * 100).get().0,
                    end: node_test_id(NODE_ID_OFFSET + offset + i * 100 + nodes_per_subnet)
                        .get()
                        .0,
                }],
                nodes,
                replica_version: "7742d96ddd30aa6b607c9d2d4093a7b714f5b25b".to_string(),
            });
        }

        RegistrySnapshot {
            version: 1,
            timestamp: 123,
            nns_public_key: vec![],
            subnets,
            nodes: nodes_hash,
            api_bns: vec![],
        }
    }

    fn node_id(id: u64) -> Principal {
        node_test_id(NODE_ID_OFFSET + id).get().0
    }

    fn check_result(height: u64) -> CheckResult {
        CheckResult {
            height,
            replica_version: "foobar".into(),
        }
    }

    fn noop_membership_fetcher() -> Arc<dyn CertifiedMembershipFetcher> {
        let mut fetcher = MockCertifiedMembershipFetcher::new();
        fetcher
            .expect_fetch_certified_members()
            .returning(|_| Err(CheckError::Generic("test: not implemented".into())));
        Arc::new(fetcher)
    }

    #[test]
    fn test_checkerror() {
        let error_str: &'static str = CheckError::Cbor("foo".into()).into();
        assert_eq!(error_str, "cbor");
        let error_str: &'static str = CheckError::ReadBody("foo".into()).into();
        assert_eq!(error_str, "read_body");
    }

    // Ensure that nodes that have failed healthcheck or lag behind are excluded
    #[tokio::test]
    async fn test_check_some_unhealthy() -> Result<(), Error> {
        let routes = Arc::new(ArcSwapOption::empty());
        let persister = Arc::new(Persister::new(routes.clone()));

        let mut checker = MockCheck::new();
        checker
            .expect_check()
            .withf(|x: &Node| x.id == node_id(0))
            .returning(|_| Ok(check_result(1000)));

        checker
            .expect_check()
            .withf(|x: &Node| x.id == node_id(1))
            .returning(|_| Err(CheckError::Health));

        checker
            .expect_check()
            .withf(|x: &Node| x.id == node_id(100))
            .returning(|_| Ok(check_result(1010)));

        checker
            .expect_check()
            .withf(|x: &Node| x.id == node_id(101))
            .returning(|_| Ok(check_result(500)));

        let (channel_send, channel_recv) = watch::channel(None);
        let runner = Runner::new(
            10,
            Duration::from_millis(100),
            Duration::from_millis(1),
            Duration::from_millis(1),
            Arc::new(checker),
            persister,
            #[allow(clippy::disallowed_types)]
            Mutex::new(channel_recv),
            noop_membership_fetcher(),
        );
        tokio::spawn(async move {
            let _ = runner.run(CancellationToken::new()).await;
        });

        let snapshot = generate_custom_registry_snapshot(2, 2, 0);
        channel_send.send(Some(Arc::new(snapshot))).unwrap();

        // Wait until the routing table is published
        // TODO improve
        for _ in 1..10 {
            if routes.load().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let rt = routes.load_full().unwrap();

        // Make sure that only nodes 1 and 101 are not included in the resulting table
        assert!(rt.node_exists(node_id(0)));
        assert!(!rt.node_exists(node_id(1)));
        assert!(rt.node_exists(node_id(100)));
        assert!(!rt.node_exists(node_id(101)));

        Ok(())
    }

    // Ensure that when nodes are removed from routing table -> they're removed from the resulting lookup table
    #[tokio::test]
    async fn test_check_nodes_gone() -> Result<(), Error> {
        let routes = Arc::new(ArcSwapOption::empty());
        let persister = Arc::new(Persister::new(routes.clone()));

        let mut checker = MockCheck::new();
        checker
            .expect_check()
            .withf(|x: &Node| [node_id(0), node_id(1), node_id(100), node_id(101)].contains(&x.id))
            .returning(|_| Ok(check_result(1000)));

        let (channel_send, channel_recv) = watch::channel(None);
        let runner = Runner::new(
            10,
            Duration::from_millis(100),
            Duration::from_millis(1),
            Duration::from_millis(1),
            Arc::new(checker),
            persister,
            #[allow(clippy::disallowed_types)]
            Mutex::new(channel_recv),
            noop_membership_fetcher(),
        );
        tokio::spawn(async move {
            let _ = runner.run(CancellationToken::new()).await;
        });

        // Generate & apply snapshot with 4 nodes first
        let snapshot = generate_custom_registry_snapshot(2, 2, 0);
        channel_send.send(Some(Arc::new(snapshot.clone()))).unwrap();

        // Wait until the routing table is published
        // TODO improve
        for _ in 1..10 {
            if routes.load().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let rt = routes.load_full().unwrap();
        assert_eq!(rt.node_count, 4);
        assert!(rt.node_exists(node_id(0)));
        assert!(rt.node_exists(node_id(1)));
        assert!(rt.node_exists(node_id(100)));
        assert!(rt.node_exists(node_id(101)));

        routes.store(None);
        // Generate a smaller snapshot with 2 nodes
        let snapshot = generate_custom_registry_snapshot(2, 1, 0);
        channel_send.send(Some(Arc::new(snapshot.clone()))).unwrap();
        // Wait until the routing table is published
        // TODO improve
        for _ in 1..10 {
            if routes.load().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // Check that only 2 nodes left
        let rt = routes.load_full().unwrap();
        assert_eq!(rt.node_count, 2);
        assert!(rt.node_exists(node_id(0)));
        assert!(!rt.node_exists(node_id(1)));
        assert!(rt.node_exists(node_id(100)));
        assert!(!rt.node_exists(node_id(101)));

        routes.store(None);
        // Generate a bigger table with 4 nodes again
        let snapshot = generate_custom_registry_snapshot(2, 2, 0);
        channel_send.send(Some(Arc::new(snapshot.clone()))).unwrap();
        // Wait until the routing table is published
        for _ in 1..10 {
            if routes.load().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // Check that nodes are back
        let rt = routes.load_full().unwrap();
        assert_eq!(rt.node_count, 4);
        assert!(rt.node_exists(node_id(0)));
        assert!(rt.node_exists(node_id(1)));
        assert!(rt.node_exists(node_id(100)));
        assert!(rt.node_exists(node_id(101)));

        Ok(())
    }

    #[tokio::test]
    async fn test_runner() -> Result<(), Error> {
        let mut checker = MockCheck::new();
        checker.expect_check().returning(|_| Ok(check_result(1000)));

        let routes = Arc::new(ArcSwapOption::empty());
        let persister = Arc::new(Persister::new(routes.clone()));

        let (channel_send, channel_recv) = watch::channel(None);
        let runner = Runner::new(
            10,
            Duration::from_millis(100),
            Duration::from_millis(1),
            Duration::from_millis(1),
            Arc::new(checker),
            persister,
            #[allow(clippy::disallowed_types)]
            Mutex::new(channel_recv),
            noop_membership_fetcher(),
        );

        tokio::spawn(async move {
            let _ = runner.run(CancellationToken::new()).await;
        });

        // Send the snapshot
        let snapshot = generate_custom_registry_snapshot(2, 2, 0);
        channel_send.send(Some(Arc::new(snapshot.clone()))).unwrap();

        // Wait until the routing table is published
        // TODO improve
        for _ in 1..10 {
            if routes.load().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let rt = routes.load_full().unwrap();
        assert_eq!(rt.node_count, snapshot.nodes.len() as u32);
        for (i, j) in [(0, 1), (1, 0)].iter() {
            let mut nodes_left = rt.routes[*i].subnet.nodes.clone();
            let mut nodes_right = snapshot.subnets[*j].nodes.clone();
            nodes_left.sort_by_key(|n| n.id);
            nodes_right.sort_by_key(|n| n.id);
            assert_eq!(nodes_left, nodes_right);
        }

        Ok(())
    }

    // Ensure that when the membership fetcher fails, all healthy nodes are
    // included (fail-open behavior).
    #[tokio::test]
    async fn test_membership_fetch_failure_includes_all_nodes() -> Result<(), Error> {
        let routes = Arc::new(ArcSwapOption::empty());
        let persister = Arc::new(Persister::new(routes.clone()));

        let mut checker = MockCheck::new();
        checker.expect_check().returning(|_| Ok(check_result(1000)));

        let (channel_send, channel_recv) = watch::channel(None);
        let runner = Runner::new(
            10,
            Duration::from_millis(100),
            Duration::from_millis(1),
            Duration::from_millis(1),
            Arc::new(checker),
            persister,
            #[allow(clippy::disallowed_types)]
            Mutex::new(channel_recv),
            noop_membership_fetcher(), // always returns Err → fail-open
        );
        tokio::spawn(async move {
            let _ = runner.run(CancellationToken::new()).await;
        });

        let snapshot = generate_custom_registry_snapshot(2, 2, 0);
        channel_send.send(Some(Arc::new(snapshot))).unwrap();

        for _ in 1..10 {
            if routes.load().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let rt = routes.load_full().unwrap();
        assert_eq!(rt.node_count, 4);
        assert!(rt.node_exists(node_id(0)));
        assert!(rt.node_exists(node_id(1)));
        assert!(rt.node_exists(node_id(100)));
        assert!(rt.node_exists(node_id(101)));

        Ok(())
    }

    fn build_node_tree(subnet_id: Principal, node_ids: &[Principal]) -> HashTree<Vec<u8>> {
        let node_subtree: HashTree<Vec<u8>> = match node_ids.len() {
            0 => empty(),
            1 => label(Label::from(node_ids[0].as_slice()), leaf(vec![1])),
            _ => {
                let mut tree = fork(
                    label(Label::from(node_ids[0].as_slice()), leaf(vec![1])),
                    label(Label::from(node_ids[1].as_slice()), leaf(vec![1])),
                );
                for id in &node_ids[2..] {
                    tree = fork(tree, label(Label::from(id.as_slice()), leaf(vec![1])));
                }
                tree
            }
        };

        label(
            "subnet",
            label(
                Label::from(subnet_id.as_slice()),
                label("node", node_subtree),
            ),
        )
    }

    #[test]
    fn test_extract_node_ids_happy_path() {
        let subnet_id = subnet_test_id(0).get().0;
        let ids = vec![node_id(0), node_id(1), node_id(2)];
        let tree = build_node_tree(subnet_id, &ids);

        let result = extract_node_ids_from_tree(&tree, subnet_id).unwrap();
        assert_eq!(result.len(), 3);
        for id in &ids {
            assert!(result.contains(id));
        }
    }

    #[test]
    fn test_extract_node_ids_empty_subtree() {
        let subnet_id = subnet_test_id(0).get().0;
        let tree = build_node_tree(subnet_id, &[]);

        let result = extract_node_ids_from_tree(&tree, subnet_id);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no node members"));
    }
}
