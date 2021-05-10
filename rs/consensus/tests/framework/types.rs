#![allow(dead_code)]
use ic_artifact_pool::{
    certification_pool::CertificationPoolImpl, consensus_pool::ConsensusPoolImpl, dkg_pool,
};
use ic_config::artifact_pool::ArtifactPoolConfig;
use ic_consensus::{consensus::ConsensusImpl, dkg};
use ic_interfaces::{
    certification::Certifier,
    certified_stream_store::CertifiedStreamStore,
    ingress_manager::IngressSelector,
    messaging::{MessageRouting, XNetPayloadBuilder},
    registry::RegistryClient,
    state_manager::StateManager,
    time_source::TimeSource,
};
use ic_logger::{replica_logger::no_op_logger, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_replicated_state::ReplicatedState;
use ic_test_artifact_pool::ingress_pool::TestIngressPool;
use ic_test_utilities::{
    ingress_selector::FakeIngressSelector, message_routing::FakeMessageRouting,
    state_manager::FakeStateManager, xnet_payload_builder::FakeXNetPayloadBuilder,
};
use ic_types::{
    consensus::{
        certification::CertificationMessage, dkg::Message as DkgMessage, CatchUpPackage,
        ConsensusMessage,
    },
    replica_config::ReplicaConfig,
    time::Time,
    NodeId, SubnetId,
};
use rand_chacha::ChaChaRng;
use std::cell::{RefCell, RefMut};
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::fmt;
use std::rc::Rc;
use std::sync::{Arc, RwLock};

/// We use priority queues for input/output messages.
pub type Queue<T> = Rc<RefCell<BinaryHeap<T>>>;

/// Default time step is 1 millisecond.
pub const UNIT_TIME_STEP: u64 = 1;

/// Polling interval is 100 millisecond.
pub const POLLING_INTERVAL: u64 = 100;

/// Messages from a consensus instance are either artifacts to be
/// delivered to peers, or to a timer expired event that should trigger
/// consensus on_state_change.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Input {
    Message(Message),
    TimerExpired(Time),
}

impl Input {
    pub fn timestamp(&self) -> Time {
        match self {
            Input::Message(m) => m.timestamp,
            Input::TimerExpired(t) => *t,
        }
    }
}

// We reverse the order so that Queue<Input> is a min-heap.
impl Ord for Input {
    fn cmp(&self, other: &Input) -> Ordering {
        self.timestamp().cmp(&other.timestamp()).reverse()
    }
}

/// We reverse the order so that Queue<Input> is a min heap.
impl PartialOrd for Input {
    fn partial_cmp(&self, other: &Input) -> Option<Ordering> {
        Some(self.timestamp().cmp(&other.timestamp()).reverse())
    }
}

/// The output of a consensus instance is just the Message type.
pub type Output = Message;

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum InputMessage {
    Consensus(ConsensusMessage),
    Dkg(DkgMessage),
    Certification(CertificationMessage),
}

/// A Message is a tuple of ConsensusMessage with a timestamp.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub(crate) message: InputMessage,
    pub(crate) timestamp: Time,
}

/// We reverse the order so that Queue<Message> is a min-heap.
impl Ord for Message {
    fn cmp(&self, other: &Message) -> Ordering {
        self.timestamp.cmp(&other.timestamp).reverse()
    }
}

/// We reverse the order so that Queue<Message> is a min-heap.
impl PartialOrd for Message {
    fn partial_cmp(&self, other: &Message) -> Option<Ordering> {
        Some(self.timestamp.cmp(&other.timestamp).reverse())
    }
}

/// Compare optional Time values, by treating None as "top" (i.e. greater
/// than other values).
pub fn compare_timestamp(i: Option<Time>, j: Option<Time>) -> Ordering {
    match (i, j) {
        (Some(t1), Some(t2)) => t1.cmp(&t2),
        (Some(_), _) => Ordering::Less,
        (_, Some(_)) => Ordering::Greater,
        _ => Ordering::Equal,
    }
}

struct RcXNetPayloadBuilder {
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    certified_stream_store: Arc<dyn CertifiedStreamStore>,
    registry_client: Arc<dyn RegistryClient>,
    node_id: NodeId,
    subnet_id: SubnetId,
}

/// Dependencies of a consensus component.
pub struct ConsensusDependencies {
    pub(crate) xnet_payload_builder: Arc<dyn XNetPayloadBuilder>,
    pub(crate) ingress_selector: Arc<dyn IngressSelector>,
    pub consensus_pool: Arc<RwLock<ConsensusPoolImpl>>,
    pub dkg_pool: Arc<RwLock<dkg_pool::DkgPoolImpl>>,
    pub message_routing: Arc<dyn MessageRouting>,
    pub state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    pub replica_config: ReplicaConfig,
    pub metrics_registry: MetricsRegistry,
    pub registry_client: Arc<dyn RegistryClient>,
}

impl ConsensusDependencies {
    pub fn new(
        replica_config: ReplicaConfig,
        pool_config: ArtifactPoolConfig,
        registry_client: Arc<dyn RegistryClient>,
        cup: CatchUpPackage,
    ) -> ConsensusDependencies {
        let state_manager = FakeStateManager::new();
        let state_manager = Arc::new(state_manager);
        // let state_manager_arc = Rc::new(state_manager);
        let metrics_registry = MetricsRegistry::new();

        let consensus_pool = Arc::new(RwLock::new(ConsensusPoolImpl::new_from_cup_without_bytes(
            replica_config.subnet_id,
            cup,
            pool_config,
            metrics_registry.clone(),
            no_op_logger(),
        )));
        let dkg_pool = dkg_pool::DkgPoolImpl::new(metrics_registry.clone());
        let xnet_payload_builder = FakeXNetPayloadBuilder::new();
        ConsensusDependencies {
            registry_client: Arc::clone(&registry_client),
            consensus_pool,
            dkg_pool: Arc::new(RwLock::new(dkg_pool)),
            message_routing: Arc::new(FakeMessageRouting::with_state_manager(
                state_manager.clone(),
            )),
            ingress_selector: Arc::new(FakeIngressSelector::new()),
            xnet_payload_builder: Arc::new(xnet_payload_builder),
            state_manager,
            metrics_registry,
            replica_config,
        }
    }
}

/// A ConsensusInstance consists of a ConsensusDriver, its dependencies,
/// input and output message queues, and a local clock to track last execution
/// time.
pub struct ConsensusInstance<'a> {
    pub node_id: NodeId,
    pub driver: ConsensusDriver<'a>,
    pub deps: &'a ConsensusDependencies,
    pub(crate) in_queue: Queue<Input>,
    pub(crate) out_queue: Queue<Output>,
    pub(crate) clock: RefCell<Time>,
    pub(crate) index: usize,
}

impl fmt::Display for ConsensusInstance<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ConsensusInstance {{ node_id: {:?}, clock: {:?}, \
             in_queue: {:?}, out_queue: {:?} }}",
            self.deps.replica_config.node_id, self.clock, self.in_queue, self.out_queue,
        )
    }
}
/// This is the type of predicates used by the ConsensusRunner to determine
/// whether or not it should terminate. It is evaluated for all consensus
/// instances at every time step.
pub type StopPredicate<'a> = &'a dyn Fn(&ConsensusInstance<'a>) -> bool;

/// A ConsensusDriver mainly consists of the consensus component, and the
/// consensus artifact pool and timer.
pub struct ConsensusDriver<'a> {
    pub(crate) consensus: ConsensusImpl,
    pub(crate) dkg: dkg::DkgImpl,
    pub(crate) certifier: Box<dyn Certifier + 'a>,
    pub(crate) logger: ReplicaLogger,
    pub consensus_pool: Arc<RwLock<ConsensusPoolImpl>>,
    pub certification_pool: Arc<RwLock<CertificationPoolImpl>>,
    pub ingress_pool: RefCell<TestIngressPool>,
    pub dkg_pool: Arc<RwLock<dkg_pool::DkgPoolImpl>>,
}

/// An execution strategy picks the next instance to execute, and execute a
/// single step by consuming one of its input messages.
///
/// It returns the updated local time of the executed instance, or None if no
/// instance could execute (i.e. empty input queue).
pub trait ExecutionStrategy: fmt::Debug {
    fn execute_next(&self, runner: &dyn ConsensusInstances<'_>) -> Option<Time>;
}

/// A delivery strategy picks the next instance that has output messages,
/// and delivers a message to other instances.
///
/// It returns true if a message is delivered, or false otherwise.
pub trait DeliveryStrategy: fmt::Debug {
    fn deliver_next(&self, runner: &dyn ConsensusInstances<'_>) -> bool;
}

/// An abstraction that returns the set of consensus instances to use with
/// execution/delivery strategies.
pub trait ConsensusInstances<'a> {
    fn instances(&self) -> &[ConsensusInstance<'a>];
    fn logger(&self) -> &ReplicaLogger;
    fn rng(&self) -> RefMut<'_, ChaChaRng>;
    fn time_source(&self) -> &dyn TimeSource;
}

/// Configuration parameters that will be read from command line argument or
/// environment.
pub struct ConsensusRunnerConfig {
    pub max_delta: u64,
    pub random_seed: u64,
    pub num_nodes: usize,
    pub num_rounds: u64,
    pub degree: usize,
    pub execution: Box<dyn ExecutionStrategy>,
    pub delivery: Box<dyn DeliveryStrategy>,
}

impl fmt::Display for ConsensusRunnerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ConsensusRunnerConfig {{ max_delta: {}, random_seed: {}, \
             num_nodes: {}, num_rounds: {}, degree: {}, execution: {}, delivery: {} }}",
            self.max_delta,
            self.random_seed,
            self.num_nodes,
            self.num_rounds,
            self.degree,
            get_name(&self.execution),
            get_name(&self.delivery)
        )
    }
}

/// Return a strategy's name using their derived Debug formatting.
pub(crate) fn get_name<T: fmt::Debug>(value: T) -> String {
    format!("{:?}", value)
        .split_whitespace()
        .collect::<Vec<_>>()
        .remove(0)
        .to_string()
}
