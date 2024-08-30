#![allow(dead_code)]
use ic_artifact_pool::{
    canister_http_pool, certification_pool::CertificationPoolImpl,
    consensus_pool::ConsensusPoolImpl, dkg_pool, idkg_pool,
};
use ic_config::artifact_pool::ArtifactPoolConfig;
use ic_consensus::{
    consensus::{ConsensusGossipImpl, ConsensusImpl},
    dkg, idkg,
};
use ic_https_outcalls_consensus::test_utils::FakeCanisterHttpPayloadBuilder;
use ic_interfaces::{
    batch_payload::BatchPayloadBuilder,
    certification::ChangeSet,
    consensus_pool::ChangeSet as ConsensusChangeSet,
    idkg::IDkgChangeSet,
    ingress_manager::IngressSelector,
    messaging::XNetPayloadBuilder,
    p2p::consensus::{Bouncer, BouncerFactory, BouncerValue, ChangeSetProducer},
    self_validating_payload::SelfValidatingPayloadBuilder,
    time_source::TimeSource,
};
use ic_interfaces_certified_stream_store::CertifiedStreamStore;
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::StateManager;
use ic_logger::{replica_logger::no_op_logger, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_replicated_state::ReplicatedState;
use ic_test_utilities::{
    ingress_selector::FakeIngressSelector, message_routing::FakeMessageRouting,
    self_validating_payload_builder::FakeSelfValidatingPayloadBuilder,
    state_manager::FakeStateManager, xnet_payload_builder::FakeXNetPayloadBuilder,
};
use ic_test_utilities_artifact_pool::ingress_pool::TestIngressPool;
use ic_test_utilities_consensus::{batch::MockBatchPayloadBuilder, IDkgStatsNoOp};
use ic_types::{
    artifact::IdentifiableArtifact,
    consensus::{
        certification::CertificationMessage, dkg::Message as DkgMessage, idkg::IDkgMessage,
        CatchUpPackage, ConsensusMessage,
    },
    replica_config::ReplicaConfig,
    time::{Time, UNIX_EPOCH},
    NodeId, SubnetId,
};
use rand_chacha::ChaChaRng;
use std::cell::{RefCell, RefMut};
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::fmt;
use std::rc::Rc;
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// We use priority queues for input/output messages.
pub type Queue<T> = Rc<RefCell<BinaryHeap<T>>>;

/// Default time step is 1 millisecond.
pub const UNIT_TIME_STEP: u64 = 1;

/// Polling interval is 100 millisecond.
pub const POLLING_INTERVAL: u64 = 100;

/// BouncerValue function refresh interval, default is 3s.
pub const PRIORITY_FN_REFRESH_INTERVAL: Duration = Duration::from_secs(3);

/// Messages from a consensus instance are either artifacts to be
/// delivered to peers, or to a timer expired event that should trigger
/// consensus on_state_change.
#[derive(Clone, Debug)]
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
        Some(self.cmp(other))
    }
}

impl PartialEq for Input {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Input {}

/// The output of a consensus instance is just the Message type.
pub type Output = Message;

#[derive(Clone, Debug)]
pub enum InputMessage {
    Consensus(ConsensusMessage),
    Dkg(Box<DkgMessage>),
    Certification(CertificationMessage),
    IDkg(IDkgMessage),
}

/// A Message is a tuple of [`InputMessage`] with a timestamp.
#[derive(Clone, Debug)]
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
        Some(self.cmp(other))
    }
}

impl PartialEq for Message {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Message {}

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
    pub(crate) self_validating_payload_builder: Arc<dyn SelfValidatingPayloadBuilder>,
    pub(crate) canister_http_payload_builder: Arc<dyn BatchPayloadBuilder>,
    pub(crate) query_stats_payload_builder: Arc<dyn BatchPayloadBuilder>,
    pub consensus_pool: Arc<RwLock<ConsensusPoolImpl>>,
    pub dkg_pool: Arc<RwLock<dkg_pool::DkgPoolImpl>>,
    pub idkg_pool: Arc<RwLock<idkg_pool::IDkgPoolImpl>>,
    pub canister_http_pool: Arc<RwLock<canister_http_pool::CanisterHttpPoolImpl>>,
    pub message_routing: Arc<FakeMessageRouting>,
    pub state_manager: Arc<FakeStateManager>,
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
        time_source: Arc<dyn TimeSource>,
    ) -> ConsensusDependencies {
        let state_manager = FakeStateManager::new();
        let state_manager = Arc::new(state_manager);
        // let state_manager_arc = Rc::new(state_manager);
        let metrics_registry = MetricsRegistry::new();

        let consensus_pool = Arc::new(RwLock::new(ConsensusPoolImpl::new(
            replica_config.node_id,
            replica_config.subnet_id,
            (&cup).into(),
            pool_config.clone(),
            metrics_registry.clone(),
            no_op_logger(),
            time_source,
        )));
        let dkg_pool = dkg_pool::DkgPoolImpl::new(metrics_registry.clone(), no_op_logger());
        let idkg_pool = idkg_pool::IDkgPoolImpl::new(
            pool_config,
            no_op_logger(),
            metrics_registry.clone(),
            Box::new(IDkgStatsNoOp {}),
        );
        let canister_http_pool =
            canister_http_pool::CanisterHttpPoolImpl::new(metrics_registry.clone(), no_op_logger());
        let xnet_payload_builder = FakeXNetPayloadBuilder::new();

        ConsensusDependencies {
            registry_client: Arc::clone(&registry_client),
            consensus_pool,
            dkg_pool: Arc::new(RwLock::new(dkg_pool)),
            idkg_pool: Arc::new(RwLock::new(idkg_pool)),
            canister_http_pool: Arc::new(RwLock::new(canister_http_pool)),
            message_routing: Arc::new(FakeMessageRouting::with_state_manager(
                state_manager.clone(),
            )),
            ingress_selector: Arc::new(FakeIngressSelector::new()),
            xnet_payload_builder: Arc::new(xnet_payload_builder),
            self_validating_payload_builder: Arc::new(FakeSelfValidatingPayloadBuilder::new()),
            canister_http_payload_builder: Arc::new(FakeCanisterHttpPayloadBuilder::new()),
            query_stats_payload_builder: Arc::new(MockBatchPayloadBuilder::new().expect_noop()),
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
    // Input messages that should be re-tried when bouncer function changes
    pub(crate) buffered: RefCell<Vec<InputMessage>>,
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
pub type StopPredicate = Box<dyn Fn(&ConsensusInstance<'_>) -> bool>;

pub(crate) struct BouncerState<Artifact: IdentifiableArtifact> {
    bouncer: Bouncer<Artifact::Id>,
    pub last_updated: Time,
}

impl<Artifact: IdentifiableArtifact> BouncerState<Artifact> {
    pub fn new<Pool, Producer: BouncerFactory<Artifact, Pool>>(
        producer: &Producer,
        pool: &Pool,
    ) -> RefCell<Self> {
        RefCell::new(BouncerState {
            bouncer: producer.new_bouncer(pool),
            last_updated: UNIX_EPOCH,
        })
    }
    /// Return the priority of the given message
    pub fn get_priority(&self, msg: &Artifact) -> BouncerValue {
        (self.bouncer)(&msg.id())
    }

    /// Compute a new bouncer function
    pub fn refresh<Pool, Producer: BouncerFactory<Artifact, Pool>>(
        &mut self,
        producer: &Producer,
        pool: &Pool,
        now: Time,
    ) {
        self.bouncer = producer.new_bouncer(pool);
        self.last_updated = now;
    }
}

/// Modifier that can potentially change a component's behavior.
pub struct ComponentModifier {
    pub(crate) consensus: Box<
        dyn Fn(
            ConsensusImpl,
        )
            -> Box<dyn ChangeSetProducer<ConsensusPoolImpl, ChangeSet = ConsensusChangeSet>>,
    >,
    pub(crate) idkg: Box<
        dyn Fn(
            idkg::IDkgImpl,
        )
            -> Box<dyn ChangeSetProducer<idkg_pool::IDkgPoolImpl, ChangeSet = IDkgChangeSet>>,
    >,
}

impl Default for ComponentModifier {
    fn default() -> Self {
        Self {
            consensus: Box::new(|x: ConsensusImpl| Box::new(x)),
            idkg: Box::new(|x: idkg::IDkgImpl| Box::new(x)),
        }
    }
}

pub fn apply_modifier_consensus(
    modifier: &Option<ComponentModifier>,
    consensus: ConsensusImpl,
) -> Box<dyn ChangeSetProducer<ConsensusPoolImpl, ChangeSet = ConsensusChangeSet>> {
    match modifier {
        Some(f) => (f.consensus)(consensus),
        _ => Box::new(consensus),
    }
}

pub fn apply_modifier_idkg(
    modifier: &Option<ComponentModifier>,
    idkg: idkg::IDkgImpl,
) -> Box<dyn ChangeSetProducer<idkg_pool::IDkgPoolImpl, ChangeSet = IDkgChangeSet>> {
    match modifier {
        Some(f) => (f.idkg)(idkg),
        _ => Box::new(idkg),
    }
}

/// A ConsensusDriver mainly consists of the consensus component, and the
/// consensus artifact pool and timer.
pub struct ConsensusDriver<'a> {
    pub(crate) consensus:
        Box<dyn ChangeSetProducer<ConsensusPoolImpl, ChangeSet = ConsensusChangeSet>>,
    pub(crate) consensus_gossip: ConsensusGossipImpl,
    pub(crate) dkg: dkg::DkgImpl,
    pub(crate) idkg: Box<dyn ChangeSetProducer<idkg_pool::IDkgPoolImpl, ChangeSet = IDkgChangeSet>>,
    pub(crate) certifier:
        Box<dyn ChangeSetProducer<CertificationPoolImpl, ChangeSet = ChangeSet> + 'a>,
    pub(crate) logger: ReplicaLogger,
    pub consensus_pool: Arc<RwLock<ConsensusPoolImpl>>,
    pub certification_pool: Arc<RwLock<CertificationPoolImpl>>,
    pub ingress_pool: RefCell<TestIngressPool>,
    pub dkg_pool: Arc<RwLock<dkg_pool::DkgPoolImpl>>,
    pub idkg_pool: Arc<RwLock<idkg_pool::IDkgPoolImpl>>,
    pub(crate) consensus_priority: RefCell<BouncerState<ConsensusMessage>>,
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
    pub use_priority_fn: bool,
    pub stall_clocks: bool,
    pub execution: Box<dyn ExecutionStrategy>,
    pub delivery: Box<dyn DeliveryStrategy>,
}

impl fmt::Display for ConsensusRunnerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ConsensusRunnerConfig {{ max_delta: {}, random_seed: {}, \
             num_nodes: {}, num_rounds: {}, degree: {}, use_priority_fn: {}, execution: {}, delivery: {} }}",
            self.max_delta,
            self.random_seed,
            self.num_nodes,
            self.num_rounds,
            self.degree,
            self.use_priority_fn,
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
