use super::delivery::*;
use super::execution::*;
use super::types::*;
use ic_config::artifact_pool::ArtifactPoolConfig;
use ic_consensus::consensus::dkg_key_manager::DkgKeyManager;
use ic_consensus::{
    certification::{CertificationCrypto, CertifierImpl},
    dkg, idkg,
};
use ic_consensus_utils::crypto::ConsensusCrypto;
use ic_consensus_utils::membership::Membership;
use ic_consensus_utils::pool_reader::PoolReader;
use ic_interfaces::time_source::TimeSource;
use ic_logger::{info, warn, ReplicaLogger};
use ic_test_utilities_time::FastForwardTimeSource;
use ic_types::malicious_flags::MaliciousFlags;
use ic_types::Height;
use ic_types::Time;
use rand::{thread_rng, Rng, RngCore};
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use slog::Drain;
use std::cell::{RefCell, RefMut};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::watch;

fn stop_immediately(_: &ConsensusInstance<'_>) -> bool {
    true
}

/// NetworkStatus indicates whether the network of consensus instances
/// have all stalled, or stopped, or should continue running.
enum NetworkStatus {
    Stalled,
    Stopped,
    Continued,
}

// Maximum lapsed time in milliseconds (in virtual clock) allowed when
// we observe no messages are being exchanged in the network. This is
// used to detect stalling.
const MAX_IDLE_TIME: u64 = 50000;

pub struct ConsensusRunner<'a> {
    idle_since: RefCell<Instant>,
    pub time: Arc<FastForwardTimeSource>,
    pub instances: Vec<ConsensusInstance<'a>>,
    pub(crate) stop_predicate: StopPredicate,
    pub(crate) logger: ReplicaLogger,
    pub(crate) rng: RefCell<ChaChaRng>,
    pub(crate) config: ConsensusRunnerConfig,
}

impl<'a> ConsensusInstances<'a> for ConsensusRunner<'a> {
    fn instances(&self) -> &[ConsensusInstance<'a>] {
        &self.instances
    }
    fn logger(&self) -> &ReplicaLogger {
        &self.logger
    }
    fn rng(&self) -> RefMut<'_, ChaChaRng> {
        self.rng.borrow_mut()
    }
    fn time_source(&self) -> &dyn TimeSource {
        self.time.as_ref()
    }
}

const SLOG_ASYNC_CHAN_SIZE: usize = 10000;

#[allow(dead_code)]
impl<'a> ConsensusRunner<'a> {
    pub fn new_with_config(
        config: ConsensusRunnerConfig,
        time_source: Arc<FastForwardTimeSource>,
    ) -> ConsensusRunner<'a> {
        let plain = slog_term::PlainSyncDecorator::new(std::io::stdout());
        let time_source_clone = time_source.clone();
        let timestamp_fn = move |w: &mut dyn std::io::Write| {
            write!(
                w,
                "{:016}",
                time_source_clone
                    .get_relative_time()
                    .as_nanos_since_unix_epoch()
            )
        };
        let drain = slog_term::FullFormat::new(plain)
            .use_custom_timestamp(timestamp_fn)
            .build()
            .fuse();
        let drain = slog_async::AsyncCore::custom(slog_envlogger::new(drain))
            .chan_size(SLOG_ASYNC_CHAN_SIZE)
            .build()
            .fuse();
        Self::new(
            config,
            time_source,
            slog::Logger::root(drain, slog::o!()).into(),
        )
    }

    /// Create a consensus runner with the given delivery strategy.
    pub fn new(
        config: ConsensusRunnerConfig,
        time_source: Arc<FastForwardTimeSource>,
        logger: ReplicaLogger,
    ) -> ConsensusRunner<'a> {
        let now = time_source.get_instant();
        let rng = RefCell::new(ChaChaRng::seed_from_u64(config.random_seed));
        ConsensusRunner {
            idle_since: RefCell::new(now),
            instances: Vec::new(),
            stop_predicate: Box::new(stop_immediately),
            time: time_source,
            logger,
            config,
            rng,
        }
    }

    /// Add a new consensus instance using the given NodeId, default
    /// configuration, NodeId and ConsensusDependencies.
    ///
    /// The NodeId and ConsensusDependencies should be different for each
    /// instance.
    pub fn add_instance(
        &mut self,
        membership: Arc<Membership>,
        consensus_crypto: Arc<dyn ConsensusCrypto>,
        certification_crypto: Arc<dyn CertificationCrypto>,
        modifier: Option<ComponentModifier>,
        deps: &'a ConsensusDependencies,
        pool_config: ArtifactPoolConfig,
        pool_reader: &PoolReader<'_>,
    ) {
        let node_id = deps.replica_config.node_id;

        let mut context = self.logger.get_context();
        context.node_id = format!("{}", node_id.get());

        let replica_logger = self.logger.with_new_context(context);

        let dkg_key_manager = Arc::new(Mutex::new(DkgKeyManager::new(
            deps.metrics_registry.clone(),
            consensus_crypto.clone(),
            replica_logger.clone(),
            pool_reader,
        )));
        let malicious_flags = MaliciousFlags::default();
        let consensus = ic_consensus::consensus::ConsensusImpl::new(
            deps.replica_config.clone(),
            Arc::clone(&deps.registry_client),
            membership.clone(),
            consensus_crypto.clone(),
            deps.ingress_selector.clone(),
            deps.xnet_payload_builder.clone(),
            deps.self_validating_payload_builder.clone(),
            deps.canister_http_payload_builder.clone(),
            deps.query_stats_payload_builder.clone(),
            deps.dkg_pool.clone(),
            deps.idkg_pool.clone(),
            dkg_key_manager.clone(),
            deps.message_routing.clone(),
            deps.state_manager.clone(),
            Arc::clone(&self.time) as Arc<_>,
            0,
            malicious_flags.clone(),
            deps.metrics_registry.clone(),
            replica_logger.clone(),
        );
        let consensus_bouncer =
            ic_consensus::consensus::ConsensusBouncer::new(deps.message_routing.clone());
        let dkg = dkg::DkgImpl::new(
            deps.replica_config.node_id,
            Arc::clone(&consensus_crypto),
            deps.consensus_pool.read().unwrap().get_cache(),
            dkg_key_manager,
            deps.metrics_registry.clone(),
            replica_logger.clone(),
        );
        let idkg = idkg::IDkgImpl::new(
            deps.replica_config.node_id,
            deps.consensus_pool.read().unwrap().get_block_cache(),
            consensus_crypto,
            deps.state_manager.clone(),
            deps.metrics_registry.clone(),
            replica_logger.clone(),
            malicious_flags,
        );
        let certifier = CertifierImpl::new(
            deps.replica_config.clone(),
            Arc::clone(&deps.registry_client),
            certification_crypto,
            deps.state_manager.clone(),
            deps.consensus_pool.read().unwrap().get_cache(),
            deps.metrics_registry.clone(),
            replica_logger.clone(),
            watch::channel(Height::from(0)).0,
        );
        let now = self.time.get_relative_time();
        let in_queue: Queue<Input> = Default::default();
        // Initial in_queue needs something to kickstart
        in_queue.borrow_mut().push(Input::TimerExpired(now));
        self.instances.push(ConsensusInstance {
            node_id,
            deps,
            in_queue,
            buffered: Default::default(),
            out_queue: Default::default(),

            driver: ConsensusDriver::new(
                node_id,
                pool_config,
                apply_modifier_consensus(&modifier, consensus),
                consensus_bouncer,
                dkg,
                apply_modifier_idkg(&modifier, idkg),
                Box::new(certifier),
                deps.consensus_pool.clone(),
                deps.dkg_pool.clone(),
                deps.idkg_pool.clone(),
                replica_logger,
                deps.metrics_registry.clone(),
            ),
            clock: RefCell::new(now),
            index: self.instances.len(),
        });
    }

    /// Run until the given StopPredicate becomes true for all instances.
    /// Return true if it runs to completion according to StopPredicate.
    /// Otherwise return false, which indicates the network has stalled.
    pub fn run_until(&mut self, pred: StopPredicate) -> bool {
        info!(self.logger, "{}", &self.config);
        self.stop_predicate = pred;
        loop {
            match self.process() {
                NetworkStatus::Continued => continue,
                NetworkStatus::Stopped => return true,
                NetworkStatus::Stalled => {
                    warn!(self.logger, "Stalled");
                    self.instances
                        .iter()
                        .for_each(|instance| warn!(self.logger, "{}", instance));
                    return false;
                }
            }
        }
    }

    /// Run a single step of all instances to finish processing their messages.
    /// Return the updated NetworkStatus.
    fn process(&self) -> NetworkStatus {
        let delivered = self.config.delivery.deliver_next(self);
        let mut idle_since = self.idle_since.borrow_mut();

        let new_time = match self.config.execution.execute_next(self) {
            Some(t) => t,
            None => self.time.get_relative_time() + Duration::from_millis(100),
        };

        // Stalled clocks means only monotonic time advances for nodes.
        if self.config.stall_clocks {
            self.time.set_time_monotonic(new_time).ok();
        } else {
            self.time.set_time(new_time).ok();
        }

        let now = self.time.get_instant();

        let mut stopped = true;
        for instance in self.instances.iter() {
            // only stop when all instances satisfy StopPredicate
            if !(self.stop_predicate)(instance) {
                stopped = false;
                break;
            }
        }
        if stopped {
            NetworkStatus::Stopped
        } else if delivered {
            *idle_since = now;
            NetworkStatus::Continued
        } else if now > *idle_since + Duration::from_millis(MAX_IDLE_TIME) {
            // if MAX_IDLE_TIME has passed without any message delivered to any node,
            // we consider the network stalled.
            NetworkStatus::Stalled
        } else {
            NetworkStatus::Continued
        }
    }
}

impl Default for ConsensusRunnerConfig {
    fn default() -> Self {
        ConsensusRunnerConfig {
            max_delta: 1000,
            random_seed: 0,
            num_nodes: 10,
            num_rounds: 20,
            degree: 9,
            use_priority_fn: false,
            stall_clocks: false,
            execution: GlobalMessage::new(false),
            delivery: Sequential::new(),
        }
    }
}

type Strategies = (
    Vec<Box<dyn ExecutionStrategy>>,
    Vec<Box<dyn DeliveryStrategy>>,
);

#[allow(dead_code)]
impl ConsensusRunnerConfig {
    /// Parse NUM_NODES and RANDOM_SEED from environment or use the default
    /// value. If RANDOM_SEED=Random, use a system generated random seed.
    /// If NUM_NODES=Random, use a generated number between 1 and 20.
    pub fn new_from_env(default_nodes: usize, default_seed: u64) -> Result<Self, String> {
        let mut num_nodes = default_nodes;
        let mut random_seed = default_seed;
        for (key, value) in std::env::vars() {
            if key.eq_ignore_ascii_case("random_seed") {
                if value.eq_ignore_ascii_case("random") {
                    random_seed = thread_rng().next_u64();
                } else {
                    random_seed = value
                        .parse()
                        .map_err(|_| "RANDOM_SEED must be an unsigned integer or Random")?;
                }
            }
        }
        let mut rng = ChaChaRng::seed_from_u64(random_seed);
        for (key, value) in std::env::vars() {
            if key.eq_ignore_ascii_case("num_nodes") {
                if value.eq_ignore_ascii_case("random") {
                    num_nodes = rng.gen_range(1..7) * 3 + 1;
                } else {
                    num_nodes = value
                        .parse()
                        .map_err(|_| "NUM_NODES must be an unsigned integer")?;
                }
            }
        }
        Ok(Self::new(num_nodes, random_seed))
    }

    /// Create a new config using the given num_nodes and random_seed.
    pub fn new(num_nodes: usize, random_seed: u64) -> Self {
        let mut rng = ChaChaRng::seed_from_u64(random_seed);
        let mut config = Self::default();
        config.num_nodes = num_nodes;
        config.random_seed = random_seed;
        config.num_rounds = rng.gen_range(10..101);
        config.degree = rng
            .gen_range(std::cmp::min(5, config.num_nodes / 2)..std::cmp::min(config.num_nodes, 20));
        config.use_priority_fn = rng.gen_bool(0.5);
        config.reset_strategies();
        config
    }

    /// Reset strategies according to config parameters.
    fn reset_strategies(&mut self) {
        let mut rng = ChaChaRng::seed_from_u64(self.random_seed);
        let (mut executions, mut deliveries) = self.strategies(&mut rng);
        self.execution = executions.remove(rng.gen_range(0..executions.len()));
        self.delivery = deliveries.remove(rng.gen_range(0..deliveries.len()));
    }

    fn strategies<R: Rng>(&self, rng: &mut R) -> Strategies {
        (
            vec![
                GlobalMessage::new(self.use_priority_fn),
                GlobalClock::new(self.use_priority_fn),
                RandomExecute::new(self.use_priority_fn),
            ],
            vec![
                Sequential::new(),
                RandomReceive::new(self.max_delta),
                RandomGraph::new(self.num_nodes, self.degree, self.max_delta, rng),
            ],
        )
    }

    /// Parse and update configuration from environment: NUM_NODES,
    /// NUM_ROUNDS, MAX_DELTA, DEGREE, USE_PRIORITY_FN, STALL_CLOCKS, EXECUTION and DELIVERY
    /// (except RANDOM_SEED, which should be used when first creating the config).
    /// Return the updated config if parsing is successful, or an error message
    /// in string otherwise.
    pub fn parse_extra_config(mut self) -> Result<Self, String> {
        // Parse environment max_delta, num_rounds, and degree.
        for (key, value) in std::env::vars() {
            match key.to_ascii_lowercase().as_str() {
                "max_delta" => {
                    self.max_delta = value
                        .parse()
                        .map_err(|_| "MAX_DELTA must be an unsigned integer (in milliseconds)")?;
                }
                "num_rounds" => {
                    self.num_rounds = value
                        .parse()
                        .map_err(|_| "NUM_ROUNDS must be an unsigned integer")?
                }
                "degree" => {
                    self.degree = value
                        .parse()
                        .map_err(|_| "DEGREE must be an unsigned integer")?
                }
                "use_priority_fn" => {
                    self.use_priority_fn = value
                        .parse()
                        .map_err(|_| "USE_PRIORITY_FN must be either true or false")?
                }
                "stall_clocks" => {
                    self.stall_clocks = value
                        .parse()
                        .map_err(|_| "STALL_CLOCKS must be either true or false")?
                }
                _ => (),
            }
        }

        // Parse strategies
        self.reset_strategies();
        let mut rng = ChaChaRng::seed_from_u64(self.random_seed);
        let (mut executions, mut deliveries) = self.strategies(&mut rng);
        let execution_names: Vec<_> = executions.iter().map(get_name).collect();
        let delivery_names: Vec<_> = deliveries.iter().map(get_name).collect();

        let parse_name = |var: &str, value: String, names: &Vec<String>| {
            names
                .iter()
                .position(|name| value.eq_ignore_ascii_case(name))
                .ok_or(var.to_string() + " must be one of Random, " + &names.join(", "))
        };

        for (key, value) in std::env::vars() {
            match key.to_ascii_lowercase().as_str() {
                "execution" => {
                    let index = parse_name("EXECUTION", value, &execution_names)?;
                    self.execution = executions.remove(index);
                }

                "delivery" => {
                    let index = parse_name("DELIVERY", value, &delivery_names)?;
                    self.delivery = deliveries.remove(index);
                }
                _ => (),
            }
        }
        Ok(self)
    }
}
