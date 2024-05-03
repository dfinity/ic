use ic_interfaces::{
    p2p::{
        artifact_manager::{ArtifactProcessorEvent, JoinGuard},
        consensus::{
            ChangeResult, ChangeSetProducer, MutablePool, UnvalidatedArtifact, ValidatedPoolReader,
        },
    },
    time_source::TimeSource,
};
use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use ic_types::{artifact::*, artifact_kind::*};
use prometheus::{histogram_opts, labels, Histogram};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering::SeqCst},
        Arc, RwLock,
    },
    thread::{Builder as ThreadBuilder, JoinHandle},
    time::Duration,
};
use tokio::{
    sync::mpsc::{unbounded_channel, Sender, UnboundedReceiver, UnboundedSender},
    time::timeout,
};

type ArtifactEventSender<Artifact> = UnboundedSender<UnvalidatedArtifactMutation<Artifact>>;

/// Metrics for a client artifact processor.
struct ArtifactProcessorMetrics {
    /// The processing time histogram.
    processing_time: Histogram,
    /// The processing interval histogram.
    processing_interval: Histogram,
    outbound_artifact_bytes: Histogram,
    /// The last update time.
    last_update: std::time::Instant,
}

impl ArtifactProcessorMetrics {
    /// The constructor creates a `ArtifactProcessorMetrics` instance.
    fn new(metrics_registry: MetricsRegistry, client: String) -> Self {
        let const_labels = labels! {"client".to_string() => client.to_string()};
        let processing_time = metrics_registry.register(
            Histogram::with_opts(histogram_opts!(
                "artifact_manager_client_processing_time_seconds",
                "Artifact manager client processing time, in seconds",
                vec![
                    0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.8, 1.0, 1.2, 1.5, 2.0, 2.2, 2.5, 5.0, 8.0,
                    10.0, 15.0, 20.0, 50.0,
                ],
                const_labels.clone()
            ))
            .unwrap(),
        );
        let processing_interval = metrics_registry.register(
            Histogram::with_opts(histogram_opts!(
                "artifact_manager_client_processing_interval_seconds",
                "Duration between Artifact manager client processing, in seconds",
                vec![
                    0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.8, 1.0, 1.2, 1.5, 2.0, 2.2, 2.5, 5.0, 8.0,
                    10.0, 15.0, 20.0, 50.0,
                ],
                const_labels.clone()
            ))
            .unwrap(),
        );

        let outbound_artifact_bytes = metrics_registry.register(
            Histogram::with_opts(histogram_opts!(
                "artifact_manager_outbound_artifact_bytes",
                "Distribution of bytes from artifacts that should be delivered to all peers.",
                decimal_buckets(0, 6),
                const_labels.clone()
            ))
            .unwrap(),
        );

        Self {
            processing_time,
            processing_interval,
            outbound_artifact_bytes,
            last_update: std::time::Instant::now(),
        }
    }

    fn with_metrics<T, F: FnOnce() -> T>(&mut self, run: F) -> T {
        self.processing_interval
            .observe((std::time::Instant::now() - self.last_update).as_secs_f64());
        let _timer = self.processing_time.start_timer();
        let result = run();
        self.last_update = std::time::Instant::now();
        result
    }
}

/// An abstraction of processing changes for each artifact client.
pub trait ArtifactProcessor<Artifact: ArtifactKind>: Send {
    /// Process changes to the client's state, which includes but not
    /// limited to:
    ///   - newly arrived artifacts (passed as input parameters)
    ///   - changes in dependencies
    ///   - changes in time
    ///
    /// As part of the processing, it may also modify its own state
    /// including both unvalidated and validated pools. The return
    /// result includes a list of adverts for P2P to disseminate to
    /// peers, deleted artifact,  as well as a result flag indicating
    /// if there are more changes to be processed so that the caller
    /// can decide whether this function should be called again
    /// immediately, or after certain period of time.
    fn process_changes(
        &self,
        time_source: &dyn TimeSource,
        new_artifact_events: Vec<UnvalidatedArtifactMutation<Artifact>>,
    ) -> ChangeResult<Artifact>;
}

/// Manages the life cycle of the client specific artifact processor thread.
pub struct ArtifactProcessorJoinGuard {
    handle: Option<JoinHandle<()>>,
    shutdown: Arc<AtomicBool>,
}

impl JoinGuard for ArtifactProcessorJoinGuard {}

impl ArtifactProcessorJoinGuard {
    pub fn new(handle: JoinHandle<()>, shutdown: Arc<AtomicBool>) -> Self {
        Self {
            handle: Some(handle),
            shutdown,
        }
    }
}

impl Drop for ArtifactProcessorJoinGuard {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            self.shutdown.store(true, SeqCst);
            handle.join().unwrap();
        }
    }
}

pub fn run_artifact_processor<Artifact: ArtifactKind + 'static>(
    time_source: Arc<dyn TimeSource>,
    metrics_registry: MetricsRegistry,
    client: Box<dyn ArtifactProcessor<Artifact>>,
    send_advert: Sender<ArtifactProcessorEvent<Artifact>>,
) -> (Box<dyn JoinGuard>, ArtifactEventSender<Artifact>)
where
    <Artifact as ic_types::artifact::ArtifactKind>::Message: Send,
    <Artifact as ic_types::artifact::ArtifactKind>::Id: Send,
{
    // Making this channel bounded can be problematic since we don't have true multiplexing
    // of P2P messages.
    // Possible scenario is - adverts+chunks arrive on the same channel, slow consensus
    // will result on slow consuption of chunks. Slow consumption of chunks will in turn
    // result in slower consumptions of adverts. Ideally adverts are consumed at rate
    // independent of consensus.
    #[allow(clippy::disallowed_methods)]
    let (sender, receiver) = unbounded_channel();
    let shutdown = Arc::new(AtomicBool::new(false));

    // Spawn the processor thread
    let shutdown_cl = shutdown.clone();
    let handle = ThreadBuilder::new()
        .name(format!("{}_Processor", Artifact::TAG))
        .spawn(move || {
            process_messages(
                time_source,
                client,
                send_advert,
                receiver,
                ArtifactProcessorMetrics::new(metrics_registry, Artifact::TAG.to_string()),
                shutdown_cl,
            );
        })
        .unwrap();

    (
        Box::new(ArtifactProcessorJoinGuard::new(handle, shutdown)),
        sender,
    )
}

// The artifact processor thread loop
fn process_messages<Artifact: ArtifactKind + 'static>(
    time_source: Arc<dyn TimeSource>,
    client: Box<dyn ArtifactProcessor<Artifact>>,
    send_advert: Sender<ArtifactProcessorEvent<Artifact>>,
    mut receiver: UnboundedReceiver<UnvalidatedArtifactMutation<Artifact>>,
    mut metrics: ArtifactProcessorMetrics,
    shutdown: Arc<AtomicBool>,
) {
    let current_thread_rt = tokio::runtime::Builder::new_current_thread()
        .thread_name("ArtifactProcessor_Thread".to_string())
        .enable_time()
        .build()
        .unwrap();
    let mut last_on_state_change_result = false;
    while !shutdown.load(SeqCst) {
        // TODO: assess impact of continued processing in same
        // iteration if StateChanged
        let recv_timeout = if last_on_state_change_result {
            Duration::from_millis(0)
        } else {
            Duration::from_millis(ARTIFACT_MANAGER_TIMER_DURATION_MSEC)
        };

        let batched_artifact_events = current_thread_rt.block_on(async {
            match timeout(recv_timeout, receiver.recv()).await {
                Ok(Some(artifact_event)) => {
                    let mut artifacts = vec![artifact_event];
                    while let Ok(artifact) = receiver.try_recv() {
                        artifacts.push(artifact);
                    }
                    Some(artifacts)
                }
                Ok(None) => {
                    // p2p is stopped
                    None
                }
                Err(_) => Some(vec![]),
            }
        });
        let batched_artifact_events = match batched_artifact_events {
            Some(v) => v,
            None => {
                return;
            }
        };
        let ChangeResult {
            artifacts_with_opt,
            purged,
            poll_immediately,
        } = metrics
            .with_metrics(|| client.process_changes(time_source.as_ref(), batched_artifact_events));
        for artifact_with_opt in artifacts_with_opt {
            metrics
                .outbound_artifact_bytes
                .observe(artifact_with_opt.advert.size as f64);
            let _ = send_advert.blocking_send(ArtifactProcessorEvent::Artifact(artifact_with_opt));
        }

        for advert in purged {
            let _ = send_advert.blocking_send(ArtifactProcessorEvent::Purge(advert));
        }
        last_on_state_change_result = poll_immediately;
    }
}

/// Periodic duration of `PollEvent` in milliseconds.
const ARTIFACT_MANAGER_TIMER_DURATION_MSEC: u64 = 200;

pub fn create_ingress_handlers<
    PoolIngress: MutablePool<IngressArtifact> + Send + Sync + ValidatedPoolReader<IngressArtifact> + 'static,
>(
    send_advert: Sender<ArtifactProcessorEvent<IngressArtifact>>,
    time_source: Arc<dyn TimeSource>,
    ingress_pool: Arc<RwLock<PoolIngress>>,
    ingress_handler: Arc<
        dyn ChangeSetProducer<
                PoolIngress,
                ChangeSet = <PoolIngress as MutablePool<IngressArtifact>>::ChangeSet,
            > + Send
            + Sync,
    >,
    metrics_registry: MetricsRegistry,
) -> (
    UnboundedSender<UnvalidatedArtifactMutation<IngressArtifact>>,
    Box<dyn JoinGuard>,
) {
    let client = IngressProcessor::new(ingress_pool.clone(), ingress_handler);
    let (jh, sender) = run_artifact_processor(
        time_source.clone(),
        metrics_registry,
        Box::new(client),
        send_advert,
    );
    (sender, jh)
}

pub fn create_artifact_handler<
    Artifact: ArtifactKind + Send + Sync,
    Pool: MutablePool<Artifact> + Send + Sync + ValidatedPoolReader<Artifact> + 'static,
    C: ChangeSetProducer<Pool, ChangeSet = <Pool as MutablePool<Artifact>>::ChangeSet> + 'static,
>(
    send_advert: Sender<ArtifactProcessorEvent<Artifact>>,
    change_set_producer: C,
    time_source: Arc<dyn TimeSource>,
    pool: Arc<RwLock<Pool>>,
    metrics_registry: MetricsRegistry,
) -> (
    UnboundedSender<UnvalidatedArtifactMutation<Artifact>>,
    Box<dyn JoinGuard>,
) {
    let client = Processor::new(pool.clone(), change_set_producer);
    let (jh, sender) = run_artifact_processor(
        time_source.clone(),
        metrics_registry,
        Box::new(client),
        send_advert,
    );
    (sender, jh)
}

pub struct Processor<A: ArtifactKind + Send, P: MutablePool<A>, C> {
    pool: Arc<RwLock<P>>,
    change_set_producer: C,
    unused: std::marker::PhantomData<A>,
}

impl<
        A: ArtifactKind + Send,
        P: MutablePool<A>,
        C: ChangeSetProducer<P, ChangeSet = <P as MutablePool<A>>::ChangeSet>,
    > Processor<A, P, C>
{
    pub fn new(pool: Arc<RwLock<P>>, change_set_producer: C) -> Self {
        Self {
            pool,
            change_set_producer,
            unused: std::marker::PhantomData,
        }
    }
}

impl<
        A: ArtifactKind + Send,
        P: MutablePool<A> + Send + Sync + 'static,
        C: ChangeSetProducer<P, ChangeSet = <P as MutablePool<A>>::ChangeSet>,
    > ArtifactProcessor<A> for Processor<A, P, C>
{
    fn process_changes(
        &self,
        time_source: &dyn TimeSource,
        artifact_events: Vec<UnvalidatedArtifactMutation<A>>,
    ) -> ChangeResult<A> {
        {
            let mut pool = self.pool.write().unwrap();
            for artifact_event in artifact_events {
                match artifact_event {
                    UnvalidatedArtifactMutation::Insert((message, peer_id)) => {
                        let unvalidated_artifact = UnvalidatedArtifact {
                            message,
                            peer_id,
                            timestamp: time_source.get_relative_time(),
                        };
                        pool.insert(unvalidated_artifact);
                    }
                    UnvalidatedArtifactMutation::Remove(id) => pool.remove(&id),
                }
            }
        }
        let change_set = self
            .change_set_producer
            .on_state_change(&self.pool.read().unwrap());
        self.pool.write().unwrap().apply_changes(change_set)
    }
}

/// The ingress `OnStateChange` client.
pub(crate) struct IngressProcessor<P: MutablePool<IngressArtifact>> {
    /// The ingress pool, protected by a read-write lock and automatic reference
    /// counting.
    ingress_pool: Arc<RwLock<P>>,
    /// The ingress handler.
    client: Arc<
        dyn ChangeSetProducer<P, ChangeSet = <P as MutablePool<IngressArtifact>>::ChangeSet>
            + Send
            + Sync,
    >,
}

impl<P: MutablePool<IngressArtifact>> IngressProcessor<P> {
    pub fn new(
        ingress_pool: Arc<RwLock<P>>,
        client: Arc<
            dyn ChangeSetProducer<P, ChangeSet = <P as MutablePool<IngressArtifact>>::ChangeSet>
                + Send
                + Sync,
        >,
    ) -> Self {
        Self {
            ingress_pool,
            client,
        }
    }
}

impl<P: MutablePool<IngressArtifact> + Send + Sync + 'static> ArtifactProcessor<IngressArtifact>
    for IngressProcessor<P>
{
    /// The method processes changes in the ingress pool.
    fn process_changes(
        &self,
        time_source: &dyn TimeSource,
        artifact_events: Vec<UnvalidatedArtifactMutation<IngressArtifact>>,
    ) -> ChangeResult<IngressArtifact> {
        {
            let mut ingress_pool = self.ingress_pool.write().unwrap();
            for artifact_event in artifact_events {
                match artifact_event {
                    UnvalidatedArtifactMutation::Insert((message, peer_id)) => {
                        let unvalidated_artifact = UnvalidatedArtifact {
                            message,
                            peer_id,
                            timestamp: time_source.get_relative_time(),
                        };
                        ingress_pool.insert(unvalidated_artifact);
                    }
                    UnvalidatedArtifactMutation::Remove(id) => ingress_pool.remove(&id),
                }
            }
        }
        let change_set = self
            .client
            .on_state_change(&self.ingress_pool.read().unwrap());
        self.ingress_pool.write().unwrap().apply_changes(change_set)
    }
}
