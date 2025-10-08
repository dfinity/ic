use ic_consensus_manager::AbortableBroadcastChannel;
use ic_interfaces::{
    p2p::{
        artifact_manager::JoinGuard,
        consensus::{
            ArtifactTransmit, ArtifactTransmits, ArtifactWithOpt, MutablePool,
            PoolMutationsProducer, UnvalidatedArtifact, ValidatedPoolReader,
        },
    },
    time_source::TimeSource,
};
use ic_limits::MAX_P2P_IO_CHANNEL_SIZE;
use ic_metrics::MetricsRegistry;
use ic_types::{artifact::*, messages::SignedIngress};
use prometheus::{Histogram, histogram_opts, labels};
use std::{
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering::SeqCst},
    },
    thread::{Builder as ThreadBuilder, JoinHandle},
    time::Duration,
};
use tokio::{
    sync::mpsc::{Receiver, Sender},
    time::timeout,
};
use tracing::instrument;

/// Metrics for a client artifact processor.
struct ArtifactProcessorMetrics {
    /// The processing time histogram.
    processing_time: Histogram,
    /// The processing interval histogram.
    processing_interval: Histogram,
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

        Self {
            processing_time,
            processing_interval,
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

trait ArtifactProcessor<A: IdentifiableArtifact>: Send {
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
        new_artifact_events: Vec<UnvalidatedArtifactMutation<A>>,
    ) -> ArtifactTransmits<A>;
}

// TODO: remove in favour of the Shutdown struct instead
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

fn run_artifact_processor<Artifact: IdentifiableArtifact>(
    time_source: Arc<dyn TimeSource>,
    metrics_registry: MetricsRegistry,
    client: Box<dyn ArtifactProcessor<Artifact>>,
    outbound_tx: Sender<ArtifactTransmit<Artifact>>,
    inbound_rx: Receiver<UnvalidatedArtifactMutation<Artifact>>,
    initial_artifacts: Vec<Artifact>,
) -> Box<dyn JoinGuard> {
    let shutdown = Arc::new(AtomicBool::new(false));
    // Spawn the processor thread
    let shutdown_cl = shutdown.clone();
    let handle = ThreadBuilder::new()
        .name(format!("{}_Processor", Artifact::NAME))
        .spawn(move || {
            for artifact in initial_artifacts {
                let _ = outbound_tx.blocking_send(ArtifactTransmit::Deliver(ArtifactWithOpt {
                    artifact,
                    is_latency_sensitive: false,
                }));
            }
            process_messages(
                time_source,
                client,
                outbound_tx,
                inbound_rx,
                ArtifactProcessorMetrics::new(metrics_registry, Artifact::NAME.to_string()),
                shutdown_cl,
            );
        })
        .unwrap();
    Box::new(ArtifactProcessorJoinGuard::new(handle, shutdown))
}

async fn read_batch<T>(receiver: &mut Receiver<T>, recv_timeout: Duration) -> Option<Vec<T>> {
    let mut artifacts = vec![];
    match timeout(
        recv_timeout,
        receiver.recv_many(&mut artifacts, MAX_P2P_IO_CHANNEL_SIZE),
    )
    .await
    {
        Ok(1..) => Some(artifacts),
        // Stream has finished because the abortable broadcast/p2p has stopped.
        // This is infallible.
        Ok(0) => None,
        // No values arrived on time
        Err(_) => Some(artifacts),
    }
}

// The artifact processor thread loop
fn process_messages<Artifact: IdentifiableArtifact + 'static>(
    time_source: Arc<dyn TimeSource>,
    client: Box<dyn ArtifactProcessor<Artifact>>,
    send_advert: Sender<ArtifactTransmit<Artifact>>,
    mut receiver: Receiver<UnvalidatedArtifactMutation<Artifact>>,
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

        let batched_artifact_events =
            current_thread_rt.block_on(read_batch(&mut receiver, recv_timeout));
        let Some(batched_artifact_events) = batched_artifact_events else {
            return;
        };
        let ArtifactTransmits {
            transmits,
            poll_immediately,
        } = metrics
            .with_metrics(|| client.process_changes(time_source.as_ref(), batched_artifact_events));

        // We must first send the addition to the replication manager because in theory in one batch we can have both an addition and removal of the same artifact.
        for mutation in transmits {
            let _ = send_advert.blocking_send(mutation);
        }
        last_on_state_change_result = poll_immediately;
    }
}

/// Periodic duration of `PollEvent` in milliseconds.
const ARTIFACT_MANAGER_TIMER_DURATION_MSEC: u64 = 200;

pub fn create_ingress_handlers<
    PoolIngress: MutablePool<SignedIngress> + Send + Sync + ValidatedPoolReader<SignedIngress> + 'static,
>(
    channel: AbortableBroadcastChannel<SignedIngress>,
    time_source: Arc<dyn TimeSource>,
    ingress_pool: Arc<RwLock<PoolIngress>>,
    ingress_handler: Arc<
        dyn PoolMutationsProducer<
                PoolIngress,
                Mutations = <PoolIngress as MutablePool<SignedIngress>>::Mutations,
            > + Send
            + Sync,
    >,
    metrics_registry: MetricsRegistry,
) -> Box<dyn JoinGuard> {
    let client = IngressProcessor::new(ingress_pool.clone(), ingress_handler);
    run_artifact_processor(
        time_source.clone(),
        metrics_registry,
        Box::new(client),
        channel.outbound_tx,
        channel.inbound_rx,
        vec![],
    )
}

/// Starts the event loop that polls consensus for updates on what needs to be replicated.
pub fn create_artifact_handler<
    Artifact: IdentifiableArtifact + Send + Sync + 'static,
    Pool: MutablePool<Artifact> + Send + Sync + ValidatedPoolReader<Artifact> + 'static,
    C: PoolMutationsProducer<Pool, Mutations = <Pool as MutablePool<Artifact>>::Mutations> + 'static,
>(
    channel: AbortableBroadcastChannel<Artifact>,
    change_set_producer: C,
    time_source: Arc<dyn TimeSource>,
    pool: Arc<RwLock<Pool>>,
    metrics_registry: MetricsRegistry,
) -> Box<dyn JoinGuard> {
    let inital_artifacts: Vec<_> = pool.read().unwrap().get_all_for_broadcast().collect();
    let client = Processor::new(pool, change_set_producer);
    run_artifact_processor(
        time_source.clone(),
        metrics_registry,
        Box::new(client),
        channel.outbound_tx,
        channel.inbound_rx,
        inital_artifacts,
    )
}

struct Processor<A: IdentifiableArtifact + Send, P: MutablePool<A>, C> {
    pool: Arc<RwLock<P>>,
    change_set_producer: C,
    unused: std::marker::PhantomData<A>,
}

impl<
    A: IdentifiableArtifact + Send,
    P: MutablePool<A>,
    C: PoolMutationsProducer<P, Mutations = <P as MutablePool<A>>::Mutations>,
> Processor<A, P, C>
{
    fn new(pool: Arc<RwLock<P>>, change_set_producer: C) -> Self {
        Self {
            pool,
            change_set_producer,
            unused: std::marker::PhantomData,
        }
    }
}

impl<
    A: IdentifiableArtifact + Send,
    P: MutablePool<A> + Send + Sync + 'static,
    C: PoolMutationsProducer<P, Mutations = <P as MutablePool<A>>::Mutations>,
> ArtifactProcessor<A> for Processor<A, P, C>
{
    #[instrument(skip_all)]
    fn process_changes(
        &self,
        time_source: &dyn TimeSource,
        artifact_events: Vec<UnvalidatedArtifactMutation<A>>,
    ) -> ArtifactTransmits<A> {
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
        self.pool.write().unwrap().apply(change_set)
    }
}

/// The ingress `OnStateChange` client.
struct IngressProcessor<P: MutablePool<SignedIngress>> {
    /// The ingress pool, protected by a read-write lock and automatic reference
    /// counting.
    ingress_pool: Arc<RwLock<P>>,
    /// The ingress handler.
    client: Arc<
        dyn PoolMutationsProducer<P, Mutations = <P as MutablePool<SignedIngress>>::Mutations>
            + Send
            + Sync,
    >,
}

impl<P: MutablePool<SignedIngress>> IngressProcessor<P> {
    fn new(
        ingress_pool: Arc<RwLock<P>>,
        client: Arc<
            dyn PoolMutationsProducer<P, Mutations = <P as MutablePool<SignedIngress>>::Mutations>
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

impl<P: MutablePool<SignedIngress> + Send + Sync + 'static> ArtifactProcessor<SignedIngress>
    for IngressProcessor<P>
{
    /// The method processes changes in the ingress pool.
    #[instrument(skip_all)]
    fn process_changes(
        &self,
        time_source: &dyn TimeSource,
        artifact_events: Vec<UnvalidatedArtifactMutation<SignedIngress>>,
    ) -> ArtifactTransmits<SignedIngress> {
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
        self.ingress_pool.write().unwrap().apply(change_set)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    use ic_interfaces::time_source::SysTimeSource;
    use ic_metrics::MetricsRegistry;
    use ic_types::artifact::UnvalidatedArtifactMutation;
    use std::{convert::Infallible, sync::Arc};
    use tokio::sync::mpsc::channel;

    use crate::{ArtifactProcessor, run_artifact_processor};

    #[tokio::test]
    async fn test_read_batch_with_closing_channel_after_consuming_all() {
        let (tx, mut rx) = channel(100);
        let recv_timeout = Duration::from_secs(100);
        tx.send(1).await.unwrap();
        assert_eq!(read_batch(&mut rx, recv_timeout).await, Some(vec![1]));
        tx.send(2).await.unwrap();
        tx.send(3).await.unwrap();
        assert_eq!(read_batch(&mut rx, recv_timeout).await, Some(vec![2, 3]));
        std::mem::drop(tx);
        assert_eq!(read_batch(&mut rx, recv_timeout).await, None);
    }

    #[tokio::test]
    async fn test_read_batch_with_closing_channel_before_consuming_all() {
        let (tx, mut rx) = channel(100);
        let recv_timeout = Duration::from_secs(100);
        tx.send(1).await.unwrap();
        tx.send(2).await.unwrap();
        std::mem::drop(tx);
        assert_eq!(read_batch(&mut rx, recv_timeout).await, Some(vec![1, 2]));
    }

    #[tokio::test]
    async fn test_read_batch_with_empty_channel_returns_empty_vec() {
        let (_tx, mut rx) = channel::<i32>(100);
        let recv_timeout = Duration::from_secs(1);
        assert_eq!(read_batch(&mut rx, recv_timeout).await, Some(vec![]));
    }

    #[test]
    fn send_initial_artifacts() {
        #[derive(Eq, PartialEq, Debug)]
        struct DummyArtifact(u64);

        impl From<u64> for DummyArtifact {
            fn from(value: u64) -> Self {
                Self(value)
            }
        }

        impl From<DummyArtifact> for u64 {
            fn from(value: DummyArtifact) -> Self {
                value.0
            }
        }

        impl IdentifiableArtifact for DummyArtifact {
            const NAME: &'static str = "dummy";
            type Id = ();
            fn id(&self) -> Self::Id {}
        }

        impl PbArtifact for DummyArtifact {
            type PbId = ();
            type PbIdError = Infallible;
            type PbMessage = u64;
            type PbMessageError = Infallible;
        }

        struct DummyProcessor;
        impl ArtifactProcessor<DummyArtifact> for DummyProcessor {
            fn process_changes(
                &self,
                _: &dyn TimeSource,
                _: Vec<UnvalidatedArtifactMutation<DummyArtifact>>,
            ) -> ArtifactTransmits<DummyArtifact> {
                ArtifactTransmits {
                    transmits: vec![],
                    poll_immediately: false,
                }
            }
        }

        let time_source = Arc::new(SysTimeSource::new());
        let (send_tx, mut send_rx) = tokio::sync::mpsc::channel(100);
        let (_, inbound_rx) = tokio::sync::mpsc::channel(100);
        run_artifact_processor::<DummyArtifact>(
            time_source,
            MetricsRegistry::default(),
            Box::new(DummyProcessor),
            send_tx,
            inbound_rx,
            (0..10).map(Into::into).collect(),
        );

        for i in 0..10 {
            match send_rx.blocking_recv().unwrap() {
                ArtifactTransmit::Deliver(a) => {
                    assert_eq!(a.artifact.0, i);
                }
                _ => panic!("initial events are not purge"),
            }
        }
    }
}
