use ic_interfaces::{
    p2p::{
        artifact_manager::JoinGuard,
        consensus::{
            ArtifactMutation, ArtifactWithOpt, ChangeResult, ChangeSetProducer, MutablePool,
            UnvalidatedArtifact, ValidatedPoolReader,
        },
    },
    time_source::TimeSource,
};
use ic_metrics::MetricsRegistry;
use ic_types::artifact::*;
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
    sync::mpsc::{unbounded_channel, Sender, UnboundedSender},
    time::timeout,
};

type ArtifactEventSender<Artifact> = UnboundedSender<UnvalidatedArtifactMutation<Artifact>>;

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

// TODO: remove in favour of the Shutdown struct instead
pub struct ArtifactProcessorJoinGuard {
    handle: Option<JoinHandle<()>>,
    shutdown: Arc<AtomicBool>,
}

impl JoinGuard for ArtifactProcessorJoinGuard {}

/// Periodic duration of `PollEvent` in milliseconds.
const ARTIFACT_MANAGER_TIMER_DURATION_MSEC: u64 = 200;

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

// TODO: make it private, it is used only for tests outside of this crate
pub fn run_artifact_processor<
    Artifact: IdentifiableArtifact,
    Pool: MutablePool<Artifact> + Send + Sync + ValidatedPoolReader<Artifact> + 'static,
>(
    send_advert: Sender<ArtifactMutation<Artifact>>,
    // TODO: to static dispatch here once the ingress code is fixed
    change_set_producer: Arc<
        dyn ChangeSetProducer<Pool, ChangeSet = <Pool as MutablePool<Artifact>>::ChangeSet>
            + Send
            + Sync,
    >,
    time_source: Arc<dyn TimeSource>,
    pool: Arc<RwLock<Pool>>,
    metrics_registry: MetricsRegistry,
    initial_artifacts: Vec<Artifact>,
) -> (Box<dyn JoinGuard>, ArtifactEventSender<Artifact>) {
    // Making this channel bounded can be problematic since we don't have true multiplexing
    // of P2P messages.
    // Possible scenario is - adverts+chunks arrive on the same channel, slow consensus
    // will result on slow consuption of chunks. Slow consumption of chunks will in turn
    // result in slower consumptions of adverts. Ideally adverts are consumed at rate
    // independent of consensus.
    #[allow(clippy::disallowed_methods)]
    let (sender, mut receiver) = unbounded_channel();
    let shutdown = Arc::new(AtomicBool::new(false));

    // Spawn the processor thread
    let shutdown_cl = shutdown.clone();
    let mut metrics = ArtifactProcessorMetrics::new(metrics_registry, Artifact::NAME.to_string());
    let handle = ThreadBuilder::new()
        .name(format!("{}_Processor", Artifact::NAME))
        .spawn(move || {
            for artifact in initial_artifacts {
                let _ = send_advert.blocking_send(ArtifactMutation::Insert(ArtifactWithOpt {
                    artifact,
                    is_latency_sensitive: false,
                }));
            }

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
                    mutations,
                    poll_immediately,
                } = metrics.with_metrics(|| {
                    {
                        let mut pool = pool.write().unwrap();
                        for artifact_event in batched_artifact_events {
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
                    let change_set = change_set_producer.on_state_change(&pool.read().unwrap());
                    pool.write().unwrap().apply_changes(change_set)
                });

                // We must first send the addition to the replication manager because in theory in one batch we can have both an addition and removal of the same artifact.
                for mutation in mutations {
                    let _ = send_advert.blocking_send(mutation);
                }
                last_on_state_change_result = poll_immediately;
            }
        })
        .unwrap();

    (
        Box::new(ArtifactProcessorJoinGuard::new(handle, shutdown_cl.clone())),
        sender,
    )
}

/*

#[cfg(test)]
mod tests {
    use super::*;

    use std::{convert::Infallible, sync::Arc};

    use ic_interfaces::time_source::SysTimeSource;
    use ic_metrics::MetricsRegistry;
    use ic_types::artifact::UnvalidatedArtifactMutation;

    use crate::run_artifact_processor;
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
            ) -> ChangeResult<DummyArtifact> {
                ChangeResult {
                    mutations: vec![],
                    poll_immediately: false,
                }
            }
        }

        let time_source = Arc::new(SysTimeSource::new());
        let (send_tx, mut send_rx) = tokio::sync::mpsc::channel(100);
        run_artifact_processor::<DummyArtifact>(
            time_source,
            MetricsRegistry::default(),
            Box::new(DummyProcessor),
            send_tx,
            (0..10).map(Into::into).collect(),
        );

        for i in 0..10 {
            match send_rx.blocking_recv().unwrap() {
                ArtifactMutation::Insert(a) => {
                    assert_eq!(a.artifact.0, i);
                }
                _ => panic!("initial events are not purge"),
            }
        }
    }
}

*/