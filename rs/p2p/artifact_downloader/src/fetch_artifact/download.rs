use std::{
    sync::{Arc, RwLock},
    time::Duration,
};

use axum::{
    extract::{DefaultBodyLimit, State},
    http::{Request, StatusCode},
    routing::any,
    Router,
};
use backoff::{backoff::Backoff, ExponentialBackoffBuilder};
use bytes::Bytes;
use ic_base_types::NodeId;
use ic_interfaces::p2p::consensus::{
    Aborted, ArtifactAssembler, Peers, Priority, PriorityFn, PriorityFnFactory, ValidatedPoolReader,
};
use ic_logger::{warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_protobuf::proxy::ProtoProxy;
use ic_quic_transport::Transport;
use ic_types::artifact::{IdentifiableArtifact, PbArtifact};
use rand::{rngs::SmallRng, seq::IteratorRandom, SeedableRng};
use tokio::{
    runtime::Handle,
    sync::watch,
    task::JoinHandle,
    time::{sleep_until, timeout_at, Instant},
};
use tracing::instrument;

use super::metrics::FetchArtifactMetrics;

const MIN_ARTIFACT_RPC_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ARTIFACT_RPC_TIMEOUT: Duration = Duration::from_secs(120);
const PRIORITY_FUNCTION_UPDATE_INTERVAL: Duration = Duration::from_secs(3);

type ValidatedPoolReaderRef<T> = Arc<RwLock<dyn ValidatedPoolReader<T> + Send + Sync>>;

pub(crate) fn uri_prefix<Artifact: PbArtifact>() -> String {
    Artifact::NAME.to_lowercase()
}

#[allow(unused)]
fn build_axum_router<Artifact: PbArtifact>(pool: ValidatedPoolReaderRef<Artifact>) -> Router {
    Router::new()
        .route(
            &format!("/{}/rpc", uri_prefix::<Artifact>()),
            any(rpc_handler),
        )
        .with_state(pool)
        // Disable request size limit since consensus might push artifacts larger than limit.
        .layer(DefaultBodyLimit::disable())
}

async fn rpc_handler<Artifact: PbArtifact>(
    State(pool): State<ValidatedPoolReaderRef<Artifact>>,
    payload: Bytes,
) -> Result<Bytes, StatusCode> {
    let jh = tokio::task::spawn_blocking(move || {
        let id: Artifact::Id =
            Artifact::PbId::proxy_decode(&payload).map_err(|_| StatusCode::BAD_REQUEST)?;
        let artifact = pool
            .read()
            .unwrap()
            .get(&id)
            .ok_or(StatusCode::NO_CONTENT)?;
        Ok::<_, StatusCode>(Bytes::from(Artifact::PbMessage::proxy_encode(artifact)))
    });
    let bytes = jh.await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)??;

    Ok(bytes)
}

pub struct FetchArtifact<Artifact: PbArtifact> {
    log: ReplicaLogger,
    transport: Arc<dyn Transport>,
    priority_fn: watch::Receiver<PriorityFn<Artifact::Id>>,
    metrics: FetchArtifactMetrics,
    jh: Arc<JoinHandle<()>>,
}

impl<Artifact: PbArtifact> Clone for FetchArtifact<Artifact> {
    fn clone(&self) -> Self {
        Self {
            log: self.log.clone(),
            transport: self.transport.clone(),
            priority_fn: self.priority_fn.clone(),
            metrics: self.metrics.clone(),
            jh: self.jh.clone(),
        }
    }
}

impl<Artifact: PbArtifact> ArtifactAssembler<Artifact, Artifact> for FetchArtifact<Artifact> {
    fn disassemble_message(&self, msg: Artifact) -> Artifact {
        msg
    }
    async fn assemble_message<P: Peers + Send + 'static>(
        &self,
        id: <Artifact as IdentifiableArtifact>::Id,
        artifact: Option<(Artifact, NodeId)>,
        peers: P,
    ) -> Result<(Artifact, NodeId), Aborted> {
        Self::download_artifact(
            self.log.clone(),
            id,
            artifact,
            peers,
            self.priority_fn.clone(),
            self.transport.clone(),
            self.metrics.clone(),
        )
        .await
    }
}

impl<Artifact: PbArtifact> FetchArtifact<Artifact> {
    pub fn new<Pool>(
        log: ReplicaLogger,
        rt: Handle,
        pool: Arc<RwLock<Pool>>,
        pfn_producer: Arc<dyn PriorityFnFactory<Artifact, Pool>>,
        metrics_registry: MetricsRegistry,
    ) -> (impl Fn(Arc<dyn Transport>) -> Self, Router)
    where
        Pool: ValidatedPoolReader<Artifact> + Send + Sync + 'static,
    {
        let pool_clone = pool.clone();
        (
            move |transport: Arc<dyn Transport>| {
                let pfn = {
                    let p = pool.read().unwrap();
                    pfn_producer.get_priority_function(&p)
                };
                let (pfn_tx, pfn_rx) = watch::channel(pfn);
                let pool_clone = pool.clone();
                let pfn_producer_clone = pfn_producer.clone();
                let log_clone = log.clone();
                let jh = rt.spawn(async move {
                    loop {
                        let pfn = {
                            let p = pool_clone.read().unwrap();
                            pfn_producer_clone.get_priority_function(&p)
                        };
                        if pfn_tx.send(pfn).is_err() {
                            break;
                        }

                        tokio::time::sleep(PRIORITY_FUNCTION_UPDATE_INTERVAL).await
                    }
                });
                Self {
                    log: log_clone,
                    transport,
                    priority_fn: pfn_rx,
                    metrics: FetchArtifactMetrics::new::<Artifact>(&metrics_registry),
                    jh: Arc::new(jh),
                }
            },
            build_axum_router(pool_clone),
        )
    }
    /// Waits until advert resolves to fetch. If all peers are removed or priority becomes drop `Aborted` is returned.
    #[instrument(skip_all)]
    async fn wait_fetch(
        id: &Artifact::Id,
        artifact: &mut Option<(Artifact, NodeId)>,
        metrics: &FetchArtifactMetrics,
        priority_fn_watcher: &mut watch::Receiver<PriorityFn<Artifact::Id>>,
    ) -> Result<(), Aborted> {
        let mut priority = priority_fn_watcher.borrow_and_update()(id);

        // Clear the artifact from memory if it was pushed.
        if let Priority::Stash = priority {
            artifact.take();
            metrics.download_task_stashed_total.inc();
        }

        while let Priority::Stash = priority {
            let _ = priority_fn_watcher.changed().await;
            priority = priority_fn_watcher.borrow_and_update()(id);
        }

        if let Priority::Drop = priority {
            return Err(Aborted);
        }
        Ok(())
    }

    /// Downloads a given artifact.
    ///
    /// The download will be scheduled based on the given priority function, `priority_fn_watcher`.
    ///
    /// The download fails iff:
    /// - The priority function evaluates the advert to [`Priority::Drop`] -> [`DownloadStopped::PriorityIsDrop`]
    /// - The set of peers advertising the artifact, `peer_rx`, becomes empty -> [`DownloadStopped::AllPeersDeletedTheArtifact`]
    /// and the failure condition is reported in the error variant of the returned result.
    #[instrument(skip_all)]
    async fn download_artifact(
        log: ReplicaLogger,
        id: Artifact::Id,
        // Only first peer for specific artifact ID is considered for push
        mut artifact: Option<(Artifact, NodeId)>,
        peer_rx: impl Peers + Send + 'static,
        mut priority_fn_watcher: watch::Receiver<PriorityFn<Artifact::Id>>,
        transport: Arc<dyn Transport>,
        metrics: FetchArtifactMetrics,
    ) -> Result<(Artifact, NodeId), Aborted> {
        // Evaluate priority and wait until we should fetch.
        Self::wait_fetch(&id, &mut artifact, &metrics, &mut priority_fn_watcher).await?;

        let mut artifact_download_backoff = ExponentialBackoffBuilder::new()
            .with_initial_interval(MIN_ARTIFACT_RPC_TIMEOUT)
            .with_max_interval(MAX_ARTIFACT_RPC_TIMEOUT)
            .with_max_elapsed_time(None)
            .build();

        match artifact {
            // Artifact was pushed by peer. In this case we don't need check that the artifact ID corresponds
            // to the artifact because we earlier derived the ID from the artifact.
            Some((artifact, peer_id)) => Ok((artifact, peer_id)),

            // Fetch artifact
            None => {
                let timer = metrics
                    .download_task_artifact_download_duration
                    .start_timer();
                let mut rng = SmallRng::from_entropy();

                let result = loop {
                    let next_request_at = Instant::now()
                        + artifact_download_backoff
                            .next_backoff()
                            .unwrap_or(MAX_ARTIFACT_RPC_TIMEOUT);
                    if let Some(peer) = peer_rx.peers().into_iter().choose(&mut rng) {
                        let bytes = Bytes::from(Artifact::PbId::proxy_encode(id.clone()));
                        let request = Request::builder()
                            .uri(format!("/{}/rpc", uri_prefix::<Artifact>()))
                            .body(bytes)
                            .unwrap();

                        match timeout_at(next_request_at, transport.rpc(&peer, request)).await {
                            Ok(Ok(response)) if response.status() == StatusCode::OK => {
                                let body = response.into_body();
                                if let Ok(message) = Artifact::PbMessage::proxy_decode(&body) {
                                    if message.id() == id {
                                        break Ok((message, peer));
                                    } else {
                                        warn!(
                                            log,
                                            "Peer {} responded with wrong artifact for advert",
                                            peer
                                        );
                                    }
                                }
                            }
                            _ => {
                                metrics.download_task_artifact_download_errors_total.inc();
                            }
                        }
                    }

                    // Wait before checking the priority so we might be able to avoid an unnecessary download.
                    sleep_until(next_request_at).await;
                    Self::wait_fetch(&id, &mut artifact, &metrics, &mut priority_fn_watcher)
                        .await?;
                };

                timer.stop_and_record();

                result
            }
        }
    }
}
