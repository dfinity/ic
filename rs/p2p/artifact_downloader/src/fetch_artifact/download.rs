use std::{
    sync::{Arc, RwLock},
    time::Duration,
};

use axum::{
    Router,
    extract::{DefaultBodyLimit, State},
    http::{Request, StatusCode},
    routing::any,
};
use backon::{BackoffBuilder, ExponentialBuilder};
use bytes::Bytes;
use ic_base_types::NodeId;
use ic_interfaces::p2p::consensus::{
    ArtifactAssembler, AssembleResult, Bouncer, BouncerFactory, BouncerValue, Peers,
    ValidatedPoolReader,
};
use ic_logger::{ReplicaLogger, warn};
use ic_metrics::MetricsRegistry;
use ic_protobuf::proxy::ProtoProxy;
use ic_quic_transport::Transport;
use ic_types::artifact::{IdentifiableArtifact, PbArtifact};
use rand::{SeedableRng, rngs::SmallRng, seq::IteratorRandom};
use tokio::{
    runtime::Handle,
    sync::watch,
    task::JoinHandle,
    time::{Instant, sleep_until, timeout_at},
};
use tracing::instrument;

use super::metrics::FetchArtifactMetrics;

const MIN_ARTIFACT_RPC_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ARTIFACT_RPC_TIMEOUT: Duration = Duration::from_secs(120);

pub(crate) fn uri_prefix<Artifact: PbArtifact>() -> String {
    Artifact::NAME.to_lowercase()
}

/// A pool shared with the components writing to it, read by taking its lock on each access.
struct SharedPool<Pool>(Arc<RwLock<Pool>>);

impl<Artifact, Pool> ValidatedPoolReader<Artifact> for SharedPool<Pool>
where
    Artifact: IdentifiableArtifact,
    Pool: ValidatedPoolReader<Artifact>,
{
    fn get(&self, id: &Artifact::Id) -> Option<Artifact> {
        self.0.read().unwrap().get(id)
    }

    fn get_all_for_initial_broadcast(&self) -> Box<dyn Iterator<Item = Artifact> + '_> {
        // Not used
        Box::new(std::iter::empty())
    }
}

async fn rpc_handler<Artifact: PbArtifact>(
    State(pool): State<Arc<dyn ValidatedPoolReader<Artifact> + Send + Sync>>,
    payload: Bytes,
) -> Result<Bytes, StatusCode> {
    let jh = tokio::task::spawn_blocking(move || {
        let id: Artifact::Id =
            Artifact::PbId::proxy_decode(&payload).map_err(|_| StatusCode::BAD_REQUEST)?;
        let artifact = pool.get(&id).ok_or(StatusCode::NO_CONTENT)?;
        Ok::<_, StatusCode>(Bytes::from(Artifact::PbMessage::proxy_encode(artifact)))
    });
    let bytes = jh.await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)??;

    Ok(bytes)
}

pub struct FetchArtifact<Artifact: PbArtifact> {
    log: ReplicaLogger,
    transport: Arc<dyn Transport>,
    bouncer_rx: watch::Receiver<Bouncer<Artifact::Id>>,
    metrics: FetchArtifactMetrics,
    jh: Arc<JoinHandle<()>>,
}

impl<Artifact: PbArtifact> Clone for FetchArtifact<Artifact> {
    fn clone(&self) -> Self {
        Self {
            log: self.log.clone(),
            transport: self.transport.clone(),
            bouncer_rx: self.bouncer_rx.clone(),
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
    ) -> AssembleResult<Artifact> {
        Self::download_artifact(
            self.log.clone(),
            id,
            artifact,
            peers,
            self.bouncer_rx.clone(),
            self.transport.clone(),
            self.metrics.clone(),
        )
        .await
    }
}

impl<Artifact: PbArtifact> FetchArtifact<Artifact> {
    /// Downloads the `Artifact`s wanted by the bouncers built from `pool`, and serves the
    /// `Artifact`s of `pool` to the peers.
    pub fn new<Pool>(
        log: ReplicaLogger,
        rt: Handle,
        pool: Arc<RwLock<Pool>>,
        bouncer_factory: Arc<dyn BouncerFactory<Artifact::Id, Pool>>,
        metrics_registry: MetricsRegistry,
    ) -> (impl Fn(Arc<dyn Transport>) -> Self, Router)
    where
        Pool: ValidatedPoolReader<Artifact> + Send + Sync + 'static,
    {
        (
            Self::downloader(log, rt, pool.clone(), bouncer_factory, metrics_registry),
            Self::router(Arc::new(SharedPool(pool))),
        )
    }

    /// Downloads the `Artifact`s wanted by the bouncers built from `pool`.
    pub(crate) fn downloader<Pool>(
        log: ReplicaLogger,
        rt: Handle,
        pool: Arc<RwLock<Pool>>,
        bouncer_factory: Arc<dyn BouncerFactory<Artifact::Id, Pool>>,
        metrics_registry: MetricsRegistry,
    ) -> impl Fn(Arc<dyn Transport>) -> Self
    where
        Pool: Send + Sync + 'static,
    {
        move |transport: Arc<dyn Transport>| {
            let bouncer = {
                let p = pool.read().unwrap();
                bouncer_factory.new_bouncer(&p)
            };
            let (bouncer_tx, bouncer_rx) = watch::channel(bouncer);
            let pool_clone = pool.clone();
            let bouncer_factory_clone = bouncer_factory.clone();
            let log_clone = log.clone();
            let jh = rt.spawn(async move {
                loop {
                    let bouncer = {
                        let p = pool_clone.read().unwrap();
                        bouncer_factory_clone.new_bouncer(&p)
                    };
                    if bouncer_tx.send(bouncer).is_err() {
                        break;
                    }

                    tokio::time::sleep(bouncer_factory_clone.refresh_period()).await
                }
            });
            Self {
                log: log_clone,
                transport,
                bouncer_rx,
                metrics: FetchArtifactMetrics::new::<Artifact>(&metrics_registry),
                jh: Arc::new(jh),
            }
        }
    }

    /// Serves the `Artifact`s of `pool` to the peers' downloaders.
    pub(crate) fn router(pool: Arc<dyn ValidatedPoolReader<Artifact> + Send + Sync>) -> Router {
        Router::new()
            .route(
                &format!("/{}/rpc", uri_prefix::<Artifact>()),
                any(rpc_handler),
            )
            .with_state(pool)
            // Disable request size limit since consensus might push artifacts larger than limit.
            .layer(DefaultBodyLimit::disable())
    }

    /// Returns a watcher over the bouncer used by this assembler, so callers can react to the
    /// artifact becoming [`BouncerValue::Unwanted`] (e.g. to cancel in-progress assembly work).
    pub(crate) fn bouncer_watcher(&self) -> watch::Receiver<Bouncer<Artifact::Id>> {
        self.bouncer_rx.clone()
    }

    /// Waits until advert resolves to wanted. If the bouncer value becomes Unwanted, false is returned.
    #[instrument(skip_all)]
    async fn should_download(
        id: &Artifact::Id,
        artifact: &mut Option<(Artifact, NodeId)>,
        metrics: &FetchArtifactMetrics,
        bouncer_watcher: &mut watch::Receiver<Bouncer<Artifact::Id>>,
    ) -> bool {
        let mut bouncer_value = bouncer_watcher.borrow_and_update()(id);

        // Clear the artifact from memory if it was pushed.
        if let BouncerValue::MaybeWantsLater = bouncer_value {
            artifact.take();
            metrics.download_task_stashed_total.inc();
        }

        while let BouncerValue::MaybeWantsLater = bouncer_value {
            let _ = bouncer_watcher.changed().await;
            bouncer_value = bouncer_watcher.borrow_and_update()(id);
        }

        BouncerValue::Unwanted != bouncer_value
    }

    /// Downloads a given artifact.
    ///
    /// The download will be scheduled based on the given bouncer function, `bouncer_watcher`.
    ///
    /// The download fails iff:
    /// - The bouncer function evaluates the advert to [`BouncerValue::Unwanted`] -> [`AssembleResult::Unwanted`]
    #[instrument(skip_all)]
    async fn download_artifact(
        log: ReplicaLogger,
        id: Artifact::Id,
        // Only first peer for specific artifact ID is considered for push
        mut artifact: Option<(Artifact, NodeId)>,
        peer_rx: impl Peers + Send + 'static,
        mut bouncer_watcher: watch::Receiver<Bouncer<Artifact::Id>>,
        transport: Arc<dyn Transport>,
        metrics: FetchArtifactMetrics,
    ) -> AssembleResult<Artifact> {
        // Evaluate bouncer and wait until we should fetch.
        if !Self::should_download(&id, &mut artifact, &metrics, &mut bouncer_watcher).await {
            return AssembleResult::Unwanted;
        }

        let mut artifact_download_backoff = ExponentialBuilder::new()
            .with_min_delay(MIN_ARTIFACT_RPC_TIMEOUT)
            .with_max_delay(MAX_ARTIFACT_RPC_TIMEOUT)
            .with_factor(1.5)
            .with_jitter()
            .without_max_times()
            .build();

        match artifact {
            // Artifact was pushed by peer. In this case we don't need check that the artifact ID corresponds
            // to the artifact because we earlier derived the ID from the artifact.
            Some((artifact, peer_id)) => AssembleResult::Done {
                message: artifact,
                peer_id,
            },

            // Fetch artifact
            None => {
                let timer = metrics
                    .download_task_artifact_download_duration
                    .start_timer();
                let mut rng = SmallRng::from_entropy();

                let result = loop {
                    let next_request_at = Instant::now()
                        + artifact_download_backoff
                            .next()
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
                                        break AssembleResult::Done {
                                            message,
                                            peer_id: peer,
                                        };
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

                    // Wait before checking the bouncer so we might be able to avoid an unnecessary download.
                    sleep_until(next_request_at).await;
                    if !Self::should_download(&id, &mut artifact, &metrics, &mut bouncer_watcher)
                        .await
                    {
                        return AssembleResult::Unwanted;
                    }
                };

                timer.stop_and_record();

                result
            }
        }
    }
}
