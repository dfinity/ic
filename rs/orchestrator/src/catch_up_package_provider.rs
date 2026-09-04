//! The catchup package provider module is responsible for identifying and retrieving the latest CUP
//! for the orchestrator.
//!
//! The latest CUP can come from two places: from the registry or from peers. Every time we manage
//! to detect a new CUP we persist it locally. The CUP carries an important information for the
//! orchestrator: it indicates whether the current node is still a member of the current subnet and
//! if yes, whether this node is running the correct replica version.
//!
//! The registry can contain the newest CUP in two cases: the subnet genesis (in fact, this is the very
//! first CUP of a subnet) and a subnet recovery. In the case of the subnet recovery, the CUP
//! contains a state hash and a height from which the subnet is supposed to restart its
//! computation.
//!
//! In the normal operation mode, the CUP fetched from the peers will be eventually always newer than
//! the one we have persisted locally because CUPs are produced by the subnet on a regular basis.
//! We try to fetch a newer CUP every 10 seconds. The orchestrator always tries to fetch the CUP
//! from its own replica first and if no newer CUP is available, it tries to fetch one from one of the
//! random peers. To avoid bandwidth waste, every request contains the CUP version available locally.
//! The request will only be responded to with a new CUP if a newer one actually exists. Moreover, trying to
//! fetch the CUP from the node's own replica makes the upgrade behaviour of a subnet more efficient. This
//! is because if all replicas are up to date, they will obtain a new CUP at about the same time. Then
//! some nodes will instantly go into the upgrade process and stop serving CUPs to their peers.
//! Hence, fetching the CUP from the node's own replica first allows the orchestrator to get the CUP
//! quicker because its own replica will serve the CUP until it gets shut down before an upgrade.
//!
//! CUPs are persisted in Protobuf format and are expected to be backwards compatible. For example,
//! if a node stays offline for a long period of time and its subnet goes through an upgrade in
//! that time, it is the CUP served by peers that will help such a node to get back on track. It
//! will contain a registry version indicating the correct replica version and a list of peers that
//! can be used to fetch newer CUPs. This way a node does not rely on the P2P protocol to catch up
//! with its subnet and allows us to upgrade the protocol with breaking changes on any protocol layer.

use crate::{
    error::{OrchestratorError, OrchestratorResult},
    metrics::OrchestratorMetrics,
    registry_helper::RegistryHelper,
    utils::https_endpoint_to_url,
};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Method, Request, StatusCode, body::Bytes};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use ic_crypto_tls_interfaces::TlsConfig;
use ic_interfaces::crypto::ThresholdSigVerifierByPublicKey;
use ic_limits::MAX_MESSAGE_SIZE_BYTES;
use ic_logger::{ReplicaLogger, error, info, warn};
use ic_protobuf::{registry::node::v1::NodeRecord, types::v1 as pb};
use ic_registry_client_helpers::subnet::SubnetTransportRegistry;
use ic_sys::fs::write_protobuf_using_tmp_file;
use ic_types::{
    Height, NodeId, RegistryVersion, SubnetId,
    consensus::{
        HasHeight, HasVersion,
        catchup::{CatchUpContentProtobufBytes, CatchUpPackage, CatchUpPackageParam},
        dkg::{PostSplitArgs, SubnetSplittingStatus},
    },
    crypto::*,
};
use prost::Message;
use rand::seq::SliceRandom;
use std::{convert::TryFrom, fs::File, path::PathBuf, sync::Arc, time::Duration};
use tokio::time::timeout;

/// A struct that can be shared among multiple components
/// that only need to read the local CUP.
#[derive(Clone)]
pub(crate) struct LocalCUPReader {
    cup_dir: PathBuf,
    logger: ReplicaLogger,
}

impl LocalCUPReader {
    /// Create a new `LocalCUPReader` instance.
    pub(crate) fn new(cup_dir: PathBuf, logger: ReplicaLogger) -> Self {
        Self { cup_dir, logger }
    }

    /// Returns the locally persisted CUP in deserialized form
    pub(crate) fn get_local_cup(&self) -> Option<CatchUpPackage> {
        let local_cup_proto = self.get_local_cup_proto()?;
        CatchUpPackage::try_from(&local_cup_proto)
            .inspect_err(|err| warn!(self.logger, "Deserialization of CUP failed: {}", err))
            .ok()
    }

    /// Returns the locally persisted CUP in protobuf form
    pub(crate) fn get_local_cup_proto(&self) -> Option<pb::CatchUpPackage> {
        let path = self.get_cup_path();
        if !path.exists() {
            return None;
        }
        match File::open(&path) {
            Ok(reader) => pb::CatchUpPackage::read_from_reader(reader)
                .inspect_err(|e| warn!(self.logger, "Failed to read CUP from file {:?}", e))
                .ok(),
            Err(err) => {
                warn!(self.logger, "Couldn't open file {:?}: {:?}", path, err);
                None
            }
        }
    }

    /// The path that should be used to read the CUP for the assigned subnet.
    pub(crate) fn get_cup_path(&self) -> PathBuf {
        self.cup_dir.join("cup.types.v1.CatchUpPackage.pb")
    }
}

/// Fetches catch-up packages from peers and local storage.
///
/// CUPs are used to determine which version of the IC peers are running
/// and hence which version of the IC this node should be starting.
pub(crate) struct CatchUpPackageProvider {
    registry: Arc<RegistryHelper>,
    metrics: Arc<OrchestratorMetrics>,
    crypto: Arc<dyn ThresholdSigVerifierByPublicKey<CatchUpContentProtobufBytes> + Send + Sync>,
    crypto_tls_config: Arc<dyn TlsConfig>,
    logger: ReplicaLogger,
    node_id: NodeId,
    backoff: Duration,
    initial_backoff: Duration,
    max_response_size_bytes: usize,
    // If the orchestrator detects that a subnet split is in progress, this field will be set to
    // our subnet ID post-split. This slightly modifies the logic when selecting peers.
    split_in_progress_subnet_id: Option<SubnetId>,
    local_cup_reader: LocalCUPReader,
}

impl CatchUpPackageProvider {
    /// Instantiate a new `CatchUpPackageProvider`
    pub(crate) fn new(
        registry: Arc<RegistryHelper>,
        metrics: Arc<OrchestratorMetrics>,
        local_cup_reader: LocalCUPReader,
        crypto: Arc<dyn ThresholdSigVerifierByPublicKey<CatchUpContentProtobufBytes> + Send + Sync>,
        crypto_tls_config: Arc<dyn TlsConfig>,
        logger: ReplicaLogger,
        node_id: NodeId,
    ) -> Self {
        Self::new_with_initial_backoff(
            registry,
            metrics,
            local_cup_reader,
            crypto,
            crypto_tls_config,
            logger,
            node_id,
            Duration::from_secs(30),
        )
    }

    fn new_with_initial_backoff(
        registry: Arc<RegistryHelper>,
        metrics: Arc<OrchestratorMetrics>,
        local_cup_reader: LocalCUPReader,
        crypto: Arc<dyn ThresholdSigVerifierByPublicKey<CatchUpContentProtobufBytes> + Send + Sync>,
        crypto_tls_config: Arc<dyn TlsConfig>,
        logger: ReplicaLogger,
        node_id: NodeId,
        initial_backoff: Duration,
    ) -> Self {
        Self {
            node_id,
            registry,
            metrics,
            crypto,
            crypto_tls_config,
            logger,
            backoff: initial_backoff,
            initial_backoff,
            max_response_size_bytes: MAX_MESSAGE_SIZE_BYTES,
            split_in_progress_subnet_id: None,
            local_cup_reader,
        }
    }

    fn select_peers(
        &self,
        subnet_id: SubnetId,
        registry_version: RegistryVersion,
        current_cup: Option<&pb::CatchUpPackage>,
    ) -> Vec<(NodeId, NodeRecord)> {
        let mut nodes: Vec<(NodeId, NodeRecord)> = self
            .registry
            .get_registry_client()
            .get_subnet_node_records(subnet_id, registry_version)
            .ok()
            .flatten()
            .unwrap_or_default();

        // Randomize the order of peer_urls
        nodes.shuffle(&mut rand::thread_rng());

        let current_node_index = nodes.iter().position(|t| t.0 == self.node_id);

        let max_num_peers_to_try = match (current_node_index, current_cup) {
            // If we don't have a local CUP, we try not to fall back to the registry CUP.
            // Therefore, we select all nodes.
            (_, None) => nodes.len(),
            (Some(index), _) => {
                // If we are still a member of the subnet, move our own data to the front, so that we
                // first try to fetch the CUP from our own replica. This improves the upgrade behaviour
                // of a healthy subnet, as we decrease the probability of hitting peers who already
                // started the upgrade process and will not serve a CUP until they're online again.
                nodes.swap(0, index);
                2
            }
            // Try only one peer at-a-time if there is already a local CUP,
            (None, _) => 1,
        };

        nodes.into_iter().take(max_num_peers_to_try).collect()
    }

    /// Randomly selects a peer from the subnet and pulls its CUP. If this CUP is
    /// newer than the currently available one and it could be verified, then this
    /// CUP is returned. Note that it is acceptable to use a single peer, because
    /// CUPs are validated. If all `f` nodes serve unusable CUPs, we have a probability
    /// of 2/3 to hit a non-faulty node, so roughly on 4th attempt we should obtain
    /// the correct peer CUP.
    /// If this node is part of the subnet according to the given registry version, then
    /// we will attempt to fetch the CUP from our own replica first, before trying a
    /// second random node.
    async fn get_peer_cup(
        &mut self,
        subnet_id: SubnetId,
        registry_version: RegistryVersion,
        current_cup: Option<&pb::CatchUpPackage>,
    ) -> Option<pb::CatchUpPackage> {
        // `split_in_progress_subnet_id` will be populated with our exepcted subnet ID if we detect
        // a post-split CUP. In that case, we want to fetch the CUP from the new peers and new
        // public key instead of what we know of so far (which would be a previous CUP from the
        // previous source subnet).
        let subnet_id = self.split_in_progress_subnet_id.unwrap_or(subnet_id);

        let peers = self.select_peers(subnet_id, registry_version, current_cup);

        if peers.is_empty() {
            warn!(
                self.logger,
                "Empty peer list for subnet {} at version {}", subnet_id, registry_version
            );
            return None;
        }

        let param = current_cup
            .map(CatchUpPackageParam::try_from)
            .and_then(Result::ok);

        for (node_id, node_record) in &peers {
            match self
                .fetch_and_verify_catch_up_package(node_id, node_record, param, subnet_id)
                .await
            {
                // Note: None is < Some(_)
                Ok(Some((proto, cup))) if Some(CatchUpPackageParam::from(&cup)) > param => {
                    if !self.is_splitting_cup_for_other_subnet(&cup) {
                        return Some(proto);
                    }

                    // This is expected to log shortly after a split. The next call to
                    // `get_peer_cup` should select the new subnet's peers and fecth CUPs from
                    // there.
                    info!(
                        self.logger,
                        "Ignoring CUP from node {} because it is for the other subnet", node_id,
                    );
                }
                Ok(Some(_)) | Ok(None) => {}
                Err(err) => {
                    warn!(
                        self.logger,
                        "Failed to fetch CUP from node {}: {}", node_id, err
                    );
                }
            }
        }
        None
    }

    // Download CUP from the given node.
    //
    // If `param` is given, download only CUPs that are newer than the
    // given CUP. This avoids unnecessary CUP downloads and hence reduces
    // network bandwidth requirements.
    //
    // Also checks the signature of the downloaded catch up package.
    async fn fetch_and_verify_catch_up_package(
        &mut self,
        node_id: &NodeId,
        node_record: &NodeRecord,
        param: Option<CatchUpPackageParam>,
        subnet_id: SubnetId,
    ) -> Result<Option<(pb::CatchUpPackage, CatchUpPackage)>, String> {
        let http = node_record.clone().http.ok_or_else(|| {
            format!("Node {node_id} record's http endpoint is None: {node_record:?}")
        })?;
        let mut uri = https_endpoint_to_url(&http)?;
        uri.path_segments_mut()
            .map_err(|()| "URL cannot be segmented".to_string())?
            .push("_")
            .push("catch_up_package");

        let uri = uri.to_string();

        let Some(protobuf) = self
            .fetch_catch_up_package(node_id, uri.clone(), param)
            .await?
        else {
            return Ok(None);
        };
        let cup = CatchUpPackage::try_from(&protobuf)
            .map_err(|e| format!("Failed to read CUP from peer at url {uri}: {e:?}"))?;

        self.crypto
            .verify_combined_threshold_sig_by_public_key(
                &CombinedThresholdSigOf::new(CombinedThresholdSig(protobuf.signature.clone())),
                &CatchUpContentProtobufBytes::from(&protobuf),
                subnet_id,
                cup.content.registry_version(),
            )
            .map_err(|e| format!("Failed to verify CUP signature at: {uri:?} with: {e:?}"))?;

        Ok(Some((protobuf, cup)))
    }

    // Attempt to fetch a `CatchUpPackage` from the given endpoint.
    //
    // Does not check the signature of the CUP. This has to be done by the
    // caller.
    async fn fetch_catch_up_package(
        &mut self,
        node_id: &NodeId,
        url: String,
        param: Option<CatchUpPackageParam>,
    ) -> Result<Option<pb::CatchUpPackage>, String> {
        let body = Bytes::from(
            param
                .and_then(|param| serde_cbor::to_vec(&param).ok())
                .unwrap_or_default(),
        );

        let client_config = self
            .crypto_tls_config
            .client_config(*node_id, self.registry.get_latest_version())
            .map_err(|e| format!("Failed to create tls client config for {node_id}: {e:?}"))?;

        let https = HttpsConnectorBuilder::new()
            .with_tls_config(client_config)
            .https_only()
            .enable_all_versions()
            .build();

        let client = Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(1)
            .build::<_, Full<Bytes>>(https);

        let req = timeout(
            Duration::from_secs(10),
            client.request(
                Request::builder()
                    .method(Method::POST)
                    .header(hyper::header::CONTENT_TYPE, "application/cbor")
                    .uri(&url)
                    .body(Full::from(body))
                    .map_err(|e| format!("Failed to create request to {url}: {e:?}"))?,
            ),
        );

        let res = req
            .await
            .map_err(|e| format!("Querying CUP endpoint at {url} timed out: {e:?}"))?
            .map_err(|e| format!("Failed to query CUP endpoint at {url}: {e:?}"))?;

        let status = res.status();
        let body_req = timeout(
            self.backoff,
            Limited::new(res.into_body(), self.max_response_size_bytes).collect(),
        );

        let bytes = match body_req.await {
            Ok(result) => {
                // Reset backoff on success
                self.backoff = self.initial_backoff;
                match result {
                    Ok(bytes) => bytes.to_bytes(),
                    Err(e) => {
                        return Err(format!(
                            "Failed to convert the response body to bytes: {e:?}"
                        ));
                    }
                }
            }
            Err(timeout_err) => {
                let old_backoff = self.backoff;
                self.backoff = old_backoff.saturating_mul(2);
                return Err(format!(
                    "Timed out while reading CUP response body of {} after {} secs: {:?}. Setting backoff to {} secs",
                    url,
                    old_backoff.as_secs(),
                    timeout_err,
                    self.backoff.as_secs()
                ));
            }
        };

        match status {
            // Replicas should return `NO_CONTENT` if their own CUP isn't higher than `param`
            StatusCode::NO_CONTENT => Ok(None),
            StatusCode::OK => pb::CatchUpPackage::decode(&bytes[..])
                .map_err(|e| format!("Failed to deserialize CUP from protobuf: {e:?}"))
                .map(Some),
            other_status => Err(format!("Status: {other_status}, body: {bytes:?}")),
        }
    }

    /// Returns true if the given CUP is a post-split CUP for the subnet other than ours.
    /// Keeps track of our subnet ID such that the next call to `select_peers` can select the new
    /// subnet's peers instead of the previous ones.
    ///
    /// Trusts the given CUP, so assumes its signature has been checked.
    fn is_splitting_cup_for_other_subnet(&mut self, cup: &CatchUpPackage) -> bool {
        let peer_subnet_id = match cup.subnet_splitting_status() {
            SubnetSplittingStatus::NotScheduled => {
                self.split_in_progress_subnet_id = None;
                return false;
            }
            SubnetSplittingStatus::Scheduled { .. } => {
                let error_message = "Received a signed CUP with scheduled subnet splitting from a peer, even though Consensus \
                should skip the scheduled height and directly produce a post-split CUP. Trusting the subnet's threshold \
                signature anyways. This is a bug.";
                if cfg!(debug_assertions) {
                    panic!("{}", error_message);
                }

                error!(self.logger, "{}", error_message);
                self.split_in_progress_subnet_id = None;
                self.metrics
                    .critical_error_observed_scheduled_splitting_cup
                    .inc();

                return false;
            }
            SubnetSplittingStatus::PostSplit(PostSplitArgs { new_subnet_id }) => new_subnet_id,
        };

        // A post-split CUP's registry version is the version at which the split was set in the
        // registry.
        let split_in_progress_reg_ver = cup.content.registry_version();
        let Some(expected_subnet_id) = self
            .registry
            .get_subnet_id_from_node_id(self.node_id, split_in_progress_reg_ver)
            .ok()
            .flatten()
        else {
            warn!(
                self.logger,
                "Failed to get subnet id for node {} at registry version {}",
                self.node_id,
                split_in_progress_reg_ver
            );
            // If we cannot read the registry or we are actually unassigned (which should not
            // happen), default to rejecting the CUP and try again later
            // If the subnet is healthy, it will at some point in the future create a `NotScheduled`
            // CUP and make us truly aware of what we are assigned to.
            return true;
        };

        self.split_in_progress_subnet_id = Some(expected_subnet_id);

        peer_subnet_id != expected_subnet_id
    }

    /// Persist the given CUP to disk.
    ///
    /// This is necessary, as it allows the orchestrator to find a CUP
    /// it previously downloaded again after restart, so that the node
    /// manager never goes back in time.  It will always find a CUP
    /// that is at least as high as the one it has previously
    /// discovered.
    ///
    /// Follows guidelines for DFINITY thread-safe I/O.
    fn persist_cup(&self, cup_proto: &pb::CatchUpPackage) -> OrchestratorResult<PathBuf> {
        let cup_file_path = self.get_cup_path();
        let cup = CatchUpPackage::try_from(cup_proto).map_err(|e| {
            OrchestratorError::IoError(
                "Failed to deserialize CUP! Couldn't persist.".to_string(),
                std::io::Error::new(std::io::ErrorKind::InvalidData, e),
            )
        })?;
        info!(
            self.logger,
            "Persisting CUP (replica_version={}, registry_version={}, height={}, signed={}, state_hash={}, timestamp={}) to file {}",
            cup.content.version(),
            cup.content.registry_version(),
            cup.content.height(),
            cup.is_signed(),
            hex::encode(cup.content.state_hash.clone().get().0),
            cup.content
                .block
                .get_value()
                .context
                .time
                .as_nanos_since_unix_epoch(),
            &cup_file_path.display(),
        );
        write_protobuf_using_tmp_file(&cup_file_path, cup_proto).map_err(|e| {
            OrchestratorError::IoError(
                format!("Failed to serialize protobuf to disk: {:?}", cup_file_path),
                e,
            )
        })?;

        Ok(cup_file_path)
    }

    /// The path that should be used to save the CUP for the assigned subnet.
    /// Includes the specific type encoded in the file for future-proofing and
    /// ease of debugging.
    pub(crate) fn get_cup_path(&self) -> PathBuf {
        self.local_cup_reader.get_cup_path()
    }

    /// Return the most up to date CUP.
    ///
    /// Choose the highest CUP among: those provided by the subnet peers,
    /// the locally persisted CUP (if one exists) and the CUP that is specified
    /// by the registry. If we manage to find a newer CUP we also persist it.
    pub(crate) async fn get_latest_cup(
        &mut self,
        local_cup: Option<pb::CatchUpPackage>,
        subnet_id: SubnetId,
    ) -> OrchestratorResult<CatchUpPackage> {
        let registry_version = self.registry.get_latest_version();
        let local_cup_height = local_cup
            .as_ref()
            .map(|cup| {
                get_cup_proto_height(cup).ok_or_else(|| {
                    OrchestratorError::deserialize_cup_error(
                        None,
                        "Failed to get CUP proto height.",
                    )
                })
            })
            .transpose()?;

        let subnet_cup = self
            .get_peer_cup(subnet_id, registry_version, local_cup.as_ref())
            .await;

        let registry_cup = self
            .registry
            .get_registry_cup(registry_version, subnet_id)
            .inspect_err(|err| warn!(self.logger, "Failed to create a registry cup: {err}"))
            .map(pb::CatchUpPackage::from)
            .ok();

        // Select the latest CUP based on the height of the CUP *proto*. This is to avoid falling
        // back to an outdated registry CUP if the local CUP can't be deserialized. If this is the
        // case, we prefer to return an error and wait until a higher recovery CUP exists.
        let latest_cup_proto = vec![local_cup, registry_cup, subnet_cup]
            .into_iter()
            .flatten()
            .max_by_key(get_cup_proto_height)
            .ok_or(OrchestratorError::MakeRegistryCupError(
                subnet_id,
                registry_version,
            ))?;
        let latest_cup = CatchUpPackage::try_from(&latest_cup_proto).map_err(|err| {
            OrchestratorError::deserialize_cup_error(get_cup_proto_height(&latest_cup_proto), err)
        })?;

        let height = Some(latest_cup.height());
        // We recreate the local registry CUP everytime to avoid incompatibility issues. Without
        // this recreation, we might run into the following problem: assume the orchestrator of
        // version A creates a local unsigned CUP from the registry contents, persists it, then
        // detects a new replica version B, upgrades to it and starts the replica on the previously
        // created CUP. Now since such a case might happen on a new subnet creation or during a
        // subnet recovery with failover nodes, all nodes before upgrading to B might have been on
        // different versions and hence might have created different CUPs, which are then consumed
        // by the same replica version B, which is not guaranteed to be deterministic.
        //
        // By re-creating the unsigned CUP every time we realize it's the newest one, we instead
        // recreate the CUP on all orchestrators of the version B before starting the replica.
        if height > local_cup_height || height == local_cup_height && !latest_cup.is_signed() {
            self.persist_cup(&latest_cup_proto)?;
        }

        Ok(latest_cup)
    }

    /// Returns the locally persisted CUP in protobuf form
    pub(crate) fn get_local_cup_proto(&self) -> Option<pb::CatchUpPackage> {
        self.local_cup_reader.get_local_cup_proto()
    }
}

// Returns the height of the CUP without converting the protobuf
fn get_cup_proto_height(cup: &pb::CatchUpPackage) -> Option<Height> {
    pb::CatchUpContent::decode(cup.content.as_slice())
        .ok()
        .and_then(|content| content.block)
        .map(|block| Height::from(block.height))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use http_body_util::{StreamBody, combinators::BoxBody};
    use hyper::{
        Response,
        body::{Bytes, Frame},
        server::conn::http2,
        service::service_fn,
    };
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use ic_crypto_test_utils_crypto_returning_ok::CryptoReturningOk;
    use ic_crypto_tls_interfaces_mocks::MockTlsConfig;
    use ic_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_protobuf::registry::node::v1::ConnectionEndpoint;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_keys::make_node_record_key;
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_test_utilities_consensus::fake::{Fake, FakeContent};
    use ic_test_utilities_in_memory_logger::{InMemoryReplicaLogger, assertions::LogEntriesAssert};
    use ic_test_utilities_registry::{
        SubnetRecordBuilder, add_single_subnet_record, add_subnet_list_record,
    };
    use ic_test_utilities_types::ids::{
        SUBNET_0, SUBNET_1, SUBNET_2, node_test_id, test_replica_version,
    };
    use ic_types::{
        ReplicaVersion,
        batch::ValidationContext,
        consensus::{
            Block, BlockPayload, CatchUpContent, HashedBlock, HashedRandomBeacon, Payload,
            RandomBeacon, RandomBeaconContent, Rank, SummaryPayload,
            dkg::{DkgSummary, SplittingArgs},
        },
        crypto::threshold_sig::ni_dkg::{NiDkgReceivers, NiDkgTargetId, NiDkgTargetSubnet},
        signature::ThresholdSignature,
        time::UNIX_EPOCH,
    };
    use rcgen::{CertificateParams, KeyPair};
    use rstest::rstest;
    use rustls::{
        ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    };
    use slog::Level;
    use std::{
        convert::Infallible,
        net::SocketAddr,
        sync::{Arc, Mutex},
        time::Duration,
    };
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    #[derive(Clone, Debug)]
    enum TestService {
        /// Service that responds with headers, and then either sends a full CUP or stalls forever.
        SendBodyOrStall(Arc<Mutex<bool>>),
        /// Service that never responds.
        Unresponsive,
        /// Service that returns no content (no newer CUP available)
        NoContent,
        /// Service that responds with an error
        BadRequest,
        /// Service that serves the given CUP
        SendCup(Arc<Mutex<pb::CatchUpPackage>>),
    }

    async fn test_service(
        service: TestService,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
        match service {
            TestService::SendBodyOrStall(send_cup) => slow_body_service(send_cup).await,
            TestService::Unresponsive => unresponsive_service().await,
            TestService::NoContent => no_content_service().await,
            TestService::BadRequest => error_service().await,
            TestService::SendCup(cup) => cup_service(cup).await,
        }
    }

    async fn cup_service(
        cup: Arc<Mutex<pb::CatchUpPackage>>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
        let bytes = Bytes::from(cup.lock().unwrap().encode_to_vec());

        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(bytes).boxed())
            .unwrap())
    }

    async fn slow_body_service(
        send_cup: Arc<Mutex<bool>>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
        let s = async_stream::stream! {
            if *send_cup.lock().unwrap() {
                yield Ok(Frame::data(Bytes::from(fake_cup().encode_to_vec())));
            } else {
                // Send one chunk
                yield Ok(Frame::data(Bytes::from("partial data")));
                // Stall forever
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        };

        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(BoxBody::new(StreamBody::new(s)))
            .unwrap())
    }

    async fn unresponsive_service() -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
        tokio::time::sleep(Duration::from_secs(3600)).await;
        unreachable!()
    }

    async fn no_content_service() -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
        Ok(Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Full::new(Bytes::from("")).boxed())
            .unwrap())
    }

    async fn error_service() -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
        Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Full::new(Bytes::from("error message")).boxed())
            .unwrap())
    }

    /// A [`ThresholdSigVerifierByPublicKey`] that accepts every signature and records the registry
    /// version it was asked to verify at.
    #[derive(Default)]
    struct RegistryVersionRecordingCrypto {
        verified_at: Mutex<Option<RegistryVersion>>,
    }

    impl ThresholdSigVerifierByPublicKey<CatchUpContentProtobufBytes>
        for RegistryVersionRecordingCrypto
    {
        fn verify_combined_threshold_sig_by_public_key(
            &self,
            _signature: &CombinedThresholdSigOf<CatchUpContentProtobufBytes>,
            _message: &CatchUpContentProtobufBytes,
            _subnet_id: SubnetId,
            registry_version: RegistryVersion,
        ) -> CryptoResult<()> {
            *self.verified_at.lock().unwrap() = Some(registry_version);
            Ok(())
        }
    }

    /// Builds a CUP whose DKG summary registry version differs from the registry version of its
    /// block's validation context.
    fn cup_with_distinct_registry_versions(
        summary_registry_version: RegistryVersion,
        context_registry_version: RegistryVersion,
    ) -> pb::CatchUpPackage {
        let height = Height::from(10);
        let replica_version = ReplicaVersion::try_from("test").unwrap();

        let mut dkg = DkgSummary::fake();
        dkg.registry_version = summary_registry_version;

        let block = Block::new(
            CryptoHashOf::from(CryptoHash(vec![])),
            Payload::new(
                crypto_hash,
                BlockPayload::Summary(SummaryPayload { dkg, idkg: None }),
            ),
            height,
            Rank(0),
            ValidationContext {
                certified_height: height,
                registry_version: context_registry_version,
                time: UNIX_EPOCH,
            },
            replica_version.clone(),
        );

        let random_beacon = RandomBeacon::fake(RandomBeaconContent {
            version: replica_version,
            height,
            parent: CryptoHashOf::from(CryptoHash(vec![])),
        });

        let cup = CatchUpPackage::fake(CatchUpContent::new(
            HashedBlock::new(crypto_hash, block),
            HashedRandomBeacon::new(crypto_hash, random_beacon),
            CryptoHashOf::from(CryptoHash(vec![])),
            /*oldest_registry_version_in_use_by_replicated_state=*/ None,
        ));

        pb::CatchUpPackage::from(cup)
    }

    /// The registry version at which a peer CUP's signature is verified must be the same one that
    /// [`CatchUpPackageParam`] orders by, i.e. the DKG summary's registry version.
    #[tokio::test]
    async fn test_peer_cup_is_verified_at_the_dkg_summary_registry_version() {
        let summary_registry_version = RegistryVersion::from(3);
        let context_registry_version = RegistryVersion::from(7);
        let cup_proto =
            cup_with_distinct_registry_versions(summary_registry_version, context_registry_version);

        let server_addr = start_server(TestService::SendCup(Arc::new(Mutex::new(
            cup_proto.clone(),
        ))))
        .await;
        let node_id = node_test_id(1);
        let node_record = NodeRecord {
            http: Some(ConnectionEndpoint {
                ip_addr: server_addr.ip().to_string(),
                port: server_addr.port() as u32,
            }),
            ..Default::default()
        };

        let crypto = Arc::new(RegistryVersionRecordingCrypto::default());
        let tmp_dir = tempfile::tempdir().unwrap();
        let mut cup_provider = make_cup_provider_with_crypto(
            tmp_dir.path().to_path_buf(),
            node_id,
            Duration::from_secs(5),
            setup_registry(),
            crypto.clone(),
            no_op_logger(),
        );

        let (_, cup) = cup_provider
            .fetch_and_verify_catch_up_package(&node_id, &node_record, None, SUBNET_0)
            .await
            .expect("failed to fetch and verify the CUP")
            .expect("expected a CUP to be served");

        let verified_at = *crypto.verified_at.lock().unwrap();
        assert_eq!(verified_at, Some(summary_registry_version));
        assert_ne!(verified_at, Some(context_registry_version));
        assert_eq!(
            CatchUpPackageParam::from(&cup),
            CatchUpPackageParam::from(&CatchUpPackage::try_from(&cup_proto).unwrap()),
        );
    }

    fn fake_cup() -> pb::CatchUpPackage {
        pb::CatchUpPackage {
            content: vec![1, 2, 3, 4],
            signature: vec![5, 6, 7, 8],
            signer: None,
        }
    }

    async fn start_server(service: TestService) -> SocketAddr {
        let addr: SocketAddr = ([127, 0, 0, 1], 0).into();
        let listener = TcpListener::bind(addr).await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        let key_pair = KeyPair::generate().unwrap();
        let priv_key = PrivatePkcs8KeyDer::from(key_pair.serialize_der());
        let cert = CertificateDer::from(
            CertificateParams::new(vec![])
                .unwrap()
                .self_signed(&key_pair)
                .unwrap(),
        );

        let mut tls_cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], priv_key.into())
            .unwrap();
        tls_cfg.alpn_protocols = vec![
            b"h2".to_vec(), // HTTP/2
        ];

        let acceptor = TlsAcceptor::from(Arc::new(tls_cfg));
        tokio::spawn(async move {
            loop {
                let service = service.clone();
                let (tcp_stream, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                tokio::task::spawn(async move {
                    let service = service.clone();
                    let tls_stream = acceptor.accept(tcp_stream).await.unwrap();
                    let _ = http2::Builder::new(TokioExecutor::new())
                        .serve_connection(
                            TokioIo::new(tls_stream),
                            service_fn(|_req| test_service(service.clone())),
                        )
                        .await;
                });
            }
        });

        local_addr
    }

    /// Starts a TLS server serving the given CUP on any request. The returned handle allows tests
    /// to swap the served CUP afterwards.
    pub(crate) async fn start_cup_server(
        cup: pb::CatchUpPackage,
    ) -> (SocketAddr, Arc<Mutex<pb::CatchUpPackage>>) {
        let served_cup = Arc::new(Mutex::new(cup));
        let addr = start_server(TestService::SendCup(Arc::clone(&served_cup))).await;

        (addr, served_cup)
    }

    /// A node record pointing at the given address, e.g. one returned by [`start_cup_server`].
    pub(crate) fn node_record_serving(addr: SocketAddr) -> NodeRecord {
        NodeRecord {
            http: Some(ConnectionEndpoint {
                ip_addr: addr.ip().to_string(),
                port: addr.port() as u32,
            }),
            ..Default::default()
        }
    }

    fn setup_registry() -> Arc<RegistryHelper> {
        setup_registry_with_membership(RegistryVersion::from(1), vec![])
    }

    fn setup_registry_with_membership(
        registry_version: RegistryVersion,
        nodes: Vec<NodeId>,
    ) -> Arc<RegistryHelper> {
        let data_provider = Arc::new(ProtoRegistryDataProvider::new());
        add_single_subnet_record(
            &data_provider,
            registry_version.get(),
            SUBNET_0,
            SubnetRecordBuilder::new()
                .with_committee(nodes.as_slice())
                .build(),
        );

        for node in nodes {
            data_provider
                .add(
                    &make_node_record_key(node),
                    registry_version,
                    Some(NodeRecord::default()),
                )
                .unwrap();
        }

        let registry_client = Arc::new(FakeRegistryClient::new(data_provider));
        registry_client.update_to_latest_version();

        Arc::new(RegistryHelper::new(
            node_test_id(1),
            registry_client as Arc<_>,
            no_op_logger(),
        ))
    }

    /// The registry version at which the subnet split is set in the registry, and thus also the
    /// registry version of the post-split CUPs.
    pub(crate) const SPLIT_REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(10);
    pub(crate) const SOURCE_SUBNET_ID: SubnetId = SUBNET_1;
    pub(crate) const DESTINATION_SUBNET_ID: SubnetId = SUBNET_2;

    /// Creates a deserializable [`CatchUpPackage`] whose DKG summary carries the given committee,
    /// registry version and subnet splitting status.
    ///
    /// Unlike [`fake_cup`], the result survives a protobuf round-trip, including the integrity
    /// check of [`CatchUpContent`].
    pub(crate) fn make_splitting_cup_for_test(
        committee: Vec<NodeId>,
        height: Height,
        registry_version: RegistryVersion,
        subnet_splitting_status: SubnetSplittingStatus,
    ) -> CatchUpPackage {
        let fake_summary = DkgSummary::fake();
        let mut current_transcripts = fake_summary.current_transcripts().clone();
        let committee = NiDkgReceivers::new(committee.into_iter().collect()).unwrap();
        for transcript in current_transcripts.values_mut() {
            transcript.committee = committee.clone();
            // Stamp the given registry version on the transcripts as well, such that
            // `get_oldest_registry_version_in_use` agrees with the summary's registry version.
            transcript.registry_version = registry_version;
        }

        let dkg = DkgSummary::new(
            /*configs=*/ vec![],
            current_transcripts,
            /*next_transcripts=*/ Default::default(),
            registry_version,
            fake_summary.interval_length,
            fake_summary.next_interval_length,
            height,
            /*remote_dkg_attempts=*/ Default::default(),
            subnet_splitting_status,
        );

        let block = Block::new(
            CryptoHashOf::from(CryptoHash(Vec::new())),
            Payload::new(
                ic_types::crypto::crypto_hash,
                BlockPayload::Summary(SummaryPayload { dkg, idkg: None }),
            ),
            height,
            Rank(0),
            ValidationContext {
                registry_version,
                certified_height: Height::from(0),
                time: UNIX_EPOCH,
            },
            test_replica_version(),
        );

        let cup_content = CatchUpContent::new(
            HashedBlock::new(ic_types::crypto::crypto_hash, block),
            HashedRandomBeacon::new(
                ic_types::crypto::crypto_hash,
                RandomBeacon::fake(RandomBeaconContent::new(
                    height,
                    CryptoHashOf::from(CryptoHash(Vec::new())),
                    test_replica_version(),
                )),
            ),
            CryptoHashOf::from(CryptoHash(Vec::new())),
            None,
        );
        let mut cup_signature = ThresholdSignature::fake();
        cup_signature.signature = CombinedThresholdSigOf::new(CombinedThresholdSig(vec![1, 2, 3]));
        if matches!(subnet_splitting_status, SubnetSplittingStatus::PostSplit(_)) {
            // Post-split CUPs use transcripts from the registry
            cup_signature.signer.target_subnet =
                NiDkgTargetSubnet::Remote(NiDkgTargetId::new([0_u8; 32]));
        }

        Signed {
            content: cup_content,
            signature: cup_signature,
        }
    }

    /// Creates a post-split CUP at [`SPLIT_REGISTRY_VERSION`] announcing `new_subnet_id` as the
    /// subnet it belongs to.
    pub(crate) fn make_post_split_cup(
        committee: Vec<NodeId>,
        height: Height,
        new_subnet_id: SubnetId,
    ) -> CatchUpPackage {
        make_splitting_cup_for_test(
            committee,
            height,
            SPLIT_REGISTRY_VERSION,
            SubnetSplittingStatus::PostSplit(PostSplitArgs { new_subnet_id }),
        )
    }

    /// Sets up a registry describing a split of `SOURCE_SUBNET_ID` into `SOURCE_SUBNET_ID` and
    /// `DESTINATION_SUBNET_ID` at [`SPLIT_REGISTRY_VERSION`].
    ///
    /// Before the split, all given nodes are members of `SOURCE_SUBNET_ID`. From the split registry
    /// version onwards, `source_nodes` remain in `SOURCE_SUBNET_ID` while `destination_nodes` are
    /// members of `DESTINATION_SUBNET_ID`. Each node's record is built using `node_record`.
    fn setup_split_registry(
        node_id: NodeId,
        source_nodes: &[NodeId],
        destination_nodes: &[NodeId],
        mut node_record: impl FnMut(NodeId) -> NodeRecord,
    ) -> Arc<RegistryHelper> {
        let data_provider = Arc::new(ProtoRegistryDataProvider::new());
        add_subnet_list_record(
            &data_provider,
            1,
            vec![SOURCE_SUBNET_ID, DESTINATION_SUBNET_ID],
        );

        let all_nodes = [source_nodes, destination_nodes].concat();
        add_single_subnet_record(
            &data_provider,
            1,
            SOURCE_SUBNET_ID,
            SubnetRecordBuilder::new()
                .with_committee(&all_nodes)
                .build(),
        );
        add_single_subnet_record(
            &data_provider,
            SPLIT_REGISTRY_VERSION.get(),
            SOURCE_SUBNET_ID,
            SubnetRecordBuilder::new()
                .with_committee(source_nodes)
                .build(),
        );
        add_single_subnet_record(
            &data_provider,
            SPLIT_REGISTRY_VERSION.get(),
            DESTINATION_SUBNET_ID,
            SubnetRecordBuilder::new()
                .with_committee(destination_nodes)
                .build(),
        );

        for node in all_nodes {
            data_provider
                .add(
                    &make_node_record_key(node),
                    RegistryVersion::from(1),
                    Some(node_record(node)),
                )
                .unwrap();
        }

        let registry_client = Arc::new(FakeRegistryClient::new(data_provider));
        registry_client.update_to_latest_version();

        Arc::new(RegistryHelper::new(
            node_id,
            registry_client as Arc<_>,
            no_op_logger(),
        ))
    }

    pub(crate) fn mock_tls_config() -> MockTlsConfig {
        mock_tls_config_impl::<usize>(None)
    }

    pub(crate) fn mock_tls_config_called_times<Times: Into<mockall::TimesRange>>(
        times: Times,
    ) -> MockTlsConfig {
        mock_tls_config_impl(Some(times))
    }

    fn mock_tls_config_impl<Times: Into<mockall::TimesRange>>(
        opt_times: Option<Times>,
    ) -> MockTlsConfig {
        #[derive(Debug)]
        struct NoVerify;
        impl ServerCertVerifier for NoVerify {
            fn verify_server_cert(
                &self,
                _end_entity: &CertificateDer,
                _intermediates: &[CertificateDer],
                _server_name: &ServerName,
                _ocsp_response: &[u8],
                _now: UnixTime,
            ) -> Result<ServerCertVerified, rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }
            fn verify_tls12_signature(
                &self,
                _: &[u8],
                _: &CertificateDer<'_>,
                _: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(
                &self,
                _: &[u8],
                _: &CertificateDer<'_>,
                _: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                rustls::crypto::aws_lc_rs::default_provider()
                    .signature_verification_algorithms
                    .supported_schemes()
            }
        }

        let accept_any_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();

        let mut tls_config = MockTlsConfig::new();
        let expectation = tls_config
            .expect_client_config()
            .returning(move |_, _| Ok(accept_any_config.clone()));
        if let Some(t) = opt_times {
            expectation.times(t);
        }
        tls_config
    }

    fn make_cup_provider(
        cup_dir: PathBuf,
        node_id: NodeId,
        backoff: Duration,
    ) -> CatchUpPackageProvider {
        make_cup_provider_with_registry(cup_dir, node_id, backoff, setup_registry(), no_op_logger())
    }

    fn make_cup_provider_with_registry(
        cup_dir: PathBuf,
        node_id: NodeId,
        backoff: Duration,
        registry: Arc<RegistryHelper>,
        logger: ReplicaLogger,
    ) -> CatchUpPackageProvider {
        make_cup_provider_with_crypto(
            cup_dir,
            node_id,
            backoff,
            registry,
            Arc::new(CryptoReturningOk::default()),
            logger,
        )
    }

    fn make_cup_provider_with_crypto(
        cup_dir: PathBuf,
        node_id: NodeId,
        backoff: Duration,
        registry: Arc<RegistryHelper>,
        crypto: Arc<dyn ThresholdSigVerifierByPublicKey<CatchUpContentProtobufBytes> + Send + Sync>,
        logger: ReplicaLogger,
    ) -> CatchUpPackageProvider {
        CatchUpPackageProvider::new_with_initial_backoff(
            registry,
            Arc::new(OrchestratorMetrics::new(&MetricsRegistry::new())),
            LocalCUPReader::new(cup_dir, logger.clone()),
            crypto,
            Arc::new(mock_tls_config()),
            logger,
            node_id,
            backoff,
        )
    }

    #[tokio::test]
    async fn test_fetch_catch_up_package_body_request_times_out() {
        let send_cup = Arc::new(Mutex::new(false));
        let server_addr = start_server(TestService::SendBodyOrStall(send_cup.clone())).await;
        let url = format!("https://{server_addr}");
        let tmp_dir = tempfile::tempdir().unwrap();
        let node_id = node_test_id(1);

        let initial_backoff = Duration::from_secs(5);
        let mut cup_provider =
            make_cup_provider(tmp_dir.path().to_path_buf(), node_id, initial_backoff);

        let err = cup_provider
            .fetch_catch_up_package(&node_id, url.clone(), None)
            .await
            .expect_err("Expected timeout error when fetching CUP from slow server");

        assert!(
            err.contains("Timed out while reading CUP response body")
                && err.contains("after 5 secs: Elapsed(()). Setting backoff to 10 secs")
        );

        // Verify that the backoff was increased
        assert_eq!(cup_provider.backoff, Duration::from_secs(10));

        // Allow the next request to succeed
        *send_cup.lock().unwrap() = true;

        let cup = cup_provider
            .fetch_catch_up_package(&node_id, url, None)
            .await
            .expect("Expected to fetch the CUP successfully")
            .expect("Expected non-empty CUP");

        assert_eq!(cup, fake_cup());

        // Verify that the backoff was reset after a successful request
        assert_eq!(cup_provider.backoff, initial_backoff);
    }

    #[tokio::test]
    async fn test_fetch_catch_up_package_body_exceeds_size_limit() {
        // The server responds with a full CUP body.
        let server_addr =
            start_server(TestService::SendBodyOrStall(Arc::new(Mutex::new(true)))).await;
        let url = format!("https://{server_addr}");
        let tmp_dir = tempfile::tempdir().unwrap();
        let node_id = node_test_id(1);

        let mut cup_provider = make_cup_provider(
            tmp_dir.path().to_path_buf(),
            node_id,
            Duration::from_secs(5),
        );
        // Set a size limit far below the size of the CUP body the server sends, so that reading
        // the body is aborted rather than buffered in full.
        cup_provider.max_response_size_bytes = 4;

        let err = cup_provider
            .fetch_catch_up_package(&node_id, url, None)
            .await
            .expect_err("Expected an error when the CUP body exceeds the size limit");

        assert!(err.contains("LengthLimitError"), "Unexpected error: {err}");
    }

    #[tokio::test]
    async fn test_fetch_catch_up_package_unresponsive_times_out() {
        let server_addr = start_server(TestService::Unresponsive).await;
        let url = format!("https://{server_addr}");
        let tmp_dir = tempfile::tempdir().unwrap();
        let node_id = node_test_id(1);

        let mut cup_provider = make_cup_provider(
            tmp_dir.path().to_path_buf(),
            node_id,
            Duration::from_secs(5),
        );

        let err = cup_provider
            .fetch_catch_up_package(&node_id, url.clone(), None)
            .await
            .expect_err("Expected timeout error when fetching CUP from slow server");

        assert!(err.contains("Querying CUP endpoint") && err.contains("timed out: Elapsed(())"));
    }

    #[tokio::test]
    async fn test_fetch_catch_up_package_no_content() {
        let server_addr = start_server(TestService::NoContent).await;
        let url = format!("https://{server_addr}");
        let tmp_dir = tempfile::tempdir().unwrap();
        let node_id = node_test_id(1);

        let mut cup_provider = make_cup_provider(
            tmp_dir.path().to_path_buf(),
            node_id,
            Duration::from_secs(5),
        );

        let res = cup_provider
            .fetch_catch_up_package(&node_id, url.clone(), None)
            .await
            .expect("Expected no content");

        assert!(res.is_none());
    }

    #[tokio::test]
    async fn test_fetch_catch_up_package_bad_request() {
        let server_addr = start_server(TestService::BadRequest).await;
        let url = format!("https://{server_addr}");
        let tmp_dir = tempfile::tempdir().unwrap();
        let node_id = node_test_id(1);

        let mut cup_provider = make_cup_provider(
            tmp_dir.path().to_path_buf(),
            node_id,
            Duration::from_secs(5),
        );

        let err = cup_provider
            .fetch_catch_up_package(&node_id, url.clone(), None)
            .await
            .expect_err("Expected error when fetching CUP");

        assert!(err.contains("Status: 400 Bad Request, body: b\"error message\""));
    }

    #[test]
    fn test_select_peers_empty() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let node_id = node_test_id(1);
        let registry_version = RegistryVersion::from(1);

        let cup_provider = make_cup_provider(
            tmp_dir.path().to_path_buf(),
            node_id,
            Duration::from_secs(5),
        );

        // If there are no nodes on the subnet, no peers should be selected
        let peers = cup_provider.select_peers(SUBNET_0, registry_version, None);
        assert!(peers.is_empty());

        let peers = cup_provider.select_peers(SUBNET_0, registry_version, Some(&fake_cup()));
        assert!(peers.is_empty());
    }

    #[test]
    fn test_select_peers_only_one_node() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let node_id = node_test_id(1);
        let registry_version = RegistryVersion::from(1);
        let nodes = vec![node_id];
        let registry = setup_registry_with_membership(registry_version, nodes.clone());

        // We are the node
        let cup_provider_assigned = make_cup_provider_with_registry(
            tmp_dir.path().to_path_buf(),
            node_id,
            Duration::from_secs(5),
            registry.clone(),
            no_op_logger(),
        );

        // We are not the node
        let cup_provider_unassigned = make_cup_provider_with_registry(
            tmp_dir.path().to_path_buf(),
            node_test_id(2),
            Duration::from_secs(5),
            registry.clone(),
            no_op_logger(),
        );

        // If there is only one node on the subnet, it should always be used to fetch the CUP
        for cup in [None, Some(fake_cup())] {
            let selected =
                cup_provider_assigned.select_peers(SUBNET_0, registry_version, cup.as_ref());
            assert_eq!(selected.iter().map(|n| n.0).collect::<Vec<_>>(), nodes);
            let selected =
                cup_provider_unassigned.select_peers(SUBNET_0, registry_version, cup.as_ref());
            assert_eq!(selected.iter().map(|n| n.0).collect::<Vec<_>>(), nodes);
        }
    }

    #[test]
    fn test_select_peers_multiple_nodes_assigned() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let node_id = node_test_id(1);
        let registry_version = RegistryVersion::from(1);
        let nodes = (1..=7).map(node_test_id).collect::<Vec<_>>();
        let registry = setup_registry_with_membership(registry_version, nodes.clone());

        let cup_provider = make_cup_provider_with_registry(
            tmp_dir.path().to_path_buf(),
            node_id,
            Duration::from_secs(5),
            registry.clone(),
            no_op_logger(),
        );

        // If there is a cup, two nodes should be selected, and this node should be the first one
        let selected_with_cup = cup_provider
            .select_peers(SUBNET_0, registry_version, Some(&fake_cup()))
            .iter()
            .map(|n| n.0)
            .collect::<Vec<_>>();
        assert_matches!(&selected_with_cup[..], &[first, _] if first == node_id);

        // If there is no cup, all nodes should be selected
        let selected_without_cup = cup_provider
            .select_peers(SUBNET_0, registry_version, None)
            .iter()
            .map(|n| n.0)
            .collect::<Vec<_>>();
        assert_eq!(nodes.len(), selected_without_cup.len())
    }

    #[test]
    fn test_select_peers_multiple_nodes_unassigned() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let node_id = node_test_id(8);
        let registry_version = RegistryVersion::from(1);
        let nodes = (1..=7).map(node_test_id).collect::<Vec<_>>();
        let registry = setup_registry_with_membership(registry_version, nodes.clone());

        let cup_provider = make_cup_provider_with_registry(
            tmp_dir.path().to_path_buf(),
            node_id,
            Duration::from_secs(5),
            registry.clone(),
            no_op_logger(),
        );

        // If there is a cup, only one node should be selected
        let selected_with_cup =
            cup_provider.select_peers(SUBNET_0, registry_version, Some(&fake_cup()));
        assert_eq!(1, selected_with_cup.len());
        assert_ne!(selected_with_cup[0].0, node_id);

        // If there is no cup, all nodes should be selected
        let selected_without_cup = cup_provider.select_peers(SUBNET_0, registry_version, None);
        assert_eq!(nodes.len(), selected_without_cup.len());
        assert!(!selected_without_cup.iter().any(|(id, _)| id == &node_id));
    }

    #[rstest]
    #[case::stays_and_contacts_source(SOURCE_SUBNET_ID, SOURCE_SUBNET_ID)]
    #[case::stays_and_contacts_destination(SOURCE_SUBNET_ID, DESTINATION_SUBNET_ID)]
    #[case::moves_and_contacts_source(DESTINATION_SUBNET_ID, SOURCE_SUBNET_ID)]
    #[case::moves_and_contacts_destination(DESTINATION_SUBNET_ID, DESTINATION_SUBNET_ID)]
    fn test_post_split_cup(#[case] new_subnet_id: SubnetId, #[case] contacted_subnet_id: SubnetId) {
        let tmp_dir = tempfile::tempdir().unwrap();
        let source_nodes = vec![node_test_id(1)];
        let destination_nodes = vec![node_test_id(2)];
        let node_id = if new_subnet_id == SOURCE_SUBNET_ID {
            source_nodes[0]
        } else {
            destination_nodes[0]
        };
        let registry = setup_split_registry(node_id, &source_nodes, &destination_nodes, |_| {
            NodeRecord::default()
        });
        let mut cup_provider = make_cup_provider_with_registry(
            tmp_dir.path().to_path_buf(),
            node_id,
            Duration::from_secs(5),
            registry,
            no_op_logger(),
        );

        let committee = if contacted_subnet_id == SOURCE_SUBNET_ID {
            source_nodes
        } else {
            destination_nodes
        };
        let cup = make_post_split_cup(committee, Height::from(100), contacted_subnet_id);

        assert_eq!(
            cup_provider.is_splitting_cup_for_other_subnet(&cup),
            new_subnet_id != contacted_subnet_id
        );
        // We should remember our new subnet, such that the next CUP is fetched from its peers.
        assert_eq!(
            cup_provider.split_in_progress_subnet_id,
            Some(new_subnet_id)
        );
    }

    #[rstest]
    #[case::contacts_source(SOURCE_SUBNET_ID)]
    #[case::contacts_destination(DESTINATION_SUBNET_ID)]
    fn test_post_split_cup_is_rejected_if_our_subnet_is_unknown(
        #[case] contacted_subnet_id: SubnetId,
    ) {
        let tmp_dir = tempfile::tempdir().unwrap();
        let source_nodes = vec![node_test_id(1)];
        let destination_nodes = vec![node_test_id(2)];
        let node_id = node_test_id(3);
        // We are member of neither subnet at the split registry version.
        let registry = setup_split_registry(node_id, &source_nodes, &destination_nodes, |_| {
            NodeRecord::default()
        });
        let logger = InMemoryReplicaLogger::new();
        let mut cup_provider = make_cup_provider_with_registry(
            tmp_dir.path().to_path_buf(),
            node_id,
            Duration::from_secs(5),
            registry,
            ReplicaLogger::from(&logger),
        );

        let committee = if contacted_subnet_id == SOURCE_SUBNET_ID {
            source_nodes
        } else {
            destination_nodes
        };
        let cup = make_post_split_cup(committee, Height::from(100), contacted_subnet_id);

        // We can't tell whether the CUP is ours, so we conservatively reject it and retry later.
        assert!(cup_provider.is_splitting_cup_for_other_subnet(&cup));
        assert_eq!(cup_provider.split_in_progress_subnet_id, None);

        LogEntriesAssert::assert_that(logger.drain_logs())
            .has_only_one_message_containing(&Level::Warning, "Failed to get subnet id for node");
    }

    #[test]
    #[should_panic(expected = "Received a signed CUP with scheduled subnet splitting")]
    fn test_scheduled_splitting_cup_panics_in_debug() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let node_id = node_test_id(1);
        let registry = setup_split_registry(node_id, &[node_id], &[node_test_id(2)], |_| {
            NodeRecord::default()
        });
        let mut cup_provider = make_cup_provider_with_registry(
            tmp_dir.path().to_path_buf(),
            node_id,
            Duration::from_secs(5),
            registry,
            no_op_logger(),
        );

        let cup = make_splitting_cup_for_test(
            vec![node_id],
            Height::from(100),
            SPLIT_REGISTRY_VERSION,
            SubnetSplittingStatus::Scheduled(SplittingArgs {
                source_subnet_id: SUBNET_1,
                destination_subnet_id: SUBNET_2,
            }),
        );

        cup_provider.is_splitting_cup_for_other_subnet(&cup);
    }

    #[rstest]
    #[case::stays_so_contacts_source_directly(SOURCE_SUBNET_ID, SPLIT_REGISTRY_VERSION)]
    #[case::stays_but_unfortunately_outdated_and_contacts_all_nodes(SOURCE_SUBNET_ID, SPLIT_REGISTRY_VERSION - 1.into())]
    #[case::moves_and_contacts_source_first(DESTINATION_SUBNET_ID, SPLIT_REGISTRY_VERSION)]
    #[case::moves_outdated_contacts_all_nodes(
        DESTINATION_SUBNET_ID,
        SPLIT_REGISTRY_VERSION - 1.into(),
    )]
    #[tokio::test]
    async fn test_get_peer_cup_first_ignores_wrong_cup_then_selects_correct_peers_after_split(
        #[case] new_subnet_id: SubnetId,
        #[case] initial_looked_up_registry_version_for_source_membership: RegistryVersion,
    ) {
        let tmp_dir = tempfile::tempdir().unwrap();
        let source_nodes = vec![node_test_id(1)];
        let destination_nodes = vec![node_test_id(2)];
        let node_id = if new_subnet_id == SOURCE_SUBNET_ID {
            source_nodes[0]
        } else {
            destination_nodes[0]
        };
        let height = Height::from(200);

        let (source_server_addr, _source_served_cup) = start_cup_server(pb::CatchUpPackage::from(
            make_post_split_cup(source_nodes.clone(), height, SOURCE_SUBNET_ID),
        ))
        .await;
        let (dest_server_addr, _dest_served_cup) = start_cup_server(pb::CatchUpPackage::from(
            make_post_split_cup(destination_nodes.clone(), height, DESTINATION_SUBNET_ID),
        ))
        .await;
        let registry =
            setup_split_registry(node_id, &source_nodes, &destination_nodes, |node_id| {
                if node_id == source_nodes[0] {
                    node_record_serving(source_server_addr)
                } else {
                    node_record_serving(dest_server_addr)
                }
            });

        let logger = InMemoryReplicaLogger::new();
        let mut cup_provider = make_cup_provider_with_registry(
            tmp_dir.path().to_path_buf(),
            node_id,
            Duration::from_secs(5),
            registry.clone(),
            ReplicaLogger::from(&logger),
        );

        let mut known_subnet_id = SOURCE_SUBNET_ID;
        // The first time we try to fetch a peer CUP after a post-split CUP has been created, we
        // are still under the old subnet ID so we will always contact the source subnet's peers.
        // Though its membership is looked up at the *latest* registry verison, meaning the *new*
        // source subnet. If we are behind, we might look at a registry version that still lists the
        // full committee for the source subnet, so we expect to contact all of them. In that case,
        // we will end up fetching our post-split CUP.
        let maybe_fetched = cup_provider
            .get_peer_cup(
                known_subnet_id,
                initial_looked_up_registry_version_for_source_membership,
                None,
            )
            .await;
        let condition_if_fetched = new_subnet_id == SOURCE_SUBNET_ID
            || initial_looked_up_registry_version_for_source_membership < SPLIT_REGISTRY_VERSION;
        if let Some(fetched) = maybe_fetched {
            assert!(condition_if_fetched);
            let fetched = CatchUpPackage::try_from(&fetched).unwrap();
            assert_eq!(fetched.height(), height);
            assert_eq!(
                fetched.subnet_splitting_status(),
                SubnetSplittingStatus::PostSplit(PostSplitArgs { new_subnet_id })
            );

            // At this moment, we know we are part of the new subnet
            known_subnet_id = new_subnet_id;
        } else {
            assert!(!condition_if_fetched);
            LogEntriesAssert::assert_that(logger.drain_logs()).has_only_one_message_containing(
                &Level::Info,
                "because it is for the other subnet",
            );
        }
        // In any case, we should detect the new subnet ID we should be in, and remember it for the
        // next iteration.
        assert_eq!(
            cup_provider.split_in_progress_subnet_id,
            Some(new_subnet_id)
        );

        // Next iteration, we should contact the peers of the new subnet ID
        let fetched = cup_provider
            .get_peer_cup(known_subnet_id, SPLIT_REGISTRY_VERSION, None)
            .await
            .expect("On the second iteration, we should fetch the post-split CUP of our subnet");
        let fetched = CatchUpPackage::try_from(&fetched).unwrap();
        assert_eq!(fetched.height(), height);
        assert_eq!(
            fetched.subnet_splitting_status(),
            SubnetSplittingStatus::PostSplit(PostSplitArgs { new_subnet_id })
        );
    }

    #[test]
    fn test_regular_cup_is_accepted_and_clears_split_in_progress() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let node_id = node_test_id(1);
        // We move to the destination subnet.
        let registry = setup_split_registry(node_id, &[node_test_id(2)], &[node_id], |_| {
            NodeRecord::default()
        });
        let mut cup_provider = make_cup_provider_with_registry(
            tmp_dir.path().to_path_buf(),
            node_id,
            Duration::from_secs(5),
            registry,
            no_op_logger(),
        );
        // Pretend that we detected a split in progress during a previous iteration.
        cup_provider.split_in_progress_subnet_id = Some(DESTINATION_SUBNET_ID);

        // The next CUP that the subnet creates sets back the splitting status to `NotScheduled`,
        // which should clear the `split_in_progress_subnet_id` field.
        let cup = make_splitting_cup_for_test(
            vec![node_id],
            Height::from(100),
            SPLIT_REGISTRY_VERSION,
            SubnetSplittingStatus::NotScheduled,
        );

        assert!(!cup_provider.is_splitting_cup_for_other_subnet(&cup));
        // A regular CUP means that the split is over, so we forget about it.
        assert_eq!(cup_provider.split_in_progress_subnet_id, None);
    }
}
