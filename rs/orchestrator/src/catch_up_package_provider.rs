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
    registry_helper::RegistryHelper,
    utils::https_endpoint_to_url,
};
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, StatusCode, body::Bytes};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use ic_crypto_tls_interfaces::TlsConfig;
use ic_interfaces::crypto::ThresholdSigVerifierByPublicKey;
use ic_logger::{ReplicaLogger, info, warn};
use ic_protobuf::{registry::node::v1::NodeRecord, types::v1 as pb};
use ic_sys::fs::write_protobuf_using_tmp_file;
use ic_types::{
    Height, NodeId, RegistryVersion, SubnetId,
    consensus::{
        HasHeight,
        catchup::{CatchUpContentProtobufBytes, CatchUpPackage, CatchUpPackageParam},
    },
    crypto::*,
};
use prost::Message;
use std::{convert::TryFrom, fs::File, path::PathBuf, sync::Arc, time::Duration};
#[allow(clippy::disallowed_types)]
use tokio::sync::Mutex;
use tokio::time::timeout;

/// Fetches catch-up packages from peers and local storage.
///
/// CUPs are used to determine which version of the IC peers are running
/// and hence which version of the IC this node should be starting.
pub(crate) struct CatchUpPackageProvider {
    registry: Arc<RegistryHelper>,
    cup_dir: PathBuf,
    crypto: Arc<dyn ThresholdSigVerifierByPublicKey<CatchUpContentProtobufBytes> + Send + Sync>,
    crypto_tls_config: Arc<dyn TlsConfig>,
    logger: ReplicaLogger,
    node_id: NodeId,
    #[allow(clippy::disallowed_types)]
    // Use a tokio mutex because the lock needs to be held across an await point,
    // and this code isn't performance-critical.
    backoff: Mutex<Duration>,
    initial_backoff: Duration,
}

impl CatchUpPackageProvider {
    /// Instantiate a new `CatchUpPackageProvider`
    pub(crate) fn new(
        registry: Arc<RegistryHelper>,
        cup_dir: PathBuf,
        crypto: Arc<dyn ThresholdSigVerifierByPublicKey<CatchUpContentProtobufBytes> + Send + Sync>,
        crypto_tls_config: Arc<dyn TlsConfig>,
        logger: ReplicaLogger,
        node_id: NodeId,
    ) -> Self {
        Self::new_with_initial_backoff(
            registry,
            cup_dir,
            crypto,
            crypto_tls_config,
            logger,
            node_id,
            Duration::from_secs(30),
        )
    }

    fn new_with_initial_backoff(
        registry: Arc<RegistryHelper>,
        cup_dir: PathBuf,
        crypto: Arc<dyn ThresholdSigVerifierByPublicKey<CatchUpContentProtobufBytes> + Send + Sync>,
        crypto_tls_config: Arc<dyn TlsConfig>,
        logger: ReplicaLogger,
        node_id: NodeId,
        initial_backoff: Duration,
    ) -> Self {
        Self {
            node_id,
            registry,
            cup_dir,
            crypto,
            crypto_tls_config,
            logger,
            #[allow(clippy::disallowed_types)]
            backoff: Mutex::new(initial_backoff),
            initial_backoff,
        }
    }

    fn select_peers(
        &self,
        subnet_id: SubnetId,
        registry_version: RegistryVersion,
        current_cup: Option<&pb::CatchUpPackage>,
    ) -> Vec<(NodeId, NodeRecord)> {
        use ic_registry_client_helpers::subnet::SubnetTransportRegistry;
        use rand::seq::SliceRandom;

        let mut nodes: Vec<(NodeId, NodeRecord)> = self
            .registry
            .registry_client
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
        &self,
        subnet_id: SubnetId,
        registry_version: RegistryVersion,
        current_cup: Option<&pb::CatchUpPackage>,
    ) -> Option<pb::CatchUpPackage> {
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
                Ok(Some((proto, cup))) => {
                    // Note: None is < Some(_)
                    if Some(CatchUpPackageParam::from(&cup)) > param {
                        return Some(proto);
                    }
                }
                Ok(None) => {}
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
        &self,
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
                cup.content.block.get_value().context.registry_version,
            )
            .map_err(|e| format!("Failed to verify CUP signature at: {uri:?} with: {e:?}"))?;

        Ok(Some((protobuf, cup)))
    }

    // Attempt to fetch a `CatchUpPackage` from the given endpoint.
    //
    // Does not check the signature of the CUP. This has to be done by the
    // caller.
    async fn fetch_catch_up_package(
        &self,
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
        let mut backoff = self.backoff.lock().await;
        let body_req = timeout(*backoff, res.into_body().collect());

        let bytes = match body_req.await {
            Ok(result) => {
                // Reset backoff on success
                *backoff = self.initial_backoff;
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
                let old_backoff = *backoff;
                *backoff = old_backoff.saturating_mul(2);
                return Err(format!(
                    "Timed out while reading CUP response body of {} after {} secs: {:?}. Setting backoff to {} secs",
                    url,
                    old_backoff.as_secs(),
                    timeout_err,
                    backoff.as_secs()
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
            "Persisting CUP (registry version={}, height={}) to file {}",
            cup.content.registry_version(),
            cup.height(),
            &cup_file_path.display(),
        );
        write_protobuf_using_tmp_file(&cup_file_path, cup_proto).map_err(|e| {
            OrchestratorError::IoError(
                format!("Failed to serialize protobuf to disk: {:?}", &cup_file_path),
                e,
            )
        })?;

        Ok(cup_file_path)
    }

    /// The path that should be used to save the CUP for the assigned subnet.
    /// Includes the specific type encoded in the file for future-proofing and
    /// ease of debugging.
    pub(crate) fn get_cup_path(&self) -> PathBuf {
        self.cup_dir.join("cup.types.v1.CatchUpPackage.pb")
    }

    /// Return the most up to date CUP.
    ///
    /// Choose the highest CUP among: those provided by the subnet peers,
    /// the locally persisted CUP (if one exists) and the CUP that is specified
    /// by the registry. If we manage to find a newer CUP we also persist it.
    pub(crate) async fn get_latest_cup(
        &self,
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
        // subnet recover with failover nodes, all nodes before upgrading to B might have been on
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

    // Returns the locally persisted CUP in deserialized form
    pub(crate) fn get_local_cup(&self) -> Option<CatchUpPackage> {
        match self.get_local_cup_proto() {
            None => None,
            Some(cup_proto) => (&cup_proto)
                .try_into()
                .map_err(|err| warn!(self.logger, "Deserialization of CUP failed: {}", err))
                .ok(),
        }
    }

    /// Returns the locally persisted CUP in protobuf form
    pub(crate) fn get_local_cup_proto(&self) -> Option<pb::CatchUpPackage> {
        let path = self.get_cup_path();
        if !path.exists() {
            return None;
        }
        match File::open(&path) {
            Ok(reader) => pb::CatchUpPackage::read_from_reader(reader)
                .map_err(|e| warn!(self.logger, "Failed to read CUP from file {:?}", e))
                .ok(),
            Err(err) => {
                warn!(self.logger, "Couldn't open file {:?}: {:?}", path, err);
                None
            }
        }
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
mod tests {
    use super::*;
    use crate::{
        catch_up_package_provider::CatchUpPackageProvider, registry_helper::RegistryHelper,
    };
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
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_keys::make_node_record_key;
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_test_utilities_registry::{SubnetRecordBuilder, add_single_subnet_record};
    use ic_test_utilities_types::ids::{SUBNET_0, node_test_id};
    use rcgen::{CertificateParams, KeyPair};
    use rustls::{
        ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    };
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
    }

    async fn test_service(
        service: TestService,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
        match service {
            TestService::SendBodyOrStall(send_cup) => slow_body_service(send_cup).await,
            TestService::Unresponsive => unresponsive_service().await,
            TestService::NoContent => no_content_service().await,
            TestService::BadRequest => error_service().await,
        }
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

    fn mock_tls_config() -> MockTlsConfig {
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
                rustls::crypto::ring::default_provider()
                    .signature_verification_algorithms
                    .supported_schemes()
            }
        }

        let accept_any_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();

        let mut tls_config = MockTlsConfig::new();
        tls_config
            .expect_client_config()
            .returning(move |_, _| Ok(accept_any_config.clone()));
        tls_config
    }

    fn make_cup_provider(
        cup_dir: PathBuf,
        node_id: NodeId,
        backoff: Duration,
    ) -> CatchUpPackageProvider {
        make_cup_provider_with_registry(cup_dir, node_id, backoff, setup_registry())
    }

    fn make_cup_provider_with_registry(
        cup_dir: PathBuf,
        node_id: NodeId,
        backoff: Duration,
        registry: Arc<RegistryHelper>,
    ) -> CatchUpPackageProvider {
        CatchUpPackageProvider::new_with_initial_backoff(
            registry,
            cup_dir,
            Arc::new(CryptoReturningOk::default()),
            Arc::new(mock_tls_config()),
            no_op_logger(),
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
        let cup_provider =
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
        {
            let backoff = cup_provider.backoff.lock().await;
            assert_eq!(*backoff, Duration::from_secs(10));
        }

        // Allow the next request to succeed
        *send_cup.lock().unwrap() = true;

        let cup = cup_provider
            .fetch_catch_up_package(&node_id, url, None)
            .await
            .expect("Expected to fetch the CUP successfully")
            .expect("Expected non-empty CUP");

        assert_eq!(cup, fake_cup());

        // Verify that the backoff was reset after a successful request
        {
            let backoff = cup_provider.backoff.lock().await;
            assert_eq!(*backoff, initial_backoff);
        }
    }

    #[tokio::test]
    async fn test_fetch_catch_up_package_unresponsive_times_out() {
        let server_addr = start_server(TestService::Unresponsive).await;
        let url = format!("https://{server_addr}");
        let tmp_dir = tempfile::tempdir().unwrap();
        let node_id = node_test_id(1);

        let cup_provider = make_cup_provider(
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

        let cup_provider = make_cup_provider(
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

        let cup_provider = make_cup_provider(
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
        );

        // We are not the node
        let cup_provider_unassigned = make_cup_provider_with_registry(
            tmp_dir.path().to_path_buf(),
            node_test_id(2),
            Duration::from_secs(5),
            registry.clone(),
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
}
