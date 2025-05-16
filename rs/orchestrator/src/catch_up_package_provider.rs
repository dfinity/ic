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
    utils::http_endpoint_to_url,
};
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, Method, Request};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use ic_crypto_tls_interfaces::TlsConfig;
use ic_interfaces::crypto::ThresholdSigVerifierByPublicKey;
use ic_logger::{info, warn, ReplicaLogger};
use ic_protobuf::{registry::node::v1::NodeRecord, types::v1 as pb};
use ic_sys::fs::write_protobuf_using_tmp_file;
use ic_types::{
    consensus::{
        catchup::{CatchUpContentProtobufBytes, CatchUpPackage, CatchUpPackageParam},
        HasHeight,
    },
    crypto::*,
    Height, NodeId, RegistryVersion, SubnetId,
};
use prost::Message;
use std::{convert::TryFrom, fs::File, path::PathBuf, sync::Arc};

#[cfg(not(test))]
const TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(10);
#[cfg(test)]
const TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(1);

/// Fetches catch-up packages from peers and local storage.
///
/// CUPs are used to determine which version of the IC peers are running
/// and hence which version of the IC this node should be starting.
#[derive(Clone)]
pub(crate) struct CatchUpPackageProvider {
    registry: Arc<RegistryHelper>,
    cup_dir: PathBuf,
    crypto: Arc<dyn ThresholdSigVerifierByPublicKey<CatchUpContentProtobufBytes> + Send + Sync>,
    crypto_tls_config: Arc<dyn TlsConfig + Send + Sync>,
    logger: ReplicaLogger,
    node_id: NodeId,
}

impl CatchUpPackageProvider {
    /// Instantiate a new `CatchUpPackageProvider`
    pub(crate) fn new(
        registry: Arc<RegistryHelper>,
        cup_dir: PathBuf,
        crypto: Arc<dyn ThresholdSigVerifierByPublicKey<CatchUpContentProtobufBytes> + Send + Sync>,
        crypto_tls_config: Arc<dyn TlsConfig + Send + Sync>,
        logger: ReplicaLogger,
        node_id: NodeId,
    ) -> Self {
        Self {
            node_id,
            registry,
            cup_dir,
            crypto,
            crypto_tls_config,
            logger,
        }
    }

    // Randomly selects a peer from the subnet and pulls its CUP. If this CUP is
    // newer than the currently available one and it could be verified, then this
    // CUP is returned. Note that it is acceptable to use a single peer, because
    // CUPs are validated. If all `f` nodes serve unusable CUPs, we have a probability
    // of 2/3 to hit a non-faulty node, so roughly on 4th attempt we should obtain
    // the correct peer CUP.
    async fn get_peer_cup(
        &self,
        subnet_id: SubnetId,
        registry_version: RegistryVersion,
        current_cup: Option<&pb::CatchUpPackage>,
    ) -> Option<pb::CatchUpPackage> {
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
        let current_node = nodes
            .as_slice()
            .iter()
            .find(|t| t.0 == self.node_id)
            .cloned();

        // Try only one peer at-a-time if there is already a local CUP,
        // Otherwise, try not to fall back to the registry CUP.
        let mut peers = match current_cup {
            Some(_) => vec![nodes.pop().or_else(|| {
                warn!(
                    self.logger,
                    "Empty peer list for subnet {} at version {}", subnet_id, registry_version
                );
                None
            })?],
            None => nodes,
        };

        // If we are still a member of the subnet, append our own data so that we first try to
        // fetch the CUP from our own replica. This improves the upgrade behaviour of a healthy
        // subnet, as we decrease the probability hitting peers who already started the upgrade
        // process and will not serve a CUP until they're online again.
        if let Some(current_node) = current_node {
            peers.push(current_node);
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
                    return Some(proto);
                }
                Ok(_) => {}
                Err(err) => {
                    warn!(
                        self.logger,
                        "Failed to fetch and verify the CUP from {node_id}: {err}"
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
        let http = node_record
            .http
            .as_ref()
            .ok_or_else(|| format!("Node record's http endpoint is None: {:?}", node_record))?;
        let mut uri = http_endpoint_to_url(http, &self.logger)
            .ok_or_else(|| format!("Failed to convert endpoint '{http:?}' to url"))?;
        uri.path_segments_mut()
            .map_err(|()| String::from("Invalid url"))?
            .push("_")
            .push("catch_up_package");

        let uri = uri.to_string();

        let Some(protobuf) = self.fetch_catch_up_package(node_id, &uri, param).await? else {
            return Ok(None);
        };
        let cup = CatchUpPackage::try_from(&protobuf)
            .map_err(|e| format!("Failed to read CUP from peer at url {}: {:?}", uri, e))?;

        self.crypto
            .verify_combined_threshold_sig_by_public_key(
                &CombinedThresholdSigOf::new(CombinedThresholdSig(protobuf.signature.clone())),
                &CatchUpContentProtobufBytes::from(&protobuf),
                subnet_id,
                cup.content.block.get_value().context.registry_version,
            )
            .map_err(|e| format!("Failed to verify CUP signature at: {:?} with: {:?}", uri, e))?;

        Ok(Some((protobuf, cup)))
    }

    // Attempt to fetch a `CatchUpPackage` from the given endpoint.
    //
    // Does not check the signature of the CUP. This has to be done by the
    // caller.
    async fn fetch_catch_up_package(
        &self,
        node_id: &NodeId,
        url: &str,
        param: Option<CatchUpPackageParam>,
    ) -> Result<Option<pb::CatchUpPackage>, String> {
        info!(self.logger, "Fetching CUP from {node_id} @ {url}.");
        let body = Bytes::from(
            param
                .and_then(|param| serde_cbor::to_vec(&param).ok())
                .unwrap_or_default(),
        );

        let client_config = self
            .crypto_tls_config
            .client_config(*node_id, self.registry.get_latest_version())
            .map_err(|e| format!("Failed to create tls client config: {:?}", e))?;

        let https = HttpsConnectorBuilder::new()
            .with_tls_config(client_config)
            .https_only()
            .enable_all_versions()
            .build();

        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(tokio::time::Duration::from_secs(600))
            .pool_max_idle_per_host(1)
            .build::<_, Full<Bytes>>(https);

        let request = Request::builder()
            .method(Method::POST)
            .header(hyper::header::CONTENT_TYPE, "application/cbor")
            .uri(url)
            .body(Full::from(body))
            .map_err(|e| format!("Failed to create request: {:?}", e))?;

        let req = tokio::time::timeout(TIMEOUT, client.request(request));

        let res = req
            .await
            .map_err(|e| format!("Querying CUP endpoint timed out: {:?}", e))?
            .map_err(|e| format!("Failed to query CUP endpoint: {:?}", e))?;

        let bytes = res
            .into_body()
            .collect()
            .await
            .map_err(|e| format!("Failed to convert the response body to bytes: {:?}", e))?
            .to_bytes();

        let cup = if bytes.is_empty() {
            None
        } else {
            Some(
                pb::CatchUpPackage::decode(&bytes[..])
                    .map_err(|e| format!("Failed to deserialize CUP from protobuf: {:?}", e))?,
            )
        };

        Ok(cup)
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
    use std::net::SocketAddr;

    use super::*;
    use axum::{body::Body, response::IntoResponse, Router};
    use axum_server::tls_rustls::RustlsConfig;
    use futures::Stream;
    use hyper::{body::Incoming, Response, StatusCode};
    use hyper_util::rt::TokioIo;
    use ic_crypto_tls_interfaces_mocks::MockTlsConfig;
    use ic_logger::no_op_logger;
    use ic_protobuf::types::v1 as pb;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_client_helpers::node::ConnectionEndpoint;
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_test_utilities::crypto::CryptoReturningOk;
    use ic_test_utilities_consensus::fake::{Fake, FakeContent};
    use ic_test_utilities_types::ids::{NODE_1, NODE_2, SUBNET_1};
    use ic_types::{
        batch::ValidationContext,
        consensus::{
            Block, BlockPayload, CatchUpContent, HashedBlock, HashedRandomBeacon, Payload,
            RandomBeacon, RandomBeaconContent, Rank, SummaryPayload,
        },
        signature::ThresholdSignature,
        time::UNIX_EPOCH,
        ReplicaVersion,
    };
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::{
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, ServerName, UnixTime},
        ClientConfig, DigitallySignedStruct, SignatureScheme,
    };
    use tokio::io::{AsyncRead, AsyncWrite};
    use tower::Service;

    // TODO: export this to some test utilities crate as the same function is used in
    // http_endpoints_public crate.
    async fn generate_self_signed_cert() -> RustlsConfig {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();

        let cert_der = CertificateDer::from(cert);

        RustlsConfig::from_der(vec![cert_der.as_ref().to_vec()], key_pair.serialize_der())
            .await
            .unwrap()
    }

    /// Get a free port on this host to which we can connect transport to.
    // TODO: export this to some test utilities crate as the same function is used in
    // http_endpoints_public crate.
    fn get_free_localhost_socket_addr() -> SocketAddr {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_reuseport(false).unwrap();
        socket.set_reuseaddr(false).unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        socket.local_addr().unwrap()
    }

    // TODO: export this to some test utilities crate as the same function is used in
    // http_endpoints_public crate.
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

    async fn serve_http<S: AsyncRead + AsyncWrite + Unpin + 'static>(stream: S, router: Router) {
        let stream = TokioIo::new(stream);
        let hyper_service = hyper::service::service_fn(move |request: Request<Incoming>| {
            router.clone().call(request)
        });
        hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
            .http2()
            .serve_connection(stream, hyper_service)
            .await
            .unwrap();
    }

    struct EndlessStream;

    impl Stream for EndlessStream {
        type Item = Result<axum::body::Bytes, String>;

        fn poll_next(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            std::task::Poll::Pending
        }
    }

    #[derive(Clone)]
    enum MockResponse {
        Empty,
        Cup(pb::CatchUpPackage),
        DelayedIndefinitely,
        BodyDelayedIndefinitely,
    }

    async fn mock_server(mock_response: MockResponse) -> NodeRecord {
        let addr = get_free_localhost_socket_addr();
        let tcp_listener = tokio::net::TcpListener::bind(addr).await.unwrap();

        let node_record = NodeRecord {
            http: Some(ConnectionEndpoint {
                ip_addr: addr.ip().to_string(),
                port: addr.port() as u32,
            }),
            ..Default::default()
        };

        tokio::spawn(async move {
            let router = Router::new().route(
                "/_/catch_up_package",
                axum::routing::any(async move || match mock_response {
                    MockResponse::Empty => StatusCode::NO_CONTENT.into_response(),
                    MockResponse::Cup(catch_up_package) => {
                        let bytes = catch_up_package.encode_to_vec();
                        Response::new(Body::new(Full::from(bytes)))
                    }
                    MockResponse::DelayedIndefinitely => {
                        tokio::time::sleep(tokio::time::Duration::from_secs(60 * 60)).await;
                        StatusCode::REQUEST_TIMEOUT.into_response()
                    }
                    MockResponse::BodyDelayedIndefinitely => {
                        Response::new(Body::from_stream(EndlessStream {}))
                    }
                }),
            );

            let (stream, _remote_addr) = tcp_listener.accept().await.unwrap();
            let mut b = [0_u8; 1];
            stream.peek(&mut b).await.unwrap();
            // TLS handshake.
            if b[0] == 22 {
                let config = generate_self_signed_cert().await;
                let tls_acceptor = tokio_rustls::TlsAcceptor::from(config.get_inner());
                serve_http(tls_acceptor.accept(stream).await.unwrap(), router).await;
            } else {
                serve_http(stream, router).await;
            }
        });

        node_record
    }

    async fn set_up_dependencies(
        mock_response: MockResponse,
    ) -> (CatchUpPackageProvider, NodeRecord) {
        let data_provider = Arc::new(ProtoRegistryDataProvider::new());
        let registry_client =
            Arc::new(FakeRegistryClient::new(Arc::clone(&data_provider) as Arc<_>));
        let node_id = NODE_1;

        let node_record = mock_server(mock_response).await;

        let cup_provider = CatchUpPackageProvider {
            registry: Arc::new(RegistryHelper::new(
                node_id,
                registry_client,
                no_op_logger(),
            )),
            cup_dir: PathBuf::from("/tmp"),
            crypto: Arc::new(CryptoReturningOk::default()),
            crypto_tls_config: Arc::new(mock_tls_config()),
            logger: no_op_logger(),
            node_id,
        };

        (cup_provider, node_record)
    }

    fn fake_cup() -> CatchUpPackage {
        CatchUpPackage {
            content: CatchUpContent::new(
                HashedBlock::new(
                    crypto_hash,
                    Block::new(
                        CryptoHashOf::from(CryptoHash(vec![])),
                        Payload::new(crypto_hash, BlockPayload::Summary(SummaryPayload::fake())),
                        Height::new(0),
                        Rank(0),
                        ValidationContext {
                            registry_version: RegistryVersion::from(99),
                            certified_height: Height::new(0),
                            time: UNIX_EPOCH,
                        },
                    ),
                ),
                HashedRandomBeacon::new(
                    crypto_hash,
                    RandomBeacon::fake(RandomBeaconContent {
                        version: ReplicaVersion::default(),
                        height: Height::new(0),
                        parent: CryptoHashOf::from(CryptoHash(vec![])),
                    }),
                ),
                CryptoHashOf::from(CryptoHash(Vec::new())),
                None,
            ),
            signature: ThresholdSignature::fake(),
        }
    }

    #[tokio::test]
    async fn empty_response_is_accepted_test() {
        let (cup_provider, node_record) = set_up_dependencies(MockResponse::Empty).await;

        assert_eq!(
            cup_provider
                .fetch_and_verify_catch_up_package(
                    &NODE_2,
                    &node_record,
                    /*param=*/ None,
                    SUBNET_1,
                )
                .await,
            Ok(None)
        );
    }

    #[tokio::test]
    async fn valid_cup_is_returned_test() {
        let cup = fake_cup();
        let cup_proto = pb::CatchUpPackage::from(&cup);
        let (cup_provider, node_record) =
            set_up_dependencies(MockResponse::Cup(cup_proto.clone())).await;

        assert_eq!(
            cup_provider
                .fetch_and_verify_catch_up_package(
                    &NODE_2,
                    &node_record,
                    /*param=*/ None,
                    SUBNET_1,
                )
                .await,
            Ok(Some((cup_proto, cup)))
        );
    }

    #[tokio::test]
    async fn time_out_when_headers_not_received_for_long_time_test() {
        let (cup_provider, node_record) =
            set_up_dependencies(MockResponse::DelayedIndefinitely).await;

        let response = cup_provider
            .fetch_and_verify_catch_up_package(
                &NODE_2,
                &node_record,
                /*param=*/ None,
                SUBNET_1,
            )
            .await;

        assert!(
            response
                .as_ref()
                .is_err_and(|err| err.contains("Querying CUP endpoint timed out")),
            "{response:?}"
        );
    }

    #[tokio::test]
    #[ignore = "We currently do not time out so the test hangs for 5 minutes and then fails..."]
    async fn time_out_when_body_not_received_for_long_time_test() {
        let (cup_provider, node_record) =
            set_up_dependencies(MockResponse::BodyDelayedIndefinitely).await;

        let response = cup_provider
            .fetch_and_verify_catch_up_package(
                &NODE_2,
                &node_record,
                /*param=*/ None,
                SUBNET_1,
            )
            .await;

        assert!(
            response
                .as_ref()
                .is_err_and(|err| err.contains("Querying CUP endpoint timed out")),
            "{response:?}"
        );
    }
}
