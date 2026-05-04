use std::{convert::TryFrom, net::SocketAddr, sync::Arc, time::Duration};

use axum::body::Body;
use futures::FutureExt;
use hickory_resolver::{Resolver, config::LookupIpStrategy};
use http_body_util::{BodyExt, Full, LengthLimitError};
use hyper::{Request, client::conn::http1::SendRequest};
use hyper_util::rt::TokioIo;
use ic_certification::validate_subnet_delegation_certificate;
use ic_config::http_handler::Config;
use ic_crypto_tls_interfaces::TlsConfig;
use ic_crypto_tree_hash::{LabeledTree, Path, lookup_path};
use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key_from_der;
use ic_interfaces_registry::RegistryClient;
use ic_logger::{ReplicaLogger, info, warn};
use ic_metrics::MetricsRegistry;
use ic_registry_client_helpers::{
    api_boundary_node::ApiBoundaryNodeRegistry,
    crypto::CryptoRegistry,
    node::{NodeRecord, NodeRegistry},
    node_operator::ConnectionEndpoint,
    subnet::SubnetRegistry,
};
use ic_registry_subnet_type::SubnetType;
use ic_types::{
    NodeId, RegistryVersion, SubnetId,
    crypto::threshold_sig::ThresholdSigPublicKey,
    messages::{
        Blob, Certificate, HttpReadState, HttpReadStateContent, HttpReadStateResponse,
        HttpRequestEnvelope,
    },
    time::expiry_time_from_now,
};
use rand::{Rng, seq::SliceRandom};
use rustls::{ClientConfig, pki_types::ServerName};
use tokio::{
    net::TcpStream,
    sync::watch,
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use tower::BoxError;

use crate::{
    NNSDelegationReader, metrics::DelegationManagerMetrics,
    nns_delegation_reader::NNSDelegationBuilder,
};

const CONTENT_TYPE_CBOR: &str = "application/cbor";

// In order to properly test the time outs we set much lower values for them when we are
// in the test mode.
#[cfg(not(test))]
const DELEGATION_UPDATE_INTERVAL: Duration = Duration::from_secs(5 * 60);
#[cfg(test)]
const DELEGATION_UPDATE_INTERVAL: Duration = Duration::from_secs(5);

const DELEGATION_RETRY_MAX_BACKOFF_SECONDS: u64 = 15;

#[cfg(not(test))]
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(test)]
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(1);

#[cfg(not(test))]
const NNS_DELEGATION_BODY_RECEIVE_TIMEOUT: Duration = Duration::from_secs(300);
#[cfg(test)]
const NNS_DELEGATION_BODY_RECEIVE_TIMEOUT: Duration = Duration::from_secs(1);

#[cfg(not(test))]
const NNS_DELEGATION_REQUEST_SEND_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(test)]
const NNS_DELEGATION_REQUEST_SEND_TIMEOUT: Duration = Duration::from_secs(1);

/// Spawns a task which periodically fetches the nns delegation.
pub fn start_nns_delegation_manager(
    metrics_registry: &MetricsRegistry,
    config: Config,
    log: ReplicaLogger,
    rt_handle: tokio::runtime::Handle,
    subnet_id: SubnetId,
    subnet_type: SubnetType,
    nns_subnet_id: SubnetId,
    registry_client: Arc<dyn RegistryClient>,
    tls_config: Arc<dyn TlsConfig>,
    cancellation_token: CancellationToken,
) -> (JoinHandle<()>, NNSDelegationReader) {
    let logger = log.clone();
    let manager = DelegationManager {
        config,
        log,
        subnet_id,
        subnet_type,
        nns_subnet_id,
        registry_client,
        tls_config,
        metrics: DelegationManagerMetrics::new(metrics_registry),
        rt_handle: rt_handle.clone(),
    };

    let (tx, rx) = watch::channel(None);

    let join_handle = rt_handle.spawn(async move {
        cancellation_token
            .run_until_cancelled(manager.run(tx))
            .map(|_| ())
            .await
    });

    (join_handle, NNSDelegationReader::new(rx, logger))
}

struct DelegationManager {
    config: Config,
    log: ReplicaLogger,
    subnet_id: SubnetId,
    subnet_type: SubnetType,
    nns_subnet_id: SubnetId,
    registry_client: Arc<dyn RegistryClient>,
    tls_config: Arc<dyn TlsConfig>,
    metrics: DelegationManagerMetrics,
    rt_handle: tokio::runtime::Handle,
}

impl DelegationManager {
    async fn fetch(&self) -> Option<NNSDelegationBuilder> {
        let _timer = self.metrics.update_duration.start_timer();

        let delegation = load_root_delegation(
            &self.config,
            &self.log,
            &self.rt_handle,
            self.subnet_id,
            self.subnet_type,
            self.nns_subnet_id,
            self.registry_client.as_ref(),
            self.tls_config.as_ref(),
            &self.metrics,
        )
        .await;

        self.metrics.updates.inc();

        delegation
    }

    async fn run(self, sender: watch::Sender<Option<NNSDelegationBuilder>>) {
        let mut interval = tokio::time::interval(DELEGATION_UPDATE_INTERVAL);
        // Since we can't distinguish between yet uninitialized and simply not present
        // (because we are on the NNS subnet) certification delegation, we explicitely keep
        // track whether the value has been initialized and notify all receivers when we initialize
        // it for the first time.
        let mut initialized = false;

        loop {
            // fetch the delegation if enough time has passed
            let _ = interval.tick().await;

            let mut delegation = self.fetch().await;

            sender.send_if_modified(move |old_delegation: &mut Option<NNSDelegationBuilder>| {
                let modified = if &delegation != old_delegation {
                    std::mem::swap(old_delegation, &mut delegation);
                    true
                } else {
                    false
                };

                modified || !initialized
            });

            initialized = true;
        }
    }
}

/// Fetches a delegation from the NNS subnet to allow this subnet to issue
/// certificates on its behalf. On the NNS subnet this method is a no-op.
async fn load_root_delegation(
    config: &Config,
    log: &ReplicaLogger,
    rt_handle: &tokio::runtime::Handle,
    subnet_id: SubnetId,
    subnet_type: SubnetType,
    nns_subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    tls_config: &dyn TlsConfig,
    metrics: &DelegationManagerMetrics,
) -> Option<NNSDelegationBuilder> {
    // On the NNS subnet. No delegation needs to be fetched.
    if subnet_id == nns_subnet_id {
        info!(log, "On the NNS subnet. Skipping fetching the delegation.");
        return None;
    }

    let mut fetching_root_delagation_attempts = 0;

    loop {
        fetching_root_delagation_attempts += 1;
        info!(
            log,
            "Fetching delegation from the NNS subnet. Attempts: {}.",
            fetching_root_delagation_attempts
        );

        let backoff = Duration::from_secs(
            rand::thread_rng().gen_range(1..DELEGATION_RETRY_MAX_BACKOFF_SECONDS),
        );

        match try_fetch_delegation_from_nns(
            config,
            log,
            rt_handle,
            subnet_id,
            subnet_type,
            nns_subnet_id,
            registry_client,
            tls_config,
            metrics,
        )
        .await
        {
            Ok(delegation) => return Some(delegation),
            Err(err) => {
                warn!(
                    log,
                    "Fetching delegation from NNS subnet failed. Retrying again in {} seconds...\
                    Error received: {}",
                    backoff.as_secs(),
                    err
                );

                metrics.errors.inc();
            }
        }

        // Fetching the NNS delegation failed. Do a random backoff and try again.
        sleep(backoff).await;
    }
}

/// Tries to fetch a delegation from the NNS subnet.
/// Returns a BoxError if any step of the process fails.
async fn try_fetch_delegation_from_nns(
    config: &Config,
    log: &ReplicaLogger,
    rt_handle: &tokio::runtime::Handle,
    subnet_id: SubnetId,
    subnet_type: SubnetType,
    nns_subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    tls_config: &dyn TlsConfig,
    metrics: &DelegationManagerMetrics,
) -> Result<NNSDelegationBuilder, BoxError> {
    let envelope = HttpRequestEnvelope {
        content: HttpReadStateContent::ReadState {
            read_state: HttpReadState {
                sender: Blob(vec![4]),
                paths: vec![
                    Path::new(vec![
                        b"subnet".into(),
                        subnet_id.get().into(),
                        b"public_key".into(),
                    ]),
                    // Old format of the canister ranges
                    Path::new(vec![
                        b"subnet".into(),
                        subnet_id.get().into(),
                        b"canister_ranges".into(),
                    ]),
                    // New format of the canister ranges
                    Path::new(vec![b"canister_ranges".into(), subnet_id.get().into()]),
                    Path::new(vec![
                        b"subnet".into(),
                        subnet_id.get().into(),
                        b"type".into(),
                    ]),
                ],
                ingress_expiry: expiry_time_from_now().as_nanos_since_unix_epoch(),
                nonce: None,
            },
        },
        sender_pubkey: None,
        sender_sig: None,
        sender_delegation: None,
    };

    let body = serde_cbor::ser::to_vec(&envelope).unwrap();

    let registry_version = registry_client.get_latest_version();

    let mut request_sender = timeout(
        CONNECTION_TIMEOUT,
        connect(
            log.clone(),
            rt_handle,
            subnet_type,
            nns_subnet_id,
            registry_client,
            tls_config,
        ),
    )
    .await
    .map_err(|_| {
        format!("Timed out while connecting to the node after {CONNECTION_TIMEOUT:?}")
    })??;

    let uri = format!("/api/v2/subnet/{nns_subnet_id}/read_state");

    info!(
        log,
        "Attempt to fetch HTTPS delegation from the NNS, uri = `{uri}`."
    );

    let nns_request = Request::builder()
        .method(hyper::Method::POST)
        .uri(uri)
        .header(hyper::header::CONTENT_TYPE, CONTENT_TYPE_CBOR)
        .body(Body::new(Full::from(body).map_err(BoxError::from)))?;

    let raw_response_res = timeout(
        NNS_DELEGATION_REQUEST_SEND_TIMEOUT,
        request_sender.send_request(nns_request),
    )
    .await
    .map_err(|_| {
        format!(
            "Timed out while sending request to the node \
            after {NNS_DELEGATION_REQUEST_SEND_TIMEOUT:?}",
        )
    })??;

    let raw_response =
        match timeout(
            NNS_DELEGATION_BODY_RECEIVE_TIMEOUT,
            http_body_util::Limited::new(
                raw_response_res.into_body(),
                config.max_delegation_certificate_size_bytes as usize,
            )
            .collect(),
        )
        .await
        {
            Ok(Ok(c)) => c.to_bytes(),
            Ok(Err(e)) if e.is::<LengthLimitError>() => {
                return Err(format!(
                    "Http body exceeds size limit of {} bytes.",
                    config.max_delegation_certificate_size_bytes
                )
                .into());
            }
            Ok(Err(e)) => return Err(format!("Failed to read body from connection: {e}").into()),
            Err(_) => return Err(format!(
                "Timed out while receiving http body after {NNS_DELEGATION_BODY_RECEIVE_TIMEOUT:?}"
            )
            .into()),
        };

    let response: HttpReadStateResponse = serde_cbor::from_slice(&raw_response).map_err(|err| {
        format!("Failed to decode the read state response: {err}. Raw response: {raw_response:?}")
    })?;

    let parsed_delegation: Certificate = serde_cbor::from_slice(&response.certificate)
        .map_err(|e| format!("Failed to parse delegation certificate: {e}"))?;

    let labeled_tree = LabeledTree::try_from(parsed_delegation.tree.clone())
        .map_err(|e| format!("Invalid hash tree in the delegation certificate: {e:?}"))?;

    let own_public_key_from_registry = match registry_client
        .get_threshold_signing_public_key_for_subnet(subnet_id, registry_version)
    {
        Ok(Some(pk)) => Ok(pk),
        Ok(None) => Err(format!(
            "subnet {subnet_id} public key from registry is empty"
        )),
        Err(err) => Err(format!(
            "subnet {subnet_id} public key could not be extracted from registry: {err:?}"
        )),
    }?;

    match lookup_path(
        &labeled_tree,
        &[b"subnet", subnet_id.get_ref().as_ref(), b"public_key"],
    ) {
        Some(LabeledTree::Leaf(pk_bytes)) => {
            let public_key_from_certificate = parse_threshold_sig_key_from_der(pk_bytes)?;

            if public_key_from_certificate != own_public_key_from_registry {
                Err(format!(
                    "invalid public key type in certificate for subnet {subnet_id}"
                ))
            } else {
                Ok(())
            }
        }
        _ => Err(format!(
            "subnet {subnet_id} public key could not be extracted from certificate"
        )),
    }?;

    let root_threshold_public_key =
        get_root_threshold_public_key(registry_client, registry_version, nns_subnet_id).map_err(
            |err| format!("could not retrieve threshold root public key from registry: {err}"),
        )?;

    validate_subnet_delegation_certificate(
        &response.certificate,
        &subnet_id,
        &root_threshold_public_key,
    )
    .map_err(|err| format!("invalid subnet delegation certificate: {err:?} "))?;

    info!(log, "Setting NNS delegation to: {:?}", response.certificate);
    let nns_delegation_builder = NNSDelegationBuilder::new(
        parsed_delegation,
        labeled_tree,
        response.certificate,
        subnet_id,
        log,
    );

    nns_delegation_builder.observe_delegation_sizes(metrics);

    Ok(nns_delegation_builder)
}

async fn connect(
    log: ReplicaLogger,
    rt_handle: &tokio::runtime::Handle,
    subnet_type: SubnetType,
    nns_subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    tls_config: &(dyn TlsConfig + Send + Sync),
) -> Result<SendRequest<Body>, BoxError> {
    let (peer_id, addr, server_name, tls_client_config) = match subnet_type {
        SubnetType::System | SubnetType::Application | SubnetType::VerifiedApplication => {
            let (peer_id, endpoint) =
                get_random_node_from_nns_subnet(registry_client, nns_subnet_id).map_err(|err| {
                    format!("Could not find a node from the NNS to talk to. Error: {err}")
                })?;

            let registry_version = registry_client.get_latest_version();

            let ip_addr = endpoint
                .ip_addr
                .parse()
                .map_err(|err| format!("Failed to parse the ip addr: {err}"))?;

            let addr = SocketAddr::new(ip_addr, endpoint.port as u16);

            let tls_client_config = tls_config
                .client_config(peer_id, registry_version)
                .map_err(|err| format!("Retrieving TLS client config failed: {err:?}."))?;

            let server_name = ServerName::from(ip_addr);

            (peer_id, addr, server_name, tls_client_config)
        }
        SubnetType::CloudEngine => {
            let (api_bn_id, domain) = get_random_api_boundary_node(registry_client)
                .map_err(|err| format!("Could not find an API BN to talk to. Error: {err}"))?;

            let mut dns_resolver = Resolver::builder_tokio()?;
            dns_resolver.options_mut().ip_strategy = LookupIpStrategy::Ipv6Only;
            #[cfg(test)]
            {
                // In unit tests, the domain does not resolve and we want to fail fast to keep a low
                // test execution time.
                dns_resolver.options_mut().timeout = Duration::from_millis(100);
                dns_resolver.options_mut().attempts = 1;
            }
            let ip_addr = dns_resolver
                .build()
                .lookup_ip(domain.as_str())
                .await?
                .iter()
                .next()
                .ok_or_else(|| {
                    format!("API BN domain {domain} does not resolve to any IPv6 address.",)
                })?;

            let addr = SocketAddr::new(ip_addr, 443);

            let root_store =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let tls_client_config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            let server_name = ServerName::try_from(domain.clone())
                .map_err(|err| format!("Invalid API BN domain {domain}: {err}"))?;

            (api_bn_id, addr, server_name, tls_client_config)
        }
    };

    connect_to(
        log,
        rt_handle,
        peer_id,
        addr,
        server_name,
        tls_client_config,
    )
    .await
}

async fn connect_to(
    log: ReplicaLogger,
    rt_handle: &tokio::runtime::Handle,
    peer_id: NodeId,
    addr: SocketAddr,
    server_name: ServerName<'static>,
    tls_client_config: ClientConfig,
) -> Result<SendRequest<Body>, BoxError> {
    info!(log, "Establishing TCP connection to {peer_id} @ {addr}");
    let tcp_stream: TcpStream = TcpStream::connect(addr)
        .await
        .map_err(|err| format!("Could not connect to node {addr}. {err:?}."))?;

    let tls_connector = TlsConnector::from(Arc::new(tls_client_config));

    info!(
        log,
        "Establishing TLS stream to {peer_id}. Tcp stream: {tcp_stream:?}"
    );
    let tls_stream = tls_connector
        .connect(server_name, tcp_stream)
        .await
        .map_err(|err| format!("Could not establish TLS stream to node {addr}. {err:?}."))?;

    info!(
        log,
        "Establishing HTTP connection to {peer_id}. Tls stream: {tls_stream:?}"
    );
    let (request_sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls_stream)).await?;

    // Spawn a task to poll the connection, driving the HTTP state
    rt_handle.spawn(async move {
        if let Err(err) = connection.await {
            warn!(log, "Polling connection failed: {err:?}.");
        }
    });

    Ok(request_sender)
}

fn get_random_node_from_nns_subnet(
    registry_client: &dyn RegistryClient,
    nns_subnet_id: SubnetId,
) -> Result<(NodeId, ConnectionEndpoint), String> {
    let nns_nodes = match registry_client
        .get_node_ids_on_subnet(nns_subnet_id, registry_client.get_latest_version())
    {
        Ok(Some(nns_nodes)) => Ok(nns_nodes),
        Ok(None) => Err("No NNS nodes found.".to_string()),
        Err(err) => Err(format!("Failed to get NNS nodes from registry: {err}")),
    }?;

    let (node_id, record) = get_random_node_record_from_ids(registry_client, &nns_nodes)?;
    let endpoint = record
        .http
        .ok_or_else(|| format!("No HTTP endpoint for NNS node {node_id}"))?;
    Ok((node_id, endpoint))
}

fn get_random_api_boundary_node(
    registry_client: &dyn RegistryClient,
) -> Result<(NodeId, String), String> {
    let api_bns = registry_client
        .get_api_boundary_node_ids(registry_client.get_latest_version())
        .map_err(|err| format!("Failed to get API BNs from registry: {err}"))?;

    let (node_id, record) = get_random_node_record_from_ids(registry_client, &api_bns)?;
    let domain = record
        .domain
        .ok_or_else(|| format!("No domain for API BN {node_id}"))?;
    Ok((node_id, domain))
}

fn get_random_node_record_from_ids(
    registry_client: &dyn RegistryClient,
    node_ids: &[NodeId],
) -> Result<(NodeId, NodeRecord), String> {
    let mut rng = rand::thread_rng();
    let node_id = node_ids.choose(&mut rng).ok_or(format!(
        "Failed to choose a random node. Node list: {node_ids:?}"
    ))?;

    match registry_client.get_node_record(*node_id, registry_client.get_latest_version()) {
        Ok(Some(record)) => Ok((*node_id, record)),
        Ok(None) => Err(format!("No node record found for node id {node_id}")),
        Err(err) => Err(format!(
            "Failed to get node record for node id {node_id}. Err: {err}"
        )),
    }
}

fn get_root_threshold_public_key(
    registry_client: &dyn RegistryClient,
    version: RegistryVersion,
    nns_subnet_id: SubnetId,
) -> Result<ThresholdSigPublicKey, String> {
    match registry_client.get_threshold_signing_public_key_for_subnet(nns_subnet_id, version) {
        Ok(Some(key)) => Ok(key),
        Err(err) => Err(format!("Failed to get key for subnet: {err}")),
        Ok(None) => Err(format!("Received no public key for subnet {nns_subnet_id}")),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::RwLock;

    use assert_matches::assert_matches;
    use axum::response::IntoResponse;
    use axum_server::tls_rustls::RustlsConfig;
    use hyper::Response;
    use ic_certification_test_utils::serialize_to_cbor;
    use ic_certification_test_utils::{
        CertificateBuilder, CertificateData, encoded_time, generate_root_of_trust,
    };
    use ic_crypto_tls_interfaces_mocks::MockTlsConfig;
    use ic_crypto_tree_hash::{Label, LabeledTree, flatmap, lookup_path};
    use ic_crypto_utils_threshold_sig_der::public_key_to_der;
    use ic_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_protobuf::registry::api_boundary_node::v1::ApiBoundaryNodeRecord;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_client_helpers::node::{ConnectionEndpoint, NodeRecord};
    use ic_registry_keys::{make_api_boundary_node_record_key, make_node_record_key};
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_test_utilities_registry::{
        SubnetRecordBuilder, add_single_subnet_record, add_subnet_key_record,
        add_subnet_list_record,
    };
    use ic_test_utilities_types::ids::canister_test_id;
    use ic_types::messages::{Certificate, CertificateDelegation};
    use ic_types::{
        NodeId,
        messages::{Blob, HttpReadStateResponse},
    };
    use rand::thread_rng;
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use rustls::{
        ClientConfig, DigitallySignedStruct, SignatureScheme,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, ServerName, UnixTime},
    };
    use std::net::TcpListener;
    use std::ops::Deref;
    use std::{net::SocketAddr, sync::Arc};

    use tokio::time::timeout;

    use crate::CanisterRangesFilter;

    use super::*;

    const NNS_SUBNET_ID: SubnetId = ic_test_utilities_types::ids::SUBNET_1;
    const SYSTEM_SUBNET_ID: SubnetId = ic_test_utilities_types::ids::SUBNET_2;
    const APP_SUBNET_ID: SubnetId = ic_test_utilities_types::ids::SUBNET_3;
    const VERIFIED_APP_SUBNET_ID: SubnetId = ic_test_utilities_types::ids::SUBNET_4;
    const CLOUD_ENGINE_SUBNET_ID: SubnetId = ic_test_utilities_types::ids::SUBNET_5;
    const NNS_NODE_ID: NodeId = ic_test_utilities_types::ids::NODE_1;
    const SYSTEM_NODE_ID: NodeId = ic_test_utilities_types::ids::NODE_2;
    const APP_NODE_ID: NodeId = ic_test_utilities_types::ids::NODE_3;
    const VERIFIED_APP_NODE_ID: NodeId = ic_test_utilities_types::ids::NODE_4;
    const CLOUD_ENGINE_NODE_ID: NodeId = ic_test_utilities_types::ids::NODE_5;
    const API_BN_ID: NodeId = ic_test_utilities_types::ids::NODE_6;
    const API_BN_DOMAIN: &str = "domain.invalid";

    // Get a free port on this host to which we can connect transport to.
    fn get_free_localhost_socket_addr() -> SocketAddr {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_reuseport(false).unwrap();
        socket.set_reuseaddr(false).unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        socket.local_addr().unwrap()
    }

    async fn generate_self_signed_cert() -> RustlsConfig {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();

        let cert_der = CertificateDer::from(cert);

        RustlsConfig::from_der(vec![cert_der.as_ref().to_vec()], key_pair.serialize_der())
            .await
            .unwrap()
    }

    #[derive(Copy, Clone, Eq, PartialEq)]
    enum Delay {
        /// We will sleep for an hour before accepting incoming request
        AcceptingConnection,
        /// We will sleep for an hour before sending back a response
        SendingResponse,
        /// We will delay sending back the response body indefinitely
        SendingBody,
    }

    /// A stream which never resolves
    struct EndlessStream;

    impl futures::Stream for EndlessStream {
        type Item = Result<axum::body::Bytes, String>;

        fn poll_next(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            std::task::Poll::Pending
        }
    }

    /// Sets up all the dependencies.
    fn set_up_nns_delegation_dependencies(
        rt_handle: tokio::runtime::Handle,
        // Optional certificate delegation returned by a mocked NNS node.
        // None means we will generate a random, valid certificate.
        override_nns_delegation: Arc<RwLock<Option<CertificateDelegation>>>,
        delay: Option<Delay>,
    ) -> (Arc<FakeRegistryClient>, Arc<MockTlsConfig>) {
        let registry_version = 1;

        let data_provider = Arc::new(ProtoRegistryDataProvider::new());

        add_single_subnet_record(
            &data_provider,
            registry_version,
            NNS_SUBNET_ID,
            SubnetRecordBuilder::new()
                .with_committee(&[NNS_NODE_ID])
                .with_subnet_type(SubnetType::System)
                .build(),
        );

        add_single_subnet_record(
            &data_provider,
            registry_version,
            SYSTEM_SUBNET_ID,
            SubnetRecordBuilder::new()
                .with_committee(&[SYSTEM_NODE_ID])
                .with_subnet_type(SubnetType::System)
                .build(),
        );

        add_single_subnet_record(
            &data_provider,
            registry_version,
            APP_SUBNET_ID,
            SubnetRecordBuilder::new()
                .with_committee(&[APP_NODE_ID])
                .build(),
        );

        add_single_subnet_record(
            &data_provider,
            registry_version,
            VERIFIED_APP_SUBNET_ID,
            SubnetRecordBuilder::new()
                .with_committee(&[VERIFIED_APP_NODE_ID])
                .with_subnet_type(SubnetType::VerifiedApplication)
                .build(),
        );

        add_single_subnet_record(
            &data_provider,
            registry_version,
            CLOUD_ENGINE_SUBNET_ID,
            SubnetRecordBuilder::new()
                .with_committee(&[CLOUD_ENGINE_NODE_ID])
                .with_subnet_type(SubnetType::CloudEngine)
                .build(),
        );

        let (nns_public_key, nns_secret_key) = generate_root_of_trust(&mut thread_rng());
        let (system_subnet_public_key, _system_subnet_secret_key) =
            generate_root_of_trust(&mut thread_rng());
        let (app_subnet_public_key, _app_subnet_secret_key) =
            generate_root_of_trust(&mut thread_rng());
        let (verified_app_subnet_public_key, _verified_app_subnet_secret_key) =
            generate_root_of_trust(&mut thread_rng());
        let (cloud_engine_public_key, _cloud_engine_secret_key) =
            generate_root_of_trust(&mut thread_rng());

        add_subnet_key_record(
            &data_provider,
            registry_version,
            NNS_SUBNET_ID,
            nns_public_key,
        );

        add_subnet_key_record(
            &data_provider,
            registry_version,
            SYSTEM_SUBNET_ID,
            system_subnet_public_key,
        );

        add_subnet_key_record(
            &data_provider,
            registry_version,
            APP_SUBNET_ID,
            app_subnet_public_key,
        );

        add_subnet_key_record(
            &data_provider,
            registry_version,
            VERIFIED_APP_SUBNET_ID,
            verified_app_subnet_public_key,
        );

        add_subnet_key_record(
            &data_provider,
            registry_version,
            CLOUD_ENGINE_SUBNET_ID,
            cloud_engine_public_key,
        );

        add_subnet_list_record(
            &data_provider,
            registry_version,
            vec![
                NNS_SUBNET_ID,
                SYSTEM_SUBNET_ID,
                APP_SUBNET_ID,
                VERIFIED_APP_SUBNET_ID,
                CLOUD_ENGINE_SUBNET_ID,
            ],
        );

        let addr = get_free_localhost_socket_addr();
        let tcp_listener = TcpListener::bind(addr).unwrap();

        data_provider
            .add(
                &make_node_record_key(NNS_NODE_ID),
                registry_version.into(),
                Some(NodeRecord {
                    http: Some(ConnectionEndpoint {
                        ip_addr: addr.ip().to_string(),
                        port: addr.port() as u32,
                    }),
                    ..Default::default()
                }),
            )
            .unwrap();

        data_provider
            .add(
                &make_node_record_key(API_BN_ID),
                registry_version.into(),
                Some(NodeRecord {
                    domain: Some(API_BN_DOMAIN.to_string()),
                    ..Default::default()
                }),
            )
            .unwrap();
        data_provider
            .add(
                &make_api_boundary_node_record_key(API_BN_ID),
                registry_version.into(),
                Some(ApiBoundaryNodeRecord {
                    ..Default::default()
                }),
            )
            .unwrap();

        let registry_client =
            Arc::new(FakeRegistryClient::new(Arc::clone(&data_provider) as Arc<_>));

        registry_client.update_to_latest_version();

        let create_certificate = move |time| {
            let (_certificate, _root_pk, cbor) =
                CertificateBuilder::new(CertificateData::CustomTree(LabeledTree::SubTree(flatmap![
                    Label::from("subnet") => LabeledTree::SubTree(flatmap![
                        Label::from(APP_SUBNET_ID.get_ref().to_vec()) => LabeledTree::SubTree(flatmap![
                            Label::from("canister_ranges") => LabeledTree::Leaf(serialize_to_cbor(&vec![(canister_test_id(0), canister_test_id(10))])),
                            Label::from("public_key") => LabeledTree::Leaf(public_key_to_der(&app_subnet_public_key.into_bytes()).unwrap()),
                        ]),
                        Label::from(SYSTEM_SUBNET_ID.get_ref().to_vec()) => LabeledTree::SubTree(flatmap![
                            Label::from("canister_ranges") => LabeledTree::Leaf(serialize_to_cbor(&vec![(canister_test_id(10), canister_test_id(20))])),
                            Label::from("public_key") => LabeledTree::Leaf(public_key_to_der(&system_subnet_public_key.into_bytes()).unwrap()),
                        ]),
                        Label::from(VERIFIED_APP_SUBNET_ID.get_ref().to_vec()) => LabeledTree::SubTree(flatmap![
                            Label::from("canister_ranges") => LabeledTree::Leaf(serialize_to_cbor(&vec![(canister_test_id(20), canister_test_id(30))])),
                            Label::from("public_key") => LabeledTree::Leaf(public_key_to_der(&verified_app_subnet_public_key.into_bytes()).unwrap()),
                        ]),
                        Label::from(CLOUD_ENGINE_SUBNET_ID.get_ref().to_vec()) => LabeledTree::SubTree(flatmap![
                            Label::from("canister_ranges") => LabeledTree::Leaf(serialize_to_cbor(&vec![(canister_test_id(30), canister_test_id(40))])),
                            Label::from("public_key") => LabeledTree::Leaf(public_key_to_der(&cloud_engine_public_key.into_bytes()).unwrap()),
                        ]),
                    ]),
                    Label::from("time") => LabeledTree::Leaf(encoded_time(time))
                ])))
                .with_root_of_trust(nns_public_key, nns_secret_key)
                .build();

            cbor
        };

        rt_handle.spawn(async move {
            if delay == Some(Delay::AcceptingConnection) {
                tokio::time::sleep(Duration::from_secs(60 * 60)).await;
            }
            let time = Arc::new(RwLock::new(42));

            let router = axum::routing::any(move || async move {
                match delay {
                    Some(Delay::SendingResponse) => {
                        tokio::time::sleep(Duration::from_secs(60 * 60)).await;
                    }
                    Some(Delay::SendingBody) => {
                        return Response::new(Body::from_stream(EndlessStream {}));
                    }
                    Some(Delay::AcceptingConnection) => unreachable!(),
                    None => {}
                }

                let mut time = time.write().unwrap();
                *time += 1;

                let certificate = match override_nns_delegation.read().unwrap().deref() {
                    Some(delegation) => delegation.certificate.clone(),
                    _ => Blob(create_certificate(*time)),
                };

                let body = serde_cbor::ser::to_vec(&HttpReadStateResponse { certificate }).unwrap();
                (
                    [(
                        hyper::header::CONTENT_TYPE,
                        hyper::header::HeaderValue::from_static(CONTENT_TYPE_CBOR),
                    )],
                    body,
                )
                    .into_response()
            });

            axum_server::from_tcp_rustls(tcp_listener, generate_self_signed_cert().await)
                .serve(router.into_make_service())
                .await
                .unwrap()
        });

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

        (registry_client, Arc::new(tls_config))
    }

    #[tokio::test]
    async fn manager_load_root_delegation_on_nns_should_return_none_test() {
        let rt_handle = tokio::runtime::Handle::current();
        let (registry_client, tls_config) = set_up_nns_delegation_dependencies(
            rt_handle.clone(),
            Arc::new(RwLock::new(None)),
            /*delay=*/ None,
        );

        let (_, mut reader) = start_nns_delegation_manager(
            &MetricsRegistry::new(),
            Config::default(),
            no_op_logger(),
            rt_handle,
            NNS_SUBNET_ID,
            SubnetType::System,
            NNS_SUBNET_ID,
            registry_client,
            tls_config,
            CancellationToken::new(),
        );

        reader.receiver.changed().await.unwrap();

        assert!(reader.get_delegation(CanisterRangesFilter::Flat).is_none());
    }

    #[tokio::test]
    async fn manager_load_root_delegation_on_app_subnet_should_return_some_test() {
        let rt_handle = tokio::runtime::Handle::current();
        let (registry_client, tls_config) = set_up_nns_delegation_dependencies(
            rt_handle.clone(),
            Arc::new(RwLock::new(None)),
            /*delay=*/ None,
        );

        for (subnet_id, subnet_type) in [
            (SYSTEM_SUBNET_ID, SubnetType::System),
            (APP_SUBNET_ID, SubnetType::Application),
            (VERIFIED_APP_SUBNET_ID, SubnetType::VerifiedApplication),
        ] {
            let (_, mut reader) = start_nns_delegation_manager(
                &MetricsRegistry::new(),
                Config::default(),
                no_op_logger(),
                rt_handle.clone(),
                subnet_id,
                subnet_type,
                NNS_SUBNET_ID,
                registry_client.clone(),
                tls_config.clone(),
                CancellationToken::new(),
            );

            reader.receiver.changed().await.unwrap();

            let delegation = reader
                .get_delegation(CanisterRangesFilter::Flat)
                .expect("Should return some delegation on non NNS subnet");
            let parsed_delegation: Certificate = serde_cbor::from_slice(&delegation.certificate)
                .expect("Should return a certificate which can be deserialized");
            let tree = LabeledTree::try_from(parsed_delegation.tree)
                .expect("Should return a state tree which can be parsed");
            // Verify that the state tree has the a subtree corresponding to the requested subnet
            match lookup_path(&tree, &[b"subnet", subnet_id.get_ref().as_ref()]) {
                Some(LabeledTree::SubTree(..)) => (),
                _ => panic!("Didn't find the subnet path in the state tree"),
            }
        }
    }

    #[tokio::test]
    async fn manager_should_not_refresh_if_not_enough_time_passed_test() {
        let rt_handle = tokio::runtime::Handle::current();
        let (registry_client, tls_config) = set_up_nns_delegation_dependencies(
            rt_handle.clone(),
            Arc::new(RwLock::new(None)),
            /*delay=*/ None,
        );

        let (_, mut reader) = start_nns_delegation_manager(
            &MetricsRegistry::new(),
            Config::default(),
            no_op_logger(),
            rt_handle,
            APP_SUBNET_ID,
            SubnetType::Application,
            NNS_SUBNET_ID,
            registry_client,
            tls_config,
            CancellationToken::new(),
        );

        // The initial delegation should be fetched immediately.
        reader.receiver.changed().await.unwrap();
        // The subsequent delegations should be fetched only after `DELEGATION_UPDATE_INTERVAL`
        // has elapsed.
        assert!(
            timeout(DELEGATION_UPDATE_INTERVAL / 2, reader.receiver.changed())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn manager_should_refresh_if_enough_time_passed_test() {
        let rt_handle = tokio::runtime::Handle::current();
        let (registry_client, tls_config) = set_up_nns_delegation_dependencies(
            rt_handle.clone(),
            Arc::new(RwLock::new(None)),
            /*delay=*/ None,
        );

        let (_, mut reader) = start_nns_delegation_manager(
            &MetricsRegistry::new(),
            Config::default(),
            no_op_logger(),
            rt_handle,
            APP_SUBNET_ID,
            SubnetType::Application,
            NNS_SUBNET_ID,
            registry_client,
            tls_config,
            CancellationToken::new(),
        );

        // The initial delegation should be fetched immediately.
        reader.receiver.changed().await.unwrap();
        // The subsequent delegations should be fetched only after `DELEGATION_UPDATE_INTERVAL`
        // has passed. We use a timeout of 2x the interval to give enough margin for the
        // time it takes to fetch the delegation (TLS handshake, HTTP request, etc.).
        assert!(
            timeout(DELEGATION_UPDATE_INTERVAL * 2, reader.receiver.changed())
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn manager_should_not_return_an_invalid_delegation_test() {
        let override_nns_delegation = Arc::new(RwLock::new(None));
        let rt_handle = tokio::runtime::Handle::current();
        let (registry_client, tls_config) = set_up_nns_delegation_dependencies(
            rt_handle.clone(),
            override_nns_delegation.clone(),
            /*delay=*/ None,
        );

        let (_, mut reader) = start_nns_delegation_manager(
            &MetricsRegistry::new(),
            Config::default(),
            no_op_logger(),
            rt_handle,
            APP_SUBNET_ID,
            SubnetType::Application,
            NNS_SUBNET_ID,
            registry_client,
            tls_config,
            CancellationToken::new(),
        );

        // The initial *valid* delegation should be fetched immediately.
        assert!(reader.receiver.changed().await.is_ok());

        // Mock an *invalid* certificate delegation.
        *override_nns_delegation.write().unwrap() = Some(CertificateDelegation {
            subnet_id: Blob(vec![]),
            certificate: Blob(vec![]),
        });

        // Since the returned certificate is invalid, we don't expect the manager to return
        // any new certification.
        assert!(
            timeout(DELEGATION_UPDATE_INTERVAL, reader.receiver.changed())
                .await
                .is_err()
        );

        *override_nns_delegation.write().unwrap() = None;
        // The mocked NNS node should now return a valid certification, so we expect that
        // the manager will fetch and send it to all receivers.
        assert!(reader.receiver.changed().await.is_ok());
    }

    #[tokio::test]
    async fn load_root_delegation_on_nns_should_return_none_test() {
        let rt_handle = tokio::runtime::Handle::current();
        let (registry_client, tls_config) = set_up_nns_delegation_dependencies(
            rt_handle.clone(),
            Arc::new(RwLock::new(None)),
            /*delay=*/ None,
        );

        let delegation = load_root_delegation(
            &Config::default(),
            &no_op_logger(),
            &rt_handle,
            NNS_SUBNET_ID,
            SubnetType::System,
            NNS_SUBNET_ID,
            registry_client.as_ref(),
            tls_config.as_ref(),
            &DelegationManagerMetrics::new(&MetricsRegistry::new()),
        )
        .await;

        assert!(delegation.is_none());
    }

    #[tokio::test]
    async fn load_root_delegation_on_app_subnet_should_return_some_test() {
        let rt_handle = tokio::runtime::Handle::current();
        let (registry_client, tls_config) = set_up_nns_delegation_dependencies(
            rt_handle.clone(),
            Arc::new(RwLock::new(None)),
            /*delay=*/ None,
        );

        for (subnet_id, subnet_type) in [
            (SYSTEM_SUBNET_ID, SubnetType::System),
            (APP_SUBNET_ID, SubnetType::Application),
            (VERIFIED_APP_SUBNET_ID, SubnetType::VerifiedApplication),
        ] {
            let builder = load_root_delegation(
                &Config::default(),
                &no_op_logger(),
                &rt_handle,
                subnet_id,
                subnet_type,
                NNS_SUBNET_ID,
                registry_client.as_ref(),
                tls_config.as_ref(),
                &DelegationManagerMetrics::new(&MetricsRegistry::new()),
            )
            .await;

            let builder = builder.expect("Should return Some delegation on non NNS subnet");
            let parsed_delegation: Certificate = serde_cbor::from_slice(
                &builder
                    .build_or_original(CanisterRangesFilter::Flat, &no_op_logger())
                    .certificate,
            )
            .expect("Should return a certificate which can be deserialized");
            let tree = LabeledTree::try_from(parsed_delegation.tree)
                .expect("The deserialized delegation should contain a correct tree");
            // Verify that the state tree has the a subtree corresponding to the requested subnet
            match lookup_path(&tree, &[b"subnet", subnet_id.get_ref().as_ref()]) {
                Some(LabeledTree::SubTree(..)) => (),
                _ => panic!("Didn't find the subnet path in the state tree"),
            }
        }
    }

    #[tokio::test]
    async fn load_root_delegation_on_cloud_engine_should_contact_api_bn_test() {
        let rt_handle = tokio::runtime::Handle::current();
        let (registry_client, tls_config) = set_up_nns_delegation_dependencies(
            rt_handle.clone(),
            Arc::new(RwLock::new(None)),
            /*delay=*/ None,
        );

        let response = try_fetch_delegation_from_nns(
            &Config::default(),
            &no_op_logger(),
            &rt_handle,
            CLOUD_ENGINE_SUBNET_ID,
            SubnetType::CloudEngine,
            NNS_SUBNET_ID,
            registry_client.as_ref(),
            tls_config.as_ref(),
            &DelegationManagerMetrics::new(&MetricsRegistry::new()),
        )
        .await;

        // Since the API BN is configured with a domain that does not resolve, we expect the
        // connection to fail with a name resolution error, which indicates that we indeed tried to
        // connect to the API BN instead of an NNS node.
        assert_matches!(response, Err(err) if format!("{err:?}").contains("ResolveError"));
    }

    #[tokio::test]
    async fn load_root_delegation_times_out_on_connect_test() {
        let rt_handle = tokio::runtime::Handle::current();
        let (registry_client, tls_config) = set_up_nns_delegation_dependencies(
            rt_handle.clone(),
            Arc::new(RwLock::new(None)),
            Some(Delay::AcceptingConnection),
        );

        let response = try_fetch_delegation_from_nns(
            &Config::default(),
            &no_op_logger(),
            &rt_handle,
            APP_SUBNET_ID,
            SubnetType::Application,
            NNS_SUBNET_ID,
            registry_client.as_ref(),
            tls_config.as_ref(),
            &DelegationManagerMetrics::new(&MetricsRegistry::new()),
        )
        .await;

        assert_matches!(response, Err(err) if err.to_string().contains("Timed out while connecting"));
    }

    #[tokio::test]
    async fn load_root_delegation_times_out_on_send_request_test() {
        let rt_handle = tokio::runtime::Handle::current();
        let (registry_client, tls_config) = set_up_nns_delegation_dependencies(
            rt_handle.clone(),
            Arc::new(RwLock::new(None)),
            Some(Delay::SendingResponse),
        );

        let response = try_fetch_delegation_from_nns(
            &Config::default(),
            &no_op_logger(),
            &rt_handle,
            APP_SUBNET_ID,
            SubnetType::Application,
            NNS_SUBNET_ID,
            registry_client.as_ref(),
            tls_config.as_ref(),
            &DelegationManagerMetrics::new(&MetricsRegistry::new()),
        )
        .await;

        assert_matches!(response, Err(err) if err.to_string().contains("Timed out while sending"));
    }

    #[tokio::test]
    async fn load_root_delegation_times_out_on_receive_body_test() {
        let rt_handle = tokio::runtime::Handle::current();
        let (registry_client, tls_config) = set_up_nns_delegation_dependencies(
            rt_handle.clone(),
            Arc::new(RwLock::new(None)),
            Some(Delay::SendingBody),
        );

        let response = try_fetch_delegation_from_nns(
            &Config::default(),
            &no_op_logger(),
            &rt_handle,
            APP_SUBNET_ID,
            SubnetType::Application,
            NNS_SUBNET_ID,
            registry_client.as_ref(),
            tls_config.as_ref(),
            &DelegationManagerMetrics::new(&MetricsRegistry::new()),
        )
        .await;

        assert_matches!(response, Err(err) if err.to_string().contains("Timed out while receiving"));
    }
}
