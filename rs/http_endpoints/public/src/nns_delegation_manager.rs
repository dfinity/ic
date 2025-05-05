use std::{convert::TryFrom, net::SocketAddr, sync::Arc, time::Duration};

use axum::body::Body;
use futures::FutureExt;
use http_body_util::{BodyExt, Full, LengthLimitError};
use hyper::Request;
use hyper_util::rt::TokioIo;
use ic_certification::validate_subnet_delegation_certificate;
use ic_config::http_handler::Config;
use ic_crypto_tls_interfaces::TlsConfig;
use ic_crypto_tree_hash::{lookup_path, LabeledTree, Path};
use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key_from_der;
use ic_interfaces_registry::RegistryClient;
use ic_logger::{debug, fatal, info, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_registry_client_helpers::{
    crypto::CryptoRegistry, node::NodeRegistry, node_operator::ConnectionEndpoint,
    subnet::SubnetRegistry,
};
use ic_types::{
    messages::{
        Blob, Certificate, CertificateDelegation, HttpReadState, HttpReadStateContent,
        HttpReadStateResponse, HttpRequestEnvelope,
    },
    time::expiry_time_from_now,
    NodeId, SubnetId,
};
use rand::Rng;
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
    common::{get_root_threshold_public_key, CONTENT_TYPE_CBOR, MAX_REQUEST_RECEIVE_TIMEOUT},
    metrics::DelegationManagerMetrics,
};

const DELEGATION_UPDATE_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// Spawns a task which periodically fetches the nns delegation.
pub fn start_nns_delegation_manager(
    metrics_registry: &MetricsRegistry,
    config: Config,
    log: ReplicaLogger,
    rt_handle: tokio::runtime::Handle,
    subnet_id: SubnetId,
    nns_subnet_id: SubnetId,
    registry_client: Arc<dyn RegistryClient>,
    tls_config: Arc<dyn TlsConfig + Send + Sync>,
    cancellation_token: CancellationToken,
) -> (
    JoinHandle<()>,
    watch::Receiver<Option<CertificateDelegation>>,
) {
    let manager = DelegationManager {
        config,
        log,
        subnet_id,
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

    (join_handle, rx)
}

struct DelegationManager {
    config: Config,
    log: ReplicaLogger,
    subnet_id: SubnetId,
    nns_subnet_id: SubnetId,
    registry_client: Arc<dyn RegistryClient>,
    tls_config: Arc<dyn TlsConfig + Send + Sync>,
    metrics: DelegationManagerMetrics,
    rt_handle: tokio::runtime::Handle,
}

impl DelegationManager {
    async fn fetch(&self) -> Option<CertificateDelegation> {
        let _timer = self.metrics.update_duration.start_timer();

        let delegation = load_root_delegation(
            &self.config,
            &self.log,
            &self.rt_handle,
            self.subnet_id,
            self.nns_subnet_id,
            self.registry_client.as_ref(),
            self.tls_config.as_ref(),
            &self.metrics,
        )
        .await;

        if let Some(delegation) = delegation.as_ref() {
            self.metrics
                .delegation_size
                .observe(delegation.certificate.len() as f64);
        }

        self.metrics.updates.inc();

        delegation
    }

    async fn run(self, sender: watch::Sender<Option<CertificateDelegation>>) {
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

            sender.send_if_modified(move |old_delegation: &mut Option<CertificateDelegation>| {
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
    nns_subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    tls_config: &(dyn TlsConfig + Send + Sync),
    metrics: &DelegationManagerMetrics,
) -> Option<CertificateDelegation> {
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
            "Fetching delegation from the nns subnet. Attempts: {}.",
            fetching_root_delagation_attempts
        );

        let backoff = Duration::from_secs(rand::thread_rng().gen_range(1..15));

        match try_fetch_delegation_from_nns(
            config,
            log,
            rt_handle,
            &subnet_id,
            &nns_subnet_id,
            registry_client,
            tls_config,
        )
        .await
        {
            Ok(delegation) => return Some(delegation),
            Err(err) => {
                warn!(
                    log,
                    "Fetching delegation from nns subnet failed. Retrying again in {} seconds...\
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
    subnet_id: &SubnetId,
    nns_subnet_id: &SubnetId,
    registry_client: &dyn RegistryClient,
    tls_config: &(dyn TlsConfig + Send + Sync),
) -> Result<CertificateDelegation, BoxError> {
    let (peer_id, node) =
        match get_random_node_from_nns_subnet(registry_client, *nns_subnet_id).await {
            Ok(node_topology) => node_topology,
            Err(err) => {
                fatal!(
                    log,
                    "Could not find a node from the root subnet to talk to. Error :{}",
                    err
                );
            }
        };

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
                    Path::new(vec![
                        b"subnet".into(),
                        subnet_id.get().into(),
                        b"canister_ranges".into(),
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

    let ip_addr = node.ip_addr.parse().unwrap();

    let addr = SocketAddr::new(ip_addr, node.port as u16);

    let tls_client_config = tls_config
        .client_config(peer_id, registry_version)
        .map_err(|err| format!("Retrieving TLS client config failed: {:?}.", err))?;

    let tcp_stream: TcpStream = TcpStream::connect(addr)
        .await
        .map_err(|err| format!("Could not connect to node {}. {:?}.", addr, err))?;

    let tls_connector = TlsConnector::from(Arc::new(tls_client_config));
    let irrelevant_domain = "domain.is-irrelevant-as-hostname-verification-is.disabled";
    let tls_stream = tls_connector
        .connect(
            irrelevant_domain
                .try_into()
                // TODO: ideally the expect should run at compile time
                .expect("failed to create domain"),
            tcp_stream,
        )
        .await
        .map_err(|err| {
            format!(
                "Could not establish TLS stream to node {}. {:?}.",
                addr, err
            )
        })?;

    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls_stream)).await?;

    let log_clone = log.clone();

    // Spawn a task to poll the connection, driving the HTTP state
    rt_handle.spawn(async move {
        if let Err(err) = connection.await {
            warn!(log_clone, "Polling connection failed: {:?}.", err);
        }
    });

    // any effective canister id can be used when invoking read_state here
    let uri = "/api/v2/canister/aaaaa-aa/read_state";

    info!(
        log,
        "Attempt to fetch HTTPS delegation from root subnet node with addr = `{}`, uri = `{}`.",
        addr,
        uri
    );

    let nns_request = Request::builder()
        .method(hyper::Method::POST)
        .uri(uri)
        .header(hyper::header::CONTENT_TYPE, CONTENT_TYPE_CBOR)
        .body(Body::new(Full::from(body).map_err(BoxError::from)))?;

    let raw_response_res = request_sender.send_request(nns_request).await?;

    let raw_response = match timeout(
        MAX_REQUEST_RECEIVE_TIMEOUT,
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
            .into())
        }
        Ok(Err(e)) => return Err(format!("Failed to read body from connection: {}", e).into()),
        Err(e) => {
            return Err(format!(
                "Timeout of {}s reached while receiving http body: {}",
                MAX_REQUEST_RECEIVE_TIMEOUT.as_secs(),
                e
            )
            .into())
        }
    };

    debug!(log, "Response from nns subnet: {:?}", raw_response);

    let response: HttpReadStateResponse = serde_cbor::from_slice(&raw_response)?;

    let parsed_delegation: Certificate = serde_cbor::from_slice(&response.certificate)
        .map_err(|e| format!("failed to parse delegation certificate: {}", e))?;

    let labeled_tree = LabeledTree::try_from(parsed_delegation.tree)
        .map_err(|e| format!("Invalid hash tree in the delegation certificate: {:?}", e))?;

    let own_public_key_from_registry = match registry_client
        .get_threshold_signing_public_key_for_subnet(*subnet_id, registry_version)
    {
        Ok(Some(pk)) => Ok(pk),
        Ok(None) => Err(format!(
            "subnet {} public key from registry is empty",
            subnet_id
        )),
        Err(err) => Err(format!(
            "subnet {} public key could not be extracted from registry: {:?}",
            subnet_id, err
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
                    "invalid public key type in certificate for subnet {}",
                    subnet_id
                ))
            } else {
                Ok(())
            }
        }
        _ => Err(format!(
            "subnet {} public key could not be extracted from certificate",
            subnet_id
        )),
    }?;

    let root_threshold_public_key =
        get_root_threshold_public_key(log, registry_client, registry_version, nns_subnet_id)
            .ok_or("could not retrieve threshold root public key from registry")?;

    validate_subnet_delegation_certificate(
        &response.certificate,
        subnet_id,
        &root_threshold_public_key,
    )
    .map_err(|err| format!("invalid subnet delegation certificate: {:?} ", err))?;

    let delegation = CertificateDelegation {
        subnet_id: Blob(subnet_id.get().to_vec()),
        certificate: response.certificate,
    };

    info!(log, "Setting NNS delegation to: {:?}", delegation);
    Ok(delegation)
}

async fn get_random_node_from_nns_subnet(
    registry_client: &dyn RegistryClient,
    nns_subnet_id: SubnetId,
) -> Result<(NodeId, ConnectionEndpoint), String> {
    use rand::seq::SliceRandom;

    let nns_nodes = match registry_client
        .get_node_ids_on_subnet(nns_subnet_id, registry_client.get_latest_version())
    {
        Ok(Some(nns_nodes)) => Ok(nns_nodes),
        Ok(None) => Err("No nns nodes found.".to_string()),
        Err(err) => Err(format!("Failed to get nns nodes from registry: {}", err)),
    }?;

    // Randomly choose a node from the nns subnet.
    let mut rng = rand::thread_rng();
    let nns_node = nns_nodes.choose(&mut rng).ok_or(format!(
        "Failed to choose random nns node. NNS node list: {:?}",
        nns_nodes
    ))?;
    match registry_client.get_node_record(*nns_node, registry_client.get_latest_version()) {
        Ok(Some(node)) => Ok((*nns_node, node.http.ok_or("No http endpoint for node")?)),
        Ok(None) => Err(format!(
            "No transport info found for nns node. {}",
            nns_node
        )),
        Err(err) => Err(format!(
            "failed to get node record for nns node {}. Err: {}",
            nns_node, err
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::RwLock;

    use crate::common::Cbor;

    use axum::response::IntoResponse;
    use axum_server::tls_rustls::RustlsConfig;
    use ic_certification_test_utils::serialize_to_cbor;
    use ic_certification_test_utils::{
        encoded_time, generate_root_of_trust, CertificateBuilder, CertificateData,
    };
    use ic_crypto_tls_interfaces_mocks::MockTlsConfig;
    use ic_crypto_tree_hash::{flatmap, lookup_path, Label, LabeledTree};
    use ic_crypto_utils_threshold_sig_der::public_key_to_der;
    use ic_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_client_helpers::node::{ConnectionEndpoint, NodeRecord};
    use ic_registry_keys::make_node_record_key;
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_test_utilities_registry::{
        add_single_subnet_record, add_subnet_key_record, add_subnet_list_record,
        SubnetRecordBuilder,
    };
    use ic_test_utilities_types::ids::canister_test_id;
    use ic_types::messages::Certificate;
    use ic_types::{
        messages::{Blob, HttpReadStateResponse},
        NodeId,
    };
    use rand::thread_rng;
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::{
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, ServerName, UnixTime},
        ClientConfig, DigitallySignedStruct, SignatureScheme,
    };
    use std::net::TcpListener;
    use std::ops::Deref;
    use std::{net::SocketAddr, sync::Arc};

    use tokio::time::timeout;

    use super::*;

    const NNS_SUBNET_ID: SubnetId = ic_test_utilities_types::ids::SUBNET_1;
    const NON_NNS_SUBNET_ID: SubnetId = ic_test_utilities_types::ids::SUBNET_2;
    const NNS_NODE_ID: NodeId = ic_test_utilities_types::ids::NODE_1;
    const NON_NNS_NODE_ID: NodeId = ic_test_utilities_types::ids::NODE_2;

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

    /// Sets up all the dependencies.
    fn set_up_nns_delegation_dependencies(
        rt_handle: tokio::runtime::Handle,
        // Optional certificate delegation returned by a mocked NNS node.
        // None means we will generate a random, valid certificate.
        override_nns_delegation: Arc<RwLock<Option<CertificateDelegation>>>,
    ) -> (Arc<FakeRegistryClient>, MockTlsConfig) {
        let registry_version = 1;

        let data_provider = Arc::new(ProtoRegistryDataProvider::new());

        add_single_subnet_record(
            &data_provider,
            registry_version,
            NNS_SUBNET_ID,
            SubnetRecordBuilder::new()
                .with_committee(&[NNS_NODE_ID])
                .build(),
        );

        add_single_subnet_record(
            &data_provider,
            registry_version,
            NON_NNS_SUBNET_ID,
            SubnetRecordBuilder::new()
                .with_committee(&[NON_NNS_NODE_ID])
                .build(),
        );

        let (non_nns_public_key, _non_nns_secret_key) = generate_root_of_trust(&mut thread_rng());
        let (nns_public_key, nns_secret_key) = generate_root_of_trust(&mut thread_rng());

        add_subnet_key_record(
            &data_provider,
            registry_version,
            NON_NNS_SUBNET_ID,
            non_nns_public_key,
        );

        add_subnet_key_record(
            &data_provider,
            registry_version,
            NNS_SUBNET_ID,
            nns_public_key,
        );

        add_subnet_list_record(
            &data_provider,
            registry_version,
            vec![NNS_SUBNET_ID, NON_NNS_SUBNET_ID],
        );

        let addr = get_free_localhost_socket_addr();
        let tcp_listener = TcpListener::bind(addr).unwrap();

        let node_record = NodeRecord {
            http: Some(ConnectionEndpoint {
                ip_addr: addr.ip().to_string(),
                port: addr.port() as u32,
            }),
            ..Default::default()
        };

        data_provider
            .add(
                &make_node_record_key(NNS_NODE_ID),
                registry_version.into(),
                Some(node_record),
            )
            .unwrap();

        let registry_client =
            Arc::new(FakeRegistryClient::new(Arc::clone(&data_provider) as Arc<_>));

        registry_client.update_to_latest_version();

        let create_certificate = move |time| {
            let (_certificate, _root_pk, cbor) =
                CertificateBuilder::new(CertificateData::CustomTree(LabeledTree::SubTree(flatmap![
                    Label::from("subnet") => LabeledTree::SubTree(flatmap![
                        Label::from(NON_NNS_SUBNET_ID.get_ref().to_vec()) => LabeledTree::SubTree(flatmap![
                            Label::from("canister_ranges") => LabeledTree::Leaf(serialize_to_cbor(&vec![(canister_test_id(0), canister_test_id(10))])),
                            Label::from("public_key") => LabeledTree::Leaf(public_key_to_der(&non_nns_public_key.into_bytes()).unwrap()),
                        ])
                    ]),
                    Label::from("time") => LabeledTree::Leaf(encoded_time(time))
                ])))
                .with_root_of_trust(nns_public_key, nns_secret_key)
                .build();

            cbor
        };

        rt_handle.spawn(async move {
            let time = Arc::new(RwLock::new(42));

            let router = axum::routing::any(move || async move {
                let mut time = time.write().unwrap();
                *time += 1;

                let certificate =
                    if let Some(delegation) = override_nns_delegation.read().unwrap().deref() {
                        delegation.certificate.clone()
                    } else {
                        Blob(create_certificate(*time))
                    };

                Cbor(HttpReadStateResponse { certificate }).into_response()
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

        (registry_client, tls_config)
    }

    #[tokio::test(start_paused = true)]
    async fn manager_load_root_delegation_on_nns_should_return_none_test() {
        let rt_handle = tokio::runtime::Handle::current();
        let (registry_client, tls_config) =
            set_up_nns_delegation_dependencies(rt_handle.clone(), Arc::new(RwLock::new(None)));

        let (_, mut rx) = start_nns_delegation_manager(
            &MetricsRegistry::new(),
            Config::default(),
            no_op_logger(),
            rt_handle,
            NNS_SUBNET_ID,
            NNS_SUBNET_ID,
            registry_client,
            Arc::new(tls_config),
            CancellationToken::new(),
        );

        rx.changed().await.unwrap();

        assert!(rx.borrow().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn manager_load_root_delegation_on_non_nns_should_return_some_test() {
        let rt_handle = tokio::runtime::Handle::current();
        let (registry_client, tls_config) =
            set_up_nns_delegation_dependencies(rt_handle.clone(), Arc::new(RwLock::new(None)));

        let (_, mut rx) = start_nns_delegation_manager(
            &MetricsRegistry::new(),
            Config::default(),
            no_op_logger(),
            rt_handle,
            NON_NNS_SUBNET_ID,
            NNS_SUBNET_ID,
            registry_client,
            Arc::new(tls_config),
            CancellationToken::new(),
        );

        rx.changed().await.unwrap();

        let delegation = rx
            .borrow()
            .clone()
            .expect("Should return some delegation on non NNS subnet");
        let parsed_delegation: Certificate = serde_cbor::from_slice(&delegation.certificate)
            .expect("Should return a certificate which can be deserialized");
        let tree = LabeledTree::try_from(parsed_delegation.tree)
            .expect("Should return a state tree which can be parsed");
        // Verify that the state tree has the a subtree corresponding to the requested subnet
        match lookup_path(&tree, &[b"subnet", NON_NNS_SUBNET_ID.get_ref().as_ref()]) {
            Some(LabeledTree::SubTree(..)) => (),
            _ => panic!("Didn't find the subnet path in the state tree"),
        }
    }

    const TIMEOUT_WAIT: Duration = Duration::from_secs(3);

    #[tokio::test(start_paused = true)]
    async fn manager_should_not_refresh_if_not_enough_time_passed_test() {
        let rt_handle = tokio::runtime::Handle::current();
        let (registry_client, tls_config) =
            set_up_nns_delegation_dependencies(rt_handle.clone(), Arc::new(RwLock::new(None)));

        let (_, mut rx) = start_nns_delegation_manager(
            &MetricsRegistry::new(),
            Config::default(),
            no_op_logger(),
            rt_handle,
            NON_NNS_SUBNET_ID,
            NNS_SUBNET_ID,
            registry_client,
            Arc::new(tls_config),
            CancellationToken::new(),
        );

        // The initial delegation should be fetched immediately.
        rx.changed().await.unwrap();
        // The subsequent delegations should be fetched only after `DELEGATION_UPDATE_INTERVAL`
        // has elapsed.
        tokio::time::advance(DELEGATION_UPDATE_INTERVAL / 2).await;
        tokio::time::resume();

        assert!(timeout(TIMEOUT_WAIT, rx.changed()).await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn manager_should_refresh_if_enough_time_passed_test() {
        let rt_handle = tokio::runtime::Handle::current();
        let (registry_client, tls_config) =
            set_up_nns_delegation_dependencies(rt_handle.clone(), Arc::new(RwLock::new(None)));

        let (_, mut rx) = start_nns_delegation_manager(
            &MetricsRegistry::new(),
            Config::default(),
            no_op_logger(),
            rt_handle,
            NON_NNS_SUBNET_ID,
            NNS_SUBNET_ID,
            registry_client,
            Arc::new(tls_config),
            CancellationToken::new(),
        );

        // The initial delegation should be fetched immediately.
        rx.changed().await.unwrap();
        // The subsequent delegations should be fetched only after `DELEGATION_UPDATE_INTERVAL`
        // has passed.
        tokio::time::advance(DELEGATION_UPDATE_INTERVAL).await;
        tokio::time::resume();

        assert!(timeout(TIMEOUT_WAIT, rx.changed()).await.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn manager_should_not_return_an_invalid_delegation_test() {
        let override_nns_delegation = Arc::new(RwLock::new(None));
        let rt_handle = tokio::runtime::Handle::current();
        let (registry_client, tls_config) =
            set_up_nns_delegation_dependencies(rt_handle.clone(), override_nns_delegation.clone());

        let (_, mut rx) = start_nns_delegation_manager(
            &MetricsRegistry::new(),
            Config::default(),
            no_op_logger(),
            rt_handle,
            NON_NNS_SUBNET_ID,
            NNS_SUBNET_ID,
            registry_client,
            Arc::new(tls_config),
            CancellationToken::new(),
        );

        // The initial *valid* delegation should be fetched immediately.
        assert!(rx.changed().await.is_ok());

        // Mock an *invalid* certificate delegation.
        *override_nns_delegation.write().unwrap() = Some(CertificateDelegation {
            subnet_id: Blob(vec![]),
            certificate: Blob(vec![]),
        });

        // Advance enough time to wake up the manager
        tokio::time::advance(2 * DELEGATION_UPDATE_INTERVAL).await;
        tokio::time::resume();

        // Since the returned certificate is invalid, we don't expect the manager to return
        // any new certification.
        assert!(timeout(TIMEOUT_WAIT, rx.changed()).await.is_err());

        *override_nns_delegation.write().unwrap() = None;
        // The mocked NNS node should now return a valid certification, so we expect that
        // the manager will fetch and send it to all receivers.
        assert!(rx.changed().await.is_ok());
    }

    #[tokio::test]
    async fn load_root_delegation_on_nns_should_return_none_test() {
        let rt_handle = tokio::runtime::Handle::current();
        let (registry_client, tls_config) =
            set_up_nns_delegation_dependencies(rt_handle.clone(), Arc::new(RwLock::new(None)));

        let delegation = load_root_delegation(
            &Config::default(),
            &no_op_logger(),
            &rt_handle,
            NNS_SUBNET_ID,
            NNS_SUBNET_ID,
            registry_client.as_ref(),
            &tls_config,
            &DelegationManagerMetrics::new(&MetricsRegistry::new()),
        )
        .await;

        assert!(delegation.is_none());
    }

    #[tokio::test]
    async fn load_root_delegation_on_non_nns_should_return_some_test() {
        let rt_handle = tokio::runtime::Handle::current();
        let (registry_client, tls_config) =
            set_up_nns_delegation_dependencies(rt_handle.clone(), Arc::new(RwLock::new(None)));

        let delegation = load_root_delegation(
            &Config::default(),
            &no_op_logger(),
            &rt_handle,
            NON_NNS_SUBNET_ID,
            NNS_SUBNET_ID,
            registry_client.as_ref(),
            &tls_config,
            &DelegationManagerMetrics::new(&MetricsRegistry::new()),
        )
        .await;

        tokio::time::pause();

        let delegation = delegation.expect("Should return Some delegation on non NNS subnet");
        let parsed_delegation: Certificate = serde_cbor::from_slice(&delegation.certificate)
            .expect("Should return a certificate which can be deserialized");
        let tree = LabeledTree::try_from(parsed_delegation.tree)
            .expect("The deserialized delegation should contain a correct tree");
        // Verify that the state tree has the a subtree corresponding to the requested subnet
        match lookup_path(&tree, &[b"subnet", NON_NNS_SUBNET_ID.get_ref().as_ref()]) {
            Some(LabeledTree::SubTree(..)) => (),
            _ => panic!("Didn't find the subnet path in the state tree"),
        }
    }
}
