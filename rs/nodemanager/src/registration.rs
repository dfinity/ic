#![allow(dead_code)]
use crate::error::{NodeManagerError, NodeManagerResult};
use candid::Encode;
use ic_canister_client::agent::Sender;
use ic_canister_client::Agent;
use ic_config::{
    http_handler::Config as HttpConfig,
    message_routing::Config as MsgRoutingConfig,
    metrics::{Config as MetricsConfig, Exporter},
    registry_client::DataProviderConfig,
    Config,
};
use ic_crypto_utils_threshold_sig::parse_threshold_sig_key;
use ic_interfaces::crypto::KeyManager;
use ic_interfaces::registry::{RegistryClient, ZERO_REGISTRY_VERSION};
use ic_logger::{info, warn, ReplicaLogger};
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_registry_common::local_store::{
    Changelog, ChangelogEntry, KeyMutation, LocalStoreImpl, LocalStoreReader, LocalStoreWriter,
};
use ic_registry_common::registry::RegistryCanister;
use ic_sys::utility_command::UtilityCommand;
use ic_types::transport::TransportConfig;
use ic_types::RegistryVersion;
use prost::Message;
use rand::prelude::*;
use registry_canister::mutations::do_add_node::AddNodePayload;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use url::Url;

pub(crate) struct NodeRegistration {
    log: ReplicaLogger,
    node_config: Config,
    registry_client: Arc<dyn RegistryClient>,
    key_manager: Arc<dyn KeyManager>,
    local_store: Arc<LocalStoreImpl>,
}

impl NodeRegistration {
    ///
    pub(crate) fn new(
        log: ReplicaLogger,
        node_config: Config,
        registry_client: Arc<dyn RegistryClient>,
        key_manager: Arc<dyn KeyManager>,
        local_store: Arc<LocalStoreImpl>,
    ) -> Self {
        Self {
            log,
            node_config,
            registry_client,
            key_manager,
            local_store,
        }
    }

    /// Register the node with the provided NNS if the node has not been
    /// registered already.
    ///
    /// If the node has not been registered, retries registering the node using
    /// one of the nns nodes in `nns_node_list`.
    pub(crate) async fn register_node(&mut self) {
        self.initialize_local_store().await;

        let latest_version = self.registry_client.get_latest_version();
        if let Err(e) = self.key_manager.check_keys_with_registry(latest_version) {
            warn!(self.log, "Node keys are not setup: {:?}", e);
            self.retry_register_node().await;
            self.touch_eject_file();
        }
        // postcondition: node keys are registered
    }

    pub(crate) async fn initialize_local_store(&mut self) {
        let local_store_path = if let DataProviderConfig::LocalStore(p) = self
            .node_config
            .registry_client
            .data_provider
            .clone()
            .expect("Data Provider is not configured.")
        {
            p
        } else {
            panic!("LocalStore is the only data registry provider supported.")
        };
        std::fs::create_dir_all(local_store_path)
            .expect("Could not create directory for registry local store.");
        if self
            .local_store
            .get_changelog_since_version(ZERO_REGISTRY_VERSION)
            .expect("Could not read registry local store.")
            .is_empty()
        {
            let nns_urls = self
                .node_config
                .registration
                .nns_url
                .clone()
                .expect("Registry Local Store is empty and no NNS Url configured.")
                .split(',')
                .map(|s| Url::parse(s).expect("Could not parse registration NNS url from config"))
                .collect::<Vec<Url>>();

            let nns_pub_key_path = self
                .node_config
                .registration
                .nns_pub_key_pem
                .clone()
                .expect("Registry Local Store is empty and no NNS Public Key configured.");

            let nns_pub_key = parse_threshold_sig_key(&nns_pub_key_path)
                .expect("Could not parse configured NNS Public Key file.");

            let registry_canister = RegistryCanister::new(nns_urls);
            while self
                .local_store
                .get_changelog_since_version(ZERO_REGISTRY_VERSION)
                .expect("Could not read registry local store.")
                .is_empty()
            {
                match registry_canister
                    .get_certified_changes_since(0, &nns_pub_key)
                    .await
                {
                    Ok((mut records, _, t)) if !records.is_empty() => {
                        records.sort_by_key(|tr| tr.version);
                        let changelog = records.iter().fold(Changelog::default(), |mut cl, r| {
                            let rel_version = (r.version - ZERO_REGISTRY_VERSION).get();
                            if cl.len() < rel_version as usize {
                                cl.push(ChangelogEntry::default());
                            }
                            cl.last_mut().unwrap().push(KeyMutation {
                                key: r.key.clone(),
                                value: r.value.clone(),
                            });
                            cl
                        });

                        changelog
                            .into_iter()
                            .enumerate()
                            .try_for_each(|(i, cle)| {
                                let v = ZERO_REGISTRY_VERSION + RegistryVersion::from(i as u64 + 1);
                                self.local_store.store(v, cle)
                            })
                            .expect("Could not write to local store.");
                        self.local_store
                            .update_certified_time(t.as_nanos_since_unix_epoch())
                            .expect("Could not store certified time");
                        return;
                    }
                    Err(e) => warn!(
                        self.log,
                        "Could not fetch registry changelog from NNS: {:?}", e
                    ),
                    _ => {}
                };
                tokio::time::delay_for(Duration::from_secs(30)).await;
            }
        }
    }

    // postcondition: we are registered with the NNS
    async fn retry_register_node(&mut self) {
        let mut version = self.registry_client.get_latest_version();
        while version == ZERO_REGISTRY_VERSION {
            warn!(self.log, "Registry cache is still at version 0.");
            tokio::time::delay_for(Duration::from_secs(10)).await;
            version = self.registry_client.get_latest_version();
        }

        use ic_registry_client::helper::{node::NodeRegistry, subnet::SubnetRegistry};

        let nns_subnet_id = self
            .registry_client
            .get_root_subnet_id(version)
            .expect("Error when fetching nns subnet id.")
            .expect("NNS subnet id not defined");
        let node_ids = self
            .registry_client
            .get_node_ids_on_subnet(nns_subnet_id, version)
            .expect("could not load node ids from nns")
            .expect("no nodes on the nns subnet");

        let mut nns_urls = node_ids
            .iter()
            .map(|nid| {
                let r = self
                    .registry_client
                    .get_transport_info(*nid, version)
                    .expect("Registration: Fetching NNS node record registry failed.")
                    .expect("Registration: No NNS node record found in registry.");
                let http = r.http.expect("no http record");
                let ip = http.ip_addr;
                let port = http.port;
                Url::parse(&format!(
                    "http://{}/",
                    get_endpoint(&self.log, ip, port as u16)
                        .expect("could not parse connection endpoint information")
                ))
                .expect("can't fail")
            })
            .collect::<Vec<_>>();

        let mut rng = thread_rng();
        nns_urls.shuffle(&mut rng);
        let mut nns_urls = nns_urls.iter().cycle();

        let sign_cmd = |msg: &[u8]| {
            UtilityCommand::try_to_attach_hsm();
            let res = UtilityCommand::sign_message(msg.to_vec(), None, None, None)
                .execute()
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>);
            UtilityCommand::try_to_detach_hsm();
            res
        };

        let add_node_payload = self.assemble_add_node_message();

        let read_public_key = UtilityCommand::read_public_key(None, None);
        let hsm_pub_key = loop {
            UtilityCommand::try_to_attach_hsm();
            match read_public_key.execute() {
                Ok(v) => {
                    UtilityCommand::try_to_detach_hsm();
                    break v;
                }
                Err(e) => {
                    warn!(self.log, "Failed to read public key from usb HSM: {:?}", e);
                }
            };

            UtilityCommand::try_to_detach_hsm();
            if self.is_node_registered() {
                return;
            }
            tokio::time::delay_for(Duration::from_secs(2)).await;
        };
        // we have the public key

        while !self.is_node_registered() {
            let sender = Sender::ExternalHsm {
                pub_key: hsm_pub_key.clone(),
                sign: Arc::new(sign_cmd),
            };
            let agent = Agent::new(nns_urls.next().unwrap().clone(), sender);

            if let Err(e) = agent
                .execute_update(
                    &REGISTRY_CANISTER_ID,
                    "add_node",
                    Encode!(&add_node_payload)
                        .expect("Could not encode payload for add_node-call."),
                    generate_nonce(),
                )
                .await
            {
                warn!(self.log, "Error when sending add node request: {:?}", e);
            };
            tokio::time::delay_for(Duration::from_secs(2)).await;
        }
    }

    fn assemble_add_node_message(&self) -> AddNodePayload {
        let node_pub_keys = self.key_manager.node_public_keys();

        AddNodePayload {
            // These four are raw bytes because sadly we can't marshal between pb and candid...
            node_signing_pk: protobuf_to_vec(node_pub_keys.node_signing_pk.unwrap()),
            committee_signing_pk: protobuf_to_vec(node_pub_keys.committee_signing_pk.unwrap()),
            ni_dkg_dealing_encryption_pk: protobuf_to_vec(
                node_pub_keys.dkg_dealing_encryption_pk.unwrap(),
            ),
            transport_tls_cert: protobuf_to_vec(node_pub_keys.tls_certificate.unwrap()),

            xnet_endpoint: msg_routing_config_to_endpoint(
                &self.log,
                &self.node_config.message_routing,
            )
            .expect("Invalid endpoints in message routing config."),
            http_endpoint: http_config_to_endpoint(&self.log, &self.node_config.http_handler)
                .expect("Invalid endpoints in http handler config."),
            p2p_flow_endpoints: transport_config_to_endpoints(
                &self.log,
                &self.node_config.transport,
            )
            .expect("Invalid endpoints in transport config."),
            prometheus_metrics_endpoint: metrics_config_to_endpoint(
                &self.log,
                &self.node_config.metrics,
            )
            .expect("Invalid endpoints in metrics config."),
        }
    }

    fn is_node_registered(&self) -> bool {
        let latest_version = self.registry_client.get_latest_version();
        match self.key_manager.check_keys_with_registry(latest_version) {
            Ok(_) => true,
            Err(e) => {
                warn!(
                    self.log,
                    "Node keys are not setup at version {}: {:?}", latest_version, e
                );
                false
            }
        }
    }

    /// Create file that signal the host vm to eject the keycard.
    fn touch_eject_file(&self) {
        if let Err(e) = std::fs::File::create(
            self.node_config
                .registration
                .eject_keycard_signal_file
                .as_path(),
        ) {
            warn!(self.log, "Could not create ejection file: {:?}", e);
        }
    }
}

pub(crate) fn http_config_to_endpoint(
    log: &ReplicaLogger,
    http_config: &HttpConfig,
) -> NodeManagerResult<String> {
    info!(log, "Reading http config for registration");
    get_endpoint(
        log,
        http_config.listen_addr.ip().to_string(),
        http_config.listen_addr.port(),
    )
}

pub(crate) fn msg_routing_config_to_endpoint(
    log: &ReplicaLogger,
    msg_routing_config: &MsgRoutingConfig,
) -> NodeManagerResult<String> {
    info!(log, "Reading msg routing config for registration");
    get_endpoint(
        log,
        msg_routing_config.xnet_ip_addr.clone(),
        msg_routing_config.xnet_port,
    )
}

pub(crate) fn transport_config_to_endpoints(
    log: &ReplicaLogger,
    transport_config: &TransportConfig,
) -> NodeManagerResult<Vec<String>> {
    info!(log, "Reading transport config for registration");
    let mut flow_endpoints: Vec<String> = vec![];

    if transport_config.p2p_flows.is_empty() {
        return Err(NodeManagerError::invalid_configuration_error(
            "Empty list of transport flows",
        ));
    }

    for tf in transport_config.p2p_flows.iter() {
        flow_endpoints.push(format!(
            "{},{}",
            tf.flow_tag,
            get_endpoint(log, transport_config.node_ip.clone(), tf.server_port)?
        ));
    }
    Ok(flow_endpoints)
}

fn metrics_config_to_endpoint(
    log: &ReplicaLogger,
    metrics_config: &MetricsConfig,
) -> NodeManagerResult<String> {
    if let Exporter::Http(saddr) = metrics_config.exporter {
        return get_endpoint(log, saddr.ip().to_string(), saddr.port());
    }

    Err(NodeManagerError::invalid_configuration_error(
        "Metrics endpoint is not configured.",
    ))
}

fn get_endpoint(log: &ReplicaLogger, ip_addr: String, port: u16) -> NodeManagerResult<String> {
    let parsed_ip_addr: IpAddr = ip_addr.parse().map_err(|_e| {
        NodeManagerError::invalid_configuration_error(format!(
            "Could not parse IP-address: {}",
            ip_addr
        ))
    })?;
    if parsed_ip_addr.is_loopback() {
        warn!(log, "Binding to loopback device!");
    }
    if port == 0 {
        warn!(log, "Binding to port 0");
    }
    let ip_addr_str = match parsed_ip_addr {
        IpAddr::V4(_) => ip_addr,
        IpAddr::V6(_) => format!("[{}]", ip_addr),
    };
    Ok(format!("{}:{}", ip_addr_str, port))
}

/// Create a nonce to be included with the ingress message sent to the node
/// handler.
fn generate_nonce() -> Vec<u8> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_le_bytes()
        .to_vec()
}

fn protobuf_to_vec<M: Message>(entry: M) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    entry.encode(&mut buf).expect("This must not fail");
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_test_utilities::with_test_replica_logger;
    use ic_types::transport::TransportFlowConfig;

    #[test]
    fn default_http_config_endpoint_succeeds() {
        let http_config = HttpConfig::default();

        with_test_replica_logger(|log| {
            assert!(http_config_to_endpoint(&log, &http_config).is_ok());
        });
    }

    #[test]
    fn transport_config_endpoints_succeeds() {
        let mut transport_config = TransportConfig::default();
        transport_config.node_ip = "::1".to_string();
        transport_config.p2p_flows = vec![
            TransportFlowConfig {
                flow_tag: 1337,
                server_port: 23,
                queue_size: 1,
            },
            TransportFlowConfig {
                flow_tag: 1338,
                server_port: 24,
                queue_size: 1,
            },
        ];

        with_test_replica_logger(|log| {
            assert_eq!(
                transport_config_to_endpoints(&log, &transport_config).unwrap(),
                vec!["1337,[::1]:23".to_string(), "1338,[::1]:24".to_string()]
            )
        });
    }

    #[test]
    fn capturing_echo_succeeds() {
        // echo `test` | sha256sum
        let input = "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2".to_string();
        let expected = format!("{}\n", input).as_bytes().to_vec();

        let utility_command = UtilityCommand::new(
            "sh".to_string(),
            vec!["-c".to_string(), format!("echo {}", input)],
        );

        assert_eq!(utility_command.execute().unwrap(), expected)
    }

    #[test]
    fn replacing_return_succeeds() {
        let input = b"coming\rfrom\rold\rmac".to_vec();
        let expected: Vec<_> = input
            .iter()
            .map(|c| if *c == b'\r' { b'\n' } else { *c })
            .collect();

        let utility_command = UtilityCommand::new(
            "tr".to_string(),
            vec!["'\\r'".to_string(), "'\\n'".to_string()],
        )
        .with_input(input);

        assert_eq!(utility_command.execute().unwrap(), expected);
    }
}
