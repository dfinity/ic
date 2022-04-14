#![allow(dead_code)]
use crate::error::{OrchestratorError, OrchestratorResult};
use candid::Encode;
use ic_canister_client::{Agent, Sender};
use ic_config::{
    http_handler::Config as HttpConfig,
    message_routing::Config as MsgRoutingConfig,
    metrics::{Config as MetricsConfig, Exporter},
    transport::TransportConfig,
    Config,
};
use ic_crypto::CryptoComponentForNonReplicaProcess;
use ic_interfaces::{
    crypto::PublicKeyRegistrationStatus,
    registry::{RegistryClient, ZERO_REGISTRY_VERSION},
};
use ic_logger::{info, warn, ReplicaLogger};
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_registry_common::local_store::LocalStore;
use ic_sys::utility_command::UtilityCommand;
use ic_types::{messages::MessageId, NodeId};
use prost::Message;
use rand::prelude::*;
use registry_canister::mutations::do_update_node_directly::UpdateNodeDirectlyPayload;
use registry_canister::mutations::node_management::do_add_node::AddNodePayload;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use url::Url;

/// Subcomponent used to register this node with the provided NNS.
pub(crate) struct NodeRegistration {
    log: ReplicaLogger,
    node_config: Config,
    registry_client: Arc<dyn RegistryClient>,
    node_id: NodeId,
    key_handler: Arc<dyn CryptoComponentForNonReplicaProcess>,
    local_store: Arc<dyn LocalStore>,
}

impl NodeRegistration {
    pub(crate) fn new(
        log: ReplicaLogger,
        node_config: Config,
        registry_client: Arc<dyn RegistryClient>,
        node_id: NodeId,
        key_handler: Arc<dyn CryptoComponentForNonReplicaProcess>,
        local_store: Arc<dyn LocalStore>,
    ) -> Self {
        Self {
            log,
            node_config,
            registry_client,
            node_id,
            key_handler,
            local_store,
        }
    }

    /// Register the node with the provided NNS if the node has not been
    /// registered already.
    ///
    /// If the node has not been registered, retries registering the node using
    /// one of the nns nodes in `nns_node_list`.
    pub(crate) async fn register_node(&mut self) {
        let latest_version = self.registry_client.get_latest_version();
        if let Err(e) = self.key_handler.check_keys_with_registry(latest_version) {
            warn!(self.log, "Node keys are not setup: {:?}", e);
            self.retry_register_node().await;
            self.touch_eject_file();
        }
        // postcondition: node keys are registered
    }

    // postcondition: we are registered with the NNS
    async fn retry_register_node(&mut self) {
        let nns_urls = self.collect_nns_urls().await.unwrap();
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
            tokio::time::sleep(Duration::from_secs(2)).await;
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
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    fn assemble_add_node_message(&self) -> AddNodePayload {
        let node_pub_keys = self.key_handler.node_public_keys();

        AddNodePayload {
            // These four are raw bytes because sadly we can't marshal between pb and candid...
            node_signing_pk: protobuf_to_vec(node_pub_keys.node_signing_pk.unwrap()),
            committee_signing_pk: protobuf_to_vec(node_pub_keys.committee_signing_pk.unwrap()),
            ni_dkg_dealing_encryption_pk: protobuf_to_vec(
                node_pub_keys.dkg_dealing_encryption_pk.unwrap(),
            ),
            transport_tls_cert: protobuf_to_vec(node_pub_keys.tls_certificate.unwrap()),
            idkg_dealing_encryption_pk: node_pub_keys
                .idkg_dealing_encryption_pk
                .map(protobuf_to_vec),
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

    /// Checks if the nodes additional key is properly registered and if it
    /// isn't try to register it.
    ///
    /// Return true means all is done.
    /// Return false means we will need to check it again later. Also we might
    /// try to register it now, but will need to check the registration later.
    pub async fn check_additional_key_registered_otherwise_register(&self) -> bool {
        let registry_version = self.registry_client.get_latest_version();
        match self.key_handler.check_keys_with_registry(registry_version) {
            Ok(PublicKeyRegistrationStatus::IDkgDealingEncPubkeyNeedsRegistration(key)) => {
                self.try_to_register_additional_key(key).await
            }
            Ok(PublicKeyRegistrationStatus::AllKeysRegistered) => {
                return true; // key is properly registered, we are all good
            }
            Err(e) => {
                warn!(self.log, "Registry error: {:?}", e);
            }
        }
        false
    }

    async fn try_to_register_additional_key(&self, idkg_pk: PublicKey) {
        let nns_urls = match self.collect_nns_urls().await {
            Ok(urls) => urls,
            Err(e) => {
                warn!(self.log, "Error collecting URLs: {:?}", e);
                return;
            }
        };

        let node_id = self.node_id;

        let node_pub_key = if let Some(pk) = self.key_handler.node_public_keys().node_signing_pk {
            pk
        } else {
            warn!(self.log, "Missing node signing key.");
            return; // missing signing key, can't continue
        };

        let key_handler = self.key_handler.clone();
        let registry_version = self.registry_client.get_latest_version();
        let sign_cmd = move |msg: &MessageId| {
            key_handler
                .sign_basic(msg, node_id, registry_version)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
                .map(|value| value.get().0)
        };

        let sender = Sender::Node {
            pub_key: node_pub_key.key_value,
            sign: Arc::new(sign_cmd),
        };

        let agent = Agent::new(nns_urls[0].clone(), sender);
        let update_node_payload = UpdateNodeDirectlyPayload {
            idkg_dealing_encryption_pk: Some(protobuf_to_vec(idkg_pk)),
        };

        if let Err(e) = agent
            .execute_update(
                &REGISTRY_CANISTER_ID,
                "update_node_directly",
                Encode!(&update_node_payload)
                    .expect("Could not encode payload for update_node-call."),
                generate_nonce(),
            )
            .await
        {
            warn!(
                self.log,
                "Error when sending register additional key request: {:?}", e
            );
        }
    }

    async fn collect_nns_urls(&self) -> Result<Vec<Url>, String> {
        let mut version = self.registry_client.get_latest_version();
        while version == ZERO_REGISTRY_VERSION {
            warn!(self.log, "Registry cache is still at version 0.");
            tokio::time::sleep(Duration::from_secs(10)).await;
            version = self.registry_client.get_latest_version();
        }
        use ic_registry_client_helpers::{node::NodeRegistry, subnet::SubnetRegistry};
        let nns_subnet_id = self
            .registry_client
            .get_root_subnet_id(version)
            .map_err(|e| format!("Error when fetching NNS subnet ID: {:?}", e))?
            .ok_or("NNS subnet ID not defined")?;
        let node_ids = self
            .registry_client
            .get_node_ids_on_subnet(nns_subnet_id, version)
            .map_err(|e| format!("Could not load node IDs from NNS: {:?}", e))?
            .ok_or("No nodes on the NNS subnet")?;
        let nns_urls: Result<Vec<Url>, String> = node_ids
            .iter()
            .map(|nid| {
                let r = self
                    .registry_client
                    .get_transport_info(*nid, version)
                    .map_err(|e| format!("Fetching NNS node record registry failed: {:?}", e))?
                    .ok_or("No NNS node record found in registry.")?;
                let http = r.http.ok_or("No http record")?;
                let ip = http.ip_addr;
                let port = http.port;
                let url = Url::parse(&format!(
                    "http://{}/",
                    get_endpoint(&self.log, ip, port as u16)
                        .map_err(|e| format!("Could not parse endpoint information: {:?}", e))?
                ))
                .map_err(|e| format!("Can't fail: {:?}", e))?;
                Ok(url)
            })
            .collect::<Result<_, _>>();
        nns_urls.map(|mut urls| {
            let mut rng = thread_rng();
            urls.shuffle(&mut rng);
            urls
        })
    }

    fn is_node_registered(&self) -> bool {
        let latest_version = self.registry_client.get_latest_version();
        match self.key_handler.check_keys_with_registry(latest_version) {
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
) -> OrchestratorResult<String> {
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
) -> OrchestratorResult<String> {
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
) -> OrchestratorResult<Vec<String>> {
    info!(log, "Reading transport config for registration");
    let mut flow_endpoints: Vec<String> = vec![];

    if transport_config.p2p_flows.is_empty() {
        return Err(OrchestratorError::invalid_configuration_error(
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
) -> OrchestratorResult<String> {
    if let Exporter::Http(saddr) = metrics_config.exporter {
        return get_endpoint(log, saddr.ip().to_string(), saddr.port());
    }

    Err(OrchestratorError::invalid_configuration_error(
        "Metrics endpoint is not configured.",
    ))
}

fn get_endpoint(log: &ReplicaLogger, ip_addr: String, port: u16) -> OrchestratorResult<String> {
    let parsed_ip_addr: IpAddr = ip_addr.parse().map_err(|_e| {
        OrchestratorError::invalid_configuration_error(format!(
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
    use ic_config::transport::TransportFlowConfig;
    use ic_test_utilities::with_test_replica_logger;

    #[test]
    fn default_http_config_endpoint_succeeds() {
        let http_config = HttpConfig::default();

        with_test_replica_logger(|log| {
            assert!(http_config_to_endpoint(&log, &http_config).is_ok());
        });
    }

    #[test]
    fn transport_config_endpoints_succeeds() {
        let transport_config = TransportConfig {
            node_ip: "::1".to_string(),
            p2p_flows: vec![
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
            ],
        };

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
