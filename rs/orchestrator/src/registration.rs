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
use ic_interfaces::crypto::PublicKeyRegistrationStatus;
use ic_interfaces_registry::RegistryClient;
use ic_logger::{info, warn, ReplicaLogger};
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_registry_client_helpers::{
    crypto::CryptoRegistry,
    node_operator::ConnectionEndpoint,
    subnet::{SubnetRegistry, SubnetTransportRegistry},
};
use ic_registry_local_store::LocalStore;
use ic_sys::utility_command::UtilityCommand;
use ic_types::{
    crypto::KeyPurpose, messages::MessageId, registry::IDKG_KEY_UPDATE_FREQUENCY_SECS, NodeId,
    RegistryVersion, SubnetId,
};
use prost::Message;
use rand::prelude::*;
use registry_canister::mutations::do_update_node_directly::UpdateNodeDirectlyPayload;
use registry_canister::mutations::node_management::do_add_node::AddNodePayload;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use std::{net::IpAddr, str::FromStr};
use url::Url;

/// When calculating Gamma (frequency at which the registry accepts key updates from the subnet as a whole)
/// we use a 15% time buffer compensating for a potential delay of the previous node.
const DELAY_COMPENSATION: f64 = 0.85;

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
        if let Err(e) = tokio::task::block_in_place(|| {
            self.key_handler.check_keys_with_registry(latest_version)
        }) {
            warn!(self.log, "Node keys are not setup: {:?}", e);
            self.retry_register_node().await;
            self.touch_eject_file();
        }
        // postcondition: node keys are registered
    }

    // postcondition: we are registered with the NNS
    async fn retry_register_node(&mut self) {
        UtilityCommand::notify_host("Starting node registration.", 1);
        UtilityCommand::notify_host("Attaching HSM.", 1);
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
        };
        // we have the public key

        UtilityCommand::notify_host("Sending add_node request.", 1);
        while !self.is_node_registered() {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let sender = Sender::ExternalHsm {
                pub_key: hsm_pub_key.clone(),
                sign: Arc::new(sign_cmd),
            };
            let nns_url = match self.get_random_nns_url_from_config() {
                Some(url) => url,
                None => continue,
            };
            let agent = Agent::new(nns_url, sender);

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
        }

        UtilityCommand::notify_host(
            "Join request successful!\nYou may now safely remove the HSM.",
            20,
        );
    }

    fn assemble_add_node_message(&self) -> AddNodePayload {
        let node_pub_keys =
            tokio::task::block_in_place(|| self.key_handler.current_node_public_keys());

        AddNodePayload {
            // These four are raw bytes because sadly we can't marshal between pb and candid...
            node_signing_pk: protobuf_to_vec(node_pub_keys.node_signing_public_key.unwrap()),
            committee_signing_pk: protobuf_to_vec(
                node_pub_keys.committee_signing_public_key.unwrap(),
            ),
            ni_dkg_dealing_encryption_pk: protobuf_to_vec(
                node_pub_keys.dkg_dealing_encryption_public_key.unwrap(),
            ),
            transport_tls_cert: protobuf_to_vec(node_pub_keys.tls_certificate.unwrap()),
            idkg_dealing_encryption_pk: node_pub_keys
                .idkg_dealing_encryption_public_key
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

    /// Checks if the nodes keys are properly registered and if there are some
    /// that aren't, try to register them.
    ///
    /// Return true means all is done.
    /// Return false means we will need to check it again later. Also we might
    /// try to register it now, but will need to check the registration later.
    pub async fn check_all_keys_registered_otherwise_register(&self, subnet_id: SubnetId) -> bool {
        let registry_version = self.registry_client.get_latest_version();
        if !self.is_tecdsa_and_time_to_rotate(registry_version, subnet_id) {
            return true;
        }
        match tokio::task::block_in_place(|| {
            self.key_handler.check_keys_with_registry(registry_version)
        }) {
            Ok(PublicKeyRegistrationStatus::IDkgDealingEncPubkeyNeedsRegistration(key)) => {
                // Try to register a key that was previously rotated but is not yet registered.
                self.try_to_register_key(registry_version, key).await
            }
            Ok(PublicKeyRegistrationStatus::RotateIDkgDealingEncryptionKeys) => {
                // Call cypto to rotate the keys and try to register the new key.
                // In case registration of the new key fails, we will enter the branch above
                // during the next call and retry registration.
                match tokio::task::block_in_place(|| {
                    self.key_handler
                        .rotate_idkg_dealing_encryption_keys(registry_version)
                }) {
                    Ok(key) => self.try_to_register_key(registry_version, key).await,
                    Err(e) => warn!(self.log, "Key rotation error: {:?}", e),
                }
            }
            Ok(PublicKeyRegistrationStatus::AllKeysRegistered) => {
                return true; // keys are properly registered, we are all good
            }
            Err(e) => {
                warn!(self.log, "Registry error: {:?}", e);
            }
        }
        false
    }

    fn is_tecdsa_and_time_to_rotate(
        &self,
        registry_version: RegistryVersion,
        subnet_id: SubnetId,
    ) -> bool {
        if !self.is_tecdsa_subnet(subnet_id) {
            warn!(self.log, "Node not part of tECDSA subnet.");
            return false;
        }

        let own_key_timestamp = self
            .registry_client
            .get_crypto_key_for_node(
                self.node_id,
                KeyPurpose::IDkgMEGaEncryption,
                registry_version,
            )
            .unwrap_or_default()
            .and_then(|pk| pk.timestamp);

        // A node can register its key if there is no previous timestamp set, regardless of Gamma
        if own_key_timestamp.is_none() {
            return true;
        }

        let node_ids = match self
            .registry_client
            .get_node_ids_on_subnet(subnet_id, registry_version)
        {
            Ok(Some(ids)) if !ids.is_empty() => ids,
            err => {
                warn!(self.log, "Failed to get node ids from subnet: {:?}", err);
                return false;
            }
        };

        let subnet_size = node_ids.len();

        let node_key_timestamps = node_ids
            .into_iter()
            .filter_map(|nid| {
                self.registry_client
                    .get_crypto_key_for_node(nid, KeyPurpose::IDkgMEGaEncryption, registry_version)
                    .unwrap_or_default()
            })
            .filter_map(|pk| pk.timestamp)
            .map(|ts| SystemTime::UNIX_EPOCH + Duration::from_millis(ts))
            .collect();

        if !is_time_to_rotate(subnet_size, node_key_timestamps) {
            warn!(self.log, "To early to register new key, aborting.");
            return false;
        }

        true
    }

    async fn try_to_register_key(&self, registry_version: RegistryVersion, idkg_pk: PublicKey) {
        let node_id = self.node_id;

        let nns_url = match self
            .get_random_nns_url()
            .or_else(|| self.get_random_nns_url_from_config())
        {
            Some(url) => url,
            None => return,
        };

        let node_pub_key = if let Some(pk) = tokio::task::block_in_place(|| {
            self.key_handler
                .current_node_public_keys()
                .node_signing_public_key
        }) {
            pk
        } else {
            warn!(self.log, "Missing node signing key.");
            return; // missing signing key, can't continue
        };

        let key_handler = self.key_handler.clone();
        let sign_cmd = move |msg: &MessageId| {
            tokio::task::block_in_place(|| {
                key_handler
                    .sign_basic(msg, node_id, registry_version)
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
                    .map(|value| value.get().0)
            })
        };

        let sender = Sender::Node {
            pub_key: node_pub_key.key_value,
            sign: Arc::new(sign_cmd),
        };

        let agent = Agent::new(nns_url.clone(), sender);
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

    // Returns one random NNS url from the node config.
    fn get_random_nns_url_from_config(&self) -> Option<Url> {
        let mut urls = self.node_config.registration.nns_url.as_ref().map(|v| {
            v.split(',')
                .flat_map(|s| match Url::parse(s) {
                    Err(_) => {
                        info!(
                            self.log,
                            "Could not parse registration NNS url {} from config.", s
                        );
                        None
                    }
                    Ok(url) => Some(url),
                })
                .collect::<Vec<Url>>()
        })?;

        let mut rng = thread_rng();
        urls.shuffle(&mut rng);
        urls.pop()
    }

    // Returns one random NNS url from registry.
    fn get_random_nns_url(&self) -> Option<Url> {
        let version = self.registry_client.get_latest_version();
        let root_subnet_id = match self.registry_client.get_root_subnet_id(version) {
            Ok(Some(id)) => id,
            err => {
                warn!(self.log, "Failed to get root subnet id: {:?}", err);
                return None;
            }
        };

        let t_infos = match self
            .registry_client
            .get_subnet_transport_infos(root_subnet_id, version)
        {
            Ok(Some(infos)) => infos,
            err => {
                warn!(self.log, "Failed to get transport infos: {:?}", err);
                return None;
            }
        };

        let mut urls: Vec<Url> = t_infos
            .iter()
            .filter_map(|(_nid, n_record)| {
                n_record
                    .http
                    .as_ref()
                    .and_then(|h| self.http_endpoint_to_url(h))
            })
            .collect();

        let mut rng = thread_rng();
        urls.shuffle(&mut rng);
        urls.pop()
    }

    fn http_endpoint_to_url(&self, http: &ConnectionEndpoint) -> Option<Url> {
        let host_str = match IpAddr::from_str(&http.ip_addr.clone()) {
            Ok(v) => {
                if v.is_ipv6() {
                    format!("[{}]", v)
                } else {
                    v.to_string()
                }
            }
            Err(_) => {
                // assume hostname
                http.ip_addr.clone()
            }
        };

        let url = format!("http://{}:{}/", host_str, http.port);
        match Url::parse(&url) {
            Ok(v) => Some(v),
            Err(e) => {
                warn!(self.log, "Invalid url: {}: {:?}", url, e);
                None
            }
        }
    }

    fn is_node_registered(&self) -> bool {
        let latest_version = self.registry_client.get_latest_version();
        match tokio::task::block_in_place(|| {
            self.key_handler.check_keys_with_registry(latest_version)
        }) {
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

    pub(crate) fn is_tecdsa_subnet(&self, subnet_id: SubnetId) -> bool {
        let version = self.registry_client.get_latest_version();
        match self.registry_client.get_ecdsa_config(subnet_id, version) {
            Ok(Some(config)) => !config.key_ids.is_empty(),
            _ => false,
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

pub(crate) fn is_time_to_rotate(subnet_size: usize, timestamps: Vec<SystemTime>) -> bool {
    let delta = Duration::from_secs(IDKG_KEY_UPDATE_FREQUENCY_SECS);
    // gamma determines the frequency at which the registry accepts key updates from the subnet as a whole
    let gamma = delta
        .div_f64(subnet_size as f64)
        .mul_f64(DELAY_COMPENSATION);
    let now = SystemTime::now();
    timestamps
        .iter()
        .all(|ts| now.duration_since(*ts).map_or(false, |d| d >= gamma))
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

    flow_endpoints.push(format!(
        "{},{}",
        transport_config.legacy_flow_tag,
        get_endpoint(
            log,
            transport_config.node_ip.clone(),
            transport_config.listening_port
        )?
    ));
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
    use ic_test_utilities_logger::with_test_replica_logger;

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
            legacy_flow_tag: 1337,
            listening_port: 23,
            send_queue_size: 1,
        };

        with_test_replica_logger(|log| {
            assert_eq!(
                transport_config_to_endpoints(&log, &transport_config).unwrap(),
                vec!["1337,[::1]:23".to_string()]
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

    #[test]
    fn test_is_time_to_rotate() {
        let subnet_size = 12;
        let hours = |hrs: u64| Duration::from_secs(hrs * 60 * 60);
        let now = SystemTime::now();
        let empty = vec![];
        let valid = vec![now - hours(25), now - hours(36), now - hours(48)];
        let too_recent = vec![now - hours(23), now - hours(25), now - hours(36)];
        let in_future = vec![now - hours(25), now - hours(36), now + hours(1)];

        assert!(is_time_to_rotate(subnet_size, empty));
        assert!(is_time_to_rotate(subnet_size, valid));
        assert!(!is_time_to_rotate(subnet_size, too_recent));
        assert!(!is_time_to_rotate(subnet_size, in_future));
    }
}
