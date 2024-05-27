#![allow(dead_code)]
use crate::{
    error::{OrchestratorError, OrchestratorResult},
    metrics::{KeyRotationStatus, OrchestratorMetrics},
    signer::{Hsm, NodeProviderSigner, Signer},
};
use candid::Encode;
use ic_canister_client::{Agent, Sender};
use ic_config::{
    http_handler::Config as HttpConfig,
    initial_ipv4_config::IPv4Config as InitialIPv4Config,
    message_routing::Config as MsgRoutingConfig,
    metrics::{Config as MetricsConfig, Exporter},
    transport::TransportConfig,
    Config,
};
use ic_interfaces::crypto::IDkgKeyRotationResult;
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
use ic_types::{crypto::KeyPurpose, messages::MessageId, NodeId, RegistryVersion, SubnetId};
use prost::Message;
use rand::prelude::*;
use registry_canister::mutations::{
    common::{check_ipv4_config, is_valid_domain},
    do_update_node_directly::UpdateNodeDirectlyPayload,
    node_management::{
        do_add_node::AddNodePayload, do_update_node_ipv4_config_directly::IPv4Config,
    },
};
use std::{
    net::IpAddr,
    str::FromStr,
    sync::Arc,
    time::{Duration, SystemTime},
};
use url::Url;

/// When calculating Gamma (frequency at which the registry accepts key updates from the subnet as a whole)
/// we use a 15% time buffer compensating for a potential delay of the previous node.
const DELAY_COMPENSATION: f64 = 0.85;

pub trait NodeRegistrationCrypto:
    ic_interfaces::crypto::KeyManager + ic_interfaces::crypto::BasicSigner<MessageId> + Send + Sync
{
}

// Blanket implementation of `NodeRegistrationCrypto` for all types that fulfill the requirements.
impl<T> NodeRegistrationCrypto for T where
    T: ic_interfaces::crypto::KeyManager
        + ic_interfaces::crypto::BasicSigner<MessageId>
        + Send
        + Sync
{
}

/// Subcomponent used to register this node with the provided NNS.
pub(crate) struct NodeRegistration {
    log: ReplicaLogger,
    node_config: Config,
    registry_client: Arc<dyn RegistryClient>,
    metrics: Arc<OrchestratorMetrics>,
    node_id: NodeId,
    key_handler: Arc<dyn NodeRegistrationCrypto>,
    local_store: Arc<dyn LocalStore>,
    signer: Box<dyn Signer>,
}

impl NodeRegistration {
    /// If the PEM is present, use the NodeProviderSigner.
    /// Else, use the HSM.
    pub(crate) fn new(
        log: ReplicaLogger,
        node_config: Config,
        registry_client: Arc<dyn RegistryClient>,
        metrics: Arc<OrchestratorMetrics>,
        node_id: NodeId,
        key_handler: Arc<dyn NodeRegistrationCrypto>,
        local_store: Arc<dyn LocalStore>,
    ) -> Self {
        // If we can open a PEM file under the path specified in the replica config,
        // we use the given node operator private key to register the node.
        let signer: Box<dyn Signer> = match node_config
            .clone()
            .registration
            .node_operator_pem
            .and_then(|path| NodeProviderSigner::new(path.as_path()))
        {
            Some(signer) => Box::new(signer),
            None => Box::new(Hsm),
        };
        Self {
            log,
            node_config,
            registry_client,
            metrics,
            node_id,
            key_handler,
            local_store,
            signer,
        }
    }

    /// Register the node with the provided NNS if the node has not been
    /// registered already.
    ///
    /// If the node has not been registered, retries registering the node using
    /// one of the nns nodes in `nns_node_list`.
    pub(crate) async fn register_node(&mut self) {
        let latest_version = self.registry_client.get_latest_version();
        let key_handler = self.key_handler.clone();
        if let Err(e) = tokio::task::spawn_blocking(move || {
            key_handler.check_keys_with_registry(latest_version)
        })
        .await
        .unwrap()
        {
            warn!(self.log, "Node keys are not setup: {:?}", e);
            UtilityCommand::notify_host(format!("Node keys are not setup: {:?}", e).as_str(), 1);
            self.retry_register_node().await;
        }
        // postcondition: node keys are registered
    }

    // postcondition: we are registered with the NNS
    async fn retry_register_node(&mut self) {
        let add_node_payload = self.assemble_add_node_message().await;

        while !self.is_node_registered().await {
            warn!(self.log, "Node registration failed. Trying again.");
            UtilityCommand::notify_host("Node registration failed. Trying again.", 1);
            match self.signer.get() {
                Ok(signer) => {
                    let nns_url = self
                        .get_random_nns_url_from_config()
                        .expect("no NNS urls available");
                    let agent = Agent::new(nns_url, signer);
                    if let Err(e) = agent
                        .execute_update(
                            &REGISTRY_CANISTER_ID,
                            &REGISTRY_CANISTER_ID,
                            "add_node",
                            Encode!(&add_node_payload)
                                .expect("Could not encode payload for the registration request"),
                            generate_nonce(),
                        )
                        .await
                    {
                        warn!(self.log, "Registration request failed: {}", e);
                        UtilityCommand::notify_host(
                            format!(
                                "node-id {}: Registration request failed: {}",
                                self.node_id, e
                            )
                            .as_str(),
                            1,
                        );
                    };
                }
                Err(e) => {
                    warn!(self.log, "Failed to create the message signer: {}", e);
                    UtilityCommand::notify_host(
                        format!(
                            "node-id {}: Failed to create the message signer: {}",
                            self.node_id, e
                        )
                        .as_str(),
                        1,
                    );
                }
            };
            tokio::time::sleep(Duration::from_secs(5)).await;
        }

        UtilityCommand::notify_host(
            format!(
                "node-id {}:\nJoin request successful! The node has successfully joined the Internet Computer, and the node onboarding is now complete.\nVerify that the node has successfully onboarded by checking its status on the Internet Computer dashboard.",
                self.node_id
            )
            .as_str(),
            10,
        );
    }

    async fn assemble_add_node_message(&self) -> AddNodePayload {
        let key_handler = self.key_handler.clone();
        let node_pub_keys =
            tokio::task::spawn_blocking(move || key_handler.current_node_public_keys())
                .await
                .unwrap()
                .expect("Failed to retrieve current node public keys");
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
            p2p_flow_endpoints: vec![],
            chip_id: None,
            prometheus_metrics_endpoint: "".to_string(),
            public_ipv4_config: process_ipv4_config(
                &self.log,
                &self.node_config.initial_ipv4_config,
            )
            .expect("Invalid IPv4 configuration"),
            domain: process_domain_name(&self.log, &self.node_config.domain)
                .expect("Domain name is invalid"),
        }
    }

    /// Checks if the nodes keys are properly registered and if there are some
    /// that aren't, try to register them.
    ///
    /// This method is intended to be called periodically, such that failed attempts
    /// to generate or register keys are retried.
    pub async fn check_all_keys_registered_otherwise_register(&self, subnet_id: SubnetId) {
        let registry_version = self.registry_client.get_latest_version();
        // If there is no ECDSA config or no key_ids, ECDSA is disabled.
        // Delta is the key rotation period of a single node, if it is None, key rotation is disabled.
        let delta = match self.get_key_rotation_period(registry_version, subnet_id) {
            Some(delta) => delta,
            None => {
                self.metrics
                    .observe_key_rotation_status(KeyRotationStatus::Disabled);
                return;
            }
        };

        let key_handler = self.key_handler.clone();
        if let Err(e) = tokio::task::spawn_blocking(move || {
            key_handler.check_keys_with_registry(registry_version)
        })
        .await
        .unwrap()
        {
            self.metrics.observe_key_rotation_error();
            warn!(self.log, "Failed to check keys with registry: {e:?}");
            UtilityCommand::notify_host(
                format!("Failed to check keys with registry: {:?}", e).as_str(),
                1,
            );
        }

        if !self.is_time_to_rotate(registry_version, subnet_id, delta) {
            self.metrics
                .observe_key_rotation_status(KeyRotationStatus::TooRecent);
            return;
        }

        // Call crypto to check if the local node should rotate its keys, and potentially
        // try to register the new key, or a previously rotated key that was not yet
        // registered.
        // In case registration of a key fails, we will enter this branch
        // during the next call and retry registration.
        let key_handler = self.key_handler.clone();
        self.metrics
            .observe_key_rotation_status(KeyRotationStatus::Rotating);
        match tokio::task::spawn_blocking(move || {
            key_handler.rotate_idkg_dealing_encryption_keys(registry_version)
        })
        .await
        .unwrap()
        {
            Ok(IDkgKeyRotationResult::IDkgDealingEncPubkeyNeedsRegistration(rotation_outcome)) => {
                self.register_key(registry_version, PublicKey::from(rotation_outcome))
                    .await
            }
            Ok(IDkgKeyRotationResult::LatestRotationTooRecent) => {}
            Err(e) => {
                self.metrics.observe_key_rotation_error();
                warn!(self.log, "Key rotation error: {e:?}");
                UtilityCommand::notify_host(format!("Key rotation error: {:?}", e).as_str(), 1);
            }
        }
    }

    async fn register_key(&self, registry_version: RegistryVersion, idkg_pk: PublicKey) {
        self.metrics
            .observe_key_rotation_status(KeyRotationStatus::Registering);
        match self.try_to_register_key(registry_version, idkg_pk).await {
            Ok(()) => {
                self.metrics
                    .observe_key_rotation_status(KeyRotationStatus::Registered);
                info!(self.log, "Registration attempt finished successfully.");
            }
            Err(e) => {
                self.metrics.observe_key_rotation_error();
                warn!(self.log, "Failed to register key: {e:?}");
            }
        }
    }

    fn get_key_rotation_period(
        &self,
        registry_version: RegistryVersion,
        subnet_id: SubnetId,
    ) -> Option<Duration> {
        match self
            .registry_client
            .get_ecdsa_config(subnet_id, registry_version)
        {
            Ok(Some(config)) if !config.key_ids.is_empty() => config
                .idkg_key_rotation_period_ms
                .map(Duration::from_millis),
            _ => None,
        }
    }

    fn is_time_to_rotate(
        &self,
        registry_version: RegistryVersion,
        subnet_id: SubnetId,
        delta: Duration,
    ) -> bool {
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

        is_time_to_rotate_in_subnet(delta, subnet_size, node_key_timestamps)
    }

    async fn try_to_register_key(
        &self,
        registry_version: RegistryVersion,
        idkg_pk: PublicKey,
    ) -> Result<(), String> {
        info!(self.log, "Trying to register rotated idkg key...");

        let node_id = self.node_id;
        let nns_url = match self
            .get_random_nns_url()
            .or_else(|| self.get_random_nns_url_from_config())
        {
            Some(url) => url,
            None => return Err("Failed to get random NNS URL.".into()),
        };
        let key_handler = self.key_handler.clone();
        let node_pub_key_opt = tokio::task::spawn_blocking(move || {
            key_handler
                .current_node_public_keys()
                .map(|cnpks| cnpks.node_signing_public_key)
        })
        .await
        .unwrap();

        let node_pub_key = match node_pub_key_opt {
            Ok(Some(pk)) => pk,
            Ok(None) => {
                return Err("Missing node signing key.".into());
            }
            Err(e) => {
                return Err(format!("Failed to retrieve current node public keys: {e}"));
            }
        };

        let key_handler = self.key_handler.clone();
        let sign_cmd = move |msg: &MessageId| {
            // Implementation of 'sign_basic' uses Tokio's 'block_on' when issuing a RPC
            // to the crypto service. 'block_on' panics when called from async context
            // that's why we need to wrap 'sign_basic' in 'block_in_place'.
            #[allow(clippy::disallowed_methods)]
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

        let arguments =
            Encode!(&update_node_payload).expect("Could not encode payload for update_node-call.");
        agent
            .execute_update(
                &REGISTRY_CANISTER_ID,
                &REGISTRY_CANISTER_ID,
                "update_node_directly",
                arguments,
                generate_nonce(),
            )
            .await
            .map_err(|e| format!("Error when sending register additional key request: {e}"))?;

        Ok(())
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
            .get_subnet_node_records(root_subnet_id, version)
        {
            Ok(Some(infos)) => infos,
            err => {
                warn!(self.log, "failed to get node records: {:?}", err);
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

    async fn is_node_registered(&self) -> bool {
        let latest_version = self.registry_client.get_latest_version();
        let key_handler = self.key_handler.clone();
        match tokio::task::spawn_blocking(move || {
            key_handler.check_keys_with_registry(latest_version)
        })
        .await
        .unwrap()
        {
            Ok(_) => true,
            Err(e) => {
                warn!(self.log, "Node keys are not setup: {:?}", e);
                UtilityCommand::notify_host(
                    format!("Node keys are not setup: {:?}", e).as_str(),
                    1,
                );
                false
            }
        }
    }
}

/// Given Δ (= key rotation period of a single node), calculates Ɣ = Δ/subnet_size * delay_compensation
/// (= key rotation period of the subnet as a whole). Then determines if at least Ɣ time has passed
/// since all of the given timestamps. Iff so, return true to indicate that the subnet is ready to accept
/// a new key rotation.
pub(crate) fn is_time_to_rotate_in_subnet(
    delta: Duration,
    subnet_size: usize,
    timestamps: Vec<SystemTime>,
) -> bool {
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
        "0,{}",
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
    let parsed_ip_addr: IpAddr = ip_addr.parse().map_err(|err| {
        OrchestratorError::invalid_configuration_error(format!(
            "Could not parse IP-address {}: {}",
            ip_addr, err
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

fn process_ipv4_config(
    log: &ReplicaLogger,
    ipv4_config: &InitialIPv4Config,
) -> OrchestratorResult<Option<IPv4Config>> {
    info!(log, "Reading ipv4 config for registration");
    if !ipv4_config.public_address.is_empty() {
        let (node_ip_address, prefix_length) = ipv4_config.public_address.split_once('/').ok_or(
            OrchestratorError::invalid_configuration_error(format!(
                "Failed to split the IPv4 public address into IP address and prefix: {}",
                ipv4_config.public_address
            )),
        )?;

        let prefix_length = prefix_length.parse::<u32>().map_err(|err| {
            OrchestratorError::invalid_configuration_error(format!(
                "IPv4 prefix length is malformed. It should be an integer: {err}",
            ))
        })?;

        let ipv4_config = IPv4Config {
            ip_addr: node_ip_address.to_string(),
            gateway_ip_addr: ipv4_config.public_gateway.clone(),
            prefix_length,
        };

        check_ipv4_config(
            ipv4_config.ip_addr.to_string(),
            vec![ipv4_config.gateway_ip_addr.to_string()],
            ipv4_config.prefix_length,
        )
        .map_err(|err| OrchestratorError::invalid_configuration_error(format!("{err}",)))?;

        return Ok(Some(ipv4_config));
    }
    Ok(None)
}

fn process_domain_name(log: &ReplicaLogger, domain: &str) -> OrchestratorResult<Option<String>> {
    info!(log, "Reading domain name for registration");
    match domain {
        "" => Ok(None),
        domain if is_valid_domain(domain) => Ok(Some(domain.into())),
        _ => Err(OrchestratorError::invalid_configuration_error(format!(
            "Provided domain name {} is invalid",
            domain
        ))),
    }
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
    use ic_sys::utility_command::UtilityCommand;
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
            listening_port: 23,
            send_queue_size: 1,
            ..Default::default()
        };

        with_test_replica_logger(|log| {
            assert_eq!(
                transport_config_to_endpoints(&log, &transport_config).unwrap(),
                vec!["0,[::1]:23".to_string()]
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
        let delta = Duration::from_secs(14 * 24 * 60 * 60); //2 weeks

        assert!(is_time_to_rotate_in_subnet(delta, subnet_size, empty));
        assert!(is_time_to_rotate_in_subnet(delta, subnet_size, valid));
        assert!(!is_time_to_rotate_in_subnet(delta, subnet_size, too_recent));
        assert!(!is_time_to_rotate_in_subnet(delta, subnet_size, in_future));
    }

    mod idkg_dealing_encryption_key_rotation {
        use super::*;
        use ic_crypto_temp_crypto::EcdsaSubnetConfig;
        use ic_interfaces::crypto::{
            BasicSigner, CheckKeysWithRegistryError, CurrentNodePublicKeysError,
            IDkgDealingEncryptionKeyRotationError, KeyManager, KeyRotationOutcome,
            ThresholdSigVerifierByPublicKey,
        };
        use ic_logger::replica_logger::no_op_logger;
        use ic_metrics::MetricsRegistry;
        use ic_protobuf::registry::subnet::v1::SubnetListRecord;
        use ic_registry_client_fake::FakeRegistryClient;
        use ic_registry_keys::{
            make_crypto_node_key, make_subnet_list_record_key, make_subnet_record_key,
        };
        use ic_registry_local_store::LocalStoreImpl;
        use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
        use ic_test_utilities_in_memory_logger::{
            assertions::LogEntriesAssert, InMemoryReplicaLogger,
        };
        use ic_types::{
            consensus::CatchUpContentProtobufBytes,
            crypto::{
                AlgorithmId, BasicSigOf, CombinedThresholdSigOf, CryptoResult,
                CurrentNodePublicKeys,
            },
            registry::RegistryClientError,
            PrincipalId,
        };
        use mockall::{predicate::*, *};
        use slog::Level;
        use std::time::UNIX_EPOCH;
        use tempfile::TempDir;

        const REGISTRY_VERSION_1: RegistryVersion = RegistryVersion::new(1);

        mock! {
            pub KeyRotationCryptoComponent{}

            impl KeyManager for KeyRotationCryptoComponent {
                fn check_keys_with_registry(
                    &self,
                    registry_version: RegistryVersion,
                ) -> Result<(), CheckKeysWithRegistryError>;

                fn current_node_public_keys(
                    &self,
                ) -> Result<CurrentNodePublicKeys, CurrentNodePublicKeysError>;

                fn rotate_idkg_dealing_encryption_keys(
                    &self,
                    registry_version: RegistryVersion,
                ) -> Result<IDkgKeyRotationResult, IDkgDealingEncryptionKeyRotationError>;
            }

            impl BasicSigner<MessageId> for KeyRotationCryptoComponent {
                fn sign_basic(
                    &self,
                    message: &MessageId,
                    signer: NodeId,
                    registry_version: RegistryVersion,
                ) -> CryptoResult<BasicSigOf<MessageId>>;
            }

            impl ThresholdSigVerifierByPublicKey<CatchUpContentProtobufBytes> for KeyRotationCryptoComponent {
                fn verify_combined_threshold_sig_by_public_key(
                    &self,
                    signature: &CombinedThresholdSigOf<CatchUpContentProtobufBytes>,
                    message: &CatchUpContentProtobufBytes,
                    subnet_id: SubnetId,
                    registry_version: RegistryVersion,
                ) -> CryptoResult<()>;
            }
        }

        struct Setup {
            node_registration: NodeRegistration,
            subnet_id: SubnetId,
        }

        impl Setup {
            fn builder() -> SetupBuilder {
                SetupBuilder {
                    check_keys_with_registry_result: None,
                    rotate_idkg_dealing_encryption_keys_result: None,
                    logger: None,
                    without_ecdsa_subnet_config: false,
                    idkg_dealing_encryption_public_key_in_registry: None,
                }
            }
        }

        struct SetupBuilder {
            check_keys_with_registry_result: Option<Result<(), CheckKeysWithRegistryError>>,
            rotate_idkg_dealing_encryption_keys_result:
                Option<Result<IDkgKeyRotationResult, IDkgDealingEncryptionKeyRotationError>>,
            logger: Option<ReplicaLogger>,
            without_ecdsa_subnet_config: bool,
            idkg_dealing_encryption_public_key_in_registry: Option<PublicKey>,
        }

        impl SetupBuilder {
            fn with_check_keys_with_registry_result(
                mut self,
                check_keys_with_registry_result: Result<(), CheckKeysWithRegistryError>,
            ) -> Self {
                self.check_keys_with_registry_result = Some(check_keys_with_registry_result);
                self
            }

            fn with_rotate_idkg_dealing_encryption_keys_result(
                mut self,
                rotate_idkg_dealing_encryption_keys_result: Result<
                    IDkgKeyRotationResult,
                    IDkgDealingEncryptionKeyRotationError,
                >,
            ) -> Self {
                self.rotate_idkg_dealing_encryption_keys_result =
                    Some(rotate_idkg_dealing_encryption_keys_result);
                self
            }

            fn with_logger(mut self, in_memory_logger: &InMemoryReplicaLogger) -> Self {
                self.logger = Some(ReplicaLogger::from(in_memory_logger));
                self
            }

            fn without_ecdsa_subnet_config(mut self) -> Self {
                self.without_ecdsa_subnet_config = true;
                self
            }

            fn with_idkg_dealing_encryption_public_key_in_registry(
                mut self,
                idkg_dealing_encryption_public_key: PublicKey,
            ) -> Self {
                self.idkg_dealing_encryption_public_key_in_registry =
                    Some(idkg_dealing_encryption_public_key);
                self
            }

            fn build(self) -> Setup {
                let temp_dir = TempDir::new().expect("error creating TempDir");
                let node_id = NodeId::from(PrincipalId::new_node_test_id(42));
                let registry_data = Arc::new(ProtoRegistryDataProvider::new());
                let registry_client =
                    Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));

                let subnet_id = SubnetId::new(PrincipalId::new(29, [0xfc; 29]));
                if !self.without_ecdsa_subnet_config {
                    let ecdsa_subnet_config = EcdsaSubnetConfig::new(
                        subnet_id,
                        Some(node_id),
                        Some(Duration::from_secs(60 * 60 * 24 * 14)),
                    );
                    registry_data
                        .add(
                            &make_subnet_record_key(ecdsa_subnet_config.subnet_id),
                            REGISTRY_VERSION_1,
                            Some(ecdsa_subnet_config.subnet_record),
                        )
                        .expect("Failed to add subnet record.");
                    let subnet_list_record = SubnetListRecord {
                        subnets: vec![ecdsa_subnet_config.subnet_id.get().into_vec()],
                    };
                    // Set subnetwork list
                    registry_data
                        .add(
                            make_subnet_list_record_key().as_str(),
                            REGISTRY_VERSION_1,
                            Some(subnet_list_record),
                        )
                        .expect("Failed to add subnet list record key");
                }
                if let Some(idkg_dealing_encryption_public_key_in_registry) =
                    self.idkg_dealing_encryption_public_key_in_registry
                {
                    registry_data
                        .add(
                            &make_crypto_node_key(node_id, KeyPurpose::IDkgMEGaEncryption),
                            REGISTRY_VERSION_1,
                            Some(idkg_dealing_encryption_public_key_in_registry),
                        )
                        .expect("failed to add iDKG dealing encryption key to registry");
                }
                registry_client.reload();

                let metrics = MetricsRegistry::new();
                let orchestrator_metrics = Arc::new(OrchestratorMetrics::new(&metrics));

                let mut key_handler = MockKeyRotationCryptoComponent::new();
                if let Some(check_keys_with_registry_result) = self.check_keys_with_registry_result
                {
                    key_handler
                        .expect_check_keys_with_registry()
                        .times(1)
                        .return_const(check_keys_with_registry_result);
                }
                if let Some(rotate_idkg_dealing_encryption_keys_result) =
                    self.rotate_idkg_dealing_encryption_keys_result
                {
                    key_handler
                        .expect_rotate_idkg_dealing_encryption_keys()
                        .times(1)
                        .return_const(rotate_idkg_dealing_encryption_keys_result);
                }

                let local_store = Arc::new(LocalStoreImpl::new(temp_dir.as_ref()));
                let node_config = Config::new(temp_dir.into_path());

                let node_registration = NodeRegistration::new(
                    self.logger.unwrap_or_else(no_op_logger),
                    node_config,
                    registry_client,
                    orchestrator_metrics,
                    node_id,
                    Arc::new(key_handler),
                    local_store,
                );

                Setup {
                    node_registration,
                    subnet_id,
                }
            }
        }

        fn valid_idkg_dealing_encryption_public_key() -> PublicKey {
            PublicKey {
                version: 0,
                algorithm: AlgorithmId::MegaSecp256k1 as i32,
                key_value: hex_decode(
                    "03e1e1f76e9d834221a26c4a080b65e60d3b6f9c1d6e5b880abf916a364893da2e",
                ),
                proof_data: None,
                timestamp: None,
            }
        }

        fn hex_decode<T: AsRef<[u8]>>(data: T) -> Vec<u8> {
            hex::decode(data).expect("failed to decode hex")
        }

        #[tokio::test]
        async fn should_not_log_anything_if_key_rotation_disabled() {
            let in_memory_logger = InMemoryReplicaLogger::new();
            let setup = Setup::builder()
                .without_ecdsa_subnet_config()
                .with_logger(&in_memory_logger)
                .build();

            setup
                .node_registration
                .check_all_keys_registered_otherwise_register(setup.subnet_id)
                .await;

            let logs = in_memory_logger.drain_logs();
            LogEntriesAssert::assert_that(logs).has_len(0);
        }

        #[tokio::test]
        async fn should_not_log_anything_if_not_time_to_rotate() {
            let in_memory_logger = InMemoryReplicaLogger::new();
            let mut idkg_dealing_encryption_public_key = valid_idkg_dealing_encryption_public_key();
            idkg_dealing_encryption_public_key.timestamp = Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("error getting current time")
                    .as_millis() as u64,
            );
            let setup = Setup::builder()
                .with_logger(&in_memory_logger)
                .with_idkg_dealing_encryption_public_key_in_registry(
                    idkg_dealing_encryption_public_key,
                )
                .with_check_keys_with_registry_result(Ok(()))
                .build();

            setup
                .node_registration
                .check_all_keys_registered_otherwise_register(setup.subnet_id)
                .await;

            let logs = in_memory_logger.drain_logs();
            LogEntriesAssert::assert_that(logs).has_len(0);
        }

        #[tokio::test]
        async fn should_not_log_anything_if_check_keys_with_registry_succeeds_and_latest_rotation_too_recent(
        ) {
            let in_memory_logger = InMemoryReplicaLogger::new();
            let setup = Setup::builder()
                .with_check_keys_with_registry_result(Ok(()))
                .with_rotate_idkg_dealing_encryption_keys_result(Ok(
                    IDkgKeyRotationResult::LatestRotationTooRecent,
                ))
                .with_logger(&in_memory_logger)
                .build();

            setup
                .node_registration
                .check_all_keys_registered_otherwise_register(setup.subnet_id)
                .await;

            let logs = in_memory_logger.drain_logs();
            LogEntriesAssert::assert_that(logs).has_len(0);
        }

        #[tokio::test]
        async fn should_log_error_if_check_keys_with_registry_returns_public_key_not_found_error() {
            let in_memory_logger = InMemoryReplicaLogger::new();
            let setup = Setup::builder()
                .with_check_keys_with_registry_result(Err(
                    CheckKeysWithRegistryError::PublicKeyNotFound {
                        node_id: NodeId::from(PrincipalId::new_node_test_id(42)),
                        key_purpose: KeyPurpose::IDkgMEGaEncryption,
                        registry_version: REGISTRY_VERSION_1,
                    },
                ))
                .with_rotate_idkg_dealing_encryption_keys_result(Ok(
                    IDkgKeyRotationResult::LatestRotationTooRecent,
                ))
                .with_logger(&in_memory_logger)
                .build();

            setup
                .node_registration
                .check_all_keys_registered_otherwise_register(setup.subnet_id)
                .await;

            let logs = in_memory_logger.drain_logs();
            LogEntriesAssert::assert_that(logs).has_only_one_message_containing(
                &Level::Warning,
                "Failed to check keys with registry: PublicKeyNotFound",
            );
        }

        #[tokio::test]
        async fn should_log_error_if_check_keys_with_registry_returns_tls_cert_not_found_error() {
            let in_memory_logger = InMemoryReplicaLogger::new();
            let setup = Setup::builder()
                .with_check_keys_with_registry_result(Err(
                    CheckKeysWithRegistryError::TlsCertNotFound {
                        node_id: NodeId::from(PrincipalId::new_node_test_id(42)),
                        registry_version: REGISTRY_VERSION_1,
                    },
                ))
                .with_rotate_idkg_dealing_encryption_keys_result(Ok(
                    IDkgKeyRotationResult::LatestRotationTooRecent,
                ))
                .with_logger(&in_memory_logger)
                .build();

            setup
                .node_registration
                .check_all_keys_registered_otherwise_register(setup.subnet_id)
                .await;

            let logs = in_memory_logger.drain_logs();
            LogEntriesAssert::assert_that(logs).has_only_one_message_containing(
                &Level::Warning,
                "Failed to check keys with registry: TlsCertNotFound",
            );
        }

        #[tokio::test]
        async fn should_log_error_if_check_keys_with_registry_returns_internal_error() {
            let in_memory_logger = InMemoryReplicaLogger::new();
            let setup = Setup::builder()
                .with_check_keys_with_registry_result(Err(
                    CheckKeysWithRegistryError::InternalError {
                        internal_error: "internal error".to_string(),
                    },
                ))
                .with_rotate_idkg_dealing_encryption_keys_result(Ok(
                    IDkgKeyRotationResult::LatestRotationTooRecent,
                ))
                .with_logger(&in_memory_logger)
                .build();

            setup
                .node_registration
                .check_all_keys_registered_otherwise_register(setup.subnet_id)
                .await;

            let logs = in_memory_logger.drain_logs();
            LogEntriesAssert::assert_that(logs).has_only_one_message_containing(
                &Level::Warning,
                "Failed to check keys with registry: InternalError",
            );
        }

        #[tokio::test]
        async fn should_log_error_if_check_keys_with_registry_returns_transient_internal_error() {
            let in_memory_logger = InMemoryReplicaLogger::new();
            let setup = Setup::builder()
                .with_check_keys_with_registry_result(Err(
                    CheckKeysWithRegistryError::TransientInternalError {
                        internal_error: "internal error".to_string(),
                    },
                ))
                .with_rotate_idkg_dealing_encryption_keys_result(Ok(
                    IDkgKeyRotationResult::LatestRotationTooRecent,
                ))
                .with_logger(&in_memory_logger)
                .build();

            setup
                .node_registration
                .check_all_keys_registered_otherwise_register(setup.subnet_id)
                .await;

            let logs = in_memory_logger.drain_logs();
            LogEntriesAssert::assert_that(logs).has_only_one_message_containing(
                &Level::Warning,
                "Failed to check keys with registry: TransientInternalError",
            );
        }

        #[tokio::test]
        async fn should_try_to_register_key_if_key_is_rotated() {
            let in_memory_logger = InMemoryReplicaLogger::new();
            let setup = Setup::builder()
                .with_check_keys_with_registry_result(Ok(()))
                .with_rotate_idkg_dealing_encryption_keys_result(Ok(
                    IDkgKeyRotationResult::IDkgDealingEncPubkeyNeedsRegistration(
                        KeyRotationOutcome::KeyRotated {
                            new_key: valid_idkg_dealing_encryption_public_key(),
                        },
                    ),
                ))
                .with_logger(&in_memory_logger)
                .build();

            setup
                .node_registration
                .check_all_keys_registered_otherwise_register(setup.subnet_id)
                .await;

            let logs = in_memory_logger.drain_logs();
            LogEntriesAssert::assert_that(logs).has_only_one_message_containing(
                &Level::Info,
                "Trying to register rotated idkg key...",
            );
        }

        #[tokio::test]
        async fn should_log_error_if_key_rotation_returns_key_generation_error() {
            let in_memory_logger = InMemoryReplicaLogger::new();
            let setup = Setup::builder()
                .with_check_keys_with_registry_result(Ok(()))
                .with_rotate_idkg_dealing_encryption_keys_result(Err(
                    IDkgDealingEncryptionKeyRotationError::KeyGenerationError(
                        "error generation iDKG dealing encryption key".to_string(),
                    ),
                ))
                .with_logger(&in_memory_logger)
                .build();

            setup
                .node_registration
                .check_all_keys_registered_otherwise_register(setup.subnet_id)
                .await;

            let logs = in_memory_logger.drain_logs();
            LogEntriesAssert::assert_that(logs).has_only_one_message_containing(
                &Level::Warning,
                "Key rotation error: KeyGenerationError(\"error generation iDKG dealing encryption key\")",
            );
        }

        #[tokio::test]
        async fn should_log_error_if_key_rotation_returns_registry_error() {
            let in_memory_logger = InMemoryReplicaLogger::new();
            let setup = Setup::builder()
                .with_check_keys_with_registry_result(Ok(()))
                .with_rotate_idkg_dealing_encryption_keys_result(Err(
                    IDkgDealingEncryptionKeyRotationError::RegistryClientError(
                        RegistryClientError::DecodeError {
                            error: "error decoding key from registry".to_string(),
                        },
                    ),
                ))
                .with_logger(&in_memory_logger)
                .build();

            setup
                .node_registration
                .check_all_keys_registered_otherwise_register(setup.subnet_id)
                .await;

            let logs = in_memory_logger.drain_logs();
            LogEntriesAssert::assert_that(logs).has_only_one_message_containing(
                &Level::Warning,
                "Key rotation error: RegistryClientError(DecodeError { error: \"error decoding key from registry\" })",
            );
        }

        #[tokio::test]
        async fn should_log_error_if_key_rotation_returns_key_rotation_not_enabled() {
            let in_memory_logger = InMemoryReplicaLogger::new();
            let setup = Setup::builder()
                .with_check_keys_with_registry_result(Ok(()))
                .with_rotate_idkg_dealing_encryption_keys_result(Err(
                    IDkgDealingEncryptionKeyRotationError::KeyRotationNotEnabled,
                ))
                .with_logger(&in_memory_logger)
                .build();

            setup
                .node_registration
                .check_all_keys_registered_otherwise_register(setup.subnet_id)
                .await;

            let logs = in_memory_logger.drain_logs();
            LogEntriesAssert::assert_that(logs).has_only_one_message_containing(
                &Level::Warning,
                "Key rotation error: KeyRotationNotEnabled",
            );
        }

        #[tokio::test]
        async fn should_log_error_if_key_rotation_returns_public_key_not_found() {
            let in_memory_logger = InMemoryReplicaLogger::new();
            let setup = Setup::builder()
                .with_check_keys_with_registry_result(Ok(()))
                .with_rotate_idkg_dealing_encryption_keys_result(Err(
                    IDkgDealingEncryptionKeyRotationError::PublicKeyNotFound,
                ))
                .with_logger(&in_memory_logger)
                .build();

            setup
                .node_registration
                .check_all_keys_registered_otherwise_register(setup.subnet_id)
                .await;

            let logs = in_memory_logger.drain_logs();
            LogEntriesAssert::assert_that(logs).has_only_one_message_containing(
                &Level::Warning,
                "Key rotation error: PublicKeyNotFound",
            );
        }

        #[tokio::test]
        async fn should_log_error_if_key_rotation_returns_transient_internal_error() {
            let in_memory_logger = InMemoryReplicaLogger::new();
            let setup = Setup::builder()
                .with_check_keys_with_registry_result(Ok(()))
                .with_rotate_idkg_dealing_encryption_keys_result(Err(
                    IDkgDealingEncryptionKeyRotationError::TransientInternalError(
                        "rpc error connecting to csp vault".to_string(),
                    ),
                ))
                .with_logger(&in_memory_logger)
                .build();

            setup
                .node_registration
                .check_all_keys_registered_otherwise_register(setup.subnet_id)
                .await;

            let logs = in_memory_logger.drain_logs();
            LogEntriesAssert::assert_that(logs).has_only_one_message_containing(
                &Level::Warning,
                "Key rotation error: TransientInternalError(\"rpc error connecting to csp vault\")",
            );
        }
    }
}
