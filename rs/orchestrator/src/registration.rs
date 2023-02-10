#![allow(dead_code)]
use crate::{
    error::{OrchestratorError, OrchestratorResult},
    metrics::{KeyRotationStatus, OrchestratorMetrics},
    signer::{Hsm, NodeProviderSigner, Signer, TestSigner},
};
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
use ic_types::{crypto::KeyPurpose, messages::MessageId, NodeId, RegistryVersion, SubnetId};
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
    metrics: Arc<OrchestratorMetrics>,
    node_id: NodeId,
    key_handler: Arc<dyn CryptoComponentForNonReplicaProcess>,
    local_store: Arc<dyn LocalStore>,
    signer: Box<dyn Signer>,
}

impl NodeRegistration {
    /// If the TestSigner path is present, use the TestSigner.
    /// Then, if the PEM is present, use the NodeProviderSigner.
    /// Else, use the HSM.
    pub(crate) fn new(
        log: ReplicaLogger,
        node_config: Config,
        registry_client: Arc<dyn RegistryClient>,
        metrics: Arc<OrchestratorMetrics>,
        node_id: NodeId,
        key_handler: Arc<dyn CryptoComponentForNonReplicaProcess>,
        local_store: Arc<dyn LocalStore>,
    ) -> Self {
        // If we can open a PEM file under the path specified in the replica config, we use a mock
        // signer using this key to register the node.
        let signer: Box<dyn Signer> = match node_config
            .clone()
            .registration
            .test_key_pem
            .and_then(|path| TestSigner::new(path.as_path()))
        {
            Some(test_signer) => Box::new(test_signer),
            None => {
                // If we can open a PEM file under the path specified in the replica config,
                // we use the given node operator private key to register the node.
                match node_config
                    .clone()
                    .registration
                    .node_operator_pem
                    .and_then(|path| NodeProviderSigner::new(path.as_path()))
                {
                    Some(signer) => Box::new(signer),
                    None => Box::new(Hsm),
                }
            }
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
            self.retry_register_node().await;
        }
        // postcondition: node keys are registered
    }

    // postcondition: we are registered with the NNS
    async fn retry_register_node(&mut self) {
        let add_node_payload = self.assemble_add_node_message().await;

        while !self.is_node_registered().await {
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
                        warn!(self.log, "Registration request failed: {:?}", e);
                    };
                }
                Err(e) => {
                    warn!(self.log, "Failed to create the message signer: {:?}", e);
                }
            };
            tokio::time::sleep(Duration::from_secs(5)).await;
        }

        UtilityCommand::notify_host(
            format!(
                "Join request successful!\nNode id: {}\nYou may now safely remove the HSM.",
                self.node_id
            )
            .as_str(),
            20,
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
        if !self.is_time_to_rotate(registry_version, subnet_id, delta) {
            self.metrics
                .observe_key_rotation_status(KeyRotationStatus::TooRecent);
            return;
        }

        let key_handler = self.key_handler.clone();
        match tokio::task::spawn_blocking(move || {
            key_handler.check_keys_with_registry(registry_version)
        })
        .await
        .unwrap()
        {
            Ok(PublicKeyRegistrationStatus::IDkgDealingEncPubkeyNeedsRegistration(key)) => {
                // Try to register a key that was previously rotated but is not yet registered.
                self.register_key(registry_version, key).await;
            }
            Ok(PublicKeyRegistrationStatus::RotateIDkgDealingEncryptionKeys) => {
                // Call cypto to rotate the keys and try to register the new key.
                // In case registration of the new key fails, we will enter the branch above
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
                    Ok(key) => self.register_key(registry_version, key).await,
                    Err(e) => {
                        self.metrics.observe_key_rotation_error();
                        warn!(self.log, "Key rotation error: {e:?}");
                    }
                }
            }
            Ok(PublicKeyRegistrationStatus::AllKeysRegistered) => {}
            Err(e) => {
                self.metrics.observe_key_rotation_error();
                warn!(self.log, "Failed to check keys with registry: {e:?}");
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

        agent
            .execute_update(
                &REGISTRY_CANISTER_ID,
                &REGISTRY_CANISTER_ID,
                "update_node_directly",
                Encode!(&update_node_payload)
                    .expect("Could not encode payload for update_node-call."),
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
                warn!(
                    self.log,
                    "Node keys are not setup at version {}: {:?}", latest_version, e
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
}
