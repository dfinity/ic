use crate::error::{OrchestratorError, OrchestratorResult};
use ic_config::Config;
use ic_consensus::dkg::make_registry_cup;
use ic_interfaces::registry::RegistryClient;
use ic_logger::{warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_protobuf::registry::firewall::v1::FirewallConfig;
use ic_protobuf::registry::node::v1::NodeRecord;
use ic_protobuf::registry::replica_version::v1::ReplicaVersionRecord;
use ic_protobuf::registry::subnet::v1::SubnetRecord;
use ic_registry_client::client::{create_data_provider, RegistryClientImpl};
use ic_registry_client::helper::firewall::FirewallRegistry;
use ic_registry_client::helper::subnet::{SubnetRegistry, SubnetTransportRegistry};
use ic_registry_client::helper::unassigned_nodes::UnassignedNodeRegistry;
use ic_types::consensus::CatchUpPackage;
use ic_types::{NodeId, RegistryVersion, ReplicaVersion, SubnetId};
use std::convert::TryFrom;
use std::net::SocketAddr;
use std::sync::Arc;
use url::Url;

/// Calls the Registry and converts errors into `OrchestratorError`
#[derive(Clone)]
pub(crate) struct RegistryHelper {
    node_id: NodeId,
    pub(crate) registry_client: Arc<dyn RegistryClient>,
    logger: ReplicaLogger,
}

/// Registry helper for the orchestrator
///
/// The orchestrator fetches information from the registry to determine:
/// - which subnetwork a node is in
/// - which peers it should attempt to fetch CUPs from
/// - which replica binary
///
/// The NNS subnetwork is a special case, as many of these are already a-priori
/// knowledge (and the registry might not be available during upgrades, so
/// lookups would fail).
///
/// Security note: The registry data accessed by the `RegistryHelper` accesses
/// data stored locally, fetched and verified by the `NnsRegistryReplicator`.
/// Thus, it does not verify the registry data threshold signature again.
impl RegistryHelper {
    pub(crate) fn new_with(
        metrics_registry: &MetricsRegistry,
        config: &Config,
        node_id: NodeId,
        logger: ReplicaLogger,
    ) -> Self {
        let data_provider = create_data_provider(
            config
                .registry_client
                .data_provider
                .as_ref()
                .expect("No data provider was provided in the registry client configuration"),
            // We set the NNS public key to `None` (and thus disable registry data signature
            // verification). See the Rustdoc of `RegistryHelper` for an explanation.
            None,
        );
        let registry_client = Arc::new(RegistryClientImpl::new(
            data_provider,
            Some(metrics_registry),
        ));

        if let Err(e) = registry_client.fetch_and_start_polling() {
            panic!("fetch_and_start_polling failed: {}", e);
        };

        Self {
            node_id,
            registry_client,
            logger,
        }
    }

    pub(crate) fn get_latest_version(&self) -> RegistryVersion {
        self.registry_client.get_latest_version()
    }

    /// Return the `SubnetId` this node belongs to (i.e. the Subnet that
    /// contains `self.node_id`) iff the node belongs to a subnet and that
    /// subnet does not have the `start_as_nns`-flag set.
    pub(crate) fn get_subnet_id(&self, version: RegistryVersion) -> OrchestratorResult<SubnetId> {
        if let Some((subnet_id, subnet_record)) = self
            .registry_client
            .get_listed_subnet_for_node_id(self.node_id, version)
            .map_err(OrchestratorError::RegistryClientError)?
        {
            if !subnet_record.start_as_nns {
                return Ok(subnet_id);
            }
        }

        Err(OrchestratorError::NodeUnassignedError(
            self.node_id,
            version,
        ))
    }

    /// Return HTTP urls for all nodes in subnetwork
    pub(crate) fn get_node_urls(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> Vec<Option<Url>> {
        let endpoints: Vec<(NodeId, NodeRecord)> = self
            .registry_client
            .get_subnet_transport_infos(subnet_id, version)
            .ok()
            .flatten()
            .unwrap_or_else(Vec::new);

        let endpoints: Vec<Option<Url>> = endpoints
            .iter()
            .map(|(_, record)| {
                if let Some(http) = &record.http {
                    let ip_addr = http
                        .ip_addr
                        .parse()
                        .map_err(|e| {
                            warn!(
                                self.logger,
                                "Failed to parse URL from endpoint: {:?}, error: {:?}", &http, e
                            );
                        })
                        .ok()?;
                    let url = Url::parse(
                        format!(
                            "http://{}",
                            SocketAddr::new(ip_addr, u16::try_from(http.port).unwrap())
                        )
                        .as_str(),
                    )
                    .map_err(|e| {
                        warn!(
                            self.logger,
                            "Failed to parse URL from endpoint: {:?}, error: {:?}", &http, e
                        );
                    })
                    .ok()?;
                    Some(url)
                } else {
                    None
                }
            })
            .collect();

        endpoints
    }

    /// Return the `SubnetRecord` for the given subnet
    pub(crate) fn get_subnet_record(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> OrchestratorResult<SubnetRecord> {
        match self.registry_client.get_subnet_record(subnet_id, version) {
            Ok(Some(record)) => Ok(record),
            _ => Err(OrchestratorError::SubnetMissingError(subnet_id, version)),
        }
    }

    /// Return the subnet that this node belongs to at the given
    /// registry version
    pub(crate) fn get_own_subnet_record(
        &self,
        registry_version: RegistryVersion,
    ) -> OrchestratorResult<(SubnetId, SubnetRecord)> {
        let new_subnet_id = self.get_subnet_id(registry_version)?;
        let new_subnet_record = self.get_subnet_record(new_subnet_id, registry_version)?;

        Ok((new_subnet_id, new_subnet_record))
    }

    /// Return the `ReplicaVersionRecord` for the given replica version
    pub(crate) fn get_replica_version_record(
        &self,
        replica_version_id: ReplicaVersion,
        version: RegistryVersion,
    ) -> OrchestratorResult<ReplicaVersionRecord> {
        self.registry_client
            .get_replica_version_record_from_version_id(&replica_version_id, version)
            .map_err(OrchestratorError::RegistryClientError)?
            .ok_or(OrchestratorError::ReplicaVersionMissingError(
                replica_version_id,
                version,
            ))
    }

    /// Return the genesis cup at the given registry version for this node
    pub(crate) fn get_registry_cup(
        &self,
        version: RegistryVersion,
    ) -> OrchestratorResult<CatchUpPackage> {
        let subnet_id = self.get_subnet_id(version)?;
        make_registry_cup(&*self.registry_client, subnet_id, Some(&self.logger))
            .ok_or(OrchestratorError::MakeRegistryCupError(subnet_id, version))
    }

    pub(crate) fn get_firewall_config(
        &self,
        version: RegistryVersion,
    ) -> OrchestratorResult<FirewallConfig> {
        match self.registry_client.get_firewall_config(version) {
            Ok(Some(firewall_config)) => Ok(firewall_config),
            _ => Err(OrchestratorError::InvalidConfigurationError(
                "Invalid firewall configuration".to_string(),
            )),
        }
    }

    pub(crate) fn get_registry_client(&self) -> Arc<dyn RegistryClient> {
        Arc::clone(&self.registry_client)
    }

    pub(crate) fn get_replica_version_from_subnet_record(
        subnet: SubnetRecord,
    ) -> OrchestratorResult<ReplicaVersion> {
        ReplicaVersion::try_from(subnet.replica_version_id.as_ref())
            .map_err(OrchestratorError::ReplicaVersionParseError)
    }

    pub(crate) fn get_own_readonly_and_backup_keysets(
        &self,
        version: RegistryVersion,
    ) -> OrchestratorResult<(Vec<String>, Vec<String>)> {
        // CON-621: get the keysets from the subnet record

        match self.get_own_subnet_record(version) {
            Ok((_subnet_id, subnet_record)) => Ok((
                subnet_record.ssh_readonly_access,
                subnet_record.ssh_backup_access,
            )),
            Err(OrchestratorError::NodeUnassignedError(_, _)) => {
                match self
                    .registry_client
                    .get_unassigned_nodes_config(version)
                    .map_err(OrchestratorError::RegistryClientError)?
                {
                    // Unassigned nodes do not need backup keys
                    Some(record) => Ok((record.ssh_readonly_access, vec![])),
                    None => Ok((vec![], vec![])),
                }
            }
            Err(e) => Err(e),
        }
    }
}
