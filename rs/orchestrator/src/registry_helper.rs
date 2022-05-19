use crate::error::{OrchestratorError, OrchestratorResult};
use ic_consensus::dkg::make_registry_cup;
use ic_interfaces::registry::RegistryClient;
use ic_logger::ReplicaLogger;
use ic_protobuf::registry::firewall::v1::{FirewallConfig, FirewallRuleSet};
use ic_protobuf::registry::replica_version::v1::ReplicaVersionRecord;
use ic_protobuf::registry::subnet::v1::SubnetRecord;
use ic_registry_client_helpers::firewall::FirewallRegistry;
use ic_registry_client_helpers::node::NodeRegistry;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_registry_keys::FirewallRulesScope;
use ic_types::consensus::CatchUpPackage;
use ic_types::{NodeId, RegistryVersion, ReplicaVersion, SubnetId};
use std::convert::TryFrom;
use std::net::IpAddr;
use std::sync::Arc;

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
/// data stored locally, fetched and verified by the `RegistryReplicator`.
/// Thus, it does not verify the registry data threshold signature again.
impl RegistryHelper {
    pub(crate) fn new(
        node_id: NodeId,
        registry_client: Arc<dyn RegistryClient>,
        logger: ReplicaLogger,
    ) -> Self {
        Self {
            node_id,
            registry_client,
            logger,
        }
    }

    /// Return the latest version that is locally available
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
        subnet_id: SubnetId,
    ) -> OrchestratorResult<CatchUpPackage> {
        make_registry_cup(&*self.registry_client, subnet_id, Some(&self.logger))
            .ok_or(OrchestratorError::MakeRegistryCupError(subnet_id, version))
    }

    // TODO: Remove after staging IC-1026
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

    pub(crate) fn get_firewall_rules(
        &self,
        version: RegistryVersion,
        scope: &FirewallRulesScope,
    ) -> OrchestratorResult<FirewallRuleSet> {
        match self.registry_client.get_firewall_rules(version, scope) {
            Ok(Some(firewall_rules)) => Ok(firewall_rules),
            _ => Err(OrchestratorError::InvalidConfigurationError(
                "Invalid firewall rules".to_string(),
            )),
        }
    }

    pub(crate) fn get_all_nodes_ip_addresses(
        &self,
        version: RegistryVersion,
    ) -> OrchestratorResult<Vec<IpAddr>> {
        match self.registry_client.get_all_nodes_ip_addresses(version) {
            Ok(Some(ip_addrs)) => Ok(ip_addrs),
            _ => Err(OrchestratorError::InvalidConfigurationError(
                "Cannot fetch IP addresses of nodes".to_string(),
            )),
        }
    }

    pub(crate) fn get_subnet_id_from_node_id(
        &self,
        node_id: NodeId,
        version: RegistryVersion,
    ) -> OrchestratorResult<Option<SubnetId>> {
        match self
            .registry_client
            .get_subnet_id_from_node_id(node_id, version)
        {
            Ok(result) => Ok(result),
            _ => Err(OrchestratorError::InvalidConfigurationError(format!(
                "Cannot find subnet ID for node {}",
                node_id
            ))),
        }
    }

    pub(crate) fn get_registry_client(&self) -> Arc<dyn RegistryClient> {
        Arc::clone(&self.registry_client)
    }

    /// Get the replica version of the given subnet in the given registry
    /// version
    pub(crate) fn get_replica_version(
        &self,
        subnet_id: SubnetId,
        registry_version: RegistryVersion,
    ) -> OrchestratorResult<ReplicaVersion> {
        let subnet_record = self.get_subnet_record(subnet_id, registry_version)?;
        ReplicaVersion::try_from(subnet_record.replica_version_id.as_ref())
            .map_err(OrchestratorError::ReplicaVersionParseError)
    }
}
