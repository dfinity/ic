use crate::error::{OrchestratorError, OrchestratorResult};
use ic_consensus_cup_utils::make_registry_cup;
use ic_interfaces_registry::RegistryClient;
use ic_logger::ReplicaLogger;
use ic_protobuf::registry::{
    api_boundary_node::v1::ApiBoundaryNodeRecord, firewall::v1::FirewallRuleSet,
    hostos_version::v1::HostosVersionRecord, node::v1::IPv4InterfaceConfig,
    replica_version::v1::ReplicaVersionRecord, subnet::v1::SubnetRecord,
};
use ic_registry_client_helpers::{
    api_boundary_node::ApiBoundaryNodeRegistry, firewall::FirewallRegistry,
    hostos_version::HostosRegistry, node::NodeRegistry, node_operator::NodeOperatorRegistry,
    subnet::SubnetRegistry, unassigned_nodes::UnassignedNodeRegistry,
};
use ic_registry_keys::FirewallRulesScope;
use ic_types::{
    NodeId, PrincipalId, RegistryVersion, ReplicaVersion, SubnetId, consensus::CatchUpPackage,
    hostos_version::HostosVersion,
};
use std::{convert::TryFrom, net::IpAddr, sync::Arc};

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
            .get_listed_subnet_for_node_id(self.node_id, version)?
            && !subnet_record.start_as_nns
        {
            return Ok(subnet_id);
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

    pub(crate) fn get_api_boundary_node_record(
        &self,
        node_id: NodeId,
        version: RegistryVersion,
    ) -> OrchestratorResult<ApiBoundaryNodeRecord> {
        match self
            .registry_client
            .get_api_boundary_node_record(node_id, version)?
        {
            Some(record) => Ok(record),
            _ => Err(OrchestratorError::ApiBoundaryNodeMissingError(
                node_id, version,
            )),
        }
    }

    /// Return the `ReplicaVersionRecord` for the given replica version
    pub(crate) fn get_replica_version_record(
        &self,
        replica_version_id: ReplicaVersion,
        version: RegistryVersion,
    ) -> OrchestratorResult<ReplicaVersionRecord> {
        self.registry_client
            .get_replica_version_record_from_version_id(&replica_version_id, version)?
            .ok_or(OrchestratorError::ReplicaVersionMissingError(
                replica_version_id,
                version,
            ))
    }

    /// Return the `HostosVersionRecord` for the given HostOS version
    pub(crate) fn get_hostos_version_record(
        &self,
        hostos_version_id: HostosVersion,
        version: RegistryVersion,
    ) -> OrchestratorResult<HostosVersionRecord> {
        self.registry_client
            .get_hostos_version_record(&hostos_version_id, version)?
            .ok_or(OrchestratorError::UpgradeError(
                "HostOS version record not found at the given ID".to_string(),
            ))
    }

    /// Return the genesis cup at the given registry version for this node
    pub(crate) fn get_registry_cup(
        &self,
        version: RegistryVersion,
        subnet_id: SubnetId,
    ) -> OrchestratorResult<CatchUpPackage> {
        make_registry_cup(&*self.registry_client, subnet_id, &self.logger)
            .ok_or(OrchestratorError::MakeRegistryCupError(subnet_id, version))
    }

    pub(crate) fn get_firewall_rules(
        &self,
        version: RegistryVersion,
        scope: &FirewallRulesScope,
    ) -> OrchestratorResult<Option<FirewallRuleSet>> {
        self.registry_client
            .get_firewall_rules(version, scope)
            .map_err(OrchestratorError::RegistryClientError)
    }

    pub(crate) fn get_all_nodes_ip_addresses(
        &self,
        version: RegistryVersion,
    ) -> OrchestratorResult<Vec<IpAddr>> {
        let ips = self.registry_client.get_all_nodes_ip_addresses(version)?;

        Ok(ips.unwrap_or_default())
    }

    pub(crate) fn get_app_subnet_nodes_ip_addresses(
        &self,
        version: RegistryVersion,
    ) -> OrchestratorResult<Vec<IpAddr>> {
        let ips = self
            .registry_client
            .get_app_subnet_nodes_ip_addresses(version)?;

        Ok(ips.unwrap_or_default())
    }

    pub(crate) fn get_system_subnet_nodes_ip_addresses(
        &self,
        version: RegistryVersion,
    ) -> OrchestratorResult<Vec<IpAddr>> {
        let ips = self
            .registry_client
            .get_system_subnet_nodes_ip_addresses(version)?;

        Ok(ips.unwrap_or_default())
    }

    pub(crate) fn get_subnet_id_from_node_id(
        &self,
        node_id: NodeId,
        version: RegistryVersion,
    ) -> OrchestratorResult<Option<SubnetId>> {
        self.registry_client
            .get_subnet_id_from_node_id(node_id, version)
            .map_err(OrchestratorError::RegistryClientError)
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

    pub(crate) fn get_expected_replica_version(
        &self,
        subnet_id: SubnetId,
    ) -> OrchestratorResult<(ReplicaVersion, RegistryVersion)> {
        let registry_version = self.get_latest_version();
        let new_replica_version = self.get_replica_version(subnet_id, registry_version)?;
        Ok((new_replica_version, registry_version))
    }

    pub(crate) fn get_unassigned_replica_version(
        &self,
        version: RegistryVersion,
    ) -> OrchestratorResult<ReplicaVersion> {
        match self.registry_client.get_unassigned_nodes_config(version) {
            Ok(Some(record)) => {
                let replica_version = ReplicaVersion::try_from(record.replica_version.as_ref())
                    .map_err(|err| {
                        OrchestratorError::UpgradeError(format!(
                            "Couldn't parse the replica version: {err}"
                        ))
                    })?;
                Ok(replica_version)
            }
            _ => Err(OrchestratorError::UpgradeError(
                "No replica version for unassigned nodes found".to_string(),
            )),
        }
    }

    pub(crate) fn get_api_boundary_node_version(
        &self,
        node_id: NodeId,
        version: RegistryVersion,
    ) -> OrchestratorResult<ReplicaVersion> {
        let api_boundary_node_record = self.get_api_boundary_node_record(node_id, version)?;
        ReplicaVersion::try_from(api_boundary_node_record.version.as_ref())
            .map_err(OrchestratorError::ReplicaVersionParseError)
    }

    pub(crate) fn is_system_api_boundary_node(
        &self,
        node_id: NodeId,
        version: RegistryVersion,
    ) -> OrchestratorResult<bool> {
        self.registry_client
            .is_system_api_boundary_node(node_id, version)
            .map_err(OrchestratorError::RegistryClientError)
    }

    /// Return the DC ID where the current replica is located.
    pub fn dc_id(&self) -> Option<String> {
        let registry_version = self.get_latest_version();
        let node_record = self
            .registry_client
            .get_node_record(self.node_id, registry_version)
            .ok()
            .flatten();
        let node_operator_id =
            node_record.and_then(|v| PrincipalId::try_from(v.node_operator_id).ok());

        let node_operator_record = node_operator_id.and_then(|id| {
            self.registry_client
                .get_node_operator_record(id, registry_version)
                .ok()
                .flatten()
        });

        node_operator_record.map(|v| v.dc_id)
    }

    /// Get the HostOS version of this node in the given registry version
    pub(crate) fn get_node_hostos_version(
        &self,
        registry_version: RegistryVersion,
    ) -> OrchestratorResult<Option<HostosVersion>> {
        let node_record = self
            .registry_client
            .get_node_record(self.node_id, registry_version)?;

        node_record
            .and_then(|node_record| node_record.hostos_version_id)
            .map(|node_record| {
                HostosVersion::try_from(node_record).map_err(|err| {
                    OrchestratorError::UpgradeError(format!(
                        "Could not parse HostOS version: {err}"
                    ))
                })
            })
            .transpose()
    }

    pub(crate) fn get_node_ipv4_config(
        &self,
        version: RegistryVersion,
    ) -> OrchestratorResult<Option<IPv4InterfaceConfig>> {
        let result = self
            .registry_client
            .get_node_record(self.node_id, version)?
            .and_then(|node_record| node_record.public_ipv4_config);
        Ok(result)
    }

    pub(crate) fn get_node_domain_name(
        &self,
        version: RegistryVersion,
    ) -> OrchestratorResult<Option<String>> {
        let result = self
            .registry_client
            .get_node_record(self.node_id, version)?
            .and_then(|node_record| node_record.domain);
        Ok(result)
    }
}
