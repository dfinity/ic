use crate::error::OrchestratorError;
use ic_consensus_cup_utils::make_registry_cup;
use ic_image_upgrader::error::UpgradeError;
use ic_interfaces_registry::RegistryClient;
use ic_logger::ReplicaLogger;
use ic_protobuf::registry::{
    api_boundary_node::v1::ApiBoundaryNodeRecord, firewall::v1::FirewallRuleSet,
    hostos_version::v1::HostosVersionRecord, node::v1::IPv4InterfaceConfig,
    replica_version::v1::ReplicaVersionRecord, subnet::v1::SubnetRecord,
    unassigned_nodes_config::v1::UnassignedNodesConfigRecord,
};
use ic_registry_client_helpers::{
    api_boundary_node::ApiBoundaryNodeRegistry, firewall::FirewallRegistry,
    hostos_version::HostosRegistry, node::NodeRegistry, node_operator::NodeOperatorRegistry,
    subnet::SubnetRegistry, unassigned_nodes::UnassignedNodeRegistry,
};
use ic_registry_keys::FirewallRulesScope;
use ic_types::{
    NodeId, PrincipalId, RegistryVersion, ReplicaVersion, SubnetId,
    consensus::CatchUpPackage,
    hostos_version::{HostosVersion, HostosVersionParseError},
    registry::RegistryClientError,
    replica_version::ReplicaVersionParseError,
};
use std::{convert::TryFrom, error::Error, fmt, net::IpAddr, sync::Arc};

pub(crate) type RegistryResult<T> = Result<T, RegistryError>;

#[derive(Debug)]
pub(crate) enum RegistryError {
    /// An error occurred when querying the registry
    RegistryClientError(RegistryClientError),

    /// The given node is not assigned to any subnet at the given version
    NodeUnassigned(NodeId, RegistryVersion),

    /// The root subnet ID is missing in the registry at the given version
    RootSubnetIdMissing(RegistryVersion),

    /// The given subnet ID does not map to a `SubnetRecord` at the given version
    SubnetMissing(SubnetId, RegistryVersion),

    /// The given node ID does not map to a `NodeRecord` at the given version
    NodeMissing(NodeId, RegistryVersion),

    /// The unassigned nodes config is missing in the registry at the given version
    UnassignedNodesConfigMissing(RegistryVersion),

    /// The given node ID does not map to an `ApiBoundaryNodeRecord` at the given version
    ApiBoundaryNodeMissing(NodeId, RegistryVersion),

    /// The given replica version is missing in the registry at the given version
    ReplicaVersionMissing(ReplicaVersion, RegistryVersion),

    /// The given HostOS version is missing in the registry at the given version
    HostOsVersionMissing(HostosVersion, RegistryVersion),

    /// The genesis or recovery CUP failed to be constructed at the given version
    MakeRegistryCupError(SubnetId, RegistryVersion),

    /// A replica version could not be parsed
    ReplicaVersionParseError(ReplicaVersionParseError),

    /// A HostOS version could not be parsed
    HostOsVersionParseError(HostosVersionParseError),
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryError::RegistryClientError(e) => write!(f, "Registry client error: {e}"),
            RegistryError::NodeUnassigned(node_id, registry_version) => write!(
                f,
                "Node {node_id} is not found in any subnet at registry version {registry_version}"
            ),
            RegistryError::RootSubnetIdMissing(registry_version) => write!(
                f,
                "Root subnet ID is missing in the Registry at registry version {registry_version}"
            ),
            RegistryError::SubnetMissing(subnet_id, registry_version) => write!(
                f,
                "Subnet ID {subnet_id} does not exist in the Registry at registry version {registry_version}"
            ),
            RegistryError::NodeMissing(node_id, registry_version) => write!(
                f,
                "Node ID {node_id} does not exist in the Registry at registry version {registry_version}"
            ),
            RegistryError::UnassignedNodesConfigMissing(registry_version) => write!(
                f,
                "Unassigned nodes config is missing in the Registry at registry version {registry_version}"
            ),
            RegistryError::ApiBoundaryNodeMissing(node_id, registry_version) => write!(
                f,
                "API Boundary Node ID {node_id} does not exist in the Registry at registry version {registry_version}"
            ),
            RegistryError::ReplicaVersionMissing(replica_version, registry_version) => {
                write!(
                    f,
                    "Replica version {replica_version} was not found in the Registry at registry version {registry_version}"
                )
            }
            RegistryError::HostOsVersionMissing(hostos_version, registry_version) => {
                write!(
                    f,
                    "HostOS version {hostos_version} was not found in the Registry at registry version {registry_version}"
                )
            }
            RegistryError::MakeRegistryCupError(subnet_id, registry_version) => write!(
                f,
                "Failed to construct the genesis/recovery CUP, subnet_id: {subnet_id}, registry_version: {registry_version}",
            ),
            RegistryError::ReplicaVersionParseError(e) => {
                write!(f, "Failed to parse replica version: {e}")
            }
            RegistryError::HostOsVersionParseError(e) => {
                write!(f, "Failed to parse HostOS version: {e}")
            }
        }
    }
}

impl From<RegistryClientError> for RegistryError {
    fn from(err: RegistryClientError) -> Self {
        RegistryError::RegistryClientError(err)
    }
}

impl From<RegistryError> for OrchestratorError {
    fn from(e: RegistryError) -> Self {
        OrchestratorError::RegistryError(e)
    }
}

impl From<RegistryError> for UpgradeError {
    fn from(e: RegistryError) -> Self {
        UpgradeError::RegistryError(e.to_string())
    }
}

impl Error for RegistryError {}

/// Calls the Registry and converts errors into `RegistryError`.
#[derive(Clone)]
pub(crate) struct RegistryHelper {
    node_id: NodeId,
    registry_client: Arc<dyn RegistryClient>,
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

    /// Return the underlying `RegistryClient`
    pub(crate) fn get_registry_client(&self) -> &dyn RegistryClient {
        self.registry_client.as_ref()
    }

    /// Return the `SubnetId` this node belongs to (i.e. the Subnet that
    /// contains `self.node_id`) iff the node belongs to a subnet and that
    /// subnet does not have the `start_as_nns`-flag set.
    pub(crate) fn get_subnet_id(&self, version: RegistryVersion) -> RegistryResult<SubnetId> {
        if let Some((subnet_id, subnet_record)) = self
            .registry_client
            .get_listed_subnet_for_node_id(self.node_id, version)?
            && !subnet_record.start_as_nns
        {
            return Ok(subnet_id);
        }

        Err(RegistryError::NodeUnassigned(self.node_id, version))
    }

    /// Return the `SubnetRecord` for the given subnet
    pub(crate) fn get_subnet_record(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryResult<SubnetRecord> {
        match self.registry_client.get_subnet_record(subnet_id, version)? {
            Some(record) => Ok(record),
            None => Err(RegistryError::SubnetMissing(subnet_id, version)),
        }
    }

    /// Return the root `SubnetId`
    pub(crate) fn get_root_subnet_id(&self, version: RegistryVersion) -> RegistryResult<SubnetId> {
        match self.registry_client.get_root_subnet_id(version)? {
            Some(subnet_id) => Ok(subnet_id),
            None => Err(RegistryError::RootSubnetIdMissing(version)),
        }
    }

    /// Return the `ApiBoundaryNodeRecord` for the given node ID
    pub(crate) fn get_api_boundary_node_record(
        &self,
        node_id: NodeId,
        version: RegistryVersion,
    ) -> RegistryResult<ApiBoundaryNodeRecord> {
        match self
            .registry_client
            .get_api_boundary_node_record(node_id, version)?
        {
            Some(record) => Ok(record),
            None => Err(RegistryError::ApiBoundaryNodeMissing(node_id, version)),
        }
    }

    /// Return the `UnassignedNodesConfigRecord` at the given registry version
    pub(crate) fn get_unassigned_nodes_config(
        &self,
        version: RegistryVersion,
    ) -> RegistryResult<Option<UnassignedNodesConfigRecord>> {
        self.registry_client
            .get_unassigned_nodes_config(version)
            .map_err(RegistryError::RegistryClientError)
    }

    /// Return the `ReplicaVersionRecord` for the given replica version
    pub(crate) fn get_replica_version_record(
        &self,
        replica_version_id: ReplicaVersion,
        version: RegistryVersion,
    ) -> RegistryResult<ReplicaVersionRecord> {
        match self
            .registry_client
            .get_replica_version_record_from_version_id(&replica_version_id, version)?
        {
            Some(record) => Ok(record),
            None => Err(RegistryError::ReplicaVersionMissing(
                replica_version_id,
                version,
            )),
        }
    }

    /// Return the `HostosVersionRecord` for the given HostOS version
    pub(crate) fn get_hostos_version_record(
        &self,
        hostos_version_id: HostosVersion,
        version: RegistryVersion,
    ) -> RegistryResult<HostosVersionRecord> {
        match self
            .registry_client
            .get_hostos_version_record(&hostos_version_id, version)?
        {
            Some(record) => Ok(record),
            None => Err(RegistryError::HostOsVersionMissing(
                hostos_version_id,
                version,
            )),
        }
    }

    /// Return the registry CUP (genesis/recovery) at the given registry version for the given
    /// subnet ID
    pub(crate) fn get_registry_cup(
        &self,
        version: RegistryVersion,
        subnet_id: SubnetId,
    ) -> RegistryResult<CatchUpPackage> {
        match make_registry_cup(self.registry_client.as_ref(), subnet_id, &self.logger) {
            Some(cup) => Ok(cup),
            None => Err(RegistryError::MakeRegistryCupError(subnet_id, version)),
        }
    }

    pub(crate) fn get_firewall_rules(
        &self,
        version: RegistryVersion,
        scope: &FirewallRulesScope,
    ) -> RegistryResult<Option<FirewallRuleSet>> {
        self.registry_client
            .get_firewall_rules(version, scope)
            .map_err(RegistryError::RegistryClientError)
    }

    pub(crate) fn get_all_nodes_ip_addresses(
        &self,
        version: RegistryVersion,
    ) -> RegistryResult<Vec<IpAddr>> {
        let ips = self.registry_client.get_all_nodes_ip_addresses(version)?;

        Ok(ips.unwrap_or_default())
    }

    pub(crate) fn get_app_subnet_nodes_ip_addresses(
        &self,
        version: RegistryVersion,
    ) -> RegistryResult<Vec<IpAddr>> {
        let ips = self
            .registry_client
            .get_app_subnet_nodes_ip_addresses(version)?;

        Ok(ips.unwrap_or_default())
    }

    pub(crate) fn get_system_subnet_nodes_ip_addresses(
        &self,
        version: RegistryVersion,
    ) -> RegistryResult<Vec<IpAddr>> {
        let ips = self
            .registry_client
            .get_system_subnet_nodes_ip_addresses(version)?;

        Ok(ips.unwrap_or_default())
    }

    pub(crate) fn get_subnet_id_from_node_id(
        &self,
        node_id: NodeId,
        version: RegistryVersion,
    ) -> RegistryResult<Option<SubnetId>> {
        self.registry_client
            .get_subnet_id_from_node_id(node_id, version)
            .map_err(RegistryError::RegistryClientError)
    }

    /// Get the replica version of the given subnet in the given registry
    /// version
    pub(crate) fn get_replica_version(
        &self,
        subnet_id: SubnetId,
        registry_version: RegistryVersion,
    ) -> RegistryResult<ReplicaVersion> {
        let subnet_record = self.get_subnet_record(subnet_id, registry_version)?;

        ReplicaVersion::try_from(subnet_record.replica_version_id.as_ref())
            .map_err(RegistryError::ReplicaVersionParseError)
    }

    /// Get the recalled replica versions of the given subnet in the given registry
    /// version
    pub(crate) fn get_recalled_replica_versions(
        &self,
        _subnet_id: SubnetId,
        _registry_version: RegistryVersion,
    ) -> RegistryResult<Vec<ReplicaVersion>> {
        // TODO(NODE-1754): Remove this placeholder and replace with the commented code below once
        // registry changes were merged
        Ok(vec![])

        // let subnet_record = self.get_subnet_record(subnet_id, registry_version)?;
        //
        // subnet_record
        //     .recalled_replica_version_ids
        //     .iter()
        //     .map(|version_str| {
        //         ReplicaVersion::try_from(version_str.as_ref())
        //             .map_err(RegistryError::ReplicaVersionParseError)
        //     })
        //     .collect()
    }

    pub(crate) fn get_expected_replica_version(
        &self,
        subnet_id: SubnetId,
    ) -> RegistryResult<(ReplicaVersion, RegistryVersion)> {
        let registry_version = self.get_latest_version();
        let new_replica_version = self.get_replica_version(subnet_id, registry_version)?;

        Ok((new_replica_version, registry_version))
    }

    pub(crate) fn get_unassigned_replica_version(
        &self,
        version: RegistryVersion,
    ) -> RegistryResult<ReplicaVersion> {
        match self.registry_client.get_unassigned_nodes_config(version)? {
            Some(record) => {
                let replica_version = ReplicaVersion::try_from(record.replica_version.as_ref())
                    .map_err(RegistryError::ReplicaVersionParseError)?;
                Ok(replica_version)
            }
            None => Err(RegistryError::UnassignedNodesConfigMissing(version)),
        }
    }

    pub(crate) fn get_api_boundary_node_version(
        &self,
        node_id: NodeId,
        version: RegistryVersion,
    ) -> RegistryResult<ReplicaVersion> {
        let api_boundary_node_record = self.get_api_boundary_node_record(node_id, version)?;

        ReplicaVersion::try_from(api_boundary_node_record.version.as_ref())
            .map_err(RegistryError::ReplicaVersionParseError)
    }

    pub(crate) fn is_system_api_boundary_node(
        &self,
        node_id: NodeId,
        version: RegistryVersion,
    ) -> RegistryResult<bool> {
        self.registry_client
            .is_system_api_boundary_node(node_id, version)
            .map_err(RegistryError::RegistryClientError)
    }

    /// Return the DC ID where the current replica is located.
    pub(crate) fn dc_id(&self) -> Option<String> {
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

    pub(crate) fn get_ssh_recovery_access(
        &self,
        registry_version: RegistryVersion,
    ) -> RegistryResult<Vec<String>> {
        match self
            .registry_client
            .get_node_record(self.node_id, registry_version)?
        {
            Some(record) => Ok(record.ssh_node_state_write_access),
            None => Err(RegistryError::NodeMissing(self.node_id, registry_version)),
        }
    }

    /// Get the HostOS version of this node in the given registry version
    pub(crate) fn get_node_hostos_version(
        &self,
        registry_version: RegistryVersion,
    ) -> RegistryResult<Option<HostosVersion>> {
        let node_record = self
            .registry_client
            .get_node_record(self.node_id, registry_version)?;

        node_record
            .and_then(|node_record| node_record.hostos_version_id)
            .map(|node_record| {
                HostosVersion::try_from(node_record).map_err(RegistryError::HostOsVersionParseError)
            })
            .transpose()
    }

    pub(crate) fn get_node_ipv4_config(
        &self,
        version: RegistryVersion,
    ) -> RegistryResult<Option<IPv4InterfaceConfig>> {
        let result = self
            .registry_client
            .get_node_record(self.node_id, version)?
            .and_then(|node_record| node_record.public_ipv4_config);

        Ok(result)
    }

    pub(crate) fn get_node_domain_name(
        &self,
        version: RegistryVersion,
    ) -> RegistryResult<Option<String>> {
        let result = self
            .registry_client
            .get_node_record(self.node_id, version)?
            .and_then(|node_record| node_record.domain);

        Ok(result)
    }
}
