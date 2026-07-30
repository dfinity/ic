//! Upgrade section builder for the Phase-2 rolling reboot.
//!
//! Produces the `upgrade` bytes in each data block's `BatchPayload`.
//! Reads the shared [`UpgradeState`] (maintained by [`UpgradeStatusManager`]
//! from finalized blocks), computes permits via [`UpgradeState::pick_permits`],
//! and includes the block maker's own [`UpgradeStatus`] heartbeat.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use ic_interfaces::batch_payload::{BatchPayloadBuilder, PastPayload, ProposalContext};
use ic_interfaces::consensus::PayloadValidationError;
use ic_interfaces_registry::RegistryClient;
use ic_logger::{ReplicaLogger, info};
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_types::consensus::upgrade::{UpgradePayload, UpgradeStatus, UpgradeState};
use ic_types::{Height, NodeId, NumBytes, ReplicaVersion, SubnetId};

/// Builds the upgrade section of a data block's `BatchPayload`.
pub struct UpgradePayloadBuilder {
    node_id: NodeId,
    subnet_id: SubnetId,
    registry_client: Arc<dyn RegistryClient>,
    shared_state: Arc<RwLock<UpgradeState>>,
    logger: ReplicaLogger,
}

impl UpgradePayloadBuilder {
    /// Create a new builder with the given shared state.
    pub fn new(
        node_id: NodeId,
        subnet_id: SubnetId,
        registry_client: Arc<dyn RegistryClient>,
        shared_state: Arc<RwLock<UpgradeState>>,
        logger: ReplicaLogger,
    ) -> Self {
        Self {
            node_id,
            subnet_id,
            registry_client,
            shared_state,
            logger,
        }
    }
}

/// A stub builder for tests/state-machine-tests that produces empty upgrade sections.
pub struct UpgradePayloadBuilderStub;

impl UpgradePayloadBuilderStub {
    /// Create a new stub builder.
    pub fn new() -> Self {
        Self
    }
}

impl Default for UpgradePayloadBuilderStub {
    fn default() -> Self {
        Self::new()
    }
}

impl BatchPayloadBuilder for UpgradePayloadBuilderStub {
    fn build_payload(
        &self,
        _height: Height,
        _max_size: NumBytes,
        _past_payloads: &[PastPayload],
        _context: &ic_types::batch::ValidationContext,
    ) -> Vec<u8> {
        vec![]
    }

    fn validate_payload(
        &self,
        _height: Height,
        _proposal_context: &ProposalContext,
        payload: &[u8],
        _past_payloads: &[PastPayload],
    ) -> Result<(), PayloadValidationError> {
        if payload.is_empty() {
            return Ok(());
        }
        let _ = serde_cbor::from_slice::<UpgradePayload>(payload);
        Ok(())
    }
}

impl BatchPayloadBuilder for UpgradePayloadBuilder {
    fn build_payload(
        &self,
        height: Height,
        _max_size: NumBytes,
        past_payloads: &[PastPayload],
        context: &ic_types::batch::ValidationContext,
    ) -> Vec<u8> {
        let registry_version = context.registry_version;

        let subnet_record = match self
            .registry_client
            .get_subnet_record(self.subnet_id, registry_version)
        {
            Ok(Some(record)) => record,
            _ => return vec![],
        };

        let target = match ReplicaVersion::try_from(subnet_record.replica_version_id.clone()) {
            Ok(version) => version,
            Err(_) => return vec![],
        };

        let members = match self
            .registry_client
            .get_node_ids_on_subnet(self.subnet_id, registry_version)
        {
            Ok(Some(members)) => members,
            _ => return vec![],
        };

        let upgrade_state = self.shared_state.read().unwrap().clone();

        let phase2_active = upgrade_state.is_phase2_active(&members, Some(target.clone()));
        let consumed = upgrade_state.consumed(&members, height);
        let f = UpgradeState::faults_tolerated(members.len());
        info!(
            self.logger,
            "upgrade_payload: height={} target={:?} members={} latest_status={} issued_permits={} \
             consumed={} f={} phase2_active={}",
            height,
            target,
            members.len(),
            upgrade_state.latest_status.len(),
            upgrade_state.issued_permits.len(),
            consumed,
            f,
            phase2_active
        );

        if !phase2_active {
            return vec![];
        }

        // Fold peer statuses from recent blocks' upgrade sections. Each
        // PastPayload.payload is the CBOR-encoded UpgradePayload from a block in
        // the certification gap. Collect the newest status per node.
        let mut pool_statuses: BTreeMap<NodeId, UpgradeStatus> = BTreeMap::new();
        for past in past_payloads {
            if let Ok(payload) = serde_cbor::from_slice::<UpgradePayload>(past.payload) {
                for status in payload.statuses {
                    pool_statuses
                        .entry(status.node_id)
                        .and_modify(|existing| {
                            if status.height > existing.height {
                                *existing = status.clone();
                            }
                        })
                        .or_insert(status.clone());
                }
            }
        }

        // Always include our own heartbeat (freshest for this node).
        let own_status = UpgradeStatus {
            version: ReplicaVersion::default(),
            node_id: self.node_id,
            guestos_version: ic_types::GuestOsVersion::default(),
            height,
        };
        pool_statuses.insert(self.node_id, own_status);

        // Only include statuses newer than what's already in the agreed state
        // (the delta). Statuses already folded into UpgradeState via finalized
        // blocks don't need to be re-committed.
        let pool_vec: Vec<UpgradeStatus> = pool_statuses.into_values().collect();
        let delta: Vec<UpgradeStatus> = upgrade_state
            .compute_delta(&pool_vec)
            .into_iter()
            .cloned()
            .collect();

        let permits = upgrade_state.pick_permits(&members, height, &target);
        info!(
            self.logger,
            "upgrade_payload: pool_statuses={} delta={} pick_permits={}",
            pool_vec.len(),
            delta.len(),
            permits.len()
        );

        let payload = UpgradePayload {
            statuses: delta,
            permits,
        };

        serde_cbor::to_vec(&payload).unwrap_or_default()
    }

    fn validate_payload(
        &self,
        _height: Height,
        _proposal_context: &ProposalContext,
        payload: &[u8],
        _past_payloads: &[PastPayload],
    ) -> Result<(), PayloadValidationError> {
        if payload.is_empty() {
            return Ok(());
        }
        let _ = serde_cbor::from_slice::<UpgradePayload>(payload);
        Ok(())
    }
}
