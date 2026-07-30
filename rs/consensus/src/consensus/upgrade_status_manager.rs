//! UpgradeStatusManager: produces [`UpgradeStatus`] heartbeats for gossip AND
//! applies finalized blocks' upgrade sections to a shared [`UpgradeState`].
//!
//! This consensus subcomponent is active during Phase 2. Every K rounds it
//! produces a fresh heartbeat. Every state change it scans newly-finalized
//! blocks for upgrade sections and applies them to the shared state (the
//! "consensus-local accumulator"), which the [`UpgradePayloadBuilder`] reads
//! to compute permits.

use std::sync::{Arc, Mutex, RwLock};

use ic_consensus_utils::pool_reader::PoolReader;
use ic_interfaces_registry::RegistryClient;
use ic_logger::{ReplicaLogger, info};
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_types::consensus::upgrade::{UpgradePayload, UpgradeStatus, UpgradeState};
use ic_types::{GuestOsVersion, Height, NodeId, ReplicaVersion, SubnetId};

/// Heartbeat interval: produce a fresh status every K rounds.
const HEARTBEAT_INTERVAL: u64 = 10;

pub(crate) struct UpgradeStatusManager {
    node_id: NodeId,
    subnet_id: SubnetId,
    registry_client: Arc<dyn RegistryClient>,
    /// Shared accumulator: updated from finalized blocks, read by the section builder.
    shared_state: Arc<RwLock<UpgradeState>>,
    last_processed: Mutex<Height>,
    last_produced: Mutex<Height>,
    logger: ReplicaLogger,
}

impl UpgradeStatusManager {
    pub(crate) fn new(
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
            last_processed: Mutex::new(Height::from(0)),
            last_produced: Mutex::new(Height::from(0)),
            logger,
        }
    }

    /// Called every consensus state change. Does two things:
    /// 1. Scans newly-finalized blocks for upgrade sections and applies them.
    /// 2. Produces a heartbeat every K rounds.
    pub(crate) fn on_state_change(&self, pool: &PoolReader<'_>) -> Option<UpgradeStatus> {
        self.apply_finalized_sections(pool);
        self.maybe_produce_heartbeat(pool)
    }

    /// Scan finalized blocks from `last_processed + 1` to the tip, decode their
    /// upgrade sections, and apply them to the shared state.
    fn apply_finalized_sections(&self, pool: &PoolReader<'_>) {
        let tip = pool.get_finalized_height();
        let mut last = self.last_processed.lock().unwrap();
        let start = last.increment();

        if start > tip {
            return;
        }

        let registry_version = pool
            .get_finalized_block(tip)
            .map(|block| block.context.registry_version)
            .unwrap_or_else(|| self.registry_client.get_latest_version());

        let target = self
            .registry_client
            .get_subnet_record(self.subnet_id, registry_version)
            .ok()
            .flatten()
            .and_then(|record| {
                ReplicaVersion::try_from(record.replica_version_id).ok()
            });

        let members = self
            .registry_client
            .get_node_ids_on_subnet(self.subnet_id, registry_version)
            .ok()
            .flatten()
            .unwrap_or_default();

        let mut state = self.shared_state.write().unwrap();
        for height_num in start.get()..=tip.get() {
            let height = Height::from(height_num);
            if let Some(block) = pool.get_finalized_block(height) {
                let payload = block.payload.as_ref();
                if !payload.is_summary() {
                    let upgrade_bytes = &payload.as_data().batch.upgrade;
                    if !upgrade_bytes.is_empty() {
                        if let Some(payload) =
                            serde_cbor::from_slice::<UpgradePayload>(upgrade_bytes).ok()
                        {
                            state.apply(&payload, target.clone(), &members);
                        }
                    }
                }
            }
        }
        info!(
            self.logger,
            "upgrade_status: applied blocks {}-{} target={:?} members={} \
             latest_status={} issued_permits={}",
            start,
            tip,
            target,
            members.len(),
            state.latest_status.len(),
            state.issued_permits.len()
        );
        *last = tip;
    }

    /// Produce a heartbeat every K rounds.
    fn maybe_produce_heartbeat(&self, pool: &PoolReader<'_>) -> Option<UpgradeStatus> {
        let tip = pool.get_finalized_height(); // TODO: replace with certified height
        let mut last = self.last_produced.lock().unwrap();
        if tip.get().saturating_sub(last.get()) < HEARTBEAT_INTERVAL {
            return None;
        }
        *last = tip;
        info!(
            self.logger,
            "upgrade_status: produced heartbeat node={} height={} replica={} guestos={}",
            self.node_id,
            tip,
            ReplicaVersion::default(),
            GuestOsVersion::default(),
        );
        Some(UpgradeStatus {
            version: ReplicaVersion::default(),
            node_id: self.node_id,
            guestos_version: GuestOsVersion::default(),
            height: tip,
        })
    }
}
