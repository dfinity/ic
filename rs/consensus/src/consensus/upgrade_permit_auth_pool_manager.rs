//! Pool manager and bouncer for the upgrade permit authorization pool.
//!
//! This is the `PoolMutationsProducer` (a.k.a. `change_set_producer`) wired into
//! the artifact manager via `create_artifact_handler`. It runs in the artifact
//! manager thread and is the *only* place that mutates the pool, so that the
//! `ArtifactTransmits` returned by `pool.apply()` (which drive P2P broadcast)
//! are never discarded.
//!
//! Responsibilities:
//!   * **Sign** locally-produced shares for every `Request` seen in finalized
//!     blocks (via `consensus_pool_cache`), returned as `AddToValidated` so they
//!     are both stored and gossiped.
//!   * **Validate** gossiped shares in the unvalidated section, moving valid
//!     ones to validated (`MoveToValidated`) and dropping invalid ones.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ic_consensus_utils::crypto::ConsensusCrypto;
use ic_consensus_utils::membership::Membership;
use crate::consensus::upgrade_protocol::{subnet_membership, validate_share, SubnetMembership};
use ic_interfaces::consensus_pool::ConsensusBlockCache;
use ic_interfaces::p2p::consensus::{Bouncer, BouncerFactory, BouncerValue, PoolMutationsProducer};
use ic_interfaces::upgrade_permit_auth::{
    UpgradePermitAuthChangeAction, UpgradePermitAuthChangeSet, UpgradePermitAuthPool,
};
use ic_logger::{ReplicaLogger, info, warn};
use ic_types::consensus::{
    Block, UpgradePermitAuthorizationContent, UpgradePermitAuthorizationShare,
    upgrade::UpgradePermitAction,
};
use ic_replicated_state::metadata_state::REQUEST_TIMEOUT_BLOCKS;
use ic_types::batch::bytes_to_upgrade_payload;
use ic_types::{Height, NodeId};
use num_traits::SaturatingSub;

/// Pool manager that signs auth shares for new requests and validates gossiped
/// auth shares.
pub struct UpgradePermitAuthPoolManager {
    node_id: NodeId,
    crypto: Arc<dyn ConsensusCrypto>,
    consensus_pool_cache: Arc<dyn ConsensusBlockCache>,
    membership: Arc<Membership>,
    /// Requests we've already signed (node, request_height).
    signed_requests: Mutex<BTreeSet<(NodeId, Height)>>,
    /// Last finalized height we scanned for requests.
    last_scanned: Mutex<Height>,
    logger: ReplicaLogger,
}

impl UpgradePermitAuthPoolManager {
    /// Create a new upgrade permit auth pool manager.
    pub fn new(
        node_id: NodeId,
        crypto: Arc<dyn ConsensusCrypto>,
        consensus_pool_cache: Arc<dyn ConsensusBlockCache>,
        membership: Arc<Membership>,
        logger: ReplicaLogger,
    ) -> Self {
        Self {
            node_id,
            crypto,
            consensus_pool_cache,
            membership,
            signed_requests: Mutex::new(BTreeSet::new()),
            last_scanned: Mutex::new(Height::from(0)),
            logger,
        }
    }

    /// Membership at the given finalized block's own height and registry
    /// version, the pair under which the block's upgrade actions were
    /// validated.
    fn block_membership(&self, block: &Block) -> SubnetMembership {
        subnet_membership(
            &self.membership,
            block.height,
            block.context.registry_version,
            &self.logger,
        )
    }

    /// Scan finalized blocks for new `Request` actions and sign an auth share
    /// for each one we haven't signed yet.
    fn sign_shares_for_new_requests(&self) -> UpgradePermitAuthChangeSet {
        let chain = self.consensus_pool_cache.finalized_chain();
        let tip = chain.tip().height;
        let mut last = self.last_scanned.lock().unwrap();
        let start = last.increment();
        if start > tip {
            return vec![];
        }
        *last = tip;

        let mut signed = self.signed_requests.lock().unwrap();
        let mut change_set = vec![];

        for height_num in start.get()..=tip.get() {
            let height = Height::from(height_num);
            let Ok(block) = chain.get_block_by_height(height) else {
                continue;
            };
            let payload = block.payload.as_ref();
            if payload.is_summary() {
                continue;
            }
            let upgrade_bytes = &payload.as_data().batch.upgrade;
            if upgrade_bytes.is_empty() {
                continue;
            }
            let Ok(actions) = bytes_to_upgrade_payload(upgrade_bytes) else {
                continue;
            };
            // Membership at the request block's own height and registry
            // version, the pair under which the request was validated.
            let membership = self.block_membership(block);
            // Sign only if we are staying in the subnet for the foreseeable
            // future.
            if !membership.staying(&self.node_id) {
                continue;
            }
            for action in actions {
                let UpgradePermitAction::Request { node, request_height } = action else {
                    continue;
                };
                if !membership.staying(&node) {
                    continue;
                }
                let key = (node, request_height);
                if signed.contains(&key) {
                    continue;
                }
                let content = UpgradePermitAuthorizationContent {
                    node,
                    request_height,
                };
                let registry_version = block.context.registry_version;
                match self.crypto.sign(&content, self.node_id, registry_version) {
                    Ok(signature) => {
                        signed.insert(key);
                        info!(
                            self.logger,
                            "permit_auth: signed share for node {:?} at height {:?}",
                            node, request_height
                        );
                        change_set.push(UpgradePermitAuthChangeAction::AddToValidated(
                            UpgradePermitAuthorizationShare { content, signature },
                        ));
                    }
                    Err(e) => {
                        warn!(
                            self.logger,
                            "permit_auth: failed to sign share for node {:?}: {:?}",
                            node, e
                        );
                    }
                }
            }
        }
        change_set
    }

    /// Validate gossiped shares found in the unvalidated section of the pool.
    fn validate_gossiped_shares(
        &self,
        pool: &dyn UpgradePermitAuthPool,
    ) -> UpgradePermitAuthChangeSet {
        let chain = self.consensus_pool_cache.finalized_chain();
        let unvalidated: Vec<UpgradePermitAuthorizationShare> =
            pool.get_unvalidated_shares().cloned().collect();
        let mut change_set = vec![];

        for share in unvalidated {
            let Ok(block) = chain.get_block_by_height(share.content.request_height) else {
                let id = (&share).into();
                change_set.push(UpgradePermitAuthChangeAction::HandleInvalid(
                    id,
                    format!(
                        "block at request_height {:?} not found in finalized chain",
                        share.content.request_height
                    ),
                ));
                continue;
            };
            // Membership at the request block's own height and registry
            // version.
            let membership = self.block_membership(block);
            match validate_share(
                &share,
                share.content.node,
                share.content.request_height,
                &membership.staying_members,
                block.context.registry_version,
                self.crypto.as_ref(),
            ) {
                Ok(_) => {
                    change_set.push(UpgradePermitAuthChangeAction::MoveToValidated(share));
                }
                Err(reason) => {
                    warn!(self.logger, "permit_auth: dropping invalid share: {:?}", reason);
                    let id = (&share).into();
                    change_set.push(UpgradePermitAuthChangeAction::HandleInvalid(
                        id,
                        format!("invalid share: {:?}", reason),
                    ));
                }
            }
        }

        change_set
    }

    /// Purge shares (both validated and unvalidated) whose request has expired
    /// (the request height is older than `REQUEST_TIMEOUT_BLOCKS` below the
    /// current finalized height).
    fn purge_expired_shares(&self, pool: &dyn UpgradePermitAuthPool) -> UpgradePermitAuthChangeSet {
        let current_height = self.consensus_pool_cache.finalized_chain().tip().height;
        let expiry_threshold = current_height.saturating_sub(&REQUEST_TIMEOUT_BLOCKS);

        let mut change_set = vec![];
        for share in pool.get_validated_shares() {
            if share.content.request_height < expiry_threshold {
                change_set.push(UpgradePermitAuthChangeAction::RemoveValidated(
                    share.into(),
                ));
            }
        }
        for share in pool.get_unvalidated_shares() {
            if share.content.request_height < expiry_threshold {
                change_set.push(UpgradePermitAuthChangeAction::RemoveUnvalidated(
                    share.into(),
                ));
            }
        }
        change_set
    }
}

impl <T: UpgradePermitAuthPool> PoolMutationsProducer<T> for UpgradePermitAuthPoolManager {
    type Mutations = UpgradePermitAuthChangeSet;

    fn on_state_change(&self, pool: &T) -> Self::Mutations {
        let mut change_set = self.sign_shares_for_new_requests();
        change_set.extend(self.validate_gossiped_shares(pool));
        change_set.extend(self.purge_expired_shares(pool));
        change_set
    }
}

/// Bouncer that accepts all upgrade permit auth shares.
pub struct UpgradePermitAuthBouncer;

impl<Pool> BouncerFactory<ic_types::artifact::UpgradePermitAuthId, Pool> for UpgradePermitAuthBouncer {
    fn new_bouncer(&self, _pool: &Pool) -> Bouncer<ic_types::artifact::UpgradePermitAuthId> {
        Box::new(|_id| BouncerValue::Wants)
    }

    fn refresh_period(&self) -> Duration {
        Duration::from_secs(60)
    }
}
