use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::{SubnetMembership, subnet_membership, validate_share};
use ic_consensus_utils::crypto::ConsensusCrypto;
use ic_consensus_utils::membership::Membership;
use ic_interfaces::consensus_pool::ConsensusBlockCache;
use ic_interfaces::p2p::consensus::{Bouncer, BouncerFactory, BouncerValue, PoolMutationsProducer};
use ic_interfaces::upgrade::{
    UpgradePermitAuthChangeAction, UpgradePermitAuthChangeSet, UpgradePermitAuthPool,
};
use ic_logger::{ReplicaLogger, info, warn};
use ic_types::artifact::IdentifiableArtifact;
use ic_types::batch::bytes_to_upgrade_payload;
use ic_types::consensus::{Block, UpgradePermitAuthorizationShare, upgrade::UpgradePermitAction};
use ic_types::{Height, NodeId};
use num_traits::SaturatingSub;

/// Shares whose request height falls this many blocks below the finalized
/// tip are purged from the pool.
const SHARE_EXPIRY_BLOCKS: Height = Height::new(20);

/// Signs shares for requests in finalized blocks, validates gossiped shares,
/// and purges expired ones.
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

    /// Membership at the finalized block's own height and registry version.
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
            let membership = self.block_membership(block);
            if !membership.staying(&self.node_id) {
                continue;
            }
            for action in actions {
                let UpgradePermitAction::Request(request) = action else {
                    continue;
                };
                let key = (request.requestor, request.request_height);
                if signed.contains(&key) {
                    continue;
                }
                match self
                    .crypto
                    .sign(&request, self.node_id, block.context.registry_version)
                {
                    Ok(signature) => {
                        signed.insert(key);
                        info!(
                            self.logger,
                            "permit_auth: signed share for node {:?} at height {:?}",
                            request.requestor,
                            request.request_height
                        );
                        change_set.push(UpgradePermitAuthChangeAction::AddToValidated(
                            UpgradePermitAuthorizationShare {
                                content: request,
                                signature,
                            },
                        ));
                    }
                    Err(e) => {
                        warn!(
                            self.logger,
                            "permit_auth: failed to sign share for node {:?}: {:?}",
                            request.requestor,
                            e
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
        let mut change_set = vec![];

        for share in pool.get_unvalidated_shares() {
            let Ok(block) = chain.get_block_by_height(share.content.request_height) else {
                change_set.push(UpgradePermitAuthChangeAction::HandleInvalid(
                    share.id(),
                    format!(
                        "block at request_height {:?} not found in finalized chain",
                        share.content.request_height
                    ),
                ));
                continue;
            };
            let membership = self.block_membership(block);
            match validate_share(
                share,
                share.content.requestor,
                share.content.request_height,
                &membership,
                block.context.registry_version,
                self.crypto.as_ref(),
            ) {
                Ok(_) => {
                    change_set.push(UpgradePermitAuthChangeAction::MoveToValidated(
                        share.clone(),
                    ));
                }
                Err(reason) => {
                    warn!(
                        self.logger,
                        "permit_auth: dropping invalid share: {reason:?}",
                    );
                    change_set.push(UpgradePermitAuthChangeAction::HandleInvalid(
                        share.id(),
                        format!("invalid share: {reason:?}"),
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
        let expiry_threshold = current_height.saturating_sub(&SHARE_EXPIRY_BLOCKS);

        let expired_validated = pool
            .get_validated_shares()
            .filter(|share| share.content.request_height < expiry_threshold)
            .map(|share| UpgradePermitAuthChangeAction::RemoveValidated(share.into()));

        let expired_unvalidated = pool
            .get_unvalidated_shares()
            .filter(|share| share.content.request_height < expiry_threshold)
            .map(|share| UpgradePermitAuthChangeAction::RemoveUnvalidated(share.into()));

        expired_validated.chain(expired_unvalidated).collect()
    }
}

impl<T: UpgradePermitAuthPool> PoolMutationsProducer<T> for UpgradePermitAuthPoolManager {
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

impl<Pool> BouncerFactory<ic_types::artifact::UpgradePermitAuthorizationShareId, Pool>
    for UpgradePermitAuthBouncer
{
    fn new_bouncer(
        &self,
        _pool: &Pool,
    ) -> Bouncer<ic_types::artifact::UpgradePermitAuthorizationShareId> {
        Box::new(|_id| BouncerValue::Wants)
    }

    fn refresh_period(&self) -> Duration {
        Duration::from_secs(60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_interfaces::consensus_pool::{ConsensusBlockChain, ConsensusBlockChainErr};
    use ic_interfaces_mocks::crypto::MockCrypto;
    use ic_logger::replica_logger::no_op_logger;
    use ic_protobuf::types::v1 as pb;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_test_utilities_consensus::{FakeConsensusPoolCache, fake::Fake, make_genesis};
    use ic_test_utilities_registry::{SubnetRecordBuilder, add_single_subnet_record};
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id, test_replica_version};
    use ic_types::NumBytes;
    use ic_types::RegistryVersion;
    use ic_types::artifact::{IdentifiableArtifact, UpgradePermitAuthorizationShareId};
    use ic_types::batch::{BatchPayload, ValidationContext, upgrade_payload_to_bytes};
    use ic_types::consensus::upgrade::UpgradePermitAction;
    use ic_types::consensus::{
        BlockPayload, DataPayload, Payload, Rank, UpgradePermitAuthorizationRequest,
        dkg::{DkgDataPayload, DkgSummary},
    };
    use ic_types::crypto::{
        BasicSig, BasicSigOf, CryptoError, CryptoHash, CryptoHashOf, crypto_hash,
    };
    use ic_types::signature::BasicSignature;
    use ic_types::time::UNIX_EPOCH;
    use std::collections::BTreeMap;
    use std::ops::RangeInclusive;

    fn registry_version() -> RegistryVersion {
        RegistryVersion::from(1)
    }

    fn members() -> Vec<NodeId> {
        vec![node_test_id(1), node_test_id(2), node_test_id(3)]
    }

    fn signing_crypto() -> MockCrypto {
        let mut crypto = MockCrypto::new();
        crypto
            .expect_sign_basic_upgrade_permit_auth()
            .returning(|_| Ok(BasicSigOf::new(BasicSig(vec![]))));
        crypto
    }

    fn verifying_crypto() -> MockCrypto {
        let mut crypto = MockCrypto::new();
        crypto
            .expect_verify_basic_sig_upgrade_permit_auth()
            .returning(|_, _, _, _| Ok(()));
        crypto
    }

    fn membership_of(members: &[NodeId]) -> Arc<Membership> {
        let data_provider = Arc::new(ProtoRegistryDataProvider::new());
        add_single_subnet_record(
            &data_provider,
            registry_version().get(),
            subnet_test_id(1),
            SubnetRecordBuilder::default()
                .with_membership(members)
                .build(),
        );
        let registry = Arc::new(FakeRegistryClient::new(Arc::clone(&data_provider) as Arc<_>));
        registry.update_to_latest_version();
        let cup = make_genesis(DkgSummary::fake());
        let consensus_cache = Arc::new(FakeConsensusPoolCache::new(pb::CatchUpPackage::from(cup)));
        Arc::new(Membership::new(
            consensus_cache,
            registry,
            subnet_test_id(1),
        ))
    }

    fn genesis_block() -> Block {
        make_genesis(DkgSummary::fake()).content.block.into_inner()
    }

    fn data_block(height: u64, actions: &[UpgradePermitAction]) -> Block {
        Block::new(
            CryptoHashOf::new(CryptoHash(vec![0; 32])),
            Payload::new(
                crypto_hash,
                BlockPayload::Data(DataPayload {
                    batch: BatchPayload {
                        upgrade: upgrade_payload_to_bytes(
                            actions.to_vec(),
                            NumBytes::new(u64::MAX),
                        ),
                        ..BatchPayload::default()
                    },
                    dkg: DkgDataPayload::new_empty(Height::from(height)),
                    idkg: None,
                }),
            ),
            Height::from(height),
            Rank(0),
            ValidationContext {
                registry_version: registry_version(),
                certified_height: Height::from(height),
                time: UNIX_EPOCH,
            },
            test_replica_version(),
        )
    }

    fn empty_blocks(heights: RangeInclusive<u64>) -> Vec<Block> {
        heights.map(|height| data_block(height, &[])).collect()
    }

    struct FakeFinalizedChain {
        blocks: Vec<Block>,
    }

    impl ConsensusBlockChain for FakeFinalizedChain {
        fn tip(&self) -> &Block {
            self.blocks.last().unwrap()
        }

        fn get_block_by_height(&self, height: Height) -> Result<&Block, ConsensusBlockChainErr> {
            self.blocks
                .iter()
                .find(|block| block.height == height)
                .ok_or(ConsensusBlockChainErr::BlockNotFound(height))
        }

        fn len(&self) -> usize {
            self.blocks.len()
        }

        fn iter_above(&self, height: Height) -> Box<dyn Iterator<Item = &Block> + '_> {
            Box::new(self.blocks.iter().filter(move |b| b.height > height))
        }
    }

    struct FakeBlockCache {
        chain: Arc<FakeFinalizedChain>,
    }

    impl ConsensusBlockCache for FakeBlockCache {
        fn finalized_chain(&self) -> Arc<dyn ConsensusBlockChain> {
            self.chain.clone()
        }
    }

    fn pool_manager(
        node_id: NodeId,
        members: &[NodeId],
        blocks: Vec<Block>,
        crypto: MockCrypto,
    ) -> UpgradePermitAuthPoolManager {
        let mut chain = vec![genesis_block()];
        chain.extend(blocks);
        UpgradePermitAuthPoolManager::new(
            node_id,
            Arc::new(crypto),
            Arc::new(FakeBlockCache {
                chain: Arc::new(FakeFinalizedChain { blocks: chain }),
            }),
            membership_of(members),
            no_op_logger(),
        )
    }

    struct FakePool {
        validated: BTreeMap<UpgradePermitAuthorizationShareId, UpgradePermitAuthorizationShare>,
        unvalidated: BTreeMap<UpgradePermitAuthorizationShareId, UpgradePermitAuthorizationShare>,
    }

    impl FakePool {
        fn new() -> Self {
            Self {
                validated: BTreeMap::new(),
                unvalidated: BTreeMap::new(),
            }
        }

        fn with_validated(mut self, share: UpgradePermitAuthorizationShare) -> Self {
            self.validated.insert(share.id(), share);
            self
        }

        fn with_unvalidated(mut self, share: UpgradePermitAuthorizationShare) -> Self {
            self.unvalidated.insert(share.id(), share);
            self
        }
    }

    impl UpgradePermitAuthPool for FakePool {
        fn get_validated_shares(
            &self,
        ) -> Box<dyn Iterator<Item = &UpgradePermitAuthorizationShare> + '_> {
            Box::new(self.validated.values())
        }

        fn get_unvalidated_shares(
            &self,
        ) -> Box<dyn Iterator<Item = &UpgradePermitAuthorizationShare> + '_> {
            Box::new(self.unvalidated.values())
        }
    }

    fn share(signer: u64, requestor: u64, request_height: u64) -> UpgradePermitAuthorizationShare {
        UpgradePermitAuthorizationShare {
            content: UpgradePermitAuthorizationRequest {
                requestor: node_test_id(requestor),
                request_height: Height::from(request_height),
            },
            signature: BasicSignature {
                signature: BasicSigOf::new(BasicSig(vec![])),
                signer: node_test_id(signer),
            },
        }
    }

    fn request(requestor: u64, request_height: u64) -> UpgradePermitAction {
        UpgradePermitAction::Request(UpgradePermitAuthorizationRequest {
            requestor: node_test_id(requestor),
            request_height: Height::from(request_height),
        })
    }

    fn assert_single_add_to_validated(
        change_set: &UpgradePermitAuthChangeSet,
        expected: &UpgradePermitAuthorizationShare,
    ) {
        assert_eq!(change_set.len(), 1);
        assert!(matches!(
            &change_set[0],
            UpgradePermitAuthChangeAction::AddToValidated(s) if s == expected
        ));
    }

    fn assert_single_handle_invalid(
        change_set: &UpgradePermitAuthChangeSet,
        expected: &UpgradePermitAuthorizationShare,
    ) {
        assert_eq!(change_set.len(), 1);
        assert!(matches!(
            &change_set[0],
            UpgradePermitAuthChangeAction::HandleInvalid(id, _) if id == &expected.id()
        ));
    }

    #[test]
    fn test_signs_share_for_request_in_finalized_block() {
        let manager = pool_manager(
            node_test_id(1),
            &members(),
            vec![data_block(1, &[request(2, 1)])],
            signing_crypto(),
        );
        let change_set = manager.on_state_change(&FakePool::new());
        assert_single_add_to_validated(&change_set, &share(1, 2, 1));
    }

    #[test]
    fn test_does_not_sign_when_node_leaving_subnet() {
        let manager = pool_manager(
            node_test_id(4),
            &members(),
            vec![data_block(1, &[request(2, 1)])],
            signing_crypto(),
        );
        assert!(manager.on_state_change(&FakePool::new()).is_empty());
    }

    #[test]
    fn test_ignores_blocks_without_requests() {
        let manager = pool_manager(
            node_test_id(1),
            &members(),
            vec![data_block(1, &[]), data_block(2, &[])],
            signing_crypto(),
        );
        assert!(manager.on_state_change(&FakePool::new()).is_empty());
    }

    #[test]
    fn test_does_not_rescan_finalized_blocks() {
        let manager = pool_manager(
            node_test_id(1),
            &members(),
            vec![data_block(1, &[request(2, 1)])],
            signing_crypto(),
        );
        assert_single_add_to_validated(&manager.on_state_change(&FakePool::new()), &share(1, 2, 1));
        assert!(manager.on_state_change(&FakePool::new()).is_empty());
    }

    #[test]
    fn test_deduplicates_repeated_requests() {
        let manager = pool_manager(
            node_test_id(1),
            &members(),
            vec![
                data_block(1, &[request(2, 1)]),
                data_block(2, &[request(2, 1)]),
            ],
            signing_crypto(),
        );
        let change_set = manager.on_state_change(&FakePool::new());
        assert_single_add_to_validated(&change_set, &share(1, 2, 1));
    }

    #[test]
    fn test_signing_failure_yields_no_action() {
        let mut crypto = MockCrypto::new();
        crypto
            .expect_sign_basic_upgrade_permit_auth()
            .returning(|_| {
                Err(CryptoError::TransientInternalError {
                    internal_error: "boom".to_string(),
                })
            });
        let manager = pool_manager(
            node_test_id(1),
            &members(),
            vec![data_block(1, &[request(2, 1)])],
            crypto,
        );
        assert!(manager.on_state_change(&FakePool::new()).is_empty());
    }

    #[test]
    fn test_validates_gossiped_share() {
        let manager = pool_manager(
            node_test_id(1),
            &members(),
            vec![data_block(5, &[])],
            verifying_crypto(),
        );
        let gossiped = share(2, 3, 5);
        let pool = FakePool::new().with_unvalidated(gossiped.clone());
        let change_set = manager.on_state_change(&pool);
        assert_eq!(change_set.len(), 1);
        assert!(matches!(
            &change_set[0],
            UpgradePermitAuthChangeAction::MoveToValidated(s) if s == &gossiped
        ));
    }

    #[test]
    fn test_drops_share_with_invalid_signature() {
        let mut crypto = MockCrypto::new();
        crypto
            .expect_verify_basic_sig_upgrade_permit_auth()
            .returning(|_, _, _, _| {
                Err(CryptoError::TransientInternalError {
                    internal_error: "boom".to_string(),
                })
            });
        let manager = pool_manager(
            node_test_id(1),
            &members(),
            vec![data_block(5, &[])],
            crypto,
        );
        let gossiped = share(2, 3, 5);
        let pool = FakePool::new().with_unvalidated(gossiped.clone());
        assert_single_handle_invalid(&manager.on_state_change(&pool), &gossiped);
    }

    #[test]
    fn test_drops_share_from_non_staying_signer() {
        let manager = pool_manager(
            node_test_id(1),
            &members(),
            vec![data_block(5, &[])],
            verifying_crypto(),
        );
        let gossiped = share(9, 3, 5);
        let pool = FakePool::new().with_unvalidated(gossiped.clone());
        assert_single_handle_invalid(&manager.on_state_change(&pool), &gossiped);
    }

    #[test]
    fn test_drops_share_without_request_block() {
        let manager = pool_manager(
            node_test_id(1),
            &members(),
            vec![data_block(5, &[])],
            verifying_crypto(),
        );
        let gossiped = share(2, 3, 99);
        let pool = FakePool::new().with_unvalidated(gossiped.clone());
        assert_single_handle_invalid(&manager.on_state_change(&pool), &gossiped);
    }

    #[test]
    fn test_purges_expired_validated_shares() {
        // Threshold is tip (100) - SHARE_EXPIRY_BLOCKS (20) = 80: shares with
        // request height below 80 are purged, at or above it are kept.
        let manager = pool_manager(
            node_test_id(1),
            &members(),
            empty_blocks(1..=100),
            MockCrypto::new(),
        );
        let expired = share(2, 3, 79);
        let pool = FakePool::new()
            .with_validated(expired.clone())
            .with_validated(share(3, 2, 80));
        let change_set = manager.on_state_change(&pool);
        assert_eq!(change_set.len(), 1);
        assert!(matches!(
            &change_set[0],
            UpgradePermitAuthChangeAction::RemoveValidated(id) if id == &expired.id()
        ));
    }

    #[test]
    fn test_purges_expired_unvalidated_shares() {
        // The share is both validated (moved out of unvalidated) and purged
        // (removed from unvalidated); applying both leaves it validated only.
        let manager = pool_manager(
            node_test_id(1),
            &members(),
            empty_blocks(1..=100),
            verifying_crypto(),
        );
        let expired = share(2, 3, 79);
        let pool = FakePool::new().with_unvalidated(expired.clone());
        let change_set = manager.on_state_change(&pool);
        assert_eq!(change_set.len(), 2);
        assert!(matches!(
            &change_set[0],
            UpgradePermitAuthChangeAction::MoveToValidated(s) if s == &expired
        ));
        assert!(matches!(
            &change_set[1],
            UpgradePermitAuthChangeAction::RemoveUnvalidated(id) if id == &expired.id()
        ));
    }
}
