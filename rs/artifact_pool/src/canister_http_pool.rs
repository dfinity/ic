//! Canister Http Artifact Pool implementation.

use crate::{
    metrics::{POOL_TYPE_UNVALIDATED, POOL_TYPE_VALIDATED},
    pool_common::{HasLabel, PoolSection},
};
use ic_interfaces::{
    canister_http::{CanisterHttpChangeAction, CanisterHttpChangeSet, CanisterHttpPool},
    p2p::consensus::{
        ArtifactTransmit, ArtifactTransmits, ArtifactWithOpt, MutablePool, UnvalidatedArtifact,
        ValidatedPoolReader,
    },
};
use ic_logger::{warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_types::{
    artifact::CanisterHttpResponseId,
    canister_http::{CanisterHttpResponse, CanisterHttpResponseShare},
    crypto::CryptoHashOf,
};
use prometheus::IntCounter;

const POOL_CANISTER_HTTP: &str = "canister_http";
const POOL_CANISTER_HTTP_CONTENT: &str = "canister_http_content";

type ValidatedCanisterHttpPoolSection = PoolSection<CanisterHttpResponseShare, ()>;

type UnvalidatedCanisterHttpPoolSection = PoolSection<CanisterHttpResponseShare, ()>;

type ContentCanisterHttpPoolSection =
    PoolSection<CryptoHashOf<CanisterHttpResponse>, CanisterHttpResponse>;

pub struct CanisterHttpPoolImpl {
    validated: ValidatedCanisterHttpPoolSection,
    unvalidated: UnvalidatedCanisterHttpPoolSection,
    content: ContentCanisterHttpPoolSection,
    invalidated_artifacts: IntCounter,
    log: ReplicaLogger,
}

impl CanisterHttpPoolImpl {
    pub fn new(metrics: MetricsRegistry, log: ReplicaLogger) -> Self {
        Self {
            invalidated_artifacts: metrics.int_counter(
                "canister_http_invalidated_artifacts",
                "The number of invalidated canister http artifacts",
            ),
            validated: PoolSection::new(metrics.clone(), POOL_CANISTER_HTTP, POOL_TYPE_VALIDATED),
            unvalidated: PoolSection::new(
                metrics.clone(),
                POOL_CANISTER_HTTP,
                POOL_TYPE_UNVALIDATED,
            ),
            content: ContentCanisterHttpPoolSection::new(
                metrics,
                POOL_CANISTER_HTTP_CONTENT,
                POOL_TYPE_VALIDATED,
            ),
            log,
        }
    }
}

impl CanisterHttpPool for CanisterHttpPoolImpl {
    fn get_validated_shares(&self) -> Box<dyn Iterator<Item = &CanisterHttpResponseShare> + '_> {
        Box::new(self.validated.keys())
    }

    fn get_unvalidated_shares(&self) -> Box<dyn Iterator<Item = &CanisterHttpResponseShare> + '_> {
        Box::new(self.unvalidated.keys())
    }

    fn get_response_content_items(
        &self,
    ) -> Box<dyn Iterator<Item = (&CryptoHashOf<CanisterHttpResponse>, &CanisterHttpResponse)> + '_>
    {
        Box::new(self.content.iter())
    }

    fn get_response_content_by_hash(
        &self,
        hash: &CryptoHashOf<CanisterHttpResponse>,
    ) -> Option<CanisterHttpResponse> {
        self.content.get(hash).cloned()
    }

    fn lookup_validated(
        &self,
        msg_id: &CanisterHttpResponseId,
    ) -> Option<CanisterHttpResponseShare> {
        self.validated.get(msg_id).map(|()| msg_id.clone())
    }

    fn lookup_unvalidated(
        &self,
        msg_id: &CanisterHttpResponseId,
    ) -> Option<CanisterHttpResponseShare> {
        self.unvalidated.get(msg_id).map(|()| msg_id.clone())
    }
}

impl MutablePool<CanisterHttpResponseShare> for CanisterHttpPoolImpl {
    type ChangeSet = CanisterHttpChangeSet;

    fn insert(&mut self, artifact: UnvalidatedArtifact<CanisterHttpResponseShare>) {
        self.unvalidated.insert(artifact.message, ());
    }

    fn remove(&mut self, id: &CanisterHttpResponseId) {
        self.unvalidated.remove(id);
    }

    fn apply_changes(
        &mut self,
        change_set: CanisterHttpChangeSet,
    ) -> ArtifactTransmits<CanisterHttpResponseShare> {
        let changed = !change_set.is_empty();
        let mut mutations = vec![];
        for action in change_set {
            match action {
                CanisterHttpChangeAction::AddToValidated(share, content) => {
                    mutations.push(ArtifactTransmit::Deliver(ArtifactWithOpt {
                        artifact: share.clone(),
                        is_latency_sensitive: true,
                    }));
                    self.validated.insert(share, ());
                    self.content
                        .insert(ic_types::crypto::crypto_hash(&content), content);
                }
                CanisterHttpChangeAction::MoveToValidated(share) => {
                    if self.unvalidated.remove(&share).is_some() {
                        self.validated.insert(share, ());
                    }
                }
                CanisterHttpChangeAction::RemoveValidated(id) => {
                    if self.validated.remove(&id).is_some() {
                        mutations.push(ArtifactTransmit::Abort(id));
                    }
                }
                CanisterHttpChangeAction::RemoveUnvalidated(id) => {
                    self.remove(&id);
                }
                CanisterHttpChangeAction::RemoveContent(id) => {
                    self.content.remove(&id);
                }
                CanisterHttpChangeAction::HandleInvalid(id, reason) => {
                    self.invalidated_artifacts.inc();
                    warn!(
                        self.log,
                        "Invalid CanisterHttp message ({:?}): {:?}", reason, id
                    );
                    self.remove(&id);
                }
            }
        }
        ArtifactTransmits {
            mutations,
            poll_immediately: changed,
        }
    }
}

impl ValidatedPoolReader<CanisterHttpResponseShare> for CanisterHttpPoolImpl {
    fn get(&self, id: &CanisterHttpResponseId) -> Option<CanisterHttpResponseShare> {
        self.validated.get(id).map(|()| id.clone())
    }

    fn get_all_validated(&self) -> Box<dyn Iterator<Item = CanisterHttpResponseShare> + '_> {
        Box::new(std::iter::empty())
    }
}

impl HasLabel for CanisterHttpResponse {
    fn label(&self) -> &str {
        "canister_http_response"
    }
}

#[cfg(test)]
mod tests {
    use ic_logger::replica_logger::no_op_logger;
    use ic_test_utilities_consensus::fake::FakeSigner;
    use ic_test_utilities_types::ids::node_test_id;
    use ic_types::{
        artifact::IdentifiableArtifact,
        canister_http::{CanisterHttpResponseContent, CanisterHttpResponseMetadata},
        crypto::{CryptoHash, Signed},
        messages::CallbackId,
        signature::BasicSignature,
        time::UNIX_EPOCH,
        CanisterId, RegistryVersion,
    };

    use super::*;

    fn to_unvalidated(
        message: CanisterHttpResponseShare,
    ) -> UnvalidatedArtifact<CanisterHttpResponseShare> {
        UnvalidatedArtifact::<CanisterHttpResponseShare> {
            message,
            peer_id: node_test_id(0),
            timestamp: UNIX_EPOCH,
        }
    }

    fn fake_share(id: u64) -> CanisterHttpResponseShare {
        Signed {
            content: CanisterHttpResponseMetadata {
                id: CallbackId::from(id),
                timeout: UNIX_EPOCH,
                content_hash: CryptoHashOf::from(CryptoHash(vec![1, 2, 3])),
                registry_version: RegistryVersion::from(id),
            },
            signature: BasicSignature::fake(node_test_id(id)),
        }
    }

    fn fake_response(id: u64) -> CanisterHttpResponse {
        CanisterHttpResponse {
            id: CallbackId::from(id),
            timeout: UNIX_EPOCH,
            canister_id: CanisterId::from_u64(id),
            content: CanisterHttpResponseContent::Success(Vec::new()),
        }
    }

    #[test]
    fn test_canister_http_pool_insert_and_remove() {
        let mut pool = CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());
        let share = fake_share(123);
        let id = share.clone();

        pool.insert(to_unvalidated(share.clone()));
        assert!(pool.get(&id).is_none());

        assert_eq!(share, pool.lookup_unvalidated(&id).unwrap());

        pool.remove(&id);
        assert!(pool.lookup_unvalidated(&id).is_none());
    }

    #[test]
    fn test_canister_http_pool_add_and_remove_validated() {
        let mut pool = CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());
        let share = fake_share(123);
        let id = share.clone();
        let response = fake_response(123);
        let content_hash = ic_types::crypto::crypto_hash(&response);

        let result = pool.apply_changes(vec![
            CanisterHttpChangeAction::AddToValidated(share.clone(), response.clone()),
            CanisterHttpChangeAction::AddToValidated(fake_share(456), fake_response(456)),
        ]);

        assert!(
            matches!(&result.mutations[0], ArtifactTransmit::Deliver(x) if x.artifact.id() == id)
        );
        assert!(matches!(&result.mutations[1], ArtifactTransmit::Deliver(_)));
        assert!(result.poll_immediately);
        assert_eq!(result.mutations.len(), 2);
        assert_eq!(share, pool.lookup_validated(&id).unwrap());
        assert_eq!(share, pool.get(&id).unwrap());
        assert_eq!(
            response,
            pool.get_response_content_by_hash(&content_hash).unwrap()
        );

        let result = pool.apply_changes(vec![
            CanisterHttpChangeAction::RemoveValidated(id.clone()),
            CanisterHttpChangeAction::RemoveContent(content_hash.clone()),
        ]);

        assert_eq!(result.mutations.len(), 1);
        assert!(result.poll_immediately);
        assert!(matches!(&result.mutations[0], ArtifactTransmit::Abort(x) if *x == id));
        assert!(pool.lookup_validated(&id).is_none());
        assert!(pool.get_response_content_by_hash(&content_hash).is_none());
        assert_eq!(pool.get_validated_shares().count(), 1);
        assert_eq!(pool.get_response_content_items().count(), 1);
    }

    #[test]
    fn test_canister_http_pool_move_to_validated() {
        let mut pool = CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());
        let share1 = fake_share(123);
        let id1 = share1.clone();
        let share2 = fake_share(456);
        let id2 = share2.clone();

        pool.insert(to_unvalidated(share1.clone()));

        let result = pool.apply_changes(vec![
            CanisterHttpChangeAction::MoveToValidated(share2.clone()),
            CanisterHttpChangeAction::MoveToValidated(share1.clone()),
        ]);

        assert!(pool.lookup_validated(&id2).is_none());
        assert!(result.poll_immediately);
        assert!(!result
            .mutations
            .iter()
            .any(|x| matches!(x, ArtifactTransmit::Abort(_))));
        assert_eq!(share1, pool.lookup_validated(&id1).unwrap());
    }

    #[test]
    fn test_canister_http_pool_remove_unvalidated() {
        let mut pool = CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());
        let share = fake_share(123);
        let id = share.clone();

        pool.insert(to_unvalidated(share.clone()));
        assert_eq!(share, pool.lookup_unvalidated(&id).unwrap());

        let result = pool.apply_changes(vec![CanisterHttpChangeAction::RemoveUnvalidated(
            id.clone(),
        )]);

        assert!(pool.lookup_unvalidated(&id).is_none());
        assert!(result.poll_immediately);
        assert!(result.mutations.is_empty());
    }

    #[test]
    fn test_canister_http_pool_handle_invalid() {
        let mut pool = CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());
        let share = fake_share(123);
        let id = share.clone();

        pool.insert(to_unvalidated(share.clone()));
        assert_eq!(share, pool.lookup_unvalidated(&id).unwrap());

        let result = pool.apply_changes(vec![CanisterHttpChangeAction::HandleInvalid(
            id.clone(),
            "TEST REASON".to_string(),
        )]);

        assert!(pool.lookup_unvalidated(&id).is_none());
        assert!(result.poll_immediately);
        assert!(result.mutations.is_empty());
    }
}
