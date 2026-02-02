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
use ic_logger::{ReplicaLogger, warn};
use ic_metrics::MetricsRegistry;
use ic_types::{
    artifact::{CanisterHttpResponseId, IdentifiableArtifact},
    canister_http::{
        CanisterHttpResponse, CanisterHttpResponseArtifact, CanisterHttpResponseShare,
    },
    crypto::CryptoHashOf,
};
use prometheus::IntCounter;

const POOL_CANISTER_HTTP: &str = "canister_http";
const POOL_CANISTER_HTTP_CONTENT: &str = "canister_http_content";

type ValidatedCanisterHttpPoolSection = PoolSection<CanisterHttpResponseShare, ()>;

type UnvalidatedCanisterHttpPoolSection =
    PoolSection<CanisterHttpResponseShare, CanisterHttpResponseArtifact>;

type ContentCanisterHttpPoolSection =
    PoolSection<CryptoHashOf<CanisterHttpResponse>, CanisterHttpResponse>;

pub struct CanisterHttpPoolImpl {
    validated: ValidatedCanisterHttpPoolSection,
    unvalidated: UnvalidatedCanisterHttpPoolSection,
    // This section will contain responses coming from either the local adapter, or from other peers.
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

    fn get_unvalidated_artifacts(
        &self,
    ) -> Box<dyn Iterator<Item = &CanisterHttpResponseArtifact> + '_> {
        Box::new(self.unvalidated.values())
    }

    fn get_unvalidated_artifact(
        &self,
        share: &CanisterHttpResponseShare,
    ) -> Option<&CanisterHttpResponseArtifact> {
        self.unvalidated.get(share)
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
        share: &CanisterHttpResponseShare,
    ) -> Option<CanisterHttpResponseShare> {
        self.validated.get(share).map(|()| share.clone())
    }
}

impl MutablePool<CanisterHttpResponseArtifact> for CanisterHttpPoolImpl {
    type Mutations = CanisterHttpChangeSet;

    fn insert(&mut self, artifact: UnvalidatedArtifact<CanisterHttpResponseArtifact>) {
        let id = artifact.message.id();
        self.unvalidated.insert(id, artifact.message);
    }

    fn remove(&mut self, id: &CanisterHttpResponseId) {
        self.unvalidated.remove(id);
    }

    fn apply(
        &mut self,
        change_set: CanisterHttpChangeSet,
    ) -> ArtifactTransmits<CanisterHttpResponseArtifact> {
        let changed = !change_set.is_empty();
        let mut transmits = vec![];
        for action in change_set {
            match action {
                CanisterHttpChangeAction::AddToValidatedAndGossipResponse(share, content) => {
                    let artifact = CanisterHttpResponseArtifact {
                        share: share.clone(),
                        response: Some(content.clone()),
                    };
                    transmits.push(ArtifactTransmit::Deliver(ArtifactWithOpt {
                        artifact,
                        is_latency_sensitive: true,
                    }));
                    self.validated.insert(share, ());
                    self.content
                        .insert(ic_types::crypto::crypto_hash(&content), content);
                }
                CanisterHttpChangeAction::AddToValidated(share, content) => {
                    let artifact = CanisterHttpResponseArtifact {
                        share: share.clone(),
                        response: None,
                    };
                    transmits.push(ArtifactTransmit::Deliver(ArtifactWithOpt {
                        artifact,
                        is_latency_sensitive: true,
                    }));
                    self.validated.insert(share, ());
                    self.content
                        .insert(ic_types::crypto::crypto_hash(&content), content);
                }
                CanisterHttpChangeAction::MoveToValidated(share) => {
                    if let Some(artifact) = self.unvalidated.remove(&share) {
                        // If there is a response associated with this share, we want to move it to the `content`
                        // section of the pool, corresponding to valid responses.
                        if let Some(content) = artifact.response {
                            self.content
                                .insert(ic_types::crypto::crypto_hash(&content), content);
                        }
                        self.validated.insert(share, ());
                    }
                }
                CanisterHttpChangeAction::RemoveValidated(id) => {
                    if self.validated.remove(&id).is_some() {
                        transmits.push(ArtifactTransmit::Abort(id));
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
            transmits,
            poll_immediately: changed,
        }
    }
}

impl ValidatedPoolReader<CanisterHttpResponseArtifact> for CanisterHttpPoolImpl {
    fn get(&self, id: &CanisterHttpResponseId) -> Option<CanisterHttpResponseArtifact> {
        // Important: this is actually never used, as Http artifacts are always sent directly (no adverts).
        // If we ever decide to use adverts, we should make the distinction between artifacts with or without a
        // response. We should either:
        //  - only use adverts when gossiping a full response; this way, this should always return the response
        //  - store a flag in the share which says whether the full response needs to be gossiped or not.
        // This is to avoid sending the response in full in the fully replicated case.
        self.validated
            .get(id)
            .map(|()| CanisterHttpResponseArtifact {
                share: id.clone(),
                response: None,
            })
    }
}

impl HasLabel for CanisterHttpResponse {
    fn label(&self) -> &str {
        "canister_http_response"
    }
}

impl HasLabel for CanisterHttpResponseArtifact {
    fn label(&self) -> &str {
        "canister_http_response_artifact"
    }
}

#[cfg(test)]
mod tests {
    use ic_logger::replica_logger::no_op_logger;
    use ic_test_utilities_consensus::fake::FakeSigner;
    use ic_test_utilities_types::ids::node_test_id;
    use ic_types::{
        CanisterId, RegistryVersion, ReplicaVersion,
        artifact::IdentifiableArtifact,
        canister_http::{CanisterHttpResponseContent, CanisterHttpResponseMetadata},
        crypto::{CryptoHash, Signed},
        messages::CallbackId,
        signature::BasicSignature,
        time::UNIX_EPOCH,
    };

    use super::*;

    fn to_unvalidated(
        message: CanisterHttpResponseShare,
    ) -> UnvalidatedArtifact<CanisterHttpResponseArtifact> {
        let artifact = CanisterHttpResponseArtifact {
            share: message,
            response: None,
        };
        UnvalidatedArtifact::<CanisterHttpResponseArtifact> {
            message: artifact,
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
                replica_version: ReplicaVersion::default(),
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

        assert_eq!(share, pool.get_unvalidated_artifact(&id).unwrap().share);

        pool.remove(&id);
        assert!(pool.get_unvalidated_artifact(&id).is_none());
    }

    #[test]
    fn test_canister_http_pool_add_and_remove_validated() {
        let mut pool = CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());
        let share = fake_share(123);
        let id = share.clone();
        let response = fake_response(123);
        let content_hash = ic_types::crypto::crypto_hash(&response);

        let result = pool.apply(vec![
            CanisterHttpChangeAction::AddToValidated(share.clone(), response.clone()),
            CanisterHttpChangeAction::AddToValidated(fake_share(456), fake_response(456)),
        ]);

        assert!(
            matches!(&result.transmits[0], ArtifactTransmit::Deliver(x) if x.artifact.id() == id)
        );
        assert!(matches!(&result.transmits[1], ArtifactTransmit::Deliver(_)));
        assert!(result.poll_immediately);
        assert_eq!(result.transmits.len(), 2);
        assert_eq!(share, pool.lookup_validated(&id).unwrap());
        assert_eq!(share, pool.get(&id).unwrap().share);
        assert_eq!(
            response,
            pool.get_response_content_by_hash(&content_hash).unwrap()
        );

        let result = pool.apply(vec![
            CanisterHttpChangeAction::RemoveValidated(id.clone()),
            CanisterHttpChangeAction::RemoveContent(content_hash.clone()),
        ]);

        assert_eq!(result.transmits.len(), 1);
        assert!(result.poll_immediately);
        assert!(matches!(&result.transmits[0], ArtifactTransmit::Abort(x) if *x == id));
        assert!(pool.lookup_validated(&id).is_none());
        assert!(pool.get_response_content_by_hash(&content_hash).is_none());
        assert_eq!(pool.get_validated_shares().count(), 1);
        assert_eq!(pool.get_response_content_items().count(), 1);
    }

    #[test]
    fn test_canister_http_pool_add_to_validated_and_gossip_response() {
        let mut pool = CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());
        let share = fake_share(123);
        let id = share.clone();
        let response = fake_response(123);
        let content_hash = ic_types::crypto::crypto_hash(&response);

        let result = pool.apply(vec![
            CanisterHttpChangeAction::AddToValidatedAndGossipResponse(
                share.clone(),
                response.clone(),
            ),
        ]);

        let expected_artifact = CanisterHttpResponseArtifact {
            share: share.clone(),
            response: Some(response.clone()),
        };

        assert!(
            matches!(&result.transmits[0], ArtifactTransmit::Deliver(x) if x.artifact == expected_artifact)
        );
        assert!(result.poll_immediately);
        assert_eq!(result.transmits.len(), 1);
        assert_eq!(share, pool.lookup_validated(&id).unwrap());
        assert_eq!(share, pool.get(&id).unwrap().share);
        assert_eq!(
            response,
            pool.get_response_content_by_hash(&content_hash).unwrap()
        );
    }

    #[test]
    fn test_canister_http_pool_move_to_validated() {
        let mut pool = CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());
        let share1 = fake_share(123);
        let id1 = share1.clone();
        let share2 = fake_share(456);
        let id2 = share2.clone();

        pool.insert(to_unvalidated(share1.clone()));

        let result = pool.apply(vec![
            CanisterHttpChangeAction::MoveToValidated(share2.clone()),
            CanisterHttpChangeAction::MoveToValidated(share1.clone()),
        ]);

        assert!(pool.lookup_validated(&id2).is_none());
        assert!(result.poll_immediately);
        assert!(
            !result
                .transmits
                .iter()
                .any(|x| matches!(x, ArtifactTransmit::Abort(_)))
        );
        assert_eq!(share1, pool.lookup_validated(&id1).unwrap());
    }

    #[test]
    fn test_canister_http_pool_remove_unvalidated() {
        let mut pool = CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());
        let share = fake_share(123);
        let id = share.clone();

        pool.insert(to_unvalidated(share.clone()));
        assert_eq!(share, pool.get_unvalidated_artifact(&id).unwrap().share);

        let result = pool.apply(vec![CanisterHttpChangeAction::RemoveUnvalidated(
            id.clone(),
        )]);

        assert!(pool.get_unvalidated_artifact(&id).is_none());
        assert!(result.poll_immediately);
        assert!(result.transmits.is_empty());
    }

    #[test]
    fn test_canister_http_pool_handle_invalid() {
        let mut pool = CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());
        let share = fake_share(123);
        let id = share.clone();

        pool.insert(to_unvalidated(share.clone()));
        assert_eq!(share, pool.get_unvalidated_artifact(&id).unwrap().share);

        let result = pool.apply(vec![CanisterHttpChangeAction::HandleInvalid(
            id.clone(),
            "TEST REASON".to_string(),
        )]);

        assert!(pool.get_unvalidated_artifact(&id).is_none());
        assert!(result.poll_immediately);
        assert!(result.transmits.is_empty());
    }
}
