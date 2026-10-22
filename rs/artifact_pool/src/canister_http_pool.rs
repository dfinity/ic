//! Canister Http Artifact Pool implementation.

use crate::{
    metrics::{POOL_TYPE_UNVALIDATED, POOL_TYPE_VALIDATED},
    pool_common::{HasLabel, PoolSection},
};
use ic_interfaces::{
    canister_http::{
        CanisterHttpChangeAction, CanisterHttpChangeSet, CanisterHttpPool, ResponseVisibility,
    },
    p2p::consensus::{
        ArtifactTransmit, ArtifactTransmits, ArtifactWithOpt, MutablePool, UnvalidatedArtifact,
        ValidatedPoolReader,
    },
};
use ic_logger::{ReplicaLogger, info, warn};
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

type ValidatedCanisterHttpPoolSection = PoolSection<CanisterHttpResponseShare, ResponseVisibility>;

type UnvalidatedCanisterHttpPoolSection =
    PoolSection<CanisterHttpResponseShare, CanisterHttpResponseArtifact>;

type ContentCanisterHttpPoolSection =
    PoolSection<CryptoHashOf<CanisterHttpResponse>, CanisterHttpResponse>;

impl HasLabel for ResponseVisibility {
    fn label(&self) -> &str {
        "response_visibility"
    }
}

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
    ) -> Option<&CanisterHttpResponse> {
        self.content.get(hash)
    }

    fn lookup_validated(
        &self,
        share: &CanisterHttpResponseShare,
    ) -> Option<CanisterHttpResponseShare> {
        self.validated.get(share).map(|_| share.clone())
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
                CanisterHttpChangeAction::AddToValidated(share, content, visibility) => {
                    // Only a published response is gossiped along with the share.
                    let response = match visibility {
                        ResponseVisibility::Publish => Some(content.clone()),
                        ResponseVisibility::Withhold => None,
                    };
                    let artifact = CanisterHttpResponseArtifact {
                        share: share.clone(),
                        response,
                    };
                    transmits.push(ArtifactTransmit::Deliver(ArtifactWithOpt {
                        artifact,
                        is_latency_sensitive: true,
                    }));
                    self.validated.insert(share, visibility);
                    self.content
                        .insert(ic_types::crypto::crypto_hash(&content), content);
                }
                CanisterHttpChangeAction::MoveToValidated(share, visibility) => {
                    if let Some(artifact) = self.unvalidated.remove(&share) {
                        if let Some(content) = artifact.response {
                            self.content
                                .insert(ic_types::crypto::crypto_hash(&content), content);
                        }
                        self.validated.insert(share, visibility);
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
        // Important: this may be called by a peer that *pulls* a validated artifact,
        // if the corresponding advert was previously stashed by the peer's bouncer.
        let response = match self.validated.get(id)? {
            ResponseVisibility::Publish => {
                let content = self.content.get(id.content.content_hash()).cloned();
                if content.is_none() {
                    // The response of an outcall that has been answered is of no use to
                    // anyone, so it may have been dropped while the share is still around
                    // as a receipt. Serve the share on its own: a peer accepts a share
                    // without a response once it sees the outcall as answered too, and
                    // holds it back until it does.
                    info!(
                        every_n_seconds => 30,
                        self.log,
                        "Validated share {:?} has no response content in the pool; \
                         serving the share on its own.",
                        id.content.id()
                    );
                }
                content
            }
            ResponseVisibility::Withhold => None,
        };
        Some(CanisterHttpResponseArtifact {
            share: id.clone(),
            response,
        })
    }

    fn get_all_for_initial_broadcast(
        &self,
    ) -> Box<dyn Iterator<Item = CanisterHttpResponseArtifact> + '_> {
        // HTTP outcalls artifacts are not persisted.
        Box::new(std::iter::empty())
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
        artifact::IdentifiableArtifact,
        canister_http::{
            CanisterHttpPaymentReceipt, CanisterHttpResponseContent, CanisterHttpResponseMetadata,
            CanisterHttpResponseReceipt,
        },
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
            content: CanisterHttpResponseReceipt {
                metadata: CanisterHttpResponseMetadata {
                    id: CallbackId::from(id),
                    content_hash: CryptoHashOf::from(CryptoHash(vec![1, 2, 3])),
                    content_size: 42,
                    is_reject: false,
                    replica_version: ic_test_utilities_types::ids::test_replica_version(),
                },
                payment_receipt: CanisterHttpPaymentReceipt::default(),
            },
            signature: BasicSignature::fake(node_test_id(id)),
        }
    }

    fn fake_response(id: u64) -> CanisterHttpResponse {
        CanisterHttpResponse {
            id: CallbackId::from(id),
            content: CanisterHttpResponseContent::Success(Vec::new()),
        }
    }

    /// Like [`fake_share`], but with a `content_hash` that matches `response`.
    fn fake_share_matching(id: u64, response: &CanisterHttpResponse) -> CanisterHttpResponseShare {
        Signed {
            content: CanisterHttpResponseReceipt {
                metadata: CanisterHttpResponseMetadata {
                    id: CallbackId::from(id),
                    content_hash: ic_types::crypto::crypto_hash(response),
                    content_size: 42,
                    is_reject: false,
                    replica_version: ic_test_utilities_types::ids::test_replica_version(),
                },
                payment_receipt: CanisterHttpPaymentReceipt::default(),
            },
            signature: BasicSignature::fake(node_test_id(id)),
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
            CanisterHttpChangeAction::AddToValidated(
                share.clone(),
                response.clone(),
                ResponseVisibility::Withhold,
            ),
            CanisterHttpChangeAction::AddToValidated(
                fake_share(456),
                fake_response(456),
                ResponseVisibility::Withhold,
            ),
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
            &response,
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
        let response = fake_response(123);
        let share = fake_share_matching(123, &response);
        let id = share.clone();
        let content_hash = ic_types::crypto::crypto_hash(&response);

        let result = pool.apply(vec![CanisterHttpChangeAction::AddToValidated(
            share.clone(),
            response.clone(),
            ResponseVisibility::Publish,
        )]);

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
        // A pulled non-fully-replicated artifact carries the full response.
        assert_eq!(pool.get(&id).unwrap(), expected_artifact);
        assert_eq!(
            &response,
            pool.get_response_content_by_hash(&content_hash).unwrap()
        );
    }

    #[test]
    fn test_canister_http_pool_add_to_validated_withholding_the_response() {
        let mut pool = CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());
        let response = fake_response(123);
        let share = fake_share_matching(123, &response);
        let id = share.clone();
        let content_hash = ic_types::crypto::crypto_hash(&response);

        let result = pool.apply(vec![CanisterHttpChangeAction::AddToValidated(
            share.clone(),
            response.clone(),
            ResponseVisibility::Withhold,
        )]);

        let expected_artifact = CanisterHttpResponseArtifact {
            share: share.clone(),
            response: None,
        };

        // Only the share is gossiped, ...
        assert!(
            matches!(&result.transmits[0], ArtifactTransmit::Deliver(x) if x.artifact == expected_artifact)
        );
        assert!(result.poll_immediately);
        assert_eq!(result.transmits.len(), 1);
        assert_eq!(share, pool.lookup_validated(&id).unwrap());
        // ... and it is not served to a peer that pulls the artifact either.
        assert_eq!(pool.get(&id).unwrap(), expected_artifact);
        // The response is still retained, until the purge pass drops it.
        assert_eq!(
            pool.get_response_content_by_hash(&content_hash),
            Some(&response)
        );
    }

    /// A peer that *pulls* a validated artifact (via
    /// [`ValidatedPoolReader::get`]) must receive the full response for
    /// non-fully-replicated requests that are still awaiting one, and must not
    /// receive one for fully replicated requests, nor for requests that have
    /// already been responded to. It always receives the share itself, even where
    /// the response it was gossiped with is no longer in the pool.
    #[test]
    fn test_get_serves_response_only_for_non_fully_replicated_shares() {
        let mut pool = CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());

        // Non-fully-replicated, locally produced: response is served on pull.
        let response = fake_response(1);
        let share = fake_share_matching(1, &response);
        let id = share.clone();
        pool.apply(vec![CanisterHttpChangeAction::AddToValidated(
            share.clone(),
            response.clone(),
            ResponseVisibility::Publish,
        )]);
        assert_eq!(pool.get(&id).unwrap().response, Some(response));

        // Fully replicated, locally produced: response is not served on pull.
        let response = fake_response(2);
        let share = fake_share_matching(2, &response);
        let id = share.clone();
        pool.apply(vec![CanisterHttpChangeAction::AddToValidated(
            share.clone(),
            response.clone(),
            ResponseVisibility::Withhold,
        )]);
        assert!(pool.get(&id).unwrap().response.is_none());

        // Non-fully-replicated, received from a peer (MoveToValidated with a
        // response present): response is served on pull.
        let response = fake_response(3);
        let share = fake_share_matching(3, &response);
        let id = share.clone();
        pool.insert(UnvalidatedArtifact {
            message: CanisterHttpResponseArtifact {
                share: share.clone(),
                response: Some(response.clone()),
            },
            peer_id: node_test_id(0),
            timestamp: UNIX_EPOCH,
        });
        pool.apply(vec![CanisterHttpChangeAction::MoveToValidated(
            share.clone(),
            ResponseVisibility::Publish,
        )]);
        assert_eq!(pool.get(&id).unwrap().response, Some(response));

        // Fully replicated, received from a peer (MoveToValidated without a
        // response): response is not served on pull.
        let share = fake_share(4);
        let id = share.clone();
        pool.insert(to_unvalidated(share.clone()));
        pool.apply(vec![CanisterHttpChangeAction::MoveToValidated(
            share.clone(),
            ResponseVisibility::Publish,
        )]);
        assert!(pool.get(&id).unwrap().response.is_none());

        // Non-fully-replicated share whose response content is missing: the share is
        // served on its own, rather than nothing at all. A peer accepts a share without
        // a response once it sees the outcall as answered, and holds it back until it
        // does, so serving the receipt is of use to it where serving nothing is not.
        let response = fake_response(5);
        let share = fake_share_matching(5, &response);
        let id = share.clone();
        let content_hash = ic_types::crypto::crypto_hash(&response);
        pool.apply(vec![CanisterHttpChangeAction::AddToValidated(
            share.clone(),
            response.clone(),
            ResponseVisibility::Publish,
        )]);
        assert!(pool.get(&id).unwrap().response.is_some());
        pool.apply(vec![CanisterHttpChangeAction::RemoveContent(content_hash)]);
        assert_eq!(
            pool.get(&id),
            Some(CanisterHttpResponseArtifact {
                share: share.clone(),
                response: None,
            })
        );

        // Already responded to, locally produced (a receipt-only share): no
        // response is served on pull, as none was retained.
        let share = fake_share(6);
        let id = share.clone();
        pool.apply(vec![CanisterHttpChangeAction::AddToValidated(
            share.clone(),
            fake_response(6),
            ResponseVisibility::Withhold,
        )]);
        assert!(pool.get(&id).unwrap().response.is_none());

        // Already responded to, received from a peer that still attached a response:
        // the response is not served on pull, even though it is still in the pool.
        let response = fake_response(7);
        let share = fake_share_matching(7, &response);
        let id = share.clone();
        let content_hash = ic_types::crypto::crypto_hash(&response);
        pool.insert(UnvalidatedArtifact {
            message: CanisterHttpResponseArtifact {
                share: share.clone(),
                response: Some(response.clone()),
            },
            peer_id: node_test_id(0),
            timestamp: UNIX_EPOCH,
        });
        pool.apply(vec![CanisterHttpChangeAction::MoveToValidated(
            share.clone(),
            ResponseVisibility::Withhold,
        )]);
        assert!(pool.get(&id).unwrap().response.is_none());
        assert_eq!(
            pool.get_response_content_by_hash(&content_hash),
            Some(&response)
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
            CanisterHttpChangeAction::MoveToValidated(share2.clone(), ResponseVisibility::Publish),
            CanisterHttpChangeAction::MoveToValidated(share1.clone(), ResponseVisibility::Publish),
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
