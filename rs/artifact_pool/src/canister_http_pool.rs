//! Canister Http Artifact Pool implementation.

// TODO: Remove
#![allow(dead_code)]
use crate::{
    metrics::{POOL_TYPE_UNVALIDATED, POOL_TYPE_VALIDATED},
    pool_common::PoolSection,
};
use ic_interfaces::{
    artifact_pool::{
        ChangeResult, MutablePool, UnvalidatedArtifact, ValidatedArtifact, ValidatedPoolReader,
    },
    canister_http::{CanisterHttpChangeAction, CanisterHttpChangeSet, CanisterHttpPool},
    time_source::TimeSource,
};
use ic_logger::{warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_types::{
    artifact::{ArtifactKind, CanisterHttpResponseId},
    artifact_kind::CanisterHttpArtifact,
    canister_http::{CanisterHttpResponse, CanisterHttpResponseShare},
    crypto::CryptoHashOf,
    time::current_time,
};
use prometheus::IntCounter;

const POOL_CANISTER_HTTP: &str = "canister_http";
const POOL_CANISTER_HTTP_CONTENT: &str = "canister_http_content";

type ValidatedCanisterHttpPoolSection = PoolSection<
    CryptoHashOf<CanisterHttpResponseShare>,
    ValidatedArtifact<CanisterHttpResponseShare>,
>;

type UnvalidatedCanisterHttpPoolSection = PoolSection<
    CryptoHashOf<CanisterHttpResponseShare>,
    UnvalidatedArtifact<CanisterHttpResponseShare>,
>;

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
        Box::new(self.validated.values().map(|artifact| &artifact.msg))
    }

    fn get_unvalidated_shares(&self) -> Box<dyn Iterator<Item = &CanisterHttpResponseShare> + '_> {
        Box::new(self.unvalidated.values().map(|artifact| &artifact.message))
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
        self.validated.get(msg_id).map(|s| s.msg.clone())
    }

    fn lookup_unvalidated(
        &self,
        msg_id: &CanisterHttpResponseId,
    ) -> Option<CanisterHttpResponseShare> {
        self.unvalidated.get(msg_id).map(|s| s.message.clone())
    }
}

impl MutablePool<CanisterHttpArtifact, CanisterHttpChangeSet> for CanisterHttpPoolImpl {
    fn insert(&mut self, artifact: UnvalidatedArtifact<CanisterHttpResponseShare>) {
        self.unvalidated
            .insert(ic_types::crypto::crypto_hash(&artifact.message), artifact);
    }

    fn apply_changes(
        &mut self,
        _time_source: &dyn TimeSource,
        change_set: CanisterHttpChangeSet,
    ) -> ChangeResult<CanisterHttpArtifact> {
        let changed = !change_set.is_empty();
        let mut adverts = Vec::new();
        let mut purged = Vec::new();
        for action in change_set {
            match action {
                CanisterHttpChangeAction::AddToValidated(share, content) => {
                    adverts.push(CanisterHttpArtifact::message_to_advert(&share));
                    self.validated.insert(
                        ic_types::crypto::crypto_hash(&share),
                        ValidatedArtifact {
                            msg: share,
                            timestamp: current_time(),
                        },
                    );
                    self.content
                        .insert(ic_types::crypto::crypto_hash(&content), content);
                }
                CanisterHttpChangeAction::MoveToValidated(share) => {
                    let id = ic_types::crypto::crypto_hash(&share);
                    match self.unvalidated.remove(&id) {
                        None => (),
                        Some(value) => {
                            adverts.push(CanisterHttpArtifact::message_to_advert(&share));
                            self.validated.insert(
                                id,
                                ValidatedArtifact {
                                    msg: value.message,
                                    timestamp: current_time(),
                                },
                            );
                        }
                    }
                }
                CanisterHttpChangeAction::RemoveValidated(id) => {
                    if self.validated.remove(&id).is_some() {
                        purged.push(id);
                    }
                }

                CanisterHttpChangeAction::RemoveUnvalidated(id) => {
                    self.unvalidated.remove(&id);
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
                    self.unvalidated.remove(&id);
                }
            }
        }
        ChangeResult {
            purged,
            adverts,
            changed,
        }
    }
}

impl ValidatedPoolReader<CanisterHttpArtifact> for CanisterHttpPoolImpl {
    fn contains(&self, id: &CanisterHttpResponseId) -> bool {
        self.unvalidated.contains_key(id) || self.validated.contains_key(id)
    }

    fn get_validated_by_identifier(
        &self,
        id: &CanisterHttpResponseId,
    ) -> Option<CanisterHttpResponseShare> {
        self.validated
            .get(id)
            .map(|artifact| (&artifact.msg))
            .cloned()
    }

    fn get_all_validated_by_filter(
        &self,
        _filter: &(),
    ) -> Box<dyn Iterator<Item = CanisterHttpResponseShare> + '_> {
        unimplemented!()
    }
}

// TODO: Tests
