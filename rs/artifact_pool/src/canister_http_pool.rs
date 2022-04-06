//! Canister Http Artifact Pool implementation.

// TODO: Remove
#![allow(dead_code)]
use crate::{
    metrics::{POOL_TYPE_UNVALIDATED, POOL_TYPE_VALIDATED},
    pool_common::PoolSection,
};
use ic_interfaces::{
    artifact_pool::{UnvalidatedArtifact, ValidatedArtifact},
    canister_http::{
        CanisterHttpChangeAction, CanisterHttpChangeSet, CanisterHttpPool, MutableCanisterHttpPool,
    },
    gossip_pool::{CanisterHttpGossipPool, GossipPool},
};
use ic_metrics::MetricsRegistry;
use ic_types::{
    artifact::CanisterHttpResponseId,
    canister_http::{CanisterHttpResponseContent, CanisterHttpResponseShare},
    crypto::CryptoHashOf,
    time::current_time,
};

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
    PoolSection<CryptoHashOf<CanisterHttpResponseContent>, CanisterHttpResponseContent>;

pub struct CanisterHttpPoolImpl {
    validated: ValidatedCanisterHttpPoolSection,
    unvalidated: UnvalidatedCanisterHttpPoolSection,
    content: ContentCanisterHttpPoolSection,
}

impl CanisterHttpPoolImpl {
    pub fn new(metrics: MetricsRegistry) -> Self {
        Self {
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
    ) -> Box<
        dyn Iterator<
                Item = (
                    &CryptoHashOf<CanisterHttpResponseContent>,
                    &CanisterHttpResponseContent,
                ),
            > + '_,
    > {
        Box::new(self.content.iter())
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

impl MutableCanisterHttpPool for CanisterHttpPoolImpl {
    fn insert(&mut self, artifact: UnvalidatedArtifact<CanisterHttpResponseShare>) {
        self.unvalidated
            .insert(ic_crypto::crypto_hash(&artifact.message), artifact);
    }

    fn apply_changes(&mut self, change_set: CanisterHttpChangeSet) {
        for action in change_set {
            match action {
                CanisterHttpChangeAction::AddToValidated(share, content) => {
                    self.validated.insert(
                        ic_crypto::crypto_hash(&share),
                        ValidatedArtifact {
                            msg: share,
                            timestamp: current_time(),
                        },
                    );
                    self.content
                        .insert(ic_crypto::crypto_hash(&content), content);
                }
                CanisterHttpChangeAction::MoveToValidated(id) => {
                    match self.unvalidated.remove(&id) {
                        None => (),
                        Some(value) => {
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
                    self.validated.remove(&id);
                }

                CanisterHttpChangeAction::RemoveUnvalidated(id) => {
                    self.unvalidated.remove(&id);
                }
                CanisterHttpChangeAction::HandleInvalid(id, _) => {
                    self.unvalidated.remove(&id);
                }
            }
        }
    }
}

impl GossipPool<CanisterHttpResponseShare, CanisterHttpChangeSet> for CanisterHttpPoolImpl {
    type MessageId = CanisterHttpResponseId;
    type Filter = ();

    fn contains(&self, id: &Self::MessageId) -> bool {
        self.unvalidated.contains_key(id) || self.validated.contains_key(id)
    }

    fn get_validated_by_identifier(
        &self,
        id: &Self::MessageId,
    ) -> Option<CanisterHttpResponseShare> {
        self.validated
            .get(id)
            .map(|artifact| (&artifact.msg))
            .cloned()
    }

    fn get_all_validated_by_filter(
        &self,
        _filter: Self::Filter,
    ) -> Box<dyn Iterator<Item = CanisterHttpResponseShare> + '_> {
        unimplemented!()
    }
}

impl CanisterHttpGossipPool for CanisterHttpPoolImpl {}

// TODO: Tests
