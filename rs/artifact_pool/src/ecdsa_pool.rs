//! ECDSA artifact pool implementation.

use crate::metrics::{PoolMetrics, POOL_TYPE_UNVALIDATED, POOL_TYPE_VALIDATED};
use ic_crypto::crypto_hash;
use ic_interfaces::artifact_pool::{UnvalidatedArtifact, ValidatedArtifact};
use ic_interfaces::ecdsa::{EcdsaChangeAction, EcdsaChangeSet, EcdsaPool, MutableEcdsaPool};
use ic_interfaces::gossip_pool::{EcdsaGossipPool, GossipPool};
use ic_metrics::MetricsRegistry;
use ic_types::consensus::ecdsa::EcdsaMessage;
use ic_types::crypto::CryptoHashOf;
use ic_types::time::current_time;

use std::collections::BTreeMap;

const POOL_ECDSA: &str = "ecdsa";

/// Workaround for `EcdsaMessage` not implementing `CountBytes`.
#[allow(dead_code)]
const MESSAGE_SIZE_BYTES: usize = 0;

struct EcdsaPoolImpl {
    validated: PoolSection<CryptoHashOf<EcdsaMessage>, ValidatedArtifact<EcdsaMessage>>,
    unvalidated: PoolSection<CryptoHashOf<EcdsaMessage>, UnvalidatedArtifact<EcdsaMessage>>,
}

impl EcdsaPoolImpl {
    #[allow(dead_code)]
    pub fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            validated: PoolSection::new(metrics_registry.clone(), POOL_ECDSA, POOL_TYPE_VALIDATED),
            unvalidated: PoolSection::new(metrics_registry, POOL_ECDSA, POOL_TYPE_UNVALIDATED),
        }
    }
}

impl EcdsaPool for EcdsaPoolImpl {
    fn get_validated(&self) -> Box<dyn Iterator<Item = &EcdsaMessage> + '_> {
        Box::new(self.validated.values().map(|artifact| artifact.as_ref()))
    }
}

impl MutableEcdsaPool for EcdsaPoolImpl {
    fn insert(&mut self, artifact: UnvalidatedArtifact<EcdsaMessage>) {
        self.unvalidated
            .insert(ic_crypto::crypto_hash(&artifact.message), artifact);
    }

    fn apply_changes(&mut self, change_set: EcdsaChangeSet) {
        for action in change_set {
            match action {
                EcdsaChangeAction::HandleInvalid(hash) => {
                    self.unvalidated.remove(&hash);
                }
                EcdsaChangeAction::AddToValidated(message) => {
                    self.validated.insert(
                        ic_crypto::crypto_hash(&message),
                        ValidatedArtifact {
                            msg: message,
                            timestamp: current_time(),
                        },
                    );
                }
                EcdsaChangeAction::MoveToValidated(message) => {
                    let hash = crypto_hash(&message);
                    self.unvalidated
                        .remove(&hash)
                        .expect("Unvalidated artifact was not found.");
                    self.validated.insert(
                        hash,
                        ValidatedArtifact {
                            msg: message,
                            timestamp: current_time(),
                        },
                    );
                }
            }
        }
    }
}

impl GossipPool<EcdsaMessage, EcdsaChangeSet> for EcdsaPoolImpl {
    type MessageId = CryptoHashOf<EcdsaMessage>;
    type Filter = ();

    fn contains(&self, hash: &Self::MessageId) -> bool {
        self.unvalidated.contains_key(hash) || self.validated.contains_key(hash)
    }

    fn get_validated_by_identifier(&self, id: &Self::MessageId) -> Option<EcdsaMessage> {
        self.validated
            .get(id)
            .map(|artifact| artifact.as_ref())
            .cloned()
    }

    fn get_all_validated_by_filter(
        &self,
        _filter: Self::Filter,
    ) -> Box<dyn Iterator<Item = EcdsaMessage>> {
        unimplemented!()
    }
}

impl EcdsaGossipPool for EcdsaPoolImpl {}

/// Validated/unvalidated sections.
struct PoolSection<K, V> {
    messages: BTreeMap<K, V>,
    metrics: PoolMetrics,
}

impl<K: Ord, V> PoolSection<K, V> {
    #[allow(dead_code)]
    fn new(metrics_registry: MetricsRegistry, pool: &str, pool_type: &str) -> Self {
        Self {
            messages: Default::default(),
            metrics: PoolMetrics::new(metrics_registry, pool, pool_type),
        }
    }

    fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.metrics.observe_insert(MESSAGE_SIZE_BYTES);
        let replaced = self.messages.insert(key, value);
        if replaced.is_some() {
            self.metrics.observe_remove(MESSAGE_SIZE_BYTES);
        }
        replaced
    }

    fn remove(&mut self, key: &K) -> Option<V> {
        let removed = self.messages.remove(key);
        if removed.is_some() {
            self.metrics.observe_remove(MESSAGE_SIZE_BYTES);
        }
        removed
    }

    fn get(&self, key: &K) -> Option<&V> {
        self.messages.get(key)
    }

    fn contains_key(&self, key: &K) -> bool {
        self.messages.contains_key(key)
    }

    fn values(&self) -> std::collections::btree_map::Values<'_, K, V> {
        self.messages.values()
    }
}
