use crate::{
    consensus::{
        batch_delivery::deliver_batches,
        block_maker::subnet_records_for_registry_version,
        metrics::{BatchStats, BlockStats},
    },
    dkg::make_registry_cup,
};
use ic_consensus_utils::{
    active_high_threshold_nidkg_id, aggregate, crypto::ConsensusCrypto, membership::Membership,
    pool_reader::PoolReader,
};
use ic_interfaces::{
    certification::CertificationPool,
    consensus_pool::{ChangeAction, Mutations, ValidatedArtifact},
    crypto::{ErrorReproducibility, NiDkgAlgorithm},
    ingress_manager::IngressSelector,
    messaging::{MessageRouting, MessageRoutingError},
    time_source::TimeSource,
    validation::ValidationError,
};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::{StateHashError, StateManager};
use ic_logger::{debug, error, info, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    consensus::{
        hashed, CatchUpContent, CatchUpPackage, CatchUpPackageShare, CatchUpShareContent,
        ConsensusMessage, ConsensusMessageHashable, FinalizationContent, FinalizationShare,
        HasCommittee, HasHeight, HashedBlock, HashedRandomBeacon, Rank,
    },
    crypto::{threshold_sig::ni_dkg::NiDkgTag, Signed},
    replica_config::ReplicaConfig,
    Height, ReplicaVersion,
};
use std::sync::{Arc, RwLock};

use super::block_maker::BlockMaker;

pub struct Recovery {
    pub(crate) replica_config: ReplicaConfig,
    registry_client: Arc<dyn RegistryClient>,
    membership: Arc<Membership>,
    pub(crate) crypto: Arc<dyn ConsensusCrypto>,
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    certification_pool: Arc<RwLock<dyn CertificationPool>>,
    message_routing: Arc<dyn MessageRouting>,
    ingress_selector: Arc<dyn IngressSelector>,
    block_maker: BlockMaker,
    time_source: Arc<dyn TimeSource>,
    pub(crate) log: ReplicaLogger,
}

impl Recovery {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        replica_config: ReplicaConfig,
        registry_client: Arc<dyn RegistryClient>,
        membership: Arc<Membership>,
        crypto: Arc<dyn ConsensusCrypto>,
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        certification_pool: Arc<RwLock<dyn CertificationPool>>,
        message_routing: Arc<dyn MessageRouting>,
        ingress_selector: Arc<dyn IngressSelector>,
        block_maker: BlockMaker,
        time_source: Arc<dyn TimeSource>,
        log: ReplicaLogger,
        _metrics_registry: MetricsRegistry,
    ) -> Self {
        Self {
            replica_config,
            registry_client,
            membership,
            crypto,
            state_manager,
            certification_pool,
            message_routing,
            ingress_selector,
            block_maker,
            time_source,
            log,
        }
    }

    /// Attempt to:
    /// * deliver finalized blocks (as `Batch`s) via `Messaging`
    pub fn on_state_change(&self, pool: &PoolReader<'_>) -> Mutations {
        let Some(mut registry_cup) = make_registry_cup(
            self.registry_client.as_ref(),
            self.replica_config.subnet_id,
            &self.log,
        ) else {
            return Mutations::new();
        };

        if registry_cup.height() <= pool.get_finalized_height() {
            return Mutations::new();
        }

        if !registry_cup.content.state_hash.get_ref().0.is_empty() {
            return Mutations::new();
        }

        let max_height = if let Ok(pool) = self.certification_pool.read() {
            if let Some(height) = pool.max_certified_height() {
                height
            } else {
                return Mutations::new();
            }
        } else {
            return Mutations::new();
        };

        let cup_height = pool.get_catch_up_height();
        if cup_height >= max_height {
            info!(
                every_n_seconds => 5,
                self.log,
                "Found CUP at height {}!", cup_height
            );
            return Mutations::new();
        }

        info!(
            every_n_seconds => 5,
            self.log,
            "Starting recovery at certified height {}", max_height
        );

        // Try to deliver finalized batches to messaging
        let _ = deliver_batches(
            &*self.message_routing,
            &self.membership,
            pool,
            &*self.registry_client,
            self.replica_config.subnet_id,
            ReplicaVersion::default(),
            &self.log,
            Some(max_height),
            Some(&|result, block_stats, batch_stats| {
                self.process_batch_delivery_result(result, block_stats, batch_stats)
            }),
        );

        let state_hash = match self.state_manager.get_state_hash_at(max_height) {
            Ok(hash) => hash,
            Err(StateHashError::Transient(_)) => return Mutations::new(),
            Err(StateHashError::Permanent(err)) => {
                warn!(
                    every_n_seconds => 5,
                    self.log,
                    "Permanent state hash error at height {}: {:?}", max_height, err
                );
                panic!("Delivered batches past the latest certified height during recovery. Restarting replica ...");
            }
        };

        info!(
            every_n_seconds => 5,
            self.log,
            "Created state hash at height {}: {:?}", max_height, state_hash
        );

        let Some(parent) = pool.get_finalized_block(max_height) else {
            error!(self.log, "Couldn't find finalized block.");
            return Mutations::new();
        };
        let parent = hashed::Hashed::new(ic_types::crypto::crypto_hash, parent);
        let mut context = registry_cup.content.block.get_value().context.clone();
        context.certified_height = max_height;
        let registry_version = context.registry_version;
        let Some(pool_registry_version) = pool.registry_version(max_height) else {
            error!(self.log, "Couldn't find registry version.");
            return Mutations::new();
        };
        let Some(subnet_records) = subnet_records_for_registry_version(
            &self.block_maker,
            pool_registry_version,
            registry_version,
        ) else {
            error!(self.log, "Couldn't create subnet records.");
            return Mutations::new();
        };

        let Some(summary) = self.block_maker.construct_block(
            pool,
            context,
            parent,
            registry_cup.height(),
            max_height,
            Rank(0),
            &subnet_records,
            true,
        ) else {
            error!(self.log, "Couldn't create a summary.");
            return Mutations::new();
        };

        let content = CatchUpContent::new(
            summary,
            registry_cup.content.random_beacon.clone(),
            state_hash,
            None, //TODO; use correct value
        );
        let cup_share_content = CatchUpShareContent::from(&content);

        let dkg = &content.block.get_value().payload.as_ref().as_summary().dkg;
        let high_transcript = dkg.current_transcript(&NiDkgTag::HighThreshold);
        let low_transcript = dkg.current_transcript(&NiDkgTag::LowThreshold);
        let dkg_id = high_transcript.dkg_id;

        match NiDkgAlgorithm::load_transcript(&*self.crypto, high_transcript) {
            Ok(s) => info!(
                every_n_seconds => 5,
                self.log,
                "High threshold transcript loaded successfully: {:?}", s
            ),
            Err(e) => warn!(
                every_n_seconds => 5,
                self.log,
                "High threshold transcript loaded unsuccessfully: {:?}", e
            ),
        }
        match NiDkgAlgorithm::load_transcript(&*self.crypto, low_transcript) {
            Ok(s) => info!(
                every_n_seconds => 5,
                self.log,
                "Low threshold transcript loaded successfully: {:?}", s
            ),
            Err(e) => warn!(
                every_n_seconds => 5,
                self.log,
                "Low threshold transcript loaded unsuccessfully: {:?}", e
            ),
        }

        let share = match self
            .crypto
            .sign(&content, self.replica_config.node_id, dkg_id)
        {
            Ok(signature) => CatchUpPackageShare {
                content: cup_share_content.clone(),
                signature,
            },
            Err(err) => {
                error!(self.log, "Couldn't create a signature: {:?}", err);
                return Mutations::new();
            }
        };

        let mut mutations = Mutations::new();

        if !pool
            .get_catch_up_package_shares(share.height())
            .any(|share| share.signature.signer == self.replica_config.node_id)
        {
            info!(self.log, "Broadcasting CUP share!");
            mutations.push(ChangeAction::AddToValidated(ValidatedArtifact {
                msg: ConsensusMessage::CatchUpPackageShare(share),
                timestamp: self.time_source.get_relative_time(),
            }));
        }

        let shares = pool
            .pool()
            .unvalidated()
            .catch_up_package_share()
            .get_by_height(registry_cup.height());

        let mut x = shares
            .filter_map(|share| {
                if !share.check_integrity() {
                    info!(self.log, "CUP share integrity check failed!",);
                    return Some(ChangeAction::HandleInvalid(
                        share.into_message(),
                        "CatchUpPackageShare integrity check failed".to_string(),
                    ));
                }
                if share.content != cup_share_content {
                    info!(self.log, "CUP share content check failed!",);
                    return Some(ChangeAction::HandleInvalid(
                        share.into_message(),
                        "CatchUpPackageShare content check failed".to_string(),
                    ));
                }

                if high_transcript
                    .committee
                    .position(share.signature.signer)
                    .is_none()
                {
                    info!(self.log, "CUP share membership check failed");
                    return Some(ChangeAction::HandleInvalid(
                        share.into_message(),
                        "CatchUpPackageShare committee check failed".to_string(),
                    ));
                }

                match self.crypto.verify(
                    &Signed {
                        content: CatchUpContent::from_share_content(
                            share.content.clone(),
                            content.block.get_value().clone(),
                        ),
                        signature: share.signature.clone(),
                    },
                    dkg_id,
                ) {
                    Ok(()) => Some(ChangeAction::MoveToValidated(share.into_message())),
                    Err(e) => {
                        info!(
                            every_n_seconds => 5,
                            self.log,
                            "CUP share signature check failed: {:?}", e
                        );
                        if e.is_reproducible() {
                            Some(ChangeAction::HandleInvalid(
                                share.into_message(),
                                format!("{:?}", e),
                            ))
                        } else {
                            None
                        }
                    }
                }
            })
            .collect::<Vec<_>>();

        if x.len() > 0 {
            info!(self.log, "Verified {} CUP shares!", x.len());
        }

        mutations.append(&mut x);

        let shares = pool
            .get_catch_up_package_shares(registry_cup.height())
            .map(|share| Signed {
                content: CatchUpContent::from_share_content(
                    share.content,
                    content.block.get_value().clone(),
                ),
                signature: share.signature,
            })
            .collect::<Vec<_>>();

        info!(
            every_n_seconds => 5,
            self.log,
            "Aggregating {} shares", shares.len()
        );

        let result = aggregate(
            &self.log,
            self.membership.as_ref(),
            self.crypto.as_aggregate(),
            Box::new(|_| Some(dkg_id)),
            shares.into_iter(),
        );
        mutations.extend(result.into_iter().map(|cup| {
            info!(self.log, "Aggregated full CUP!");
            ChangeAction::AddToValidated(ValidatedArtifact {
                msg: ConsensusMessage::CatchUpPackage(cup),
                timestamp: self.time_source.get_relative_time(),
            })
        }));

        mutations
    }

    // Write logs, report metrics depending on the batch deliver result.
    #[allow(clippy::too_many_arguments)]
    fn process_batch_delivery_result(
        &self,
        result: &Result<(), MessageRoutingError>,
        _block_stats: BlockStats,
        batch_stats: BatchStats,
    ) {
        match result {
            Ok(()) => {
                self.ingress_selector
                    .request_purge_finalized_messages(batch_stats.ingress_ids);
            }
            Err(MessageRoutingError::QueueIsFull) => {}
            Err(MessageRoutingError::Ignored { .. }) => {
                unreachable!("Unexpected error on a valid batch number");
            }
        }
    }
}
