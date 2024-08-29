use crate::{
    certification::{CertificationCrypto, VerifierImpl},
    consensus::MINIMUM_CHAIN_LENGTH,
};
use ic_consensus_utils::{
    active_high_threshold_nidkg_id, aggregate, membership::Membership, registry_version_at_height,
};
use ic_interfaces::{
    certification::{CertificationPool, ChangeAction, ChangeSet, Verifier, VerifierError},
    consensus_pool::ConsensusPoolCache,
    p2p::consensus::{Bouncer, BouncerFactory, BouncerValue, ChangeSetProducer},
    validation::ValidationError,
};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::StateManager;
use ic_logger::{debug, error, trace, ReplicaLogger};
use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use ic_replicated_state::ReplicatedState;
use ic_types::{
    artifact::CertificationMessageId,
    consensus::{
        certification::{
            Certification, CertificationContent, CertificationMessage, CertificationShare,
        },
        Committee, HasCommittee, HasHeight,
    },
    crypto::Signed,
    replica_config::ReplicaConfig,
    CryptoHashOfPartialState, Height,
};
use prometheus::{Histogram, IntCounter, IntGauge};
use std::{cell::RefCell, sync::Arc, time::Instant};
use tokio::sync::watch;

/// The Certification component, processing the changes on the certification
/// pool and submitting the corresponding change sets.
pub struct CertifierImpl {
    replica_config: ReplicaConfig,
    membership: Arc<Membership>,
    crypto: Arc<dyn CertificationCrypto>,
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
    metrics: CertifierMetrics,
    /// The highest height that has been purged. Used to avoid redundant purging.
    highest_purged_height: RefCell<Height>,
    max_certified_height_tx: watch::Sender<Height>,
    log: ReplicaLogger,
}

/// The Certification component, processing the changes on the certification
/// pool and submitting the corresponding change sets.
pub struct CertifierGossipImpl {
    consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
}

struct CertifierMetrics {
    shares_created: IntCounter,
    certifications_aggregated: IntCounter,
    last_certified_height: IntGauge,
    execution_time: Histogram,
}

impl<Pool: CertificationPool> BouncerFactory<CertificationMessage, Pool> for CertifierGossipImpl {
    // The priority function requires just the height of the artifact to decide if
    // it should be fetched or not: if we already have a full certification at
    // that height or this height is below the CUP height, we're not interested in
    // any new artifacts at that height. If it is above the CUP height and we do not
    // have a full certification at that height, we're interested in all artifacts.
    fn new_bouncer(&self, certification_pool: &Pool) -> Bouncer<CertificationMessageId> {
        let certified_heights = certification_pool.certified_heights();
        let cup_height = self.consensus_pool_cache.catch_up_package().height();
        Box::new(move |id| {
            let height = id.height;
            // We drop all artifacts below the CUP height or those for which we have a full
            // certification already.
            if height < cup_height || certified_heights.contains(&height) {
                BouncerValue::Unwanted
            } else {
                BouncerValue::Wants
            }
        })
    }
}

/// Return both Certifier and CertifierGossip components.
pub fn setup(
    replica_config: ReplicaConfig,
    registry_client: Arc<dyn RegistryClient>,
    crypto: Arc<dyn CertificationCrypto>,
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
    metrics_registry: MetricsRegistry,
    log: ReplicaLogger,
    max_certified_height_tx: watch::Sender<Height>,
) -> (CertifierImpl, CertifierGossipImpl) {
    (
        CertifierImpl::new(
            replica_config,
            registry_client,
            crypto,
            state_manager,
            consensus_pool_cache.clone(),
            metrics_registry,
            log,
            max_certified_height_tx,
        ),
        CertifierGossipImpl {
            consensus_pool_cache,
        },
    )
}

/// The certifier component is responsible for signing execution states.
/// These signatures are required, to securely transmit a set of inter-canister
/// messages from one sub-network to another, or to synchronize the replica
/// state.
///
/// For creating a signature for a state, every replica follows the
/// following algorithm:
///
/// 1. Request a set of (height, hash) tuples from its local StateManager, where
///    `hash` is the hash of the replicated state after processing the batch at the
///    specified height. The StateManager is responsible for selecting which parts
///    of the replicated state are included in the computation of the hash.
///
/// 2. Sign the hash-height tuple, resulting in a CertificationShare, and place
///    the CertificationShare in the certification pool, to be gossiped to other
///    replicas.
///
/// 3. On every invocation of `on_state_change`, if sufficiently many
///    CertificationShares for the same (height, hash) pair were received, combine
///    them into a full Certification and put it into the certification pool. At
///    that point, the CertificationShares are not required anymore and can be
///    purged.
///
/// 4. For every (height, hash) pair with a full Certification, submit
///    the pair (height, Certification) to the StateManager.
///
/// 5. Whenever the catch-up package height increases, remove all certification
///    artifacts below this height.
impl<T: CertificationPool> ChangeSetProducer<T> for CertifierImpl {
    type ChangeSet = ChangeSet;

    /// Should be called on every change of the certification pool and timeouts.
    fn on_state_change(&self, certification_pool: &T) -> ChangeSet {
        // This timer will make an entry in the metrics histogram automatically, when
        // it's dropped.
        let _timer = self.metrics.execution_time.start_timer();
        let start = Instant::now();

        // First, we iterate over requested heights and deliver certifications to the
        // state manager, if they're available or return those hashes which do not have
        // certifications and for which we did not issue a share yet.
        let state_hashes_to_certify: Vec<_> = self
            .state_manager
            .list_state_hashes_to_certify()
            .into_iter()
            .filter_map(
                |(height, hash)| match certification_pool.certification_at_height(height) {
                    // if we have a valid certification, deliver it to the state manager and skip
                    // the pair
                    Some(certification) => {
                        // TODO[NET-1711]: Remove deliver_state_certification(), and include them in the
                        // change set for the artifact processor to handle.
                        self.state_manager
                            .deliver_state_certification(certification);
                        self.metrics.last_certified_height.set(height.get() as i64);
                        debug!(&self.log, "Delivered certification for height {}", height);

                        self.max_certified_height_tx.send_if_modified(|h| {
                            if height > *h {
                                *h = height;
                                true
                            } else {
                                false
                            }
                        });
                        None
                    }
                    // return this pair to be signed by the current replica
                    _ => Some((height, hash)),
                },
            )
            .collect();
        trace!(
            &self.log,
            "Received {} hash(es) to be certified in {:?}",
            state_hashes_to_certify.len(),
            start.elapsed()
        );

        // Next we try to execute 4 steps: signing, purging, aggregating and validating
        // sequentially and stop whenever any of these steps produces a non empty
        // set of changes, because it might affect the next step and so has to be
        // applied to the certification pool first.

        // Filter out only those heights, where the current node belongs to the
        // committee.
        let start = Instant::now();
        let shares = self.sign(certification_pool, &state_hashes_to_certify);
        if !shares.is_empty() {
            self.metrics.shares_created.inc_by(shares.len() as u64);
            trace!(
                &self.log,
                "Created {} certification shares in {:?}",
                shares.len(),
                start.elapsed()
            );
            return shares
                .into_iter()
                .map(ChangeAction::AddToValidated)
                .collect();
        }

        let start = Instant::now();
        if let Some(purge_height) = self.get_purge_height() {
            trace!(
                &self.log,
                "Determined a new purge height {:?} in {:?}",
                purge_height,
                start.elapsed()
            );
            return vec![ChangeAction::RemoveAllBelow(purge_height)];
        }

        let start = Instant::now();

        let certifications = state_hashes_to_certify
            .iter()
            .flat_map(|(height, _)| self.aggregate(certification_pool, *height))
            .collect::<Vec<_>>();

        if !certifications.is_empty() {
            self.metrics
                .certifications_aggregated
                .inc_by(certifications.len() as u64);
            trace!(
                &self.log,
                "Aggregated {} threshold-signatures in {:?}",
                certifications.len(),
                start.elapsed()
            );
            return certifications
                .into_iter()
                .map(ChangeAction::AddToValidated)
                .collect();
        }

        let start = Instant::now();
        let change_set = self.validate(certification_pool, &state_hashes_to_certify);
        if change_set.is_empty() {
            trace!(
                &self.log,
                "Certifier finishes with an empty change set in {:?}",
                start.elapsed()
            );
        } else {
            trace!(
                &self.log,
                "Validation finished with {} change actions in {:?}",
                change_set.len(),
                start.elapsed()
            );
        }

        change_set
    }
}

impl CertifierImpl {
    /// Construct a new CertifierImpl.
    pub fn new(
        replica_config: ReplicaConfig,
        registry_client: Arc<dyn RegistryClient>,
        crypto: Arc<dyn CertificationCrypto>,
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
        metrics_registry: MetricsRegistry,
        log: ReplicaLogger,
        max_certified_height_tx: watch::Sender<Height>,
    ) -> Self {
        let membership = Arc::new(Membership::new(
            consensus_pool_cache.clone(),
            registry_client.clone(),
            replica_config.subnet_id,
        ));

        Self {
            replica_config,
            membership,
            crypto,
            state_manager,
            consensus_pool_cache,
            metrics: CertifierMetrics {
                shares_created: metrics_registry.int_counter(
                    "certification_shares_created",
                    "Amount of certification shares created.",
                ),
                certifications_aggregated: metrics_registry.int_counter(
                    "certification_certifications_aggregated",
                    "Amount of full certifications created.",
                ),
                execution_time: metrics_registry.histogram(
                    "certification_execution_time",
                    "Certifier execution time in seconds.",
                    decimal_buckets(-3, 1),
                ),
                last_certified_height: metrics_registry.int_gauge(
                    "certification_last_certified_height",
                    "The last certified height.",
                ),
            },
            log,
            highest_purged_height: RefCell::new(Height::from(1)),
            max_certified_height_tx,
        }
    }

    // Gets height/hash pairs and creates certification shares for them.
    fn sign(
        &self,
        certification_pool: &dyn CertificationPool,
        state_hashes: &[(Height, CryptoHashOfPartialState)],
    ) -> Vec<CertificationMessage> {
        state_hashes
            .iter()
            // Filter out all heights, where the current replica does not belong to the committee
            // and, hence, should not sign.
            .filter(|&(height, _)| {
                self.membership
                    .node_belongs_to_threshold_committee(
                        self.replica_config.node_id,
                        *height,
                        Certification::committee(),
                    )
                    .unwrap_or_else(|err| {
                        debug!(
                            self.log,
                            "Couldn't check committee membership while signing: {:?}", err
                        );
                        false
                    })
            })
            // Filter out all heights if we have a share signed by us already (this is a linear scan
            // through all shares of the same height, but is bound by the number of replicas).
            .filter(|&(height, _)| {
                certification_pool
                    .shares_at_height(*height)
                    .all(|share| share.signed.signature.signer != self.replica_config.node_id)
            })
            .cloned()
            .filter_map(|(height, hash)| {
                let content = CertificationContent::new(hash);
                let dkg_id =
                    active_high_threshold_nidkg_id(self.consensus_pool_cache.as_ref(), height)?;
                match self
                    .crypto
                    .sign(&content, self.replica_config.node_id, dkg_id)
                {
                    Ok(signature) => Some(CertificationShare {
                        height,
                        signed: Signed { content, signature },
                    }),
                    Err(err) => {
                        error!(self.log, "Couldn't create a signature: {:?}", err);
                        None
                    }
                }
            })
            .map(CertificationMessage::CertificationShare)
            .collect()
    }

    // Gets all shares from the certification pool at a given height and
    // aggregates into full certification artifacts if possible.
    fn aggregate(
        &self,
        certification_pool: &dyn CertificationPool,
        height: Height,
    ) -> Vec<CertificationMessage> {
        // A struct defined to morph `Certification` into a format that can be
        // accepted by `utils::aggregate`.
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        struct CertificationTuple(Height, CertificationContent);

        impl HasHeight for CertificationTuple {
            fn height(&self) -> Height {
                self.0
            }
        }

        impl HasCommittee for CertificationTuple {
            fn committee() -> Committee {
                Certification::committee()
            }
        }

        let shares = certification_pool.shares_at_height(height).map(|s| Signed {
            content: CertificationTuple(s.height, s.signed.content),
            signature: s.signed.signature,
        });
        aggregate(
            &self.log,
            self.membership.as_ref(),
            self.crypto.as_aggregate(),
            Box::new(|cert: &CertificationTuple| {
                Some(active_high_threshold_nidkg_id(
                    self.consensus_pool_cache.as_ref(),
                    cert.height(),
                )?)
            }),
            shares,
        )
        .into_iter()
        .map(|signed_cert_tuple| {
            CertificationMessage::Certification(Certification {
                height: signed_cert_tuple.content.0,
                signed: Signed {
                    content: signed_cert_tuple.content.1,
                    signature: signed_cert_tuple.signature,
                },
            })
        })
        .collect()
    }

    // Validates all unvalidated artifacts and returns corresponding change set.
    fn validate(
        &self,
        certification_pool: &dyn CertificationPool,
        state_hashes: &[(Height, CryptoHashOfPartialState)],
    ) -> ChangeSet {
        // Iterate over all state hashes, obtain list of corresponding unvalidated
        // artifacts by the height and try to verify their signatures.

        state_hashes
            .iter()
            .flat_map(|(height, hash)| -> Box<dyn Iterator<Item = ChangeAction>> {
                // First we check if we have any valid full certification available for the
                // given height and if yes, our job is done for this height.
                let mut cert_change_set = Vec::new();
                for certification in
                    certification_pool.unvalidated_certifications_at_height(*height)
                {
                    if let Some(val) = self.validate_certification(hash, certification) {
                        match val {
                            ChangeAction::MoveToValidated(_) => {
                                cert_change_set.push(val);
                                // We have found one valid certification for the given height, so
                                // our job is done.
                                return Box::new(cert_change_set.into_iter());
                            }
                            _ => {
                                cert_change_set.push(val);
                            }
                        }
                    }
                }

                Box::new(
                    certification_pool
                        .unvalidated_shares_at_height(*height)
                        .filter_map(move |share| {
                            self.validate_share(certification_pool, hash, share)
                        })
                        .chain(cert_change_set),
                )
            })
            .collect()
    }

    // Returns the purge height, if artifacts below this height can be purged.
    // Return None if there are no new artifacts to be purged.
    fn get_purge_height(&self) -> Option<Height> {
        let cup_height = self.consensus_pool_cache.catch_up_package().height();
        // We pick cup_height, but retain at least the last MINIMUM_CHAIN_LENGTH heights
        let purge_height = Height::from(cup_height.get().saturating_sub(MINIMUM_CHAIN_LENGTH));

        let mut prev_highest_purged_height = self.highest_purged_height.borrow_mut();
        if *prev_highest_purged_height < purge_height {
            *prev_highest_purged_height = purge_height;
            return Some(purge_height);
        }
        None
    }

    fn validate_certification(
        &self,
        hash: &CryptoHashOfPartialState,
        certification: &Certification,
    ) -> Option<ChangeAction> {
        let msg = CertificationMessage::Certification(certification.clone());
        let verifier = VerifierImpl::new(self.crypto.clone());
        let registry_version =
            registry_version_at_height(self.consensus_pool_cache.as_ref(), certification.height)?;

        // check if the certification contains the same state hash as our local one. If
        // not, we consider the certification invalid.
        if hash != &certification.signed.content.hash {
            return Some(ChangeAction::HandleInvalid(
                msg,
                format!(
                    "Unexpected state hash (expected: {:?}, received: {:?})",
                    hash, certification.signed.content.hash
                ),
            ));
        }

        // Verify the certification signature.
        match verifier.validate(
            self.replica_config.subnet_id,
            certification,
            registry_version,
        ) {
            Ok(()) => Some(ChangeAction::MoveToValidated(msg)),
            Err(ValidationError::InvalidArtifact(err)) => {
                Some(ChangeAction::HandleInvalid(msg, format!("{:?}", err)))
            }
            Err(ValidationError::ValidationFailed(err)) => {
                debug!(
                    self.log,
                    "Couldn't verify certification signature: {:?}", err
                );
                None
            }
        }
    }

    fn validate_share(
        &self,
        certification_pool: &dyn CertificationPool,
        hash: &CryptoHashOfPartialState,
        share: &CertificationShare,
    ) -> Option<ChangeAction> {
        let msg = CertificationMessage::CertificationShare(share.clone());
        let content = &share.signed.content;
        // If the share has an invalid content or does not belong to the
        // committee
        if !hash.eq(&content.hash) {
            return Some(ChangeAction::HandleInvalid(
                msg,
                format!(
                    "Unexpected state hash (expected: {:?}, received: {:?})",
                    hash, content.hash
                ),
            ));
        }
        let signer = share.signed.signature.signer;
        match self.membership.node_belongs_to_threshold_committee(
            signer,
            share.height,
            Certification::committee(),
        ) {
            // In case of an error, we simply skip this artifact.
            Err(err) => {
                debug!(
                    self.log,
                    "Couldn't check committee membership during share validation: {:?}", err
                );
                None
            }
            // If the signer does not belong to the signers committee at the
            // given height, reject this artifact.
            Ok(false) => Some(ChangeAction::HandleInvalid(
                msg,
                "Signer does not belong to the committee".to_string(),
            )),
            // The signer is valid.
            Ok(true) => {
                // If the signer has signed a share before, invalidate the new one.
                if certification_pool
                    .shares_at_height(share.height)
                    .any(|valid_share| signer == valid_share.signed.signature.signer)
                {
                    return Some(ChangeAction::RemoveFromUnvalidated(msg));
                }
                // Verify the signature.
                Some(
                    match self
                        .crypto
                        .verify(
                            &share.signed,
                            active_high_threshold_nidkg_id(
                                self.consensus_pool_cache.as_ref(),
                                share.height,
                            )?,
                        )
                        .map_err(VerifierError::from)
                    {
                        Ok(()) => ChangeAction::MoveToValidated(msg),
                        Err(ValidationError::InvalidArtifact(err)) => {
                            ChangeAction::HandleInvalid(msg, format!("{:?}", err))
                        }
                        Err(ValidationError::ValidationFailed(err)) => {
                            debug!(self.log, "Couldn't verify share signature: {:?}", err);
                            return None;
                        }
                    },
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_artifact_pool::certification_pool::CertificationPoolImpl;
    use ic_consensus_mocks::{dependencies, Dependencies};
    use ic_interfaces::{
        certification::CertificationPool,
        p2p::consensus::{MutablePool, UnvalidatedArtifact},
    };
    use ic_test_utilities_consensus::fake::*;
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use ic_types::{
        artifact::CertificationMessageId,
        consensus::certification::{
            Certification, CertificationContent, CertificationMessage, CertificationMessageHash,
            CertificationShare,
        },
        crypto::{
            threshold_sig::ni_dkg::{NiDkgId, NiDkgTag, NiDkgTargetSubnet},
            CryptoHash, CryptoHashOf,
        },
        signature::*,
        time::UNIX_EPOCH,
        CryptoHashOfPartialState, Height,
    };

    fn to_unvalidated(message: CertificationMessage) -> UnvalidatedArtifact<CertificationMessage> {
        UnvalidatedArtifact::<CertificationMessage> {
            message,
            peer_id: node_test_id(0),
            timestamp: UNIX_EPOCH,
        }
    }

    fn gen_content() -> CertificationContent {
        CertificationContent::new(CryptoHashOfPartialState::from(CryptoHash(Vec::new())))
    }

    fn fake_share(height: Height, node_id: u64) -> UnvalidatedArtifact<CertificationMessage> {
        let content = gen_content();
        to_unvalidated(CertificationMessage::CertificationShare(
            CertificationShare {
                height,
                signed: Signed {
                    signature: ThresholdSignatureShare::fake(node_test_id(node_id)),
                    content,
                },
            },
        ))
    }

    fn fake_dkg_id(h: u64) -> NiDkgId {
        NiDkgId {
            start_block_height: Height::from(h),
            dealer_subnet: subnet_test_id(0),
            dkg_tag: NiDkgTag::HighThreshold,
            target_subnet: NiDkgTargetSubnet::Local,
        }
    }

    fn fake_cert_default(height: Height) -> UnvalidatedArtifact<CertificationMessage> {
        fake_cert(height, fake_dkg_id(0))
    }

    fn fake_cert(height: Height, dkg_id: NiDkgId) -> UnvalidatedArtifact<CertificationMessage> {
        let content = gen_content();
        let mut signature = ThresholdSignature::fake();
        signature.signer = dkg_id;
        to_unvalidated(CertificationMessage::Certification(Certification {
            height,
            signed: Signed { content, signature },
        }))
    }

    // Adds an expectation to the StateManager mock, which asks for empty hashes for
    // heights in the range `from` to `to`.
    fn add_expectations(
        state_manager: Arc<ic_test_utilities::state_manager::RefMockStateManager>,
        from: u64,
        to: u64,
    ) {
        // make the mock state manager return empty hashes for heights 3, 4 and 5
        state_manager
            .get_mut()
            .expect_list_state_hashes_to_certify()
            .return_const(
                (from..=to)
                    .map(move |h| {
                        (
                            Height::from(h),
                            CryptoHashOfPartialState::from(CryptoHash(Vec::new())),
                        )
                    })
                    .collect::<Vec<(Height, CryptoHashOfPartialState)>>(),
            );
    }

    #[test]
    fn test_certification_prio_func() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|log| {
                let Dependencies {
                    mut pool,
                    replica_config,
                    registry,
                    crypto,
                    state_manager,
                    ..
                } = dependencies(pool_config.clone(), 4);
                pool.advance_round_normal_operation();
                add_expectations(state_manager.clone(), 1, 4);
                let metrics_registry = MetricsRegistry::new();
                let mut cert_pool = CertificationPoolImpl::new(
                    replica_config.node_id,
                    pool_config,
                    ic_logger::replica_logger::no_op_logger(),
                    metrics_registry.clone(),
                );
                let (max_certified_height_tx, _) = watch::channel(Height::from(0));

                let (certifier, certifier_gossip) = setup(
                    replica_config,
                    registry,
                    crypto,
                    state_manager.clone(),
                    pool.get_cache(),
                    metrics_registry,
                    log,
                    max_certified_height_tx,
                );

                // generate a certifications for heights 1 and 3
                for height in &[1, 3] {
                    cert_pool.insert(fake_cert_default(Height::from(*height)));
                }
                let change_set =
                    certifier.validate(&cert_pool, &state_manager.list_state_hashes_to_certify());
                cert_pool.apply_changes(change_set);

                let bouncer = certifier_gossip.new_bouncer(&cert_pool);
                for (height, prio) in &[
                    (1, BouncerValue::Unwanted),
                    (2, BouncerValue::Wants),
                    (3, BouncerValue::Unwanted),
                    (4, BouncerValue::Wants),
                ] {
                    assert_eq!(
                        bouncer(&CertificationMessageId {
                            height: Height::from(*height),
                            hash: CertificationMessageHash::Certification(CryptoHashOf::from(
                                CryptoHash(Vec::new())
                            )),
                        },),
                        *prio
                    );
                }
            })
        })
    }

    #[test]
    fn test_certification_purger() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|log| {
                let Dependencies {
                    mut pool,
                    replica_config,
                    registry,
                    crypto,
                    state_manager,
                    ..
                } = dependencies(pool_config.clone(), 4);

                pool.advance_round_normal_operation_n(6);
                add_expectations(state_manager.clone(), 1, 4);
                let metrics_registry = MetricsRegistry::new();
                let (max_certified_height_tx, _) = watch::channel(Height::from(0));
                let mut cert_pool = CertificationPoolImpl::new(
                    replica_config.node_id,
                    pool_config,
                    ic_logger::replica_logger::no_op_logger(),
                    metrics_registry.clone(),
                );
                let certifier = CertifierImpl::new(
                    replica_config,
                    registry,
                    crypto,
                    state_manager.clone(),
                    pool.get_cache(),
                    metrics_registry,
                    log,
                    max_certified_height_tx,
                );

                // generate a certifications for heights 1, 2 and 4
                for height in &[1, 2, 4] {
                    cert_pool.insert(fake_cert_default(Height::from(*height)));
                }

                // generate 2 shares for heights from 1 to 4
                for height in 1..=3 {
                    let height = Height::new(height);
                    cert_pool.insert(fake_share(height, 1));
                    cert_pool.insert(fake_share(height, 2));
                }

                // let's move everything to validated
                let change_set =
                    certifier.validate(&cert_pool, &state_manager.list_state_hashes_to_certify());
                // expect 5 change actions: 3 full certifications moved to validated section + 2
                // shares, where no certification is available (at height 3)
                assert_eq!(change_set.len(), 5);
                cert_pool.apply_changes(change_set);

                // if the minimum chain length is outside of the interval (60, 120),
                // then you need to adjust the test values below.

                // Make sure we skip one DKG round and a new CUP is created.
                pool.advance_round_normal_operation_n(60);
                let purge_height = *certifier.highest_purged_height.borrow();
                // purge height stays at 1 because MINIMUM_CHAIN_LENGTH > 60
                assert_eq!(purge_height.get(), 1);

                pool.advance_round_normal_operation_n(30);
                let purge_height = *certifier.highest_purged_height.borrow();
                // We didn't reach the next cup, so no new purge height
                assert_eq!(purge_height.get(), 1);

                // We crossed the next cup (height=120). Since MIN < 120, our
                // purge height must be larger than 1.
                let new_height = pool.advance_round_normal_operation_n(30);
                let purge_height = certifier
                    .get_purge_height()
                    .expect("No new purge height was found");
                assert!(purge_height.get() > 1);

                // add 1 certitifaction and 2 more shares for `new_height` and let them
                // unvalidated
                cert_pool.insert(fake_cert_default(new_height));
                cert_pool.insert(fake_share(new_height, 1));
                cert_pool.insert(fake_share(new_height, 2));

                assert_eq!(
                    cert_pool.unvalidated_shares_at_height(new_height).count(),
                    2
                );
                assert_eq!(
                    cert_pool
                        .unvalidated_certifications_at_height(new_height)
                        .count(),
                    1
                );

                // Make sure the cert at height 1 is still there.
                let height = Height::from(1);
                assert!(cert_pool.certification_at_height(height).is_some());

                cert_pool.apply_changes(vec![ChangeAction::RemoveAllBelow(purge_height)]);

                let mut back_off_factor = 1;
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(
                        50 * (1 << back_off_factor),
                    ));
                    if cert_pool.certification_at_height(height).is_none() {
                        break;
                    }
                    back_off_factor += 1;
                    if back_off_factor > 6 {
                        panic!("Purging couldn't finish in more than 6 seconds.")
                    }
                }

                // since height 1 is below the maximal change length (which is 3 =>
                // heights 4, 3 and 2 should stay), no certifications, shares or
                // any unvalidated artifacts should stay at height 1
                assert_eq!(cert_pool.shares_at_height(height).count(), 0);
                assert_eq!(cert_pool.unvalidated_shares_at_height(height).count(), 0);
                assert_eq!(
                    cert_pool
                        .unvalidated_certifications_at_height(height)
                        .count(),
                    0
                );

                // Now that we have purged, we expect that there are no new change actions.
                let purge_height = certifier.get_purge_height();
                assert!(purge_height.is_none());
            })
        })
    }

    /// Here we insert certification shares for 3 different contents, so that we can
    /// test the correct aggregation, if there are enough shares for an
    /// aggregation, too few and just enough.
    #[test]
    fn test_certification_aggregation() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies {
                pool,
                replica_config,
                registry,
                crypto,
                state_manager,
                ..
            } = dependencies(pool_config.clone(), 6);
            // make the mock state manager return empty hashes for heights 3, 4 and 5
            add_expectations(state_manager.clone(), 3, 5);
            let metrics_registry = MetricsRegistry::new();
            let mut cert_pool = CertificationPoolImpl::new(
                replica_config.node_id,
                pool_config,
                ic_logger::replica_logger::no_op_logger(),
                metrics_registry.clone(),
            );
            let (max_certified_height_tx, _) = watch::channel(Height::from(0));

            with_test_replica_logger(|log| {
                let certifier = CertifierImpl::new(
                    replica_config,
                    registry,
                    crypto,
                    state_manager.clone(),
                    pool.get_cache(),
                    metrics_registry,
                    log,
                    max_certified_height_tx,
                );

                std::iter::empty()
                    .chain((0..6).map(move |node_id| fake_share(Height::from(3), node_id))) // enough
                    .chain((0..4).map(move |node_id| fake_share(Height::from(4), node_id))) // just enough
                    .chain((0..2).map(move |node_id| fake_share(Height::from(5), node_id))) // too few
                    .for_each(|x| cert_pool.insert(x));

                // this moves unvalidated shares to validated
                let change_set =
                    certifier.validate(&cert_pool, &state_manager.list_state_hashes_to_certify());
                cert_pool.apply_changes(change_set);

                // emulates a call from inside on_state_change
                let mut messages = vec![];
                for i in 1..6 {
                    messages.append(&mut certifier.aggregate(&cert_pool, Height::from(i)));
                }

                assert_eq!(
                    messages.len(),
                    2,
                    "shares for heights 3 and 4 should be aggregated"
                );

                let mut certs: Vec<Certification> = messages
                    .into_iter()
                    .map(|a| match a {
                        CertificationMessage::Certification(cert) => cert,
                        _ => unreachable!("No other artifacts should be in that change set."),
                    })
                    .collect();

                // sort by heights
                certs.sort_by(|s1, s2| s1.height.cmp(&s2.height));

                assert_eq!(certs[0].height, Height::from(3));
                assert_eq!(certs[1].height, Height::from(4));
            })
        })
    }

    /// Here we test, that the validation stops after finding a certification for a
    /// specified height.
    #[test]
    fn test_certification_validate() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            // We must choose a membership size of the form 3i + 1 for some integer
            // i, to ensure that all nodes will be part of the committee.
            let Dependencies {
                mut pool,
                replica_config,
                registry,
                crypto,
                state_manager,
                ..
            } = dependencies(pool_config.clone(), 7);
            pool.insert_beacon_chain(&pool.make_next_beacon(), Height::from(10));
            // make the mock state manager return empty hashes for heights 3, 4 and 5
            add_expectations(state_manager.clone(), 3, 5);
            let metrics_registry = MetricsRegistry::new();
            let mut cert_pool = CertificationPoolImpl::new(
                replica_config.node_id,
                pool_config,
                ic_logger::replica_logger::no_op_logger(),
                metrics_registry.clone(),
            );
            let (max_certified_height_tx, _) = watch::channel(Height::from(0));

            with_test_replica_logger(|log| {
                let certifier = CertifierImpl::new(
                    replica_config,
                    registry,
                    crypto,
                    state_manager.clone(),
                    pool.get_cache(),
                    metrics_registry,
                    log,
                    max_certified_height_tx,
                );

                std::iter::empty()
                    .chain((0..6).map(move |node_id| fake_share(Height::from(3), node_id))) // enough
                    .chain((0..5).map(move |node_id| fake_share(Height::from(4), node_id))) // just enough
                    .chain((0..2).map(move |node_id| fake_share(Height::from(5), node_id))) // too few
                    .for_each(|x| cert_pool.insert(x));

                // Add one certification for height 4.
                let cert = fake_cert_default(Height::from(4));
                cert_pool.insert(cert);

                // this moves unvalidated shares to validated
                let change_set =
                    certifier.validate(&cert_pool, &state_manager.list_state_hashes_to_certify());
                cert_pool.apply_changes(change_set);

                assert_eq!(cert_pool.shares_at_height(Height::from(3)).count(), 6);
                assert_eq!(
                    cert_pool
                        .unvalidated_shares_at_height(Height::from(3))
                        .count(),
                    0
                );
                assert_eq!(cert_pool.shares_at_height(Height::from(5)).count(), 2);
                assert_eq!(
                    cert_pool
                        .unvalidated_shares_at_height(Height::from(5))
                        .count(),
                    0
                );
                // because we've found a certification
                assert_eq!(cert_pool.shares_at_height(Height::from(4)).count(), 0);
            })
        })
    }

    /// Simply tests creating new certification shares.
    #[test]
    fn test_certification_sign() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies {
                mut pool,
                replica_config,
                registry,
                crypto,
                state_manager,
                ..
            } = dependencies(pool_config.clone(), 4);
            pool.advance_round_normal_operation_n(10);
            // make the mock state manager return empty hashes for heights 3, 4 and 5
            add_expectations(state_manager.clone(), 3, 5);
            let metrics_registry = MetricsRegistry::new();
            let cert_pool = CertificationPoolImpl::new(
                replica_config.node_id,
                pool_config,
                ic_logger::replica_logger::no_op_logger(),
                metrics_registry.clone(),
            );
            let (max_certified_height_tx, _) = watch::channel(Height::from(0));

            with_test_replica_logger(|log| {
                let certifier = CertifierImpl::new(
                    replica_config,
                    registry,
                    crypto,
                    state_manager,
                    pool.get_cache(),
                    metrics_registry,
                    log,
                    max_certified_height_tx,
                );

                let shares = certifier.sign(
                    &cert_pool,
                    &[
                        (
                            Height::from(1),
                            CryptoHashOfPartialState::from(CryptoHash(vec![0])),
                        ),
                        (
                            Height::from(2),
                            CryptoHashOfPartialState::from(CryptoHash(vec![1, 2])),
                        ),
                    ],
                );

                if let CertificationMessage::CertificationShare(share) = &shares[0] {
                    assert_eq!(
                        share.signed.content.hash,
                        CryptoHashOfPartialState::from(CryptoHash(vec![0]))
                    );
                } else {
                    panic!("unexpected content")
                }

                if let CertificationMessage::CertificationShare(share) = &shares[1] {
                    assert_eq!(
                        share.signed.content.hash,
                        CryptoHashOfPartialState::from(CryptoHash(vec![1, 2]))
                    );
                } else {
                    panic!("unexpected content")
                }
            })
        })
    }

    /// We test that the validator actually stops after the first discovered
    /// certification, even if multiple are available.
    #[test]
    fn test_certification_validate_2() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|log| {
                let Dependencies {
                    mut pool,
                    replica_config,
                    registry,
                    crypto,
                    state_manager,
                    ..
                } = dependencies(pool_config.clone(), 1);
                pool.advance_round_normal_operation_n(10);
                // make the mock state manager return empty hashes for heights 3, 4 and 5
                add_expectations(state_manager.clone(), 3, 5);
                let metrics_registry = MetricsRegistry::new();
                let (max_certified_height_tx, _) = watch::channel(Height::from(0));

                let certifier = CertifierImpl::new(
                    replica_config.clone(),
                    registry,
                    crypto,
                    state_manager.clone(),
                    pool.get_cache(),
                    metrics_registry.clone(),
                    log,
                    max_certified_height_tx,
                );
                let mut cert_pool = CertificationPoolImpl::new(
                    replica_config.node_id,
                    pool_config,
                    ic_logger::replica_logger::no_op_logger(),
                    metrics_registry,
                );

                // we generate 3 valid, but different full certifications
                (0..3)
                    .map(|i| {
                        if let CertificationMessage::Certification(mut cert) =
                            fake_cert_default(Height::from(5)).message
                        {
                            cert.signed.signature.signer = fake_dkg_id(i);
                            to_unvalidated(CertificationMessage::Certification(cert))
                        } else {
                            unreachable!("only full certifications are expected")
                        }
                    })
                    .for_each(|x| cert_pool.insert(x));

                assert_eq!(
                    cert_pool
                        .unvalidated_certifications_at_height(Height::from(5))
                        .count(),
                    3
                );
                assert!(cert_pool.certification_at_height(Height::from(5)).is_none());

                // this moves unvalidated shares to validated
                let change_set =
                    certifier.validate(&cert_pool, &state_manager.list_state_hashes_to_certify());
                assert_eq!(change_set.len(), 1);
                cert_pool.apply_changes(change_set);

                assert!(cert_pool.certification_at_height(Height::from(5)).is_some());
            })
        })
    }

    /// Test that an unexpected hash leads to marking the certification as invalid.
    #[test]
    fn test_invalidate_certificate_with_incorrect_state() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|log| {
                let Dependencies {
                    pool,
                    replica_config,
                    registry,
                    crypto,
                    state_manager,
                    ..
                } = dependencies(pool_config.clone(), 1);

                let (max_certified_height_tx, _) = watch::channel(Height::from(0));

                let certifier = CertifierImpl::new(
                    replica_config,
                    registry,
                    crypto,
                    state_manager,
                    pool.get_cache(),
                    MetricsRegistry::new(),
                    log,
                    max_certified_height_tx,
                );

                let cert = if let CertificationMessage::Certification(cert) =
                    fake_cert_default(Height::from(5)).message
                {
                    cert
                } else {
                    unreachable!("only full certifications are expected")
                };

                let hash = CryptoHashOfPartialState::from(CryptoHash(vec![88, 99, 00]));

                assert_eq!(
                    certifier.validate_certification(&hash, &cert),
                    Some(ChangeAction::HandleInvalid(
                        CertificationMessage::Certification(cert.clone()),
                        format!(
                            "Unexpected state hash (expected: {:?}, received: {:?})",
                            hash, &cert.signed.content.hash
                        )
                    ))
                );
            })
        })
    }

    /// Here we insert certification shares for 3 different contents, so that we can
    /// test the correct aggregation, if there are enough shares for an
    /// aggregation, too few and just enough.
    #[test]
    fn test_invalidate_a_second_certification_share_from_the_same_signer() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies {
                pool,
                replica_config,
                registry,
                crypto,
                state_manager,
                ..
            } = dependencies(pool_config.clone(), 4);
            // make the mock state manager return empty hashes for heights 4 and 5
            add_expectations(state_manager.clone(), 4, 5);
            let metrics_registry = MetricsRegistry::new();
            let mut cert_pool = CertificationPoolImpl::new(
                replica_config.node_id,
                pool_config,
                ic_logger::replica_logger::no_op_logger(),
                metrics_registry.clone(),
            );
            let (max_certified_height_tx, _) = watch::channel(Height::from(0));

            with_test_replica_logger(|log| {
                let certifier = CertifierImpl::new(
                    replica_config,
                    registry,
                    crypto,
                    state_manager.clone(),
                    pool.get_cache(),
                    metrics_registry,
                    log,
                    max_certified_height_tx,
                );

                std::iter::empty()
                    .chain((0..5).map(move |node_id| fake_share(Height::from(4), node_id))) // enough
                    .chain((0..2).map(move |node_id| fake_share(Height::from(5), node_id))) // not enough
                    .for_each(|x| cert_pool.insert(x));

                // this moves unvalidated shares to validated
                let change_set =
                    certifier.validate(&cert_pool, &state_manager.list_state_hashes_to_certify());
                cert_pool.apply_changes(change_set);

                // Let's insert valid shares from the same signer again:
                cert_pool.insert(fake_share(Height::from(4), 0));
                cert_pool.insert(fake_share(Height::from(5), 0));

                // This is supposed to invalidate the two new shares
                let change_set =
                    certifier.validate(&cert_pool, &state_manager.list_state_hashes_to_certify());

                assert_eq!(
                    change_set.len(),
                    2,
                    "unexpected changeset: {:?}",
                    change_set
                );

                assert!(
                    change_set
                        .iter()
                        .all(|x| matches!(x, ChangeAction::RemoveFromUnvalidated(_))),
                    "Both items should be RemoveFromUnvalidated"
                );

                cert_pool.apply_changes(change_set);

                // At level 4, we find a certification
                assert_eq!(cert_pool.shares_at_height(Height::from(4)).count(), 4);
                assert_eq!(
                    cert_pool
                        .unvalidated_shares_at_height(Height::from(5))
                        .count(),
                    0
                );
                // At level 5, we only have 2 valid shares
                assert_eq!(cert_pool.shares_at_height(Height::from(5)).count(), 2);
                assert_eq!(
                    cert_pool
                        .unvalidated_shares_at_height(Height::from(5))
                        .count(),
                    0
                );
            })
        })
    }

    /// Test that the certifier always transmits the highest certified height that
    /// has been seen so far. I.e. always transmit the global maximum height.
    /// Test scenario:
    /// 1. Certifier receives certifications for heights 1, 2, 3.
    ///     - Certifier should transmit height 3.
    /// 2. Certifier receives certification for height 4.
    ///    - Certifier should transmit height 4.
    /// 3. Certifier receives certifications for heights 4, 3, 2, 1.
    ///   - Certifier should not transmit any height, as none of the heights are higher
    ///     than the last transmitted height.
    #[test]
    fn test_certified_heights_are_transmitted() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|log| {
                let Dependencies {
                    pool,
                    replica_config,
                    registry,
                    crypto,
                    state_manager,
                    ..
                } = dependencies(pool_config.clone(), 4);

                let metrics_registry = MetricsRegistry::new();
                let (max_certified_height_tx, mut max_certified_height_rx) =
                    watch::channel(Height::from(0));
                let cert_pool = CertificationPoolImpl::new(
                    replica_config.node_id,
                    pool_config,
                    ic_logger::replica_logger::no_op_logger(),
                    metrics_registry.clone(),
                );

                for height in 1..=4 {
                    cert_pool
                        .persistent_pool
                        .insert(CertificationMessage::Certification(Certification {
                            height: Height::from(height),
                            signed: Signed {
                                content: gen_content(),
                                signature: ThresholdSignature::fake(),
                            },
                        }));
                }

                let certifier = CertifierImpl::new(
                    replica_config,
                    registry,
                    crypto,
                    state_manager.clone(),
                    pool.get_cache(),
                    metrics_registry,
                    log,
                    max_certified_height_tx,
                );

                // We expect deliver_state_certification() to be called 8 times since we call
                // CertifierImpl::on_state_change 3 times with 8 heights in total:
                // We mock the certified heights [1, 2, 3], [4], [4, 3, 2, 1] which are in total 8 heights.
                // I.e. the certifier should deliver the state certification 8 times.
                state_manager
                    .get_mut()
                    .expect_deliver_state_certification()
                    .times(8)
                    .return_const(());

                let state_hashes = |heights: Vec<u64>| {
                    heights
                        .into_iter()
                        .map(|h| {
                            (
                                Height::from(h),
                                CryptoHashOfPartialState::from(CryptoHash(Vec::new())),
                            )
                        })
                        .collect::<Vec<_>>()
                };

                // We mock the state manager to return the heights
                // of the states that are certified. The CertifierImpl
                // should transmit the highest height that it has seen
                // each time it sees a new height it certifies by delivering it
                // to the state manager.
                state_manager
                    .get_mut()
                    .expect_list_state_hashes_to_certify()
                    .times(1)
                    .return_const(state_hashes(vec![1, 2, 3]));

                certifier.on_state_change(&cert_pool);
                assert_eq!(
                    *max_certified_height_rx.borrow_and_update(),
                    Height::from(3)
                );

                // New max height is 4, so it should be transmitted
                state_manager
                    .get_mut()
                    .expect_list_state_hashes_to_certify()
                    .times(1)
                    .return_const(state_hashes(vec![4]));
                certifier.on_state_change(&cert_pool);
                assert_eq!(
                    *max_certified_height_rx.borrow_and_update(),
                    Height::from(4),
                    "Expected height 4 to be transmitted as it is higher than previous transmitted heights"
                );

                // None of these heights are higher than the last transmitted height
                state_manager
                    .get_mut()
                    .expect_list_state_hashes_to_certify()
                    .times(1)
                    .return_const(state_hashes(vec![4, 3, 2, 1]));
                certifier.on_state_change(&cert_pool);
                assert!(
                    !max_certified_height_rx.has_changed().unwrap(),
                    "No new height should be sent if they are lower than a previously sent height."
                );
            })
        })
    }
}
