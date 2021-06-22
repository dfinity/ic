use super::verifier::VerifierImpl;
use super::CertificationCrypto;
use crate::consensus::{membership::Membership, utils};
use ic_interfaces::{
    certification::{
        CertificationPool, Certifier, CertifierGossip, ChangeAction, ChangeSet, Verifier,
        VerifierError,
    },
    consensus_pool::ConsensusPoolCache,
    state_manager::StateManager,
    validation::ValidationError,
};
use ic_logger::{debug, error, trace, ReplicaLogger};
use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use ic_replicated_state::ReplicatedState;
use ic_types::consensus::{Committee, HasCommittee, HasHeight};
use ic_types::{
    artifact::{
        CertificationMessageAttribute, CertificationMessageFilter, CertificationMessageId,
        Priority, PriorityFn,
    },
    consensus::certification::{
        Certification, CertificationContent, CertificationMessage, CertificationShare,
    },
    crypto::Signed,
    replica_config::ReplicaConfig,
    CryptoHashOfPartialState, Height,
};
use prometheus::{Histogram, IntCounter, IntGauge};
use std::cell::RefCell;
use std::sync::{Arc, RwLock};
use std::time::Instant;

/// The Certification component, processing the changes on the certification
/// pool and submitting the corresponding change sets.
pub struct CertifierImpl {
    replica_config: ReplicaConfig,
    membership: Arc<Membership>,
    crypto: Arc<dyn CertificationCrypto>,
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    metrics: CertifierMetrics,
    /// The highest height that has been purged. Used to avoid redudant purging.
    highest_purged_height: RefCell<Height>,
    log: ReplicaLogger,
}

/// The Certification component, processing the changes on the certification
/// pool and submitting the corresponding change sets.
pub struct CertifierGossipImpl {
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
}

struct CertifierMetrics {
    shares_created: IntCounter,
    certifications_aggregated: IntCounter,
    last_certified_height: IntGauge,
    execution_time: Histogram,
}

impl CertifierGossip for CertifierGossipImpl {
    // The priority function requires just the height of the artifact to decide if
    // it should be fetched or not: if we already have a full certification at
    // that height or this height is below the CUP height, we're not interested in
    // any new artifacts at that height. If it is above the CUP height and we do not
    // have a full certification at that height, we're interested in all artifacts.
    fn get_priority_function(
        &self,
        consensus_cache: &dyn ConsensusPoolCache,
        certification_pool: &dyn CertificationPool,
    ) -> PriorityFn<CertificationMessageId, CertificationMessageAttribute> {
        let certified_heights = certification_pool.certified_heights();
        let cup_height = consensus_cache.catch_up_package().height();
        Box::new(move |_, attribute| {
            let height = match attribute {
                CertificationMessageAttribute::Certification(height) => height,
                CertificationMessageAttribute::CertificationShare(height) => height,
            };
            // We drop all artifacts below the CUP height or those for which we have a full
            // certification already.
            if *height < cup_height || certified_heights.contains(height) {
                Priority::Drop
            } else {
                Priority::Fetch
            }
        })
    }

    /// Return the height above which we want a certification. Note that
    /// this is not always equal the upper bound of what we have in the
    /// certification pool for the following reasons:
    /// 1. The pool is not persisted. We will not have any certification
    ///    in there.
    /// 2. We might have certification in the pool that is not yet
    ///    verified or delivered to the state_manager.
    fn get_filter(&self) -> CertificationMessageFilter {
        let to_certify = self.state_manager.list_state_hashes_to_certify();
        let filter_height = if to_certify.is_empty() {
            self.state_manager.latest_state_height()
        } else {
            let h = to_certify[0].0;
            assert!(
                h > Height::from(0),
                "State height to certify must be 1 or above"
            );
            h.decrement()
        };
        CertificationMessageFilter {
            height: filter_height,
        }
    }
}

/// Return both Certifier and CertifierGossip components.
pub fn setup(
    replica_config: ReplicaConfig,
    membership: Arc<Membership>,
    crypto: Arc<dyn CertificationCrypto>,
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    metrics_registry: MetricsRegistry,
    log: ReplicaLogger,
) -> (CertifierImpl, CertifierGossipImpl) {
    (
        CertifierImpl::new(
            replica_config,
            membership,
            crypto,
            state_manager.clone(),
            metrics_registry,
            log,
        ),
        CertifierGossipImpl { state_manager },
    )
}

impl Certifier for CertifierImpl {
    fn on_state_change(
        &self,
        consensus_cache: &dyn ConsensusPoolCache,
        certification_pool: Arc<RwLock<dyn CertificationPool>>,
    ) -> ChangeSet {
        // This timer will make an entry in the metrics histogram automatically, when
        // it's dropped.
        let _timer = self.metrics.execution_time.start_timer();
        let start = Instant::now();

        // First, we iterate over requested heights and deliver certifications to the
        // state manager, if they're available or return those hashes which do not have
        // certifications and for which we did not issue a share yet.
        let certification_pool = &*certification_pool.read().unwrap();
        let state_hashes_to_certify: Vec<_> = self
            .state_manager
            .list_state_hashes_to_certify()
            .into_iter()
            .filter_map(
                |(height, hash)| match certification_pool.certification_at_height(height) {
                    // if we have a valid certification, deliver it to the state manager and skip
                    // the pair
                    Some(certification) => {
                        self.state_manager
                            .deliver_state_certification(certification);
                        self.metrics.last_certified_height.set(height.get() as i64);
                        debug!(&self.log, "Delivered certification for height {}", height);
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
        let shares = self.sign(
            consensus_cache,
            certification_pool,
            &state_hashes_to_certify,
        );
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
        if let Some(purge_height) = self.get_purge_height(consensus_cache) {
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
            .flat_map(|(height, _)| self.aggregate(consensus_cache, certification_pool, *height))
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
        let change_set = self.validate(
            consensus_cache,
            certification_pool,
            &state_hashes_to_certify,
        );
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
        membership: Arc<Membership>,
        crypto: Arc<dyn CertificationCrypto>,
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        metrics_registry: MetricsRegistry,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            replica_config,
            membership,
            crypto,
            state_manager,
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
        }
    }

    // Gets height/hash pairs and creates certification shares for them.
    fn sign(
        &self,
        consensus_cache: &dyn ConsensusPoolCache,
        certification_pool: &dyn CertificationPool,
        state_hashes: &[(Height, CryptoHashOfPartialState)],
    ) -> Vec<CertificationMessage> {
        state_hashes
            .iter()
            .cloned()
            // Filter out all heights, where the current replica does not belong to the committee
            // and, hence, should not sign.
            .filter(|(height, _)| {
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
            .filter(|(height, _)| {
                certification_pool
                    .shares_at_height(*height)
                    .all(|share| share.signed.signature.signer != self.replica_config.node_id)
            })
            .filter_map(|(height, hash)| {
                let content = CertificationContent::new(hash);
                let dkg_id =
                    utils::active_high_threshold_transcript(consensus_cache, height)?.dkg_id;
                match self
                    .crypto
                    .sign(&content, self.replica_config.node_id, dkg_id)
                {
                    Ok(signature) => Some(CertificationShare {
                        height,
                        signed: Signed { signature, content },
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
        consensus_cache: &dyn ConsensusPoolCache,
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
        utils::aggregate(
            &self.log,
            self.membership.as_ref(),
            self.crypto.as_aggregate(),
            Box::new(|cert: &CertificationTuple| {
                Some(
                    utils::active_high_threshold_transcript(consensus_cache, cert.height())?.dkg_id,
                )
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
        consensus_cache: &dyn ConsensusPoolCache,
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
                    if let Some(val) =
                        self.validate_certification(consensus_cache, hash, certification)
                    {
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
                            self.validate_share(consensus_cache, certification_pool, hash, share)
                        })
                        .chain(cert_change_set.into_iter()),
                )
            })
            .collect()
    }

    // Returns the purge height, if artifacts below this height can be purged.
    // Return None if there are no new artifacts to be purged.
    fn get_purge_height(&self, consensus_cache: &dyn ConsensusPoolCache) -> Option<Height> {
        let purge_height = consensus_cache.catch_up_package().height();
        let mut prev_highest_purged_height = self.highest_purged_height.borrow_mut();
        if *prev_highest_purged_height < purge_height {
            *prev_highest_purged_height = purge_height;
            return Some(purge_height);
        }
        None
    }

    fn validate_certification(
        &self,
        consensus_cache: &dyn ConsensusPoolCache,
        hash: &CryptoHashOfPartialState,
        certification: &Certification,
    ) -> Option<ChangeAction> {
        let msg = CertificationMessage::Certification(certification.clone());
        let verifier = VerifierImpl::new(self.crypto.clone());
        let registry_version =
            utils::registry_version_at_height(consensus_cache, certification.height)?;

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
            Err(ValidationError::Permanent(err)) => {
                Some(ChangeAction::HandleInvalid(msg, format!("{:?}", err)))
            }
            Err(ValidationError::Transient(err)) => {
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
        consensus_cache: &dyn ConsensusPoolCache,
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
                            utils::active_high_threshold_transcript(consensus_cache, share.height)?
                                .dkg_id,
                        )
                        .map_err(VerifierError::from)
                    {
                        Ok(()) => ChangeAction::MoveToValidated(msg),
                        Err(ValidationError::Permanent(err)) => {
                            ChangeAction::HandleInvalid(msg, format!("{:?}", err))
                        }
                        Err(ValidationError::Transient(err)) => {
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
    use crate::consensus::mocks::{dependencies, Dependencies};
    use ic_artifact_pool::certification_pool::CertificationPoolImpl;
    use ic_interfaces::certification::{CertificationPool, MutableCertificationPool};
    use ic_interfaces::consensus_pool::ConsensusPool;
    use ic_test_utilities::consensus::fake::*;
    use ic_test_utilities::types::ids::{node_test_id, subnet_test_id};
    use ic_test_utilities::with_test_replica_logger;
    use ic_types::artifact::CertificationMessageId;
    use ic_types::consensus::certification::CertificationMessageHash;
    use ic_types::{
        artifact::Priority,
        consensus::{
            certification::{
                Certification, CertificationContent, CertificationMessage, CertificationShare,
            },
            ThresholdSignature, ThresholdSignatureShare,
        },
        crypto::{
            threshold_sig::ni_dkg::{NiDkgId, NiDkgTag, NiDkgTargetSubnet},
            CryptoHash, CryptoHashOf,
        },
        CryptoHashOfPartialState, Height,
    };

    fn gen_content() -> CertificationContent {
        CertificationContent::new(CryptoHashOfPartialState::from(CryptoHash(Vec::new())))
    }

    fn fake_share(height: Height, node_id: u64) -> CertificationMessage {
        let content = gen_content();
        CertificationMessage::CertificationShare(CertificationShare {
            height,
            signed: Signed {
                signature: ThresholdSignatureShare::fake(node_test_id(node_id)),
                content,
            },
        })
    }

    fn fake_dkg_id(h: u64) -> NiDkgId {
        NiDkgId {
            start_block_height: Height::from(h),
            dealer_subnet: subnet_test_id(0),
            dkg_tag: NiDkgTag::HighThreshold,
            target_subnet: NiDkgTargetSubnet::Local,
        }
    }

    fn fake_cert_default(height: Height) -> CertificationMessage {
        fake_cert(height, fake_dkg_id(0))
    }

    fn fake_cert(height: Height, dkg_id: NiDkgId) -> CertificationMessage {
        let content = gen_content();
        let mut signature = ThresholdSignature::fake();
        signature.signer = dkg_id;
        CertificationMessage::Certification(Certification {
            height,
            signed: Signed { signature, content },
        })
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
                    membership,
                    crypto,
                    state_manager,
                    ..
                } = dependencies(pool_config.clone(), 4);
                pool.advance_round_normal_operation();
                add_expectations(state_manager.clone(), 1, 4);
                let metrics_registry = MetricsRegistry::new();
                let mut cert_pool = CertificationPoolImpl::new(
                    pool_config,
                    ic_logger::replica_logger::no_op_logger(),
                    metrics_registry.clone(),
                );
                let (certifier, certifier_gossip) = setup(
                    replica_config,
                    membership,
                    crypto,
                    state_manager.clone(),
                    metrics_registry,
                    log,
                );

                // generate a certifications for heights 1 and 3
                for height in &[1, 3] {
                    cert_pool.insert(fake_cert_default(Height::from(*height)));
                }
                let change_set = certifier.validate(
                    pool.as_cache(),
                    &cert_pool,
                    &state_manager.list_state_hashes_to_certify(),
                );
                cert_pool.apply_changes(change_set);

                let prio_fn = certifier_gossip.get_priority_function(pool.as_cache(), &cert_pool);
                for (height, prio) in &[
                    (1, Priority::Drop),
                    (2, Priority::Fetch),
                    (3, Priority::Drop),
                    (4, Priority::Fetch),
                ] {
                    assert_eq!(
                        prio_fn(
                            &CertificationMessageId {
                                height: Height::from(*height),
                                hash: CertificationMessageHash::Certification(CryptoHashOf::from(
                                    CryptoHash(Vec::new())
                                )),
                            },
                            &CertificationMessageAttribute::Certification(Height::from(*height))
                        ),
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
                    membership,
                    crypto,
                    state_manager,
                    ..
                } = dependencies(pool_config.clone(), 4);

                pool.advance_round_normal_operation_n(6);
                add_expectations(state_manager.clone(), 1, 4);
                let metrics_registry = MetricsRegistry::new();
                let mut cert_pool = CertificationPoolImpl::new(
                    pool_config,
                    ic_logger::replica_logger::no_op_logger(),
                    metrics_registry.clone(),
                );
                let certifier = CertifierImpl::new(
                    replica_config,
                    membership,
                    crypto,
                    state_manager.clone(),
                    metrics_registry,
                    log,
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
                let change_set = certifier.validate(
                    pool.as_cache(),
                    &cert_pool,
                    &state_manager.list_state_hashes_to_certify(),
                );
                // expect 5 change actions: 3 full certifications moved to validated section + 2
                // shares, where no certification is available (at height 3)
                assert_eq!(change_set.len(), 5);
                cert_pool.apply_changes(change_set);

                // Make sure we skip one DKG round and a new CUP is created.
                let new_height = pool.advance_round_normal_operation_n(60);

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

                let purge_height = certifier
                    .get_purge_height(pool.as_cache())
                    .expect("No new purge height was found");

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
                let purge_height = certifier.get_purge_height(pool.as_cache());
                assert!(purge_height.is_none());
            })
        })
    }

    // Here we insert certification shares for 3 different contents, so that we can
    // test the correct aggregation, if there are enough shares for an
    // aggregation, too few and just enough.
    #[test]
    fn test_certification_aggregation() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies {
                pool,
                replica_config,
                membership,
                crypto,
                state_manager,
                ..
            } = dependencies(pool_config.clone(), 6);
            // make the mock state manager return empty hashes for heights 3, 4 and 5
            add_expectations(state_manager.clone(), 3, 5);
            let metrics_registry = MetricsRegistry::new();
            let mut cert_pool = CertificationPoolImpl::new(
                pool_config,
                ic_logger::replica_logger::no_op_logger(),
                metrics_registry.clone(),
            );

            with_test_replica_logger(|log| {
                let certifier = CertifierImpl::new(
                    replica_config,
                    membership,
                    crypto,
                    state_manager.clone(),
                    metrics_registry,
                    log,
                );

                std::iter::empty()
                    .chain((0..6).map(move |node_id| fake_share(Height::from(3), node_id))) // enough
                    .chain((0..4).map(move |node_id| fake_share(Height::from(4), node_id))) // just enough
                    .chain((0..2).map(move |node_id| fake_share(Height::from(5), node_id))) // too few
                    .for_each(|x| cert_pool.insert(x));

                // this moves unvalidated shares to validated
                let change_set = certifier.validate(
                    pool.as_cache(),
                    &cert_pool,
                    &state_manager.list_state_hashes_to_certify(),
                );
                cert_pool.apply_changes(change_set);

                // emulates a call from inside on_state_change
                let mut messages = vec![];
                for i in 1..6 {
                    messages.append(&mut certifier.aggregate(
                        pool.as_cache(),
                        &cert_pool,
                        Height::from(i),
                    ));
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

    // Here we test, that the validation stops after finding a certification for a
    // specified height.
    #[test]
    fn test_certification_validate() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            // We must choose a membership size of the form 3i + 1 for some integer
            // i, to ensure that all nodes will be part of the committee.
            let Dependencies {
                mut pool,
                replica_config,
                membership,
                crypto,
                state_manager,
                ..
            } = dependencies(pool_config.clone(), 7);
            pool.insert_beacon_chain(&pool.make_next_beacon(), Height::from(10));
            // make the mock state manager return empty hashes for heights 3, 4 and 5
            add_expectations(state_manager.clone(), 3, 5);
            let metrics_registry = MetricsRegistry::new();
            let mut cert_pool = CertificationPoolImpl::new(
                pool_config,
                ic_logger::replica_logger::no_op_logger(),
                metrics_registry.clone(),
            );

            with_test_replica_logger(|log| {
                let certifier = CertifierImpl::new(
                    replica_config,
                    membership,
                    crypto,
                    state_manager.clone(),
                    metrics_registry,
                    log,
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
                let change_set = certifier.validate(
                    pool.as_cache(),
                    &cert_pool,
                    &state_manager.list_state_hashes_to_certify(),
                );
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

    // Simply tests creating new certification shares.
    #[test]
    fn test_certification_sign() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies {
                mut pool,
                replica_config,
                membership,
                crypto,
                state_manager,
                ..
            } = dependencies(pool_config.clone(), 4);
            pool.advance_round_normal_operation_n(10);
            // make the mock state manager return empty hashes for heights 3, 4 and 5
            add_expectations(state_manager.clone(), 3, 5);
            let metrics_registry = MetricsRegistry::new();
            let cert_pool = CertificationPoolImpl::new(
                pool_config,
                ic_logger::replica_logger::no_op_logger(),
                metrics_registry.clone(),
            );

            with_test_replica_logger(|log| {
                let certifier = CertifierImpl::new(
                    replica_config,
                    membership,
                    crypto,
                    state_manager,
                    metrics_registry,
                    log,
                );

                let shares = certifier.sign(
                    pool.as_cache(),
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

    // We test that the validator actually stops after the first discovered
    // certification, even if multiple are available.
    #[test]
    fn test_certification_validate_2() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|log| {
                let Dependencies {
                    mut pool,
                    replica_config,
                    membership,
                    crypto,
                    state_manager,
                    ..
                } = dependencies(pool_config.clone(), 1);
                pool.advance_round_normal_operation_n(10);
                // make the mock state manager return empty hashes for heights 3, 4 and 5
                add_expectations(state_manager.clone(), 3, 5);
                let metrics_registry = MetricsRegistry::new();
                let certifier = CertifierImpl::new(
                    replica_config,
                    membership,
                    crypto,
                    state_manager.clone(),
                    metrics_registry.clone(),
                    log,
                );
                let mut cert_pool = CertificationPoolImpl::new(
                    pool_config,
                    ic_logger::replica_logger::no_op_logger(),
                    metrics_registry,
                );

                // we generate 3 valid, but different full certifications
                (0..3)
                    .map(|i| {
                        if let CertificationMessage::Certification(mut cert) =
                            fake_cert_default(Height::from(5))
                        {
                            cert.signed.signature.signer = fake_dkg_id(i);
                            CertificationMessage::Certification(cert)
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
                let change_set = certifier.validate(
                    pool.as_cache(),
                    &cert_pool,
                    &state_manager.list_state_hashes_to_certify(),
                );
                assert_eq!(change_set.len(), 1);
                cert_pool.apply_changes(change_set);

                assert!(cert_pool.certification_at_height(Height::from(5)).is_some());
            })
        })
    }

    // Test that an unexpected hash leads to marking the certification as invalid.
    #[test]
    fn test_invalidate_certificate_with_incorrect_state() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|log| {
                let Dependencies {
                    pool,
                    replica_config,
                    membership,
                    crypto,
                    state_manager,
                    ..
                } = dependencies(pool_config.clone(), 1);

                let certifier = CertifierImpl::new(
                    replica_config,
                    membership,
                    crypto,
                    state_manager,
                    MetricsRegistry::new(),
                    log,
                );

                let cert = if let CertificationMessage::Certification(cert) =
                    fake_cert_default(Height::from(5))
                {
                    cert
                } else {
                    unreachable!("only full certifications are expected")
                };

                let hash = CryptoHashOfPartialState::from(CryptoHash(vec![88, 99, 00]));

                assert_eq!(
                    certifier.validate_certification(pool.as_cache(), &hash, &cert),
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

    // Here we insert certification shares for 3 different contents, so that we can
    // test the correct aggregation, if there are enough shares for an
    // aggregation, too few and just enough.
    #[test]
    fn test_invalidate_a_second_certification_share_from_the_same_signer() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies {
                pool,
                replica_config,
                membership,
                crypto,
                state_manager,
                ..
            } = dependencies(pool_config.clone(), 4);
            // make the mock state manager return empty hashes for heights 4 and 5
            add_expectations(state_manager.clone(), 4, 5);
            let metrics_registry = MetricsRegistry::new();
            let mut cert_pool = CertificationPoolImpl::new(
                pool_config,
                ic_logger::replica_logger::no_op_logger(),
                metrics_registry.clone(),
            );

            with_test_replica_logger(|log| {
                let certifier = CertifierImpl::new(
                    replica_config,
                    membership,
                    crypto,
                    state_manager.clone(),
                    metrics_registry,
                    log,
                );

                std::iter::empty()
                    .chain((0..5).map(move |node_id| fake_share(Height::from(4), node_id))) // enough
                    .chain((0..2).map(move |node_id| fake_share(Height::from(5), node_id))) // not enough
                    .for_each(|x| cert_pool.insert(x));

                // this moves unvalidated shares to validated
                let change_set = certifier.validate(
                    pool.as_cache(),
                    &cert_pool,
                    &state_manager.list_state_hashes_to_certify(),
                );
                cert_pool.apply_changes(change_set);

                // Let's insert valid shares from the same signer again:
                cert_pool.insert(fake_share(Height::from(4), 0));
                cert_pool.insert(fake_share(Height::from(5), 0));

                // This is supposed to invalidate the two new shares
                let change_set = certifier.validate(
                    pool.as_cache(),
                    &cert_pool,
                    &state_manager.list_state_hashes_to_certify(),
                );

                assert_eq!(
                    change_set.len(),
                    2,
                    "unexpected changeset: {:?}",
                    change_set
                );

                assert!(
                    change_set
                        .iter()
                        .all(|x| if let ChangeAction::RemoveFromUnvalidated(_) = x {
                            true
                        } else {
                            false
                        }),
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
}
