//! The signature process manager

use crate::consensus::{
    metrics::{timed_call, EcdsaSignerMetrics},
    utils::RoundRobin,
    ConsensusCrypto,
};

use ic_interfaces::consensus_pool::ConsensusPoolCache;
use ic_interfaces::crypto::ErrorReplication;
use ic_interfaces::crypto::{ThresholdEcdsaSigVerifier, ThresholdEcdsaSigner};
use ic_interfaces::ecdsa::{EcdsaChangeAction, EcdsaChangeSet, EcdsaPool};
use ic_logger::{debug, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_types::artifact::EcdsaMessageId;
use ic_types::consensus::ecdsa::{
    EcdsaBlockReader, EcdsaBlockReaderImpl, EcdsaMessage, EcdsaSigShare, RequestId,
};
use ic_types::crypto::canister_threshold_sig::ThresholdEcdsaSigInputs;
use ic_types::{Height, NodeId};

use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

pub(crate) trait EcdsaSigner: Send {
    /// The on_state_change() called from the main ECDSA path.
    fn on_state_change(&self, ecdsa_pool: &dyn EcdsaPool) -> EcdsaChangeSet;
}

pub(crate) struct EcdsaSignerImpl {
    node_id: NodeId,
    consensus_cache: Arc<dyn ConsensusPoolCache>,
    crypto: Arc<dyn ConsensusCrypto>,
    schedule: RoundRobin,
    metrics: EcdsaSignerMetrics,
    log: ReplicaLogger,
}

impl EcdsaSignerImpl {
    pub(crate) fn new(
        node_id: NodeId,
        consensus_cache: Arc<dyn ConsensusPoolCache>,
        crypto: Arc<dyn ConsensusCrypto>,
        metrics_registry: MetricsRegistry,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            node_id,
            consensus_cache,
            crypto,
            schedule: RoundRobin::default(),
            metrics: EcdsaSignerMetrics::new(metrics_registry),
            log,
        }
    }

    /// Generates signature shares for the newly added signature requests
    fn send_signature_shares(
        &self,
        ecdsa_pool: &dyn EcdsaPool,
        block_reader: &dyn EcdsaBlockReader,
    ) -> EcdsaChangeSet {
        block_reader
            .requested_signatures()
            .filter(|(request_id, _)| {
                !self.signer_has_issued_signature_share(ecdsa_pool, &self.node_id, request_id)
            })
            .map(|(request_id, sig_inputs)| {
                self.crypto_create_signature_share(block_reader, request_id, sig_inputs)
            })
            .flatten()
            .collect()
    }

    /// Processes the received signature shares
    fn validate_signature_shares(
        &self,
        ecdsa_pool: &dyn EcdsaPool,
        block_reader: &dyn EcdsaBlockReader,
    ) -> EcdsaChangeSet {
        // Pass 1: collection of <RequestId, SignerId>
        let mut dealing_keys = BTreeSet::new();
        let mut duplicate_keys = BTreeSet::new();
        for (_, share) in ecdsa_pool.unvalidated().signature_shares() {
            let key = (share.request_id.clone(), share.signer_id);
            if !dealing_keys.insert(key.clone()) {
                duplicate_keys.insert(key);
            }
        }

        let mut ret = Vec::new();
        for (id, share) in ecdsa_pool.unvalidated().signature_shares() {
            // Remove the duplicate entries
            let key = (share.request_id.clone(), share.signer_id);
            if duplicate_keys.contains(&key) {
                self.metrics
                    .sign_errors_inc("duplicate_sig_shares_in_batch");
                ret.push(EcdsaChangeAction::HandleInvalid(
                    id,
                    format!(
                        "Duplicate share in unvalidated batch: signer = {:?}, height = {:?},
                          request_id = {:?}",
                        share.signer_id, share.requested_height, share.request_id
                    ),
                ));
                continue;
            }

            match Action::action(block_reader, share.requested_height, &share.request_id) {
                Action::Process(sig_inputs) => {
                    if self.signer_has_issued_signature_share(
                        ecdsa_pool,
                        &share.signer_id,
                        &share.request_id,
                    ) {
                        // The node already sent a valid share for this request
                        self.metrics.sign_errors_inc("duplicate_sig_share");
                        ret.push(EcdsaChangeAction::HandleInvalid(
                            id,
                            format!(
                                "Duplicate share: signer = {:?}, height = {:?},
                                  request_id = {:?}",
                                share.signer_id, share.requested_height, share.request_id
                            ),
                        ))
                    } else {
                        let mut changes =
                            self.crypto_verify_signature_share(&id, sig_inputs, share);
                        ret.append(&mut changes);
                    }
                }
                Action::Drop => ret.push(EcdsaChangeAction::RemoveUnvalidated(id)),
                Action::Defer => {}
            }
        }
        ret
    }

    /// Helper to create the signature share
    fn crypto_create_signature_share(
        &self,
        block_reader: &dyn EcdsaBlockReader,
        request_id: &RequestId,
        sig_inputs: &ThresholdEcdsaSigInputs,
    ) -> EcdsaChangeSet {
        ThresholdEcdsaSigner::sign_share(&*self.crypto, sig_inputs).map_or_else(
            |error| {
                warn!(
                    self.log,
                    "Failed to create share: request_id = {:?}, {:?}", request_id, error
                );
                self.metrics.sign_errors_inc("create_sig_share");
                Default::default()
            },
            |share| {
                let sig_share = EcdsaSigShare {
                    requested_height: block_reader.height(),
                    signer_id: self.node_id,
                    request_id: request_id.clone(),
                    share,
                };
                self.metrics.sign_metrics_inc("sig_shares_sent");
                vec![EcdsaChangeAction::AddToValidated(
                    EcdsaMessage::EcdsaSigShare(sig_share),
                )]
            },
        )
    }

    /// Helper to verify the signature share
    fn crypto_verify_signature_share(
        &self,
        id: &EcdsaMessageId,
        sig_inputs: &ThresholdEcdsaSigInputs,
        share: &EcdsaSigShare,
    ) -> EcdsaChangeSet {
        ThresholdEcdsaSigVerifier::verify_sig_share(
            &*self.crypto,
            share.signer_id,
            sig_inputs,
            &share.share,
        )
        .map_or_else(
            |error| {
                if error.is_replicated() {
                    self.metrics.sign_errors_inc("verify_sig_share_permanent");
                    vec![EcdsaChangeAction::HandleInvalid(
                        id.clone(),
                        format!(
                            "Share validation(permanent error): signer = {:?},
                              height = {:?}, request_id = {:?}, error = {:?}",
                            share.signer_id, share.requested_height, share.request_id, error
                        ),
                    )]
                } else {
                    // Defer in case of transient errors
                    debug!(
                        self.log,
                        "Share validation(transient error): signer = {:?},
                            height = {:?}, request_id = {:?}, error = {:?}",
                        share.signer_id,
                        share.requested_height,
                        share.request_id,
                        error
                    );
                    self.metrics.sign_errors_inc("verify_sig_share_transient");
                    Default::default()
                }
            },
            |()| {
                self.metrics.sign_metrics_inc("sig_shares_received");
                vec![EcdsaChangeAction::MoveToValidated(id.clone())]
            },
        )
    }

    /// Checks if the signer node has already issued a signature share for the
    /// request
    fn signer_has_issued_signature_share(
        &self,
        ecdsa_pool: &dyn EcdsaPool,
        signer_id: &NodeId,
        request_id: &RequestId,
    ) -> bool {
        ecdsa_pool
            .validated()
            .signature_shares()
            .any(|(_, share)| share.request_id == *request_id && share.signer_id == *signer_id)
    }
}

impl EcdsaSigner for EcdsaSignerImpl {
    fn on_state_change(&self, ecdsa_pool: &dyn EcdsaPool) -> EcdsaChangeSet {
        let block_reader = EcdsaBlockReaderImpl::new(self.consensus_cache.finalized_block());
        let metrics = self.metrics.clone();

        let send_signature_shares = || {
            timed_call(
                "send_signature_shares",
                || self.send_signature_shares(ecdsa_pool, &block_reader),
                &metrics.on_state_change_duration,
            )
        };
        let validate_signature_shares = || {
            timed_call(
                "validate_signature_shares",
                || self.validate_signature_shares(ecdsa_pool, &block_reader),
                &metrics.on_state_change_duration,
            )
        };

        let calls: [&'_ dyn Fn() -> EcdsaChangeSet; 2] =
            [&send_signature_shares, &validate_signature_shares];
        self.schedule.call_next(&calls)
    }
}

/// Specifies how to handle a received share
#[derive(Eq, PartialEq)]
enum Action<'a> {
    /// The message is relevant to our current state, process it
    /// immediately. The transcript params for this transcript
    /// (as specified by the finalized block) is the argument
    Process(&'a ThresholdEcdsaSigInputs),

    /// Keep it to be processed later (e.g) this is from a node
    /// ahead of us
    Defer,

    /// Don't need it
    Drop,
}

impl<'a> Action<'a> {
    /// Decides the action to take on a received message with the given
    /// height/RequestId
    #[allow(clippy::self_named_constructors)]
    fn action(
        block_reader: &'a dyn EcdsaBlockReader,
        msg_height: Height,
        msg_request_id: &RequestId,
    ) -> Action<'a> {
        if msg_height > block_reader.height() {
            // Message is from a node ahead of us, keep it to be
            // processed later
            return Action::Defer;
        }

        for (request_id, sig_inputs) in block_reader.requested_signatures() {
            if *msg_request_id == *request_id {
                return Action::Process(sig_inputs);
            }
        }

        // Its for a transcript that has not been requested, drop it
        Action::Drop
    }
}

impl<'a> Debug for Action<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self {
            Self::Process(sig_inputs) => {
                write!(
                    f,
                    "Action::Process(): caller = {:?}",
                    sig_inputs.derivation_path().caller
                )
            }
            Self::Defer => write!(f, "Action::Defer"),
            Self::Drop => write!(f, "Action::Drop"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecdsa::utils::test_utils::*;
    use ic_ecdsa_object::EcdsaObject;
    use ic_interfaces::artifact_pool::UnvalidatedArtifact;
    use ic_interfaces::ecdsa::MutableEcdsaPool;
    use ic_interfaces::time_source::TimeSource;
    use ic_test_utilities::types::ids::{NODE_1, NODE_2, NODE_3};
    use ic_test_utilities::with_test_replica_logger;
    use ic_test_utilities::FastForwardTimeSource;
    use ic_types::Height;

    // Tests the Action logic
    #[test]
    fn test_ecdsa_signer_action() {
        let (id_1, id_2, id_3, id_4) = (
            create_request_id(1),
            create_request_id(2),
            create_request_id(3),
            create_request_id(4),
        );

        // The finalized block requests signatures 1, 2, 3
        let block_reader = TestEcdsaBlockReader::for_signer_test(
            Height::from(100),
            vec![
                (id_1.clone(), create_sig_inputs(1)),
                (id_2.clone(), create_sig_inputs(2)),
                (id_3, create_sig_inputs(3)),
            ],
        );

        // Message from a node ahead of us
        assert_eq!(
            Action::action(&block_reader, Height::from(200), &id_4),
            Action::Defer
        );

        // Messages for transcripts not being currently requested
        assert_eq!(
            Action::action(&block_reader, Height::from(100), &create_request_id(123)),
            Action::Drop
        );
        assert_eq!(
            Action::action(&block_reader, Height::from(10), &create_request_id(123)),
            Action::Drop
        );

        // Messages for signatures currently requested
        let action = Action::action(&block_reader, Height::from(100), &id_1);
        match action {
            Action::Process(_) => {}
            _ => panic!("Unexpected action: {:?}", action),
        }

        let action = Action::action(&block_reader, Height::from(10), &id_2);
        match action {
            Action::Process(_) => {}
            _ => panic!("Unexpected action: {:?}", action),
        }
    }

    // Tests that signature shares are sent for new requests, and requests already
    // in progress are filtered out.
    #[test]
    fn test_ecdsa_send_signature_shares() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut ecdsa_pool, signer) = create_signer_dependencies(pool_config, logger);
                let (id_1, id_2, id_3, id_4, id_5) = (
                    create_request_id(1),
                    create_request_id(2),
                    create_request_id(3),
                    create_request_id(4),
                    create_request_id(5),
                );

                // Set up the ECDSA pool. Pool has shares for requests 1, 2, 3.
                // Only the share for request 1 is issued by us
                let share_1 = create_signature_share(NODE_1, id_1.clone());
                let share_2 = create_signature_share(NODE_2, id_2);
                let share_3 = create_signature_share(NODE_3, id_3);
                let change_set = vec![
                    EcdsaChangeAction::AddToValidated(EcdsaMessage::EcdsaSigShare(share_1)),
                    EcdsaChangeAction::AddToValidated(EcdsaMessage::EcdsaSigShare(share_2)),
                    EcdsaChangeAction::AddToValidated(EcdsaMessage::EcdsaSigShare(share_3)),
                ];
                ecdsa_pool.apply_changes(change_set);

                // Set up the signature requests
                // The block requests signatures 1, 4, 5
                let block_reader = TestEcdsaBlockReader::for_signer_test(
                    Height::from(100),
                    vec![
                        (id_1, create_sig_inputs(1)),
                        (id_4.clone(), create_sig_inputs(4)),
                        (id_5.clone(), create_sig_inputs(5)),
                    ],
                );

                // Since request 1 is already in progress, we should issue
                // shares only for transcripts 4, 5
                let change_set = signer.send_signature_shares(&ecdsa_pool, &block_reader);
                assert_eq!(change_set.len(), 2);
                assert!(is_signature_share_added_to_validated(
                    &change_set,
                    &id_4,
                    block_reader.height()
                ));
                assert!(is_signature_share_added_to_validated(
                    &change_set,
                    &id_5,
                    block_reader.height()
                ));
            })
        })
    }

    // Tests that received dealings are accepted/processed for eligible signature
    // requests, and others dealings are either deferred or dropped.
    #[test]
    fn test_ecdsa_validate_signature_shares() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut ecdsa_pool, signer) = create_signer_dependencies(pool_config, logger);
                let time_source = FastForwardTimeSource::new();
                let (id_1, id_2, id_3, id_4) = (
                    create_request_id(1),
                    create_request_id(2),
                    create_request_id(3),
                    create_request_id(4),
                );

                // Set up the transcript creation request
                // The block requests transcripts 2, 3
                let block_reader = TestEcdsaBlockReader::for_signer_test(
                    Height::from(100),
                    vec![
                        (id_2.clone(), create_sig_inputs(2)),
                        (id_3.clone(), create_sig_inputs(3)),
                    ],
                );

                // Set up the ECDSA pool
                // A share from a node ahead of us (deferred)
                let mut share = create_signature_share(NODE_2, id_1);
                share.requested_height = Height::from(200);
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaSigShare(share),
                    peer_id: NODE_2,
                    timestamp: time_source.get_relative_time(),
                });

                // A share for a request in the finalized block (accepted)
                let mut share = create_signature_share(NODE_2, id_2);
                share.requested_height = Height::from(100);
                let key = share.key();
                let msg_id_2 = EcdsaSigShare::key_to_outer_hash(&key);
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaSigShare(share),
                    peer_id: NODE_2,
                    timestamp: time_source.get_relative_time(),
                });

                // A share for a request in the finalized block (accepted)
                let mut share = create_signature_share(NODE_2, id_3);
                share.requested_height = Height::from(10);
                let key = share.key();
                let msg_id_3 = EcdsaSigShare::key_to_outer_hash(&key);
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaSigShare(share),
                    peer_id: NODE_2,
                    timestamp: time_source.get_relative_time(),
                });

                // A share for a request not in the finalized block (dropped)
                let mut share = create_signature_share(NODE_2, id_4);
                share.requested_height = Height::from(5);
                let key = share.key();
                let msg_id_4 = EcdsaSigShare::key_to_outer_hash(&key);
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaSigShare(share),
                    peer_id: NODE_2,
                    timestamp: time_source.get_relative_time(),
                });

                let change_set = signer.validate_signature_shares(&ecdsa_pool, &block_reader);
                assert_eq!(change_set.len(), 3);
                assert!(is_moved_to_validated(&change_set, &msg_id_2));
                assert!(is_moved_to_validated(&change_set, &msg_id_3));
                assert!(is_removed_from_unvalidated(&change_set, &msg_id_4));
            })
        })
    }

    // Tests that duplicate shares from a signer for the same request
    // are dropped.
    #[test]
    fn test_ecdsa_duplicate_signature_shares() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut ecdsa_pool, signer) = create_signer_dependencies(pool_config, logger);
                let time_source = FastForwardTimeSource::new();
                let id_2 = create_request_id(2);

                // Set up the ECDSA pool
                // Validated pool has: {signature share 2, signer = NODE_2}
                let share = create_signature_share(NODE_2, id_2.clone());
                let change_set = vec![EcdsaChangeAction::AddToValidated(
                    EcdsaMessage::EcdsaSigShare(share),
                )];
                ecdsa_pool.apply_changes(change_set);

                // Unvalidated pool has: {signature share 2, signer = NODE_2, height = 100}
                let mut share = create_signature_share(NODE_2, id_2.clone());
                share.requested_height = Height::from(100);
                let key = share.key();
                let msg_id_2 = EcdsaSigShare::key_to_outer_hash(&key);
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaSigShare(share),
                    peer_id: NODE_2,
                    timestamp: time_source.get_relative_time(),
                });

                let block_reader = TestEcdsaBlockReader::for_signer_test(
                    Height::from(100),
                    vec![(id_2, create_sig_inputs(2))],
                );

                let change_set = signer.validate_signature_shares(&ecdsa_pool, &block_reader);
                assert_eq!(change_set.len(), 1);
                assert!(is_handle_invalid(&change_set, &msg_id_2));
            })
        })
    }

    // Tests that duplicate shares from a signer for the same request
    // in the unvalidated pool are dropped.
    #[test]
    fn test_ecdsa_duplicate_signature_shares_in_batch() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let (mut ecdsa_pool, signer) = create_signer_dependencies(pool_config, logger);
                let time_source = FastForwardTimeSource::new();
                let id_2 = create_request_id(2);

                // Unvalidated pool has: {signature share 2, signer = NODE_2, height = 100}
                let mut share = create_signature_share(NODE_2, id_2.clone());
                share.requested_height = Height::from(100);
                let key = share.key();
                let msg_id_2_a = EcdsaSigShare::key_to_outer_hash(&key);
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaSigShare(share),
                    peer_id: NODE_2,
                    timestamp: time_source.get_relative_time(),
                });

                // Unvalidated pool has: {signature share 2, signer = NODE_2, height = 10}
                let mut share = create_signature_share(NODE_2, id_2.clone());
                share.requested_height = Height::from(10);
                let key = share.key();
                let msg_id_2_b = EcdsaSigShare::key_to_outer_hash(&key);
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaSigShare(share),
                    peer_id: NODE_2,
                    timestamp: time_source.get_relative_time(),
                });

                // Unvalidated pool has: {signature share 2, signer = NODE_3, height = 90}
                let mut share = create_signature_share(NODE_3, id_2.clone());
                share.requested_height = Height::from(10);
                let key = share.key();
                let msg_id_3 = EcdsaSigShare::key_to_outer_hash(&key);
                ecdsa_pool.insert(UnvalidatedArtifact {
                    message: EcdsaMessage::EcdsaSigShare(share),
                    peer_id: NODE_3,
                    timestamp: time_source.get_relative_time(),
                });

                let block_reader = TestEcdsaBlockReader::for_signer_test(
                    Height::from(100),
                    vec![(id_2, create_sig_inputs(2))],
                );

                let change_set = signer.validate_signature_shares(&ecdsa_pool, &block_reader);
                assert_eq!(change_set.len(), 3);
                assert!(is_handle_invalid(&change_set, &msg_id_2_a));
                assert!(is_handle_invalid(&change_set, &msg_id_2_b));
                assert!(is_moved_to_validated(&change_set, &msg_id_3));
            })
        })
    }
}
