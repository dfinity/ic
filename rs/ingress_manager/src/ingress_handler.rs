use crate::IngressManager;
use ic_constants::MAX_INGRESS_TTL;
use ic_interfaces::{
    ingress_pool::{
        ChangeAction::{
            MoveToValidated, PurgeBelowExpiry, RemoveFromUnvalidated, RemoveFromValidated,
        },
        ChangeSet, IngressPool, IngressPoolObject,
    },
    p2p::consensus::ChangeSetProducer,
};
use ic_logger::debug;
use ic_registry_client_helpers::subnet::IngressMessageSettings;
use ic_types::{
    artifact::IngressMessageId, ingress::IngressStatus, messages::MessageId, CountBytes,
    RegistryVersion, Time,
};
use ic_validator::RequestValidationError;

impl<T: IngressPool> ChangeSetProducer<T> for IngressManager {
    type ChangeSet = ChangeSet;

    fn on_state_change(&self, pool: &T) -> ChangeSet {
        // Skip on_state_change when ingress_message_setting is not available in
        // registry.
        let registry_version = self.registry_client.get_latest_version();
        let Some(ingress_message_settings) = self.get_ingress_message_settings(registry_version)
        else {
            return ChangeSet::new();
        };

        let _timer = self.metrics.ingress_handler_time.start_timer();
        let get_status = self.ingress_hist_reader.get_latest_status();

        // Do not run on_state_change if consensus_time is not initialized yet.
        let Some(consensus_time) = self.consensus_time.consensus_time() else {
            return ChangeSet::new();
        };

        let mut change_set = Vec::new();

        // Purge only when consensus_time has changed.
        let mut last_purge_time = self.last_purge_time.write().unwrap();
        if consensus_time != *last_purge_time {
            *last_purge_time = consensus_time;
            change_set.push(PurgeBelowExpiry(consensus_time));
        }

        let current_time = self.time_source.get_relative_time();
        let expiry_range = current_time..=(current_time + MAX_INGRESS_TTL);

        // looks at the unvalidated ingress messages and
        // 1. either discards them
        // 2. or moves them to validated.
        let unvalidated_artifacts_changeset = pool
            .unvalidated()
            .get_all_by_expiry_range(expiry_range.clone())
            .map(|artifact| {
                let ingress_object = &artifact.message;

                // If the ingress pool is full, discard the message.
                // Note: since here we don't remove ingress messages from the ingress pool directly,
                // if `exceeds_limit` returns `true` for a peer `p`, we will remove *all*
                // unvalidated ingress messages originating from that peer. This should be okay, as
                // we don't expect to have many unvalidated ingress messages in the pool at any
                // time, because we call `on_state_change` at most every 200ms and every time we
                // receive an ingress message from a peer. Historically, we have had at most 2
                // unvalidated ingress messages in the pool.
                // Since we plan(IC-1718) to have only one section in the Ingress Pool and to
                // validate ingress messages on-the-fly, this problem will eventually go away.
                if pool.exceeds_limit(&ingress_object.originator_id) {
                    return RemoveFromUnvalidated(IngressMessageId::from(ingress_object));
                }

                match self.validate_ingress_pool_object(
                    ingress_object,
                    &ingress_message_settings,
                    get_status.as_ref(),
                    consensus_time,
                    registry_version,
                ) {
                    Ok(()) => MoveToValidated(IngressMessageId::from(ingress_object)),
                    Err(err) => {
                        debug!(
                            self.log,
                            "ingress_message_remove_unvalidated";
                            ingress_message.message_id => ingress_object.message_id.to_string(),
                            ingress_message.reason => err.to_string(),
                        );

                        RemoveFromUnvalidated(IngressMessageId::from(ingress_object))
                    }
                }
            });

        change_set.extend(unvalidated_artifacts_changeset);

        // Check validated messages and remove if they are not required anymore (i.e.
        // IngressHistoryReader returns status other than Unknown).
        for validated_artifact in pool.validated().get_all_by_expiry_range(expiry_range) {
            let ingress_object = &validated_artifact.msg;

            // Check status of the ingress message against IngressHistoryReader,
            // If Unknown, consider the ingress message valid
            let status = get_status(&ingress_object.message_id);
            if status != IngressStatus::Unknown {
                debug!(
                    self.log,
                    "ingress_message_remove_validated";
                    ingress_message.message_id => format!("{}", ingress_object.message_id),
                    ingress_message.reason => format!("{:?}", status),
                );
                change_set.push(RemoveFromValidated(IngressMessageId::from(ingress_object)));
            }
        }

        // Also include finalized messages that were requested to purge.
        let mut to_purge = self.messages_to_purge.write().unwrap();
        while let Some(message_ids) = to_purge.pop() {
            message_ids
                .into_iter()
                .for_each(|id| change_set.push(RemoveFromValidated(id)))
        }

        change_set
    }
}

enum IngressMessageValidationError {
    IngressMessageTooLarge { max: usize, actual: usize },
    UnexpectedStatus(IngressStatus),
    InvalidRequest(RequestValidationError),
}

impl std::fmt::Display for IngressMessageValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IngressMessageValidationError::IngressMessageTooLarge { max, actual } => {
                write!(f, "Ingress Message is too large {} > {}", actual, max)
            }
            IngressMessageValidationError::UnexpectedStatus(status) => write!(
                f,
                "Ingress Message is not `Unknown` to the IngressHistoryReader: {:?}",
                status
            ),
            IngressMessageValidationError::InvalidRequest(error) => {
                write!(f, "Ingress Message failed validation: {}", error)
            }
        }
    }
}

impl IngressManager {
    fn validate_ingress_pool_object(
        &self,
        ingress_object: &IngressPoolObject,
        settings: &IngressMessageSettings,
        ingress_message_status: impl Fn(&MessageId) -> IngressStatus,
        consensus_time: Time,
        registry_version: RegistryVersion,
    ) -> Result<(), IngressMessageValidationError> {
        // If the message is too large, consider the ingress message invalid
        let size = ingress_object.count_bytes();
        if size > settings.max_ingress_bytes_per_message {
            return Err(IngressMessageValidationError::IngressMessageTooLarge {
                max: settings.max_ingress_bytes_per_message,
                actual: size,
            });
        }

        let status = ingress_message_status(&ingress_object.message_id);
        if status != IngressStatus::Unknown {
            return Err(IngressMessageValidationError::UnexpectedStatus(status));
        }

        // Check signatures, remove from unvalidated if they can't be
        // verified, add to validated otherwise.
        //
        // Note that consensus_time is used here instead of current_time,
        // in order to be consistent with expiry_range, which imposes
        // a precondition that all messages processed here are in range.
        if let Err(err) = self.request_validator.validate_request(
            ingress_object.signed_ingress.as_ref(),
            consensus_time,
            &self.registry_root_of_trust_provider(registry_version),
        ) {
            return Err(IngressMessageValidationError::InvalidRequest(err));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{access_ingress_pool, setup_with_params};
    use ic_interfaces::{
        ingress_pool::ChangeAction,
        p2p::consensus::{MutablePool, UnvalidatedArtifact},
        time_source::TimeSource,
    };
    use ic_interfaces_mocks::consensus_pool::MockConsensusTime;
    use ic_interfaces_state_manager::StateManager;
    use ic_test_utilities::state_manager::FakeStateManager;
    use ic_test_utilities_state::MockIngressHistory;
    use ic_test_utilities_time::FastForwardTimeSource;
    use ic_test_utilities_types::{
        ids::{canister_test_id, node_test_id, user_test_id},
        messages::SignedIngressBuilder,
    };
    use ic_types::time::UNIX_EPOCH;
    use ic_types::{
        ingress::{IngressState, IngressStatus},
        messages::SignedIngress,
    };
    use std::time::Duration;
    use std::{collections::HashSet, sync::Arc};

    #[tokio::test]
    async fn test_ingress_on_state_change_valid() {
        let time = UNIX_EPOCH;
        let mut consensus_time = MockConsensusTime::new();
        consensus_time
            .expect_consensus_time()
            .return_const(Some(time));
        let mut ingress_hist_reader = Box::new(MockIngressHistory::new());
        ingress_hist_reader
            .expect_get_latest_status()
            .returning(|| Box::new(|_| IngressStatus::Unknown {}));

        setup_with_params(
            Some(ingress_hist_reader),
            None,
            Some(Arc::new(consensus_time)),
            None,
            /*ingress_pool_max_count=*/ None,
            |ingress_manager, ingress_pool| {
                let (ingress_message, message_id) = fake_ingress_message(time + MAX_INGRESS_TTL, 2);

                let change_set = access_ingress_pool(&ingress_pool, |ingress_pool| {
                    ingress_pool.insert(UnvalidatedArtifact {
                        message: ingress_message.clone(),
                        peer_id: node_test_id(0),
                        timestamp: time,
                    });
                    ingress_manager.on_state_change(ingress_pool)
                });

                let expected_change_action = ChangeAction::MoveToValidated(message_id);
                assert!(change_set.contains(&expected_change_action));
            },
        )
    }

    #[tokio::test]
    async fn test_ingress_on_state_change_too_many_get_removed() {
        let time = UNIX_EPOCH;
        let mut consensus_time = MockConsensusTime::new();
        consensus_time
            .expect_consensus_time()
            .return_const(Some(time));
        let mut ingress_hist_reader = Box::new(MockIngressHistory::new());
        ingress_hist_reader
            .expect_get_latest_status()
            .returning(|| Box::new(|_| IngressStatus::Unknown {}));

        setup_with_params(
            Some(ingress_hist_reader),
            None,
            Some(Arc::new(consensus_time)),
            None,
            Some(1),
            |ingress_manager, ingress_pool| {
                let peer_id = node_test_id(0);
                let peer_id_2 = node_test_id(1);

                let (ingress_message_1, message_id_1) =
                    fake_ingress_message(time + MAX_INGRESS_TTL, 1);
                let (ingress_message_2, message_id_2) =
                    fake_ingress_message(time + MAX_INGRESS_TTL, 2);
                let (ingress_message_3, message_id_3) =
                    fake_ingress_message(time + MAX_INGRESS_TTL, 3);

                ingress_pool.write().unwrap().insert(UnvalidatedArtifact {
                    message: ingress_message_1,
                    peer_id,
                    timestamp: time,
                });
                ingress_pool
                    .write()
                    .unwrap()
                    .apply_changes(vec![ChangeAction::MoveToValidated(message_id_1)]);

                let change_set = access_ingress_pool(&ingress_pool, |ingress_pool| {
                    ingress_pool.insert(UnvalidatedArtifact {
                        message: ingress_message_2,
                        peer_id,
                        timestamp: time,
                    });
                    ingress_pool.insert(UnvalidatedArtifact {
                        message: ingress_message_3,
                        peer_id: peer_id_2,
                        timestamp: time,
                    });

                    ingress_manager.on_state_change(ingress_pool)
                });
                let change_set = HashSet::from_iter(change_set);

                let expected_change_set = HashSet::from([
                    // `message_3` is valid and there is still space in the ingress pool for it
                    ChangeAction::MoveToValidated(message_id_3),
                    // `message_2` is removed because we already have too many ingresses from
                    // `peer_0`.
                    ChangeAction::RemoveFromUnvalidated(message_id_2),
                ]);

                assert_eq!(change_set, expected_change_set);
            },
        )
    }

    #[tokio::test]
    async fn test_ingress_on_state_change_invalid() {
        let time = UNIX_EPOCH;
        let mut consensus_time = MockConsensusTime::new();
        consensus_time
            .expect_consensus_time()
            .return_const(Some(time));

        let mut ingress_hist_reader = Box::new(MockIngressHistory::new());
        ingress_hist_reader
            .expect_get_latest_status()
            .returning(|| {
                Box::new(|_| IngressStatus::Known {
                    receiver: canister_test_id(0).get(),
                    user_id: user_test_id(0),
                    time: UNIX_EPOCH,
                    state: IngressState::Received,
                })
            });

        setup_with_params(
            Some(ingress_hist_reader),
            None,
            Some(Arc::new(consensus_time)),
            None,
            /*ingress_pool_max_count=*/ None,
            |ingress_manager, ingress_pool| {
                let ingress_message = SignedIngressBuilder::new()
                    .expiry_time(time + MAX_INGRESS_TTL)
                    .nonce(2)
                    .build();
                let message_id = IngressMessageId::from(&ingress_message);

                let change_set = access_ingress_pool(&ingress_pool, |ingress_pool| {
                    ingress_pool.insert(UnvalidatedArtifact {
                        message: ingress_message,
                        peer_id: node_test_id(0),
                        timestamp: time,
                    });
                    ingress_manager.on_state_change(ingress_pool)
                });

                let expected_change_action = ChangeAction::RemoveFromUnvalidated(message_id);
                assert!(change_set.contains(&expected_change_action));
            },
        )
    }

    /// Verify that a message with an expiry time after MAX_INGRESS_TTL is
    /// removed from the unvalidated pool
    #[tokio::test]
    async fn test_ingress_on_state_change_invalid_expiry() {
        let mut ingress_hist_reader = Box::new(MockIngressHistory::new());
        ingress_hist_reader
            .expect_get_latest_status()
            .returning(|| Box::new(|_| IngressStatus::Unknown));

        let time_source = FastForwardTimeSource::new();
        let state_manager = FakeStateManager::new();
        let (_height, state) = state_manager.take_tip();
        let batch_time = state.system_metadata().batch_time + Duration::from_secs(1);

        let mut consensus_time = MockConsensusTime::new();
        consensus_time
            .expect_consensus_time()
            .return_const(Some(batch_time));

        setup_with_params(
            Some(ingress_hist_reader),
            None,
            Some(Arc::new(consensus_time)),
            None,
            /*ingress_pool_max_count=*/ None,
            |ingress_manager, ingress_pool| {
                // Message should expire at the current time, and should not be selected
                let ingress_message = SignedIngressBuilder::new()
                    .expiry_time(batch_time + MAX_INGRESS_TTL + Duration::from_nanos(1))
                    .nonce(2)
                    .build();
                let change_set = access_ingress_pool(&ingress_pool, |ingress_pool| {
                    ingress_pool.insert(UnvalidatedArtifact {
                        message: ingress_message,
                        peer_id: node_test_id(0),
                        timestamp: time_source.get_relative_time(),
                    });
                    ingress_manager.on_state_change(ingress_pool)
                });

                // Since we changed to PurgeBelowExpiry insteads of individual removal,
                // It is enough to check if there is PurgeBelowExpiry, and nothing being
                // moved to validated.
                assert_eq!(change_set.len(), 1);
                let expected_action = PurgeBelowExpiry(batch_time);
                assert!(change_set.contains(&expected_action));
            },
        )
    }

    #[tokio::test]
    async fn test_ingress_on_state_change_remove_validated() {
        let mut ingress_hist_reader = Box::new(MockIngressHistory::new());
        ingress_hist_reader
            .expect_get_latest_status()
            .times(1)
            .returning(|| Box::new(|_| IngressStatus::Unknown));
        ingress_hist_reader
            .expect_get_latest_status()
            .times(1)
            .returning(|| {
                Box::new(|_| IngressStatus::Known {
                    receiver: canister_test_id(0).get(),
                    user_id: user_test_id(0),
                    time: UNIX_EPOCH,
                    state: IngressState::Received,
                })
            });

        let time = UNIX_EPOCH;

        let mut consensus_time = MockConsensusTime::new();
        consensus_time
            .expect_consensus_time()
            .return_const(Some(time));

        setup_with_params(
            Some(ingress_hist_reader),
            None,
            Some(Arc::new(consensus_time)),
            None,
            /*ingress_pool_max_count=*/ None,
            |ingress_manager, ingress_pool| {
                let (ingress_message, message_id) = fake_ingress_message(time + MAX_INGRESS_TTL, 2);

                let change_set = access_ingress_pool(&ingress_pool, |ingress_pool| {
                    ingress_pool.insert(UnvalidatedArtifact {
                        message: ingress_message,
                        peer_id: node_test_id(0),
                        timestamp: time,
                    });
                    let change_set = ingress_manager.on_state_change(ingress_pool);
                    ingress_pool.apply_changes(change_set);
                    ingress_manager.on_state_change(ingress_pool)
                });

                let expected_change_action = ChangeAction::RemoveFromValidated(message_id);
                assert!(change_set.contains(&expected_change_action));
            },
        )
    }

    #[tokio::test]
    async fn test_ingress_signature_verification() {
        let mut ingress_hist_reader = Box::new(MockIngressHistory::new());
        ingress_hist_reader
            .expect_get_latest_status()
            .returning(|| Box::new(|_| IngressStatus::Unknown));

        // Ensure that there is a state with a time of our choosing, so
        // we can select an appropriate expiry time for the message.
        // Furthermore, the time of choosing needs to be set to the current
        // time so that conversion to SignedIngress does not fail.
        let current_time = UNIX_EPOCH;
        let batch_time = current_time + Duration::from_secs(1);

        let mut consensus_time = MockConsensusTime::new();
        consensus_time
            .expect_consensus_time()
            .return_const(Some(batch_time));

        setup_with_params(
            Some(ingress_hist_reader),
            None,
            Some(Arc::new(consensus_time)),
            None,
            /*ingress_pool_max_count=*/ None,
            |ingress_manager, ingress_pool| {
                let (good_msg, good_id) =
                    fake_ingress_message(current_time + MAX_INGRESS_TTL / 2, 2);
                let bad_msg = SignedIngressBuilder::new()
                    .expiry_time(current_time + MAX_INGRESS_TTL)
                    .sign_for_randomly_generated_sender()
                    .nonce(4)
                    .build();
                let bad_id = IngressMessageId::from(&bad_msg);

                let change_set = access_ingress_pool(&ingress_pool, |ingress_pool| {
                    ingress_pool.insert(UnvalidatedArtifact {
                        message: good_msg,
                        peer_id: node_test_id(0),
                        timestamp: UNIX_EPOCH,
                    });
                    ingress_pool.insert(UnvalidatedArtifact {
                        message: bad_msg.clone(),
                        peer_id: node_test_id(0),
                        timestamp: UNIX_EPOCH,
                    });
                    ingress_manager.on_state_change(ingress_pool)
                });

                let expected_change_action0 = PurgeBelowExpiry(batch_time);
                let expected_change_action1 = ChangeAction::MoveToValidated(good_id);
                let expected_change_action2 = ChangeAction::RemoveFromUnvalidated(bad_id);
                assert_eq!(change_set.len(), 3);
                assert!(change_set.contains(&expected_change_action0));
                assert!(change_set.contains(&expected_change_action1));
                assert!(change_set.contains(&expected_change_action2));
            },
        )
    }

    fn fake_ingress_message(expiry_time: Time, nonce: u64) -> (SignedIngress, IngressMessageId) {
        let ingress_message = SignedIngressBuilder::new()
            .expiry_time(expiry_time)
            .nonce(nonce)
            .sign_for_randomly_generated_sender()
            .build();

        let message_id = IngressMessageId::from(&ingress_message);

        (ingress_message, message_id)
    }
}
