use crate::IngressManager;
use ic_constants::MAX_INGRESS_TTL;
use ic_interfaces::{
    ingress_pool::{
        ChangeAction::{
            MoveToValidated, PurgeBelowExpiry, RemoveFromUnvalidated, RemoveFromValidated,
        },
        ChangeSet, IngressPool,
    },
    p2p::consensus::ChangeSetProducer,
};
use ic_logger::{debug, warn};
use ic_types::{artifact::IngressMessageId, ingress::IngressStatus, CountBytes};

impl<T: IngressPool> ChangeSetProducer<T> for IngressManager {
    type ChangeSet = ChangeSet;

    #[allow(clippy::cognitive_complexity)]
    fn on_state_change(&self, pool: &T) -> ChangeSet {
        // Skip on_state_change when ingress_message_setting is not available in
        // registry.
        let registry_version = self.registry_client.get_latest_version();
        let ingress_message_settings = match self.get_ingress_message_settings(registry_version) {
            Some(settings) => settings,
            None => return ChangeSet::new(),
        };

        let _timer = self.metrics.ingress_handler_time.start_timer();
        let get_status = self.ingress_hist_reader.get_latest_status();

        // Do not run on_state_change if consensus_time is not initialized yet.
        let consensus_time = match self.consensus_time.consensus_time() {
            Some(time) => time,
            None => return ChangeSet::new(),
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
        let unvalidated_artifacts = pool
            .unvalidated()
            .get_all_by_expiry_range(expiry_range.clone());
        change_set.extend(unvalidated_artifacts.map(|artifact| {
            let ingress_object = &artifact.message;
            let ingress_message = &ingress_object.signed_ingress;
            let max_ingress_bytes_per_message =
                ingress_message_settings.max_ingress_bytes_per_message;
            // If the message is too large, consider the ingress message invalid
            let size = ingress_object.count_bytes();
            if size > max_ingress_bytes_per_message {
                warn!(
                    self.log,
                    "ingress_message_remove_unvalidated";
                    ingress_message.message_id => format!("{}", ingress_object.message_id),
                    ingress_message.reason => "message_too_large",
                    ingress_message.size => size as u64,
                );
                return RemoveFromUnvalidated(IngressMessageId::from(ingress_object));
            }

            // Check status of the ingress message against IngressHistoryReader,
            // If Unknown, consider the ingress message valid
            let status = get_status(&ingress_object.message_id);
            if status != IngressStatus::Unknown {
                debug!(
                    self.log,
                    "ingress_message_remove_unvalidated";
                    ingress_message.message_id => format!("{}", ingress_object.message_id),
                    ingress_message.reason => format!("unexpected_status_{}", status.as_str()),
                );
                return RemoveFromUnvalidated(IngressMessageId::from(ingress_object));
            }

            // Check signatures, remove from unvalidated if they can't be
            // verified, add to validated otherwise.
            //
            // Note that consensus_time is used here instead of current_time,
            // in order to be consistent with expiry_range, which imposes
            // a precondition that all messages processed here are in range.
            if let Err(err) = self.request_validator.validate_request(
                ingress_message.as_ref(),
                consensus_time,
                &self.registry_root_of_trust_provider(registry_version),
            ) {
                debug!(
                    self.log,
                    "ingress_message_remove_unvalidated";
                    ingress_message.message_id => format!("{}", ingress_object.message_id),
                    ingress_message.reason => format!("auth_failure: {}", err),
                );
                return RemoveFromUnvalidated(IngressMessageId::from(ingress_object));
            }

            debug!(
                self.log,
                "ingress_message_insert_validated";
                ingress_message.message_id => format!("{}", ingress_object.message_id),
            );
            MoveToValidated((
                IngressMessageId::from(ingress_object),
                artifact.peer_id,
                size,
            ))
        }));

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
    use ic_types::ingress::{IngressState, IngressStatus};
    use ic_types::time::UNIX_EPOCH;
    use std::sync::Arc;
    use std::time::Duration;

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
            |ingress_manager, ingress_pool| {
                let ingress_message = SignedIngressBuilder::new()
                    .expiry_time(time + MAX_INGRESS_TTL)
                    .nonce(2)
                    .sign_for_randomly_generated_sender()
                    .build();
                let message_id = IngressMessageId::from(&ingress_message);

                let change_set = access_ingress_pool(&ingress_pool, |ingress_pool| {
                    ingress_pool.insert(UnvalidatedArtifact {
                        message: ingress_message.clone(),
                        peer_id: node_test_id(0),
                        timestamp: time,
                    });
                    ingress_manager.on_state_change(ingress_pool)
                });

                let size = ingress_message.count_bytes();
                let expected_change_action =
                    ChangeAction::MoveToValidated((message_id, node_test_id(0), size));
                assert!(change_set.contains(&expected_change_action));
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
            |ingress_manager, ingress_pool| {
                let ingress_message = SignedIngressBuilder::new()
                    .expiry_time(time + MAX_INGRESS_TTL)
                    .nonce(2)
                    .sign_for_randomly_generated_sender()
                    .build();
                let message_id = IngressMessageId::from(&ingress_message);

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
            |ingress_manager, ingress_pool| {
                let good_msg = SignedIngressBuilder::new()
                    .expiry_time(current_time + MAX_INGRESS_TTL / 2)
                    .sign_for_randomly_generated_sender()
                    .build();
                let bad_msg = SignedIngressBuilder::new()
                    .expiry_time(current_time + MAX_INGRESS_TTL)
                    .sign_for_randomly_generated_sender()
                    .nonce(4)
                    .build();

                let change_set = access_ingress_pool(&ingress_pool, |ingress_pool| {
                    ingress_pool.insert(UnvalidatedArtifact {
                        message: good_msg.clone(),
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

                let good_id = IngressMessageId::from(&good_msg);
                let bad_id = IngressMessageId::from(&bad_msg);
                let expected_change_action0 = PurgeBelowExpiry(batch_time);
                let expected_change_action1 = ChangeAction::MoveToValidated((
                    good_id,
                    node_test_id(0),
                    good_msg.count_bytes(),
                ));
                let expected_change_action2 = ChangeAction::RemoveFromUnvalidated(bad_id);
                assert_eq!(change_set.len(), 3);
                assert!(change_set.contains(&expected_change_action0));
                assert!(change_set.contains(&expected_change_action1));
                assert!(change_set.contains(&expected_change_action2));
            },
        )
    }
}
