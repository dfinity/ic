use ic_config::execution_environment::Config;
use ic_error_types::{ErrorCode::CanisterNotFound, UserError};
use ic_execution_environment::{IngressHistoryReaderImpl, IngressHistoryWriterImpl};
use ic_interfaces::execution_environment::{IngressHistoryReader, IngressHistoryWriter};
use ic_interfaces_state_manager::Labeled;
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::ReplicatedState;
use ic_test_utilities::{
    mock_time,
    state_manager::MockStateManager,
    types::ids::{canister_test_id, message_test_id, subnet_test_id, user_test_id},
    with_test_replica_logger,
};
use ic_types::{
    ingress::{IngressState, IngressStatus, WasmResult},
    Height,
};
use IngressStatus::*;

#[test]
fn get_status_for_non_existing_message_id() {
    let mut state_manager = MockStateManager::new();
    state_manager
        .expect_get_latest_state()
        .times(1)
        .returning(|| {
            Labeled::new(
                Height::new(0),
                std::sync::Arc::new(ReplicatedState::new_rooted_at(
                    subnet_test_id(1),
                    SubnetType::Application,
                    "NOT_USED".into(),
                )),
            )
        });

    let state_manager = std::sync::Arc::new(state_manager);
    let ingress_history_handler = IngressHistoryReaderImpl::new(state_manager);

    let message_id = message_test_id(1);
    let history = (ingress_history_handler.get_latest_status())(&message_id);
    assert_eq!(history, IngressStatus::Unknown);
}

fn received() -> IngressStatus {
    Known {
        receiver: canister_test_id(0).get(),
        user_id: user_test_id(0),
        time: mock_time(),
        state: IngressState::Received,
    }
}

fn processing() -> IngressStatus {
    Known {
        receiver: canister_test_id(0).get(),
        user_id: user_test_id(0),
        time: mock_time(),
        state: IngressState::Processing,
    }
}

fn completed() -> IngressStatus {
    Known {
        receiver: canister_test_id(0).get(),
        user_id: user_test_id(0),
        time: mock_time(),
        state: IngressState::Completed(WasmResult::Reply(vec![])),
    }
}

fn failed() -> IngressStatus {
    Known {
        receiver: canister_test_id(0).get(),
        user_id: user_test_id(0),
        time: mock_time(),
        state: IngressState::Failed(UserError::new(CanisterNotFound, "")),
    }
}

fn valid_transitions() -> Vec<(IngressStatus, Vec<IngressStatus>)> {
    vec![
        (
            Unknown,
            vec![Unknown, received(), processing(), completed(), failed()],
        ),
        (received(), vec![processing(), completed(), failed()]),
        (processing(), vec![processing(), completed(), failed()]),
    ]
}

#[test]
fn test_valid_transitions() {
    with_test_replica_logger(|log| {
        let state = ReplicatedState::new_rooted_at(
            subnet_test_id(1),
            SubnetType::Application,
            "NOT_USED".into(),
        );
        let ingress_history_writer =
            IngressHistoryWriterImpl::new(Config::default(), log, &MetricsRegistry::new());
        let message_id = message_test_id(1);

        for (origin_state, next_states) in valid_transitions().into_iter() {
            let mut state = state.clone();
            ingress_history_writer.set_status(&mut state, message_id.clone(), origin_state);

            for next_state in next_states {
                let mut state = state.clone();
                ingress_history_writer.set_status(
                    &mut state,
                    message_id.clone(),
                    next_state.clone(),
                );
                assert_eq!(state.get_ingress_status(&message_id), next_state);
            }
        }
    })
}

#[test]
fn test_invalid_transitions() {
    with_test_replica_logger(|log| {
        let ingress_history_writer =
            IngressHistoryWriterImpl::new(Config::default(), log, &MetricsRegistry::new());
        let message_id = message_test_id(1);

        // creates a set of valid transitions
        use std::collections::HashSet;
        let valid_transitions = valid_transitions()
            .into_iter()
            .flat_map(|(origin, next_states)| {
                next_states
                    .into_iter()
                    .map(move |next| (origin.clone(), next))
            })
            .collect::<HashSet<(IngressStatus, IngressStatus)>>();

        let all_statuses = vec![Unknown, received(), processing(), completed(), failed()];
        // creates the cartesian product of all states and filters out the valid
        // transitions

        for (origin_state, next_state) in all_statuses
            .iter()
            .flat_map(|from| {
                all_statuses
                    .iter()
                    .map(move |to| (from.clone(), to.clone()))
            })
            .filter(|t| !valid_transitions.contains(t))
        {
            // ingress_history_writer contains a prometheus::Histogram which is not
            // unwind-safe. It doesn't matter for the purposes of this test.
            let ingress_history_writer = std::panic::AssertUnwindSafe(&ingress_history_writer);
            let result = std::panic::catch_unwind(|| {
                let mut state = ReplicatedState::new_rooted_at(
                    subnet_test_id(1),
                    SubnetType::Application,
                    "NOT_USED".into(),
                );
                ingress_history_writer.set_status(
                    &mut state,
                    message_id.clone(),
                    origin_state.clone(),
                );
                ingress_history_writer.set_status(
                    &mut state,
                    message_id.clone(),
                    next_state.clone(),
                )
            });
            assert!(
                result.is_err(),
                "transition from {:?} to {:?} worked but should have failed",
                origin_state,
                next_state
            );
        }
    })
}
