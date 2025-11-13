use super::*;

use assert_matches::assert_matches;
use ic_limits::SMALL_APP_SUBNET_MAX_SIZE;
use ic_logger::replica_logger::no_op_logger;
use ic_management_canister_types_private::{
    CanisterSettingsArgsBuilder, IC_00, Payload, UpdateSettingsArgs,
};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::testing::CanisterQueuesTesting;
use ic_test_utilities::cycles_account_manager::CyclesAccountManagerBuilder;
use ic_test_utilities_logger::with_test_replica_logger;
use ic_test_utilities_metrics::{
    HistogramStats, MetricVec, fetch_histogram_stats, fetch_int_counter_vec, metric_vec,
    nonzero_values,
};
use ic_test_utilities_state::{
    CanisterStateBuilder, MockIngressHistory, ReplicatedStateBuilder, get_running_canister,
    get_stopped_canister, get_stopping_canister,
};
use ic_test_utilities_types::{
    ids::{canister_test_id, message_test_id, node_test_id, subnet_test_id, user_test_id},
    messages::SignedIngressBuilder,
};
use ic_types::{
    CanisterId,
    batch::CanisterCyclesCostSchedule,
    ingress::{IngressState, IngressStatus},
    messages::{MessageId, SignedIngress},
    time::UNIX_EPOCH,
};
use mockall::predicate::{always, eq};

struct NoopIngressHistoryWriter;

impl IngressHistoryWriter for NoopIngressHistoryWriter {
    type State = ReplicatedState;

    fn set_status(
        &self,
        _state: &mut ReplicatedState,
        _message_id: MessageId,
        _status: IngressStatus,
    ) -> Arc<IngressStatus> {
        IngressStatus::Unknown.into()
    }
}

fn insert_canister(state: &mut ReplicatedState, canister_id: CanisterId) {
    state.put_canister_state(
        CanisterStateBuilder::new()
            .with_canister_id(canister_id)
            .build(),
    );
}

fn ingress_queue_size(state: &ReplicatedState, canister_id: CanisterId) -> usize {
    state
        .canister_state(&canister_id)
        .unwrap()
        .system_state
        .queues()
        .ingress_queue_size()
}

/// Asserts that the values of the `METRIC_INDUCTED_INGRESS_MESSAGES` metric
/// match for the given statuses and are zero for all other statuses.
fn assert_inducted_ingress_messages_eq(
    expected: MetricVec<u64>,
    metrics_registry: &MetricsRegistry,
) {
    assert_eq!(
        expected,
        nonzero_values(fetch_int_counter_vec(
            metrics_registry,
            METRIC_INDUCTED_INGRESS_MESSAGES
        ))
    );
}

/// Retrieves the stats of the `METRIC_INDUCTED_PAYLOAD_SIZES` histogram.
fn fetch_inducted_payload_size_stats(metrics_registry: &MetricsRegistry) -> HistogramStats {
    fetch_histogram_stats(metrics_registry, METRIC_INDUCTED_INGRESS_PAYLOAD_SIZES)
        .unwrap_or_else(|| panic!("Histogram not found: {METRIC_INDUCTED_INGRESS_PAYLOAD_SIZES}"))
}

#[test]
fn induct_message_with_successful_history_update() {
    with_test_replica_logger(|log| {
        let payload = vec![1, 2, 4, 8];
        let payload_len = payload.len();
        let canister_id = canister_test_id(0);
        let signed_ingress = SignedIngressBuilder::new()
            .canister_id(canister_id)
            .sender(user_test_id(0))
            .method_payload(payload)
            .build();
        let msg = signed_ingress.content();
        let msg_id = msg.id();
        let mut ingress_history_writer = MockIngressHistory::new();
        ingress_history_writer
            .expect_set_status()
            .with(always(), eq(msg.id()), always())
            .times(1)
            .returning(move |state, _, _| {
                state.set_ingress_status(
                    msg_id.clone(),
                    IngressStatus::Known {
                        receiver: canister_id.get(),
                        user_id: user_test_id(0),
                        time: UNIX_EPOCH,
                        state: IngressState::Received,
                    },
                    NumBytes::from(u64::MAX),
                    |_| {},
                );
                IngressStatus::Unknown.into()
            });

        let ingress_history_writer = Arc::new(ingress_history_writer);
        let metrics_registry = MetricsRegistry::new();
        let subnet_type = SubnetType::Application;
        let cycles_account_manager = Arc::new(
            CyclesAccountManagerBuilder::new()
                .with_subnet_type(subnet_type)
                .build(),
        );
        let valid_set_rule = ValidSetRuleImpl::new(
            ingress_history_writer,
            cycles_account_manager,
            &metrics_registry,
            log,
        );

        let mut state = ReplicatedState::new(subnet_test_id(1), subnet_type);
        insert_canister(&mut state, canister_id);

        valid_set_rule.induct_message(&mut state, signed_ingress, SMALL_APP_SUBNET_MAX_SIZE);
        assert_eq!(ingress_queue_size(&state, canister_id), 1);
        assert_inducted_ingress_messages_eq(
            metric_vec(&[(&[(LABEL_STATUS, LABEL_VALUE_SUCCESS)], 1)]),
            &metrics_registry,
        );
        assert_eq!(
            HistogramStats {
                count: 1,
                sum: payload_len as f64
            },
            fetch_inducted_payload_size_stats(&metrics_registry)
        );
    });
}

#[test]
fn induct_message_fails_for_stopping_canister() {
    with_test_replica_logger(|log| {
        let canister_id = canister_test_id(0);
        let signed_ingress = SignedIngressBuilder::new()
            .canister_id(canister_id)
            .sender(user_test_id(2))
            .build();
        let msg = signed_ingress.content();
        let msg_id = msg.id();
        let mut ingress_history_writer = MockIngressHistory::new();
        ingress_history_writer
            .expect_set_status()
            .with(
                always(),
                eq(msg.id()),
                eq(IngressStatus::Known {
                    receiver: canister_id.get(),
                    user_id: user_test_id(2),
                    time: UNIX_EPOCH,
                    state: IngressState::Failed(UserError::new(
                        ErrorCode::CanisterStopping,
                        format!("Canister {canister_id} is stopping"),
                    )),
                }),
            )
            .times(1)
            .returning(move |state, _, status| {
                state.set_ingress_status(msg_id.clone(), status, NumBytes::from(u64::MAX), |_| {});
                IngressStatus::Unknown.into()
            });
        let ingress_history_writer = Arc::new(ingress_history_writer);
        let metrics_registry = MetricsRegistry::new();
        let valid_set_rule = ValidSetRuleImpl::new(
            ingress_history_writer,
            Arc::new(CyclesAccountManagerBuilder::new().build()),
            &metrics_registry,
            log,
        );

        let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);
        state.put_canister_state(get_stopping_canister(canister_id));

        valid_set_rule.induct_message(&mut state, signed_ingress, SMALL_APP_SUBNET_MAX_SIZE);
        assert_eq!(ingress_queue_size(&state, canister_id), 0);
        assert_inducted_ingress_messages_eq(
            metric_vec(&[(&[(LABEL_STATUS, LABEL_VALUE_CANISTER_STOPPING)], 1)]),
            &metrics_registry,
        );
        assert_eq!(
            0,
            fetch_inducted_payload_size_stats(&metrics_registry).count
        );
    });
}

#[test]
fn induct_message_fails_for_stopped_canister() {
    with_test_replica_logger(|log| {
        let canister_id = canister_test_id(0);
        let signed_ingress = SignedIngressBuilder::new()
            .canister_id(canister_id)
            .sender(user_test_id(2))
            .build();
        let msg = signed_ingress.content();
        let msg_id = msg.id();
        let mut ingress_history_writer = MockIngressHistory::new();
        ingress_history_writer
            .expect_set_status()
            .with(
                always(),
                eq(msg.id()),
                eq(IngressStatus::Known {
                    receiver: canister_id.get(),
                    user_id: user_test_id(2),
                    time: UNIX_EPOCH,
                    state: IngressState::Failed(UserError::new(
                        ErrorCode::CanisterStopped,
                        format!("Canister {canister_id} is stopped"),
                    )),
                }),
            )
            .times(1)
            .returning(move |state, _, status| {
                state.set_ingress_status(msg_id.clone(), status, NumBytes::from(u64::MAX), |_| {});
                IngressStatus::Unknown.into()
            });

        let ingress_history_writer = Arc::new(ingress_history_writer);
        let metrics_registry = MetricsRegistry::new();
        let valid_set_rule = ValidSetRuleImpl::new(
            ingress_history_writer,
            Arc::new(CyclesAccountManagerBuilder::new().build()),
            &metrics_registry,
            log,
        );

        let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);
        state.put_canister_state(get_stopped_canister(canister_id));

        valid_set_rule.induct_message(&mut state, signed_ingress, SMALL_APP_SUBNET_MAX_SIZE);
        assert_eq!(ingress_queue_size(&state, canister_id), 0);
        assert_inducted_ingress_messages_eq(
            metric_vec(&[(&[(LABEL_STATUS, LABEL_VALUE_CANISTER_STOPPED)], 1)]),
            &metrics_registry,
        );
        assert_eq!(
            0,
            fetch_inducted_payload_size_stats(&metrics_registry).count
        );
    });
}

#[test]
#[should_panic(expected = "duplicate message induction")]
fn try_to_induct_a_message_marked_as_already_inducted() {
    with_test_replica_logger(|log| {
        let canister_id = canister_test_id(0);
        let signed_ingress = SignedIngressBuilder::new().canister_id(canister_id).build();
        let msg = signed_ingress.content();

        let mut ingress_history_writer = MockIngressHistory::new();
        ingress_history_writer
            .expect_set_status()
            .with(always(), eq(msg.id()), always())
            .times(1)
            .returning(|_, _, _| panic!("duplicate message induction"));
        let ingress_history_writer = Arc::new(ingress_history_writer);
        let metrics_registry = MetricsRegistry::new();
        let valid_set_rule = ValidSetRuleImpl::new(
            ingress_history_writer,
            Arc::new(CyclesAccountManagerBuilder::new().build()),
            &metrics_registry,
            log,
        );

        let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);
        insert_canister(&mut state, canister_id);

        let status = IngressStatus::Known {
            receiver: canister_id.get(),
            user_id: user_test_id(0),
            time: UNIX_EPOCH,
            state: IngressState::Received,
        };
        state.set_ingress_status(msg.id(), status, NumBytes::from(u64::MAX), |_| {});
        valid_set_rule.induct_message(&mut state, signed_ingress, SMALL_APP_SUBNET_MAX_SIZE);
    });
}

#[test]
fn update_history_if_induction_failed() {
    with_test_replica_logger(|log| {
        let canister_id = canister_test_id(0);
        let signed_ingress = SignedIngressBuilder::new().canister_id(canister_id).build();
        let msg = signed_ingress.content();
        let msg_id = msg.id();

        let mut ingress_history_writer = MockIngressHistory::new();
        let canister_id = canister_test_id(0);
        let status = IngressStatus::Known {
            receiver: canister_id.get(),
            user_id: user_test_id(0),
            time: UNIX_EPOCH,
            state: IngressState::Failed(UserError::new(
                ErrorCode::CanisterNotFound,
                format!("Canister {canister_id} not found"),
            )),
        };
        let status_clone = status.clone();
        ingress_history_writer
            .expect_set_status()
            .with(always(), eq(msg.id()), always())
            .times(1)
            .returning(move |state, _, _| {
                state.set_ingress_status(
                    msg_id.clone(),
                    status.clone(),
                    NumBytes::from(u64::MAX),
                    |_| {},
                );
                IngressStatus::Unknown.into()
            });

        let ingress_history_writer = Arc::new(ingress_history_writer);
        let metrics_registry = MetricsRegistry::new();
        let valid_set_rule = ValidSetRuleImpl::new(
            ingress_history_writer,
            Arc::new(CyclesAccountManagerBuilder::new().build()),
            &metrics_registry,
            log,
        );

        let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);
        // The induction is expected to fail because there is no canister 0 in the
        // ReplicatedState.
        valid_set_rule.induct_message(
            &mut state,
            signed_ingress.clone(),
            SMALL_APP_SUBNET_MAX_SIZE,
        );
        assert!(state.canister_state(&canister_id).is_none());
        assert_eq!(state.get_ingress_status(&msg.id()), &status_clone);
        assert_inducted_ingress_messages_eq(
            metric_vec(&[(&[(LABEL_STATUS, LABEL_VALUE_CANISTER_NOT_FOUND)], 1)]),
            &metrics_registry,
        );
        assert_eq!(
            0,
            fetch_inducted_payload_size_stats(&metrics_registry).count
        );
    });
}

#[test]
// This test verifies that we don't induct duplicate messages. It sets up a
// state with 2 messages already inducted (i.e. two entries in the ingress
// history) and we try to induct 3 messages. The first is a duplicate of an
// already inducted message, the second is new and the third is a duplicate of
// the second one. We expect only the second message to be inducted.
fn dont_induct_duplicate_messages() {
    with_test_replica_logger(|log| {
        let mut ingress_history_writer = MockIngressHistory::new();
        let canister_id1 = canister_test_id(0);
        let canister_id2 = canister_test_id(1);
        let metrics_registry = MetricsRegistry::new();

        let msg1 = SignedIngressBuilder::new()
            .canister_id(canister_id1)
            .sender(user_test_id(0))
            .nonce(2)
            .build();
        let msg2 = SignedIngressBuilder::new()
            .canister_id(canister_id2)
            .sender(user_test_id(0))
            .nonce(3)
            .build();
        let msg3 = msg2.clone();

        ingress_history_writer
            .expect_set_status()
            .with(always(), eq(msg3.id()), always())
            .times(1)
            .returning(|state, message_id3, _| {
                state.set_ingress_status(
                    message_id3,
                    IngressStatus::Known {
                        receiver: canister_test_id(0).get(),
                        user_id: user_test_id(0),
                        time: UNIX_EPOCH,
                        state: IngressState::Received,
                    },
                    NumBytes::from(u64::MAX),
                    |_| {},
                );
                IngressStatus::Unknown.into()
            });

        let ingress_history_writer = Arc::new(ingress_history_writer);
        let valid_set_rule = ValidSetRuleImpl::new(
            ingress_history_writer,
            Arc::new(CyclesAccountManagerBuilder::new().build()),
            &metrics_registry,
            log,
        );

        let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);
        state.set_ingress_status(
            message_test_id(1),
            IngressStatus::Known {
                receiver: canister_id1.get(),
                user_id: user_test_id(0),
                time: UNIX_EPOCH,
                state: IngressState::Received,
            },
            NumBytes::from(u64::MAX),
            |_| {},
        );
        state.set_ingress_status(
            msg1.id(),
            IngressStatus::Known {
                receiver: canister_id1.get(),
                user_id: user_test_id(0),
                time: UNIX_EPOCH,
                state: IngressState::Received,
            },
            NumBytes::from(u64::MAX),
            |_| {},
        );

        insert_canister(&mut state, canister_id1);
        insert_canister(&mut state, canister_id2);

        valid_set_rule.induct_messages(&mut state, vec![msg1, msg2, msg3]);
        assert_eq!(ingress_queue_size(&state, canister_id1), 0);
        assert_eq!(ingress_queue_size(&state, canister_id2), 1);
        assert_inducted_ingress_messages_eq(
            metric_vec(&[
                (&[(LABEL_STATUS, LABEL_VALUE_SUCCESS)], 1),
                (&[(LABEL_STATUS, LABEL_VALUE_DUPLICATE)], 2),
            ]),
            &metrics_registry,
        );
        assert_eq!(
            1,
            fetch_inducted_payload_size_stats(&metrics_registry).count
        );
    });
}

#[test]
fn canister_on_application_subnet_charges_for_ingress() {
    let own_subnet_type = SubnetType::Application;
    let own_subnet_id = subnet_test_id(0);
    let mut state = ReplicatedStateBuilder::new()
        .with_node_ids(
            (1..=SMALL_APP_SUBNET_MAX_SIZE as u64)
                .map(node_test_id)
                .collect(),
        )
        .with_subnet_type(own_subnet_type)
        .with_canister(
            CanisterStateBuilder::new()
                .with_canister_id(canister_test_id(0))
                .build(),
        )
        .build();

    let cycles_account_manager = Arc::new(
        CyclesAccountManagerBuilder::new()
            .with_subnet_type(own_subnet_type)
            .with_subnet_id(own_subnet_id)
            .build(),
    );
    let signed_ingress: SignedIngress = SignedIngressBuilder::new()
        .canister_id(canister_test_id(0))
        .build();
    let cost_of_ingress = cycles_account_manager
        .ingress_induction_cost(
            &signed_ingress,
            None,
            SMALL_APP_SUBNET_MAX_SIZE,
            CanisterCyclesCostSchedule::Normal,
        )
        .cost();

    let ingress_history_writer = NoopIngressHistoryWriter;
    let metrics_registry = MetricsRegistry::new();
    let ingress_history_writer = Arc::new(ingress_history_writer);
    let valid_set_rule = ValidSetRuleImpl::new(
        ingress_history_writer,
        cycles_account_manager,
        &metrics_registry,
        no_op_logger(),
    );

    let balance_before = state
        .canister_states
        .get(&canister_test_id(0))
        .unwrap()
        .system_state
        .balance();

    valid_set_rule.induct_messages(&mut state, vec![signed_ingress]);

    let balance_after = state
        .canister_states
        .get(&canister_test_id(0))
        .unwrap()
        .system_state
        .balance();

    assert_eq!(balance_after, balance_before - cost_of_ingress);
}

#[test]
fn canister_on_system_subnet_does_not_charge_for_ingress() {
    let own_subnet_type = SubnetType::System;
    let mut state = ReplicatedStateBuilder::new()
        .with_subnet_type(own_subnet_type)
        .with_canister(
            CanisterStateBuilder::new()
                .with_canister_id(canister_test_id(0))
                .build(),
        )
        .build();

    let ingress_history_writer = NoopIngressHistoryWriter;
    let metrics_registry = MetricsRegistry::new();
    let ingress_history_writer = Arc::new(ingress_history_writer);
    let cycles_account_manager = Arc::new(
        CyclesAccountManagerBuilder::new()
            .with_subnet_type(own_subnet_type)
            .build(),
    );
    let valid_set_rule = ValidSetRuleImpl::new(
        ingress_history_writer,
        cycles_account_manager,
        &metrics_registry,
        no_op_logger(),
    );

    let balance_before = state
        .canister_states
        .get(&canister_test_id(0))
        .unwrap()
        .system_state
        .balance();

    let msg = SignedIngressBuilder::new()
        .canister_id(canister_test_id(0))
        .build();
    valid_set_rule.induct_messages(&mut state, vec![msg]);

    let balance_after = state
        .canister_states
        .get(&canister_test_id(0))
        .unwrap()
        .system_state
        .balance();

    assert_eq!(balance_after, balance_before);
}

#[test]
fn ingress_to_stopping_canister_is_rejected() {
    let ingress_history_writer = Arc::new(NoopIngressHistoryWriter);
    let metrics_registry = MetricsRegistry::new();
    let valid_set_rule = ValidSetRuleImpl::new(
        ingress_history_writer,
        Arc::new(CyclesAccountManagerBuilder::new().build()),
        &metrics_registry,
        no_op_logger(),
    );

    let mut state = ReplicatedStateBuilder::new()
        .with_canister(
            CanisterStateBuilder::new()
                .with_canister_id(canister_test_id(0))
                .with_status(CanisterStatusType::Stopping)
                .build(),
        )
        .build();

    let ingress = SignedIngressBuilder::new()
        .canister_id(canister_test_id(0))
        .build();
    assert_eq!(
        valid_set_rule.enqueue(&mut state, ingress, SMALL_APP_SUBNET_MAX_SIZE),
        Err(IngressInductionError::CanisterStopping(canister_test_id(0)))
    );
}

#[test]
fn ingress_to_stopped_canister_is_rejected() {
    let ingress_history_writer = Arc::new(NoopIngressHistoryWriter);
    let metrics_registry = MetricsRegistry::new();
    let valid_set_rule = ValidSetRuleImpl::new(
        ingress_history_writer,
        Arc::new(CyclesAccountManagerBuilder::new().build()),
        &metrics_registry,
        no_op_logger(),
    );

    let mut state = ReplicatedStateBuilder::new()
        .with_canister(
            CanisterStateBuilder::new()
                .with_canister_id(canister_test_id(0))
                .with_status(CanisterStatusType::Stopped)
                .build(),
        )
        .build();

    let ingress = SignedIngressBuilder::new()
        .canister_id(canister_test_id(0))
        .build();

    assert_eq!(
        valid_set_rule.enqueue(&mut state, ingress, SMALL_APP_SUBNET_MAX_SIZE),
        Err(IngressInductionError::CanisterStopped(canister_test_id(0)))
    );
}

#[test]
fn running_canister_on_application_subnet_accepts_and_charges_for_ingress() {
    with_test_replica_logger(|log| {
        let mut ingress_history_writer = MockIngressHistory::new();
        ingress_history_writer
            .expect_set_status()
            .times(1)
            .return_const(Arc::new(IngressStatus::Unknown));
        let metrics_registry = MetricsRegistry::new();

        let valid_set_rule = ValidSetRuleImpl::new(
            Arc::new(ingress_history_writer),
            Arc::new(CyclesAccountManagerBuilder::new().build()),
            &metrics_registry,
            log,
        );

        let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);
        let canister_id = canister_test_id(0);
        let canister = get_running_canister(canister_id);
        let balance_before = canister.system_state.balance();
        state.put_canister_state(canister);

        let ingress = SignedIngressBuilder::new().build();
        let effective_canister_id = None;
        let cost = CyclesAccountManagerBuilder::new()
            .build()
            .ingress_induction_cost(
                &ingress,
                effective_canister_id,
                SMALL_APP_SUBNET_MAX_SIZE,
                CanisterCyclesCostSchedule::Normal,
            )
            .cost();

        valid_set_rule.induct_message(&mut state, ingress, SMALL_APP_SUBNET_MAX_SIZE);

        let balance_after = state
            .canister_state(&canister_id)
            .unwrap()
            .system_state
            .balance();

        assert_eq!(balance_after, balance_before - cost);
    });
}

#[test]
fn running_canister_on_system_subnet_accepts_and_does_not_charge_for_ingress() {
    with_test_replica_logger(|log| {
        let mut ingress_history_writer = MockIngressHistory::new();
        ingress_history_writer
            .expect_set_status()
            .times(1)
            .return_const(Arc::new(IngressStatus::Unknown));
        let metrics_registry = MetricsRegistry::new();
        let valid_set_rule = ValidSetRuleImpl::new(
            Arc::new(ingress_history_writer),
            Arc::new(
                CyclesAccountManagerBuilder::new()
                    .with_subnet_type(SubnetType::System)
                    .build(),
            ),
            &metrics_registry,
            log,
        );

        let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::System);
        let canister_id = canister_test_id(0);
        let canister = get_running_canister(canister_id);
        let balance_before = canister.system_state.balance();
        state.put_canister_state(canister);

        let ingress = SignedIngressBuilder::new().build();
        valid_set_rule.induct_message(&mut state, ingress, SMALL_APP_SUBNET_MAX_SIZE);

        let balance_after = state
            .canister_state(&canister_id)
            .unwrap()
            .system_state
            .balance();

        assert_eq!(balance_after, balance_before);
    });
}

#[test]
fn management_message_with_unknown_method_is_not_inducted() {
    let ingress_history_writer = MockIngressHistory::new();
    let metrics_registry = MetricsRegistry::new();
    let subnet_id = subnet_test_id(1);
    let valid_set_rule = ValidSetRuleImpl::new(
        Arc::new(ingress_history_writer),
        Arc::new(
            CyclesAccountManagerBuilder::new()
                .with_subnet_id(subnet_id)
                .build(),
        ),
        &metrics_registry,
        no_op_logger(),
    );

    let mut state = ReplicatedStateBuilder::new().build();
    let ingress = SignedIngressBuilder::new()
        .canister_id(IC_00)
        .method_name("test")
        .build();
    assert_eq!(
        valid_set_rule.enqueue(&mut state, ingress, SMALL_APP_SUBNET_MAX_SIZE),
        Err(IngressInductionError::CanisterMethodNotFound(String::from(
            "test"
        )))
    );
}

#[test]
fn management_message_with_invalid_payload_is_not_inducted() {
    let ingress_history_writer = MockIngressHistory::new();
    let metrics_registry = MetricsRegistry::new();
    let subnet_id = subnet_test_id(1);
    let valid_set_rule = ValidSetRuleImpl::new(
        Arc::new(ingress_history_writer),
        Arc::new(
            CyclesAccountManagerBuilder::new()
                .with_subnet_id(subnet_id)
                .build(),
        ),
        &metrics_registry,
        no_op_logger(),
    );

    let mut state = ReplicatedStateBuilder::new().build();
    let ingress = SignedIngressBuilder::new()
        .canister_id(IC_00)
        .method_name("update_settings")
        .method_payload(vec![1, 2, 3]) // invalid
        .build();

    assert_eq!(
        valid_set_rule.enqueue(&mut state, ingress, SMALL_APP_SUBNET_MAX_SIZE),
        Err(IngressInductionError::InvalidManagementPayload)
    );
}

#[test]
fn management_message_update_setting_is_inducted_but_not_charged() {
    let ingress_history_writer = MockIngressHistory::new();
    let metrics_registry = MetricsRegistry::new();
    let subnet_id = subnet_test_id(1);
    let valid_set_rule = ValidSetRuleImpl::new(
        Arc::new(ingress_history_writer),
        Arc::new(
            CyclesAccountManagerBuilder::new()
                .with_subnet_id(subnet_id)
                .build(),
        ),
        &metrics_registry,
        no_op_logger(),
    );

    let mut state = ReplicatedStateBuilder::new().build();
    let canister_id = canister_test_id(0);
    let canister = get_running_canister(canister_id);
    let balance_before = canister.system_state.balance();
    state.put_canister_state(canister);

    let payload = UpdateSettingsArgs {
        canister_id: canister_id.get(),
        settings: CanisterSettingsArgsBuilder::new()
            .with_freezing_threshold(1 << 20)
            .build(),
        sender_canister_version: None,
    }
    .encode();
    let ingress = SignedIngressBuilder::new()
        .canister_id(IC_00)
        .method_name("update_settings")
        .method_payload(payload)
        .build();
    assert!(
        valid_set_rule
            .enqueue(&mut state, ingress, SMALL_APP_SUBNET_MAX_SIZE)
            .is_ok()
    );

    let balance_after = state
        .canister_state(&canister_id)
        .unwrap()
        .system_state
        .balance();

    assert_eq!(balance_after, balance_before);
}

#[test]
fn ingress_history_max_messages_application_subnet() {
    ingress_history_max_messages_impl(SubnetType::Application);
}

#[test]
fn ingress_history_max_messages_verified_application_subnet() {
    ingress_history_max_messages_impl(SubnetType::VerifiedApplication);
}

#[test]
fn ingress_history_max_messages_system_subnet() {
    ingress_history_max_messages_impl(SubnetType::System);
}

/// Common implementation for all `ingress_history_max_messages` tests.
fn ingress_history_max_messages_impl(subnet_type: SubnetType) {
    with_test_replica_logger(|log| {
        let canister_id = canister_test_id(0);
        let mut msgs: Vec<SignedIngress> = Vec::new();
        for i in 0..4 {
            let ingress = SignedIngressBuilder::new()
                .canister_id(canister_id)
                .sender(user_test_id(i))
                .method_payload(vec![i as u8])
                .build();
            msgs.push(ingress);
        }
        let msg3_id = msgs[3].id();

        let mut ingress_history_writer = MockIngressHistory::new();
        ingress_history_writer
            .expect_set_status()
            .with(always(), always(), always())
            .times(4)
            .returning(move |state, msg_id, status| {
                state.set_ingress_status(msg_id, status, NumBytes::from(u64::MAX), |_| {});
                IngressStatus::Unknown.into()
            });

        let mut state = ReplicatedState::new(subnet_test_id(1), subnet_type);
        insert_canister(&mut state, canister_id);

        let ingress_history_writer = Arc::new(ingress_history_writer);
        let metrics_registry = MetricsRegistry::new();
        let cycles_account_manager = Arc::new(
            CyclesAccountManagerBuilder::new()
                .with_subnet_type(subnet_type)
                .build(),
        );

        // Create a `ValidSetRule` with a maximum ingress history size of 3.
        let mut valid_set_rule = ValidSetRuleImpl::new(
            ingress_history_writer,
            cycles_account_manager,
            &metrics_registry,
            log,
        );
        valid_set_rule.ingress_history_max_messages = 3;

        // Attempt inducting all 4 messages.
        valid_set_rule.induct_messages(&mut state, msgs);

        match subnet_type {
            // System subnets ignore the `ingress_history_max_messages` limit.
            SubnetType::System => {
                // All 4 messages should have been inducted.
                assert_eq!(ingress_queue_size(&state, canister_id), 4);
                // And all 4 should have a state in the ingress history.
                assert_eq!(state.metadata.ingress_history.len(), 4);
                // With msg3 having state `Received`.
                let status = state.metadata.ingress_history.get(&msg3_id).cloned();
                assert_matches!(
                    status,
                    Some(IngressStatus::Known {
                        state: IngressState::Received,
                        ..
                    })
                );

                assert_inducted_ingress_messages_eq(
                    metric_vec(&[(&[(LABEL_STATUS, LABEL_VALUE_SUCCESS)], 4)]),
                    &metrics_registry,
                );
                assert_eq!(
                    HistogramStats { count: 4, sum: 4.0 },
                    fetch_inducted_payload_size_stats(&metrics_registry)
                );
            }

            // Application subnets respect the `ingress_history_max_messages` limit.
            SubnetType::Application | SubnetType::VerifiedApplication => {
                // 3 messages should have been inducted.
                assert_eq!(ingress_queue_size(&state, canister_id), 3);
                // But all 4 should have a state in the ingress history.
                assert_eq!(state.metadata.ingress_history.len(), 4);
                // With msg3 having state `Failed`.
                let status = state.metadata.ingress_history.get(&msg3_id).cloned();
                assert_matches!(
                    status,
                    Some(IngressStatus::Known {
                        state: IngressState::Failed(error),
                        ..
                    }) if error.code() == ErrorCode::IngressHistoryFull
                );

                assert_inducted_ingress_messages_eq(
                    metric_vec(&[
                        (&[(LABEL_STATUS, LABEL_VALUE_SUCCESS)], 3),
                        (&[(LABEL_STATUS, LABEL_VALUE_INGRESS_HISTORY_FULL)], 1),
                    ]),
                    &metrics_registry,
                );
                assert_eq!(
                    HistogramStats { count: 3, sum: 3.0 },
                    fetch_inducted_payload_size_stats(&metrics_registry)
                );
            }
        }
    });
}
