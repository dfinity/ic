use super::*;
use ic_interfaces_state_manager_mocks::MockStateManager;
use ic_test_utilities::{
    notification::{Notification, WaitResult},
    types::batch::BatchBuilder,
};
use ic_test_utilities_logger::with_test_replica_logger;
use ic_test_utilities_metrics::{fetch_int_counter_vec, metric_vec};
use std::sync::Arc;
use std::time::Duration;

/// Helper function for testing the values of the
/// `METRIC_DELIVER_BATCH_COUNT` metric.
fn assert_deliver_batch_count_eq(
    ignored: u64,
    queue_full: u64,
    success: u64,
    metrics_registry: &MetricsRegistry,
) {
    assert_eq!(
        metric_vec(&[
            (&[(LABEL_STATUS, STATUS_IGNORED)], ignored),
            (&[(LABEL_STATUS, STATUS_QUEUE_FULL)], queue_full),
            (&[(LABEL_STATUS, STATUS_SUCCESS)], success),
        ]),
        fetch_int_counter_vec(metrics_registry, METRIC_DELIVER_BATCH_COUNT)
    );
}

#[test]
fn message_routing_does_not_block() {
    with_test_replica_logger(|log| {
        let timeout = Duration::from_secs(10);

        let mut mock = MockBatchProcessor::new();
        let started_notification = Arc::new(Notification::new());
        let notification = Arc::new(Notification::new());
        mock.expect_process_batch().returning({
            let notification = Arc::clone(&notification);
            let started_notification = Arc::clone(&started_notification);
            move |_| {
                started_notification.notify(());
                assert_eq!(
                    notification.wait_with_timeout(timeout),
                    WaitResult::Notified(())
                );
            }
        });

        let mock_box = Box::new(mock);
        let mut state_manager = MockStateManager::new();
        state_manager
            .expect_latest_state_height()
            .return_const(Height::from(0));

        let state_manager = Arc::new(state_manager);
        let metrics_registry = MetricsRegistry::new();
        let metrics = Arc::new(MessageRoutingMetrics::new(&metrics_registry));
        let mr =
            MessageRoutingImpl::from_batch_processor(state_manager, mock_box, metrics, log.clone());
        // We need to submit one extra batch because the very first one
        // is removed from the queue by the background worker.
        for batch_number in 1..BATCH_QUEUE_BUFFER_SIZE + 2 {
            let batch_number = Height::from(batch_number as u64);
            info!(log, "Delivering batch {}", batch_number);
            assert_eq!(batch_number, mr.expected_batch_height());
            mr.deliver_batch(BatchBuilder::default().batch_number(batch_number).build())
                .unwrap();
            assert_eq!(
                started_notification.wait_with_timeout(timeout),
                WaitResult::Notified(())
            );
            assert_deliver_batch_count_eq(0, 0, batch_number.get(), &metrics_registry);
        }

        let last_batch = Height::from(BATCH_QUEUE_BUFFER_SIZE as u64 + 2);
        assert_eq!(last_batch, mr.expected_batch_height());
        assert_eq!(
            mr.deliver_batch(BatchBuilder::default().batch_number(last_batch).build()),
            Err(MessageRoutingError::QueueIsFull)
        );
        assert_deliver_batch_count_eq(0, 1, 1 + BATCH_QUEUE_BUFFER_SIZE as u64, &metrics_registry);
        notification.notify(());
    });
}
