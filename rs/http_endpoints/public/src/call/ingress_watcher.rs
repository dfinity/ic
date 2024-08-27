use crate::metrics::HttpHandlerMetrics;
use ic_async_utils::JoinMap;
use ic_logger::{info, ReplicaLogger};
use ic_types::{messages::MessageId, Height};
use std::{
    cmp::max,
    collections::{btree_map, hash_map::Entry, BTreeMap, HashMap, HashSet},
    sync::Arc,
};
use tokio::{
    runtime::Handle,
    select,
    sync::{
        mpsc::{channel, Receiver, Sender},
        oneshot, watch, Notify,
    },
    task::JoinHandle,
};
use tokio_util::sync::{CancellationToken, DropGuard};

const INGRESS_WATCHER_CHANNEL_SIZE: usize = 1000;

#[derive(Debug)]
pub(crate) enum SubscriptionError {
    /// Another subscription for the same message id already exists.
    DuplicateSubscriptionError,
    /// The [`IngressWatcher`] is not running.
    IngressWatcherNotRunning { error_message: &'static str },
}

/// Used to register a subscription for an ingress message to be tracked by the [`IngressWatcher`].
struct IngressWatcherSubscription {
    /// The message id of the ingress message.
    message: MessageId,
    /// A oneshot channel to send a notifier to the subscriber.
    certification_notifier_tx: oneshot::Sender<Result<Arc<Notify>, SubscriptionError>>,
    /// Cancellation token. Used to cancel the subscription.
    cancellation_token: CancellationToken,
}

/// A handle to the [`IngressWatcher`] used to register subscription over a channel.
#[derive(Clone)]
pub struct IngressWatcherHandle {
    subscriber_registration_tx: Sender<IngressWatcherSubscription>,
    metrics: HttpHandlerMetrics,
}

impl IngressWatcherHandle {
    /// Subscribes for the certification of an ingress message, and returns a [`IngressCertificationSubscriber`], that can be
    /// used to wait for a message to be certified.
    pub(crate) async fn subscribe_for_certification(
        self,
        message: MessageId,
    ) -> Result<IngressCertificationSubscriber, SubscriptionError> {
        let _timer = self
            .metrics
            .ingress_watcher_subscription_latency_duration_seconds
            .start_timer();
        // Cancel the subscription if the handle is dropped.
        let cancellation_token = CancellationToken::new();
        let cancellation_token_clone = cancellation_token.clone();
        let drop_guard = cancellation_token.drop_guard();

        let (certification_notifier_tx, certification_notifier_rx) = oneshot::channel();

        self.subscriber_registration_tx
            .send(IngressWatcherSubscription {
                message,
                certification_notifier_tx,
                cancellation_token: cancellation_token_clone,
            })
            .await
            .map_err(|_| SubscriptionError::IngressWatcherNotRunning {
                error_message: "IngressWatcher failed to receive message subscription.",
            })?;

        let certification_notifier = certification_notifier_rx.await.map_err(|_| {
            SubscriptionError::IngressWatcherNotRunning {
                error_message: "IngressWatcher failed to send a notifier.",
            }
        })??;

        Ok(IngressCertificationSubscriber {
            certification_notifier,
            metrics: self.metrics,
            _drop_guard: drop_guard,
        })
    }
}

pub(crate) struct IngressCertificationSubscriber {
    certification_notifier: Arc<Notify>,
    metrics: HttpHandlerMetrics,
    /// Cancels the subscription if the subscriber is dropped.
    _drop_guard: DropGuard,
}

impl IngressCertificationSubscriber {
    pub(crate) async fn wait_for_certification(self) {
        let _timer = self
            .metrics
            .ingress_watcher_wait_for_certification_duration_seconds
            .start_timer();
        self.certification_notifier.notified().await;
    }
}

enum MessageExecutionStatus {
    /// The message is still being executed.
    InProgress,
    /// The message has completed execution.
    Completed(Height),
}

/// Invariants:
/// - 1:1 mapping of keys in `message_statuses` and `cancellations`.
/// - 1:1 mapping of keys in `message_statuses` with execution status as completed and `completed_execution_heights`.
pub struct IngressWatcher {
    log: ReplicaLogger,
    metrics: HttpHandlerMetrics,
    rt_handle: Handle,
    cancellation_token: CancellationToken,
    /// Keeps track of the certified height.
    certified_height: Height,

    /// Maps message id to a future that resolves when all subscribers stop waiting for its certification.
    cancellations: JoinMap<MessageId, ()>,
    /// Maps the message id to its [`MessageExecutionStatus`] and a [`Notify`]er to notify its subscribers when the message is certified.
    message_statuses: HashMap<MessageId, (MessageExecutionStatus, Arc<Notify>)>,
    /// Inverse index, maps the height to the set of message ids that completed execution at that height.
    completed_execution_heights: BTreeMap<Height, HashSet<MessageId>>,
}

impl IngressWatcher {
    pub fn start(
        rt_handle: Handle,
        log: ReplicaLogger,
        metrics: HttpHandlerMetrics,
        certified_height_watcher: watch::Receiver<Height>,
        completed_execution_messages_rx: Receiver<(MessageId, Height)>,
        cancellation_token: CancellationToken,
    ) -> (IngressWatcherHandle, JoinHandle<()>) {
        #[allow(clippy::disallowed_methods)]
        let (subscriber_registration_tx, subscriber_registration_rx) =
            channel::<IngressWatcherSubscription>(INGRESS_WATCHER_CHANNEL_SIZE);

        let ingress_watcher = Self {
            log,
            metrics: metrics.clone(),
            rt_handle: rt_handle.clone(),
            cancellation_token,
            certified_height: *certified_height_watcher.borrow(),
            cancellations: JoinMap::new(),
            message_statuses: HashMap::new(),
            completed_execution_heights: BTreeMap::new(),
        };

        let join_handle = rt_handle.spawn(ingress_watcher.run(
            certified_height_watcher,
            subscriber_registration_rx,
            completed_execution_messages_rx,
        ));

        (
            IngressWatcherHandle {
                subscriber_registration_tx,
                metrics,
            },
            join_handle,
        )
    }

    async fn run(
        mut self,
        mut certified_height: watch::Receiver<Height>,
        mut ingress_message_rx: Receiver<IngressWatcherSubscription>,
        mut completed_execution_messages_rx: Receiver<(MessageId, Height)>,
    ) {
        loop {
            // - 1:1 mapping of keys in `message_statuses` and `cancellations`.
            #[cfg(debug_assertions)]
            {
                debug_assert_eq!(
                    self.message_statuses.len(),
                    self.cancellations.len(),
                    "The number of messages in `self.message_statuses` and `self.cancellations` should be equal."
                );

                for message_id in self.message_statuses.keys() {
                    debug_assert!(self.cancellations.contains(message_id));
                }
            }

            // - 1:1 mapping of keys in `message_statuses` with completed execution status and `completed_execution_heights`.
            #[cfg(debug_assertions)]
            {
                let messages_with_completed_execution = self
                    .message_statuses
                    .iter()
                    .filter_map(|(message_id, (message_status, _))| {
                        if let MessageExecutionStatus::Completed(height) = message_status {
                            Some((message_id, height))
                        } else {
                            None
                        }
                    })
                    .collect::<HashSet<_>>();

                for (message_id, height) in &messages_with_completed_execution {
                    debug_assert!(
                        self.completed_execution_heights
                            .get(height)
                            .expect("Completed execution height should be in `self.completed_execution_heights`.")
                            .contains(message_id),
                        "Message should be in the inverted index `self.completed_execution_heights`."
                    );
                }

                debug_assert_eq!(
                    messages_with_completed_execution.len(),
                    self.completed_execution_heights.values().map(|messages| messages.len())
                        .sum::<usize>(),
                    "The number of messages in `self.message_statuses` with completed
                    execution status should be equal to the number of messages in `self.completed_execution_heights`."
                );
            }

            select! {
                // A new ingress message that needs to be tracked.
                Some(ingress_subscription) = ingress_message_rx.recv() => {
                    self.metrics.ingress_watcher_subscriptions_total.inc();
                    self.handle_ingress_message(ingress_subscription);
                }
                // Ingress message completed execution at `height`.
                Some((message_id, height)) = completed_execution_messages_rx.recv() => {
                    self.handle_message_completed_execution(message_id, height);
                }
                // Certified height has changed.
                Ok(_) = certified_height.changed() => {
                    self.handle_certification(*certified_height.borrow_and_update());
                }
                // Cancel the tracking of an ingress message.
                // TODO: Handle Some(Err(_)) case?
                Some(Ok((_, message_id))) = self.cancellations.join_next() => {
                    self.metrics.ingress_watcher_cancelled_subscriptions_total.inc();
                    self.handle_cancellation(&message_id);
                }

                _ = self.cancellation_token.cancelled() => {
                    info!(
                        self.log,
                        "Ingress watcher event loop cancelled.",
                    );
                    break;
                }
            }

            self.metrics
                .ingress_watcher_heights_waiting_for_certification
                .set(self.completed_execution_heights.len() as i64);

            self.metrics
                .ingress_watcher_tracked_messages
                .set(self.message_statuses.len() as i64);

            self.metrics
                .ingress_watcher_messages_completed_execution_channel_capacity
                .set(completed_execution_messages_rx.capacity() as i64);
        }
    }

    /// Tracks a new ingress message b
    fn handle_ingress_message(
        &mut self,
        IngressWatcherSubscription {
            message,
            certification_notifier_tx,
            cancellation_token,
        }: IngressWatcherSubscription,
    ) {
        let certification_notifier = match self.message_statuses.entry(message.clone()) {
            // New message, create a new notifier.
            Entry::Vacant(vacant_entry) => {
                self.cancellations.spawn_on(
                    message.clone(),
                    cancellation_token.cancelled_owned(),
                    &self.rt_handle,
                );

                let certification_notifier = Arc::new(tokio::sync::Notify::new());
                vacant_entry.insert((
                    MessageExecutionStatus::InProgress,
                    certification_notifier.clone(),
                ));

                Ok(certification_notifier)
            }
            // Seen message, return the existing notifier. This can happen if the replica gets two or more requests for the same message.
            Entry::Occupied(_) => {
                self.metrics.ingress_watcher_duplicate_requests_total.inc();
                Err(SubscriptionError::DuplicateSubscriptionError)
            }
        };

        let _ = certification_notifier_tx.send(certification_notifier);
    }

    /// Handles the cancellation of a subscription of an ingress message, by removing
    /// it from the internal state.
    fn handle_cancellation(&mut self, message_id: &MessageId) {
        match self
            .message_statuses
            .remove(message_id)
            .map(|(status, _)| status)
        {
            Some(MessageExecutionStatus::Completed(height)) => {
                // Also remove the message from the inverted index `self.completed_execution_heights`.
                match self.completed_execution_heights.entry(height) {
                    btree_map::Entry::Occupied(mut entry) => {
                        let messages_at_height = entry.get_mut();
                        let message_in_set = messages_at_height.remove(message_id);
                        debug_assert!(
                            message_in_set,
                            "Message should be in the inverted index`self.completed_execution_heights`."
                        );

                        // Prune the height if there are no more messages that completed execution at that height.
                        if messages_at_height.is_empty() {
                            entry.remove();
                        }
                    }
                    btree_map::Entry::Vacant(_) => {
                        #[cfg(debug_assertions)]
                        panic!(
                            "Completed execution height should be in `self.completed_execution_heights`."
                        );
                    }
                }
            }
            Some(MessageExecutionStatus::InProgress) => {}
            None => {
                #[cfg(debug_assertions)]
                {
                    panic!("A cancellation request for an unknown message should not be possible.");
                }
            }
        };
    }

    /// Notifies the subscribers of messages that completed execution at some state height that is now certified.
    ///
    ///  A state height `H` is certified, if `H` >= to `certified_height`.
    fn handle_certification(&mut self, certified_height: Height) {
        self.certified_height = max(self.certified_height, certified_height);

        // Process all messages that completed execution up to `certified_height`.
        while let Some(entry) = self.completed_execution_heights.first_entry() {
            let completed_execution_height = entry.key();
            let height_is_certified = *completed_execution_height <= self.certified_height;
            if !height_is_certified {
                return;
            }

            let certified_messages = entry.remove();

            for message_id in certified_messages {
                match self.message_statuses.remove(&message_id) {
                    // Notify waiters that the message is certified.
                    Some((MessageExecutionStatus::Completed(_), notifier)) => {
                        notifier.notify_one();
                        let removed = self.cancellations.remove(&message_id);

                        debug_assert!(
                            removed,
                            "Cancellation future should be in `self.cancellations`."
                        );
                    }
                    // Invalid invariants.
                    Some((MessageExecutionStatus::InProgress, _)) => {
                        panic!("Invalid variant. Execution status must be `Completed` if it is in `completed_execution_heights`.");
                    }
                    None => {
                        panic!("Message should be in `self.notifiers`.");
                    }
                }
            }
        }
    }

    /// Handles an ingress message that has completes execution at the given [`Height`].
    fn handle_message_completed_execution(&mut self, message_id: MessageId, height: Height) {
        if let Entry::Occupied(mut entry) = self.message_statuses.entry(message_id.clone()) {
            let (status, _) = entry.get_mut();
            match status {
                MessageExecutionStatus::InProgress => {
                    *status = MessageExecutionStatus::Completed(height);
                    self.completed_execution_heights
                        .entry(height)
                        .or_default()
                        .insert(message_id);

                    // Optimization to avoid waiting for a new certification if the
                    // height of the state which the message completed execution is already certified.
                    self.handle_certification(self.certified_height);
                }
                MessageExecutionStatus::Completed(_) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::FutureExt;
    use ic_logger::replica_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_types::messages::EXPECTED_MESSAGE_ID_LENGTH;
    use rstest::{fixture, rstest};

    #[fixture]
    fn ingress_watcher() -> IngressWatcher {
        let metrics = HttpHandlerMetrics::new(&MetricsRegistry::default());
        let log = no_op_logger();
        let cancellation_token = CancellationToken::new();

        let runtime = tokio::runtime::Runtime::new().unwrap();
        IngressWatcher {
            log,
            metrics,
            rt_handle: runtime.handle().clone(),
            cancellation_token,
            message_statuses: HashMap::new(),
            cancellations: JoinMap::new(),
            completed_execution_heights: BTreeMap::new(),
            certified_height: Height::from(0),
        }
    }

    /// Test that the IngressWatcher correctly handles the certification of messages.
    /// We should test that invariants of the IngressWatcher are maintained.
    #[rstest]
    fn test_certified_message_is_notified(mut ingress_watcher: IngressWatcher) {
        let message = MessageId::from([0; EXPECTED_MESSAGE_ID_LENGTH]);
        let (certification_notifier_tx, mut certification_notificatier_rx) = oneshot::channel();

        ingress_watcher.handle_ingress_message(IngressWatcherSubscription {
            message: message.clone(),
            certification_notifier_tx,
            cancellation_token: CancellationToken::new(),
        });

        let certification_notifier = certification_notificatier_rx.try_recv().unwrap().unwrap();

        assert_eq!(ingress_watcher.message_statuses.len(), 1);
        assert_eq!(ingress_watcher.cancellations.len(), 1);
        assert_eq!(ingress_watcher.completed_execution_heights.len(), 0);

        ingress_watcher.handle_message_completed_execution(message, Height::from(1));

        assert!(
            certification_notifier.notified().now_or_never().is_none(),
            "Message is not certified and is not notified."
        );

        assert_eq!(ingress_watcher.message_statuses.len(), 1);
        assert_eq!(ingress_watcher.cancellations.len(), 1);
        assert_eq!(ingress_watcher.completed_execution_heights.len(), 1);

        ingress_watcher.handle_certification(Height::from(1));

        certification_notifier
            .notified()
            .now_or_never()
            .expect("Notified");

        assert_eq!(ingress_watcher.message_statuses.len(), 0);
        assert_eq!(ingress_watcher.cancellations.len(), 0);
        assert_eq!(ingress_watcher.completed_execution_heights.len(), 0);
    }

    /// TODO: Can be removed. We have integration test covering the sames scenario.
    #[rstest]
    fn test_handling_of_duplicate_requests(mut ingress_watcher: IngressWatcher) {
        let message = MessageId::from([0; EXPECTED_MESSAGE_ID_LENGTH]);

        let (certification_notifier_tx, mut certification_notifier_rx) = oneshot::channel();
        ingress_watcher.handle_ingress_message(IngressWatcherSubscription {
            message: message.clone(),
            certification_notifier_tx,
            cancellation_token: CancellationToken::new(),
        });
        let certification_notifier_1 = certification_notifier_rx.try_recv().unwrap().unwrap();

        let (certification_notifier_tx, mut certification_notifier_rx) = oneshot::channel();
        ingress_watcher.handle_ingress_message(IngressWatcherSubscription {
            message: message.clone(),
            certification_notifier_tx,
            cancellation_token: CancellationToken::new(),
        });
        let _certification_notifier_2 = certification_notifier_rx
            .try_recv()
            .unwrap()
            .expect_err("Duplicate subscription should return an error.");

        assert_eq!(ingress_watcher.message_statuses.len(), 1);
        assert_eq!(ingress_watcher.cancellations.len(), 1);
        assert_eq!(ingress_watcher.completed_execution_heights.len(), 0);

        ingress_watcher.handle_message_completed_execution(message, Height::from(1));

        assert!(
            certification_notifier_1.notified().now_or_never().is_none(),
            "Message is not certified and is not notified."
        );

        assert_eq!(ingress_watcher.message_statuses.len(), 1);
        assert_eq!(ingress_watcher.cancellations.len(), 1);
        assert_eq!(ingress_watcher.completed_execution_heights.len(), 1);

        ingress_watcher.handle_certification(Height::from(1));

        certification_notifier_1
            .notified()
            .now_or_never()
            .expect("Notified");

        assert_eq!(ingress_watcher.message_statuses.len(), 0);
        assert_eq!(ingress_watcher.cancellations.len(), 0);
        assert_eq!(ingress_watcher.completed_execution_heights.len(), 0);
    }

    #[rstest]
    fn test_messages_without_subscription_are_ignored(mut ingress_watcher: IngressWatcher) {
        let message = MessageId::from([0; EXPECTED_MESSAGE_ID_LENGTH]);

        ingress_watcher.handle_message_completed_execution(message, Height::from(1));

        assert_eq!(ingress_watcher.message_statuses.len(), 0);
        assert_eq!(ingress_watcher.cancellations.len(), 0);
        assert_eq!(ingress_watcher.completed_execution_heights.len(), 0);
    }

    #[rstest]
    fn test_ingress_watcher_ignores_lower_certification_heights(
        mut ingress_watcher: IngressWatcher,
        #[values(Height::from(1), Height::from(2))] height: Height,
    ) {
        ingress_watcher.handle_certification(Height::from(2));
        // A lower certified height should be ignored.
        ingress_watcher.handle_certification(Height::from(1));

        assert_eq!(ingress_watcher.certified_height, Height::from(2));
        let message = MessageId::from([0; EXPECTED_MESSAGE_ID_LENGTH]);
        let (certification_notifier_tx, mut certification_notifier_rx) = oneshot::channel();

        ingress_watcher.handle_ingress_message(IngressWatcherSubscription {
            message: message.clone(),
            certification_notifier_tx,
            cancellation_token: CancellationToken::new(),
        });

        let certification_notifier = certification_notifier_rx.try_recv().unwrap().unwrap();

        ingress_watcher.handle_message_completed_execution(message, height);

        certification_notifier
            .notified()
            .now_or_never()
            .expect("Notified");
    }

    /// Test that the IngressWatcher correctly handles the cancellation of messages,
    /// by removing it from the internal state.
    #[rstest]
    fn test_cancellation_of_messages(
        mut ingress_watcher: IngressWatcher,
        #[values(false, true)] completed_execution: bool,
    ) {
        let message = MessageId::from([0; EXPECTED_MESSAGE_ID_LENGTH]);
        let (certification_notifier_tx, mut certification_notifier_rx) = oneshot::channel();

        let cancellation_token = CancellationToken::new();
        ingress_watcher.handle_ingress_message(IngressWatcherSubscription {
            message: message.clone(),
            certification_notifier_tx,
            cancellation_token: cancellation_token.clone(),
        });

        let certification_notifier = certification_notifier_rx.try_recv().unwrap().unwrap();

        assert_eq!(ingress_watcher.message_statuses.len(), 1);
        assert_eq!(ingress_watcher.completed_execution_heights.len(), 0);

        if completed_execution {
            ingress_watcher.handle_message_completed_execution(message.clone(), Height::from(1));
            assert_eq!(ingress_watcher.completed_execution_heights.len(), 1);
        }

        assert!(
            certification_notifier.notified().now_or_never().is_none(),
            "Message is not certified and is not notified."
        );

        ingress_watcher.handle_cancellation(&message);

        assert_eq!(ingress_watcher.message_statuses.len(), 0);
        assert_eq!(ingress_watcher.completed_execution_heights.len(), 0);
    }
}
