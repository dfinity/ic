//! Helper functionality for transport.

use crate::metrics::SendQueueMetrics;
use crate::types::{DequeuedMessage, QueueSize, SendQueue, SendQueueReader};
use ic_protobuf::registry::node::v1::NodeRecord;
use ic_types::transport::{FlowTag, TransportErrorCode, TransportPayload};
use ic_types::NodeId;

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::{channel, error::TrySendError, Receiver, Sender};
use tokio::time::Duration;
use tokio::time::{timeout_at, Instant};

// High level design of the send queue flow:
// - tokio::mpsc::channel is used as the send queue. This acts as a single
//   producer single consumer queue
// - Producer: Transport client threads calling transport.send(). They are
//   serialized by the SendQueueImpl.channel_ends mutex to write to the send end
//   of the channel
// - Consumer: the per-connection write task. It takes ownership of the receive
//   end and exclusively owns it
// - Clients like P2P need to clear the queue periodically. ReceiveEndContainer
//   is a light weight wrapper that is shared between the SendQueueImpl and the
//   write task. It is a low contention mechanism to update the write task's
//   receive end, when the channel is recreated
//
//   queue.clear() results in ReceiveEndContainer.update(), to fill in the new
//   receiver. The write task periodically calls ReceiveEndContainer.take()
//   to take ownership of the updated end. Since update() is an infrequent
//   operation, take() should have minimal contention

pub(crate) type SendEnd = Sender<(Instant, TransportPayload)>;
pub(crate) type ReceiveEnd = Receiver<(Instant, TransportPayload)>;

// Since there is no try_recv(), this is the max duration after the first
// dequeue to batch for
/// Maximal time to wait for batching
const MAX_BATCHING_DURATION_MSEC: u64 = 20;

/// Guarded receive end
struct ReceiveEndContainer {
    state: Mutex<Option<ReceiveEnd>>,
}

impl ReceiveEndContainer {
    /// Wraps a given receive end and returns it
    fn new(receive_end: ReceiveEnd) -> Self {
        Self {
            state: Mutex::new(Some(receive_end)),
        }
    }

    /// Sets up receive_end state for use by reader.
    /// Returns true if the receive end was updated.
    fn on_reader_start(&self, receive_end: ReceiveEnd) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.is_some() {
            // Continue using the current channel, so that the send requests
            // queued so far(before the connection was established) are not
            // dropped
            false
        } else {
            // Writer task took ownership of the last created channel and exited,
            // accept the new channel
            *state = Some(receive_end);
            true
        }
    }

    /// Updates the receive end
    fn update(&self, receive_end: ReceiveEnd) {
        let mut state = self.state.lock().unwrap();
        *state = Some(receive_end);
    }

    /// Takes out the currently active receive end (if any)
    fn take(&self) -> Option<ReceiveEnd> {
        let mut state = self.state.lock().unwrap();
        state.take()
    }
}

/// Transport client -> scheduler adapter.
pub(crate) struct SendQueueImpl {
    /// Flow label, string for use as the value for a metric label
    flow_label: String,

    /// Flow Tag, string for use as the value for a metric label
    flow_tag: String,

    /// Size of queue
    queue_size: QueueSize,

    /// A Mutex is needed around the send/receive end tuples, as they
    /// need to be updated in sync.
    channel_ends: Mutex<(SendEnd, Arc<ReceiveEndContainer>)>,

    /// Error flag
    error: Arc<AtomicBool>,

    /// Metrics
    metrics: SendQueueMetrics,
}

/// Implementation for the send queue
impl SendQueueImpl {
    /// Initializes and returns a send queue
    pub(crate) fn new(
        flow_label: String,
        flow_tag: &FlowTag,
        queue_size: QueueSize,
        metrics: SendQueueMetrics,
    ) -> Self {
        let (send_end, receive_end) = channel(queue_size.get());
        let receieve_end_wrapper = ReceiveEndContainer::new(receive_end);
        Self {
            flow_label,
            flow_tag: flow_tag.to_string(),
            error: Arc::new(AtomicBool::new(false)),
            queue_size,
            channel_ends: Mutex::new((send_end, Arc::new(receieve_end_wrapper))),
            metrics,
        }
    }
}

#[async_trait]
impl SendQueue for SendQueueImpl {
    fn get_reader(&self) -> Box<dyn SendQueueReader + Send + Sync> {
        let (send_end, receive_end) = channel(self.queue_size.get());
        let mut channel_ends = self.channel_ends.lock().unwrap();
        if channel_ends.1.on_reader_start(receive_end) {
            // Receive end was updated, so update send end as well.
            channel_ends.0 = send_end;
        }

        let reader = SendQueueReaderImpl {
            flow_label: self.flow_label.clone(),
            flow_tag: self.flow_tag.clone(),
            receive_end_container: channel_ends.1.clone(),
            cur_receive_end: None,
            error: self.error.clone(),
            metrics: self.metrics.clone(),
        };
        Box::new(reader)
    }

    fn enqueue(&self, message: TransportPayload) -> Option<TransportPayload> {
        self.metrics
            .add_count
            .with_label_values(&[&self.flow_label, &self.flow_tag])
            .inc();
        self.metrics
            .add_bytes
            .with_label_values(&[&self.flow_label, &self.flow_tag])
            .inc_by(message.0.len() as u64);

        let mut channel_ends = self.channel_ends.lock().unwrap();
        match channel_ends.0.try_send((Instant::now(), message)) {
            Ok(_) => None,
            Err(TrySendError::Full((_, unsent))) => {
                self.error.store(true, Ordering::Release);
                self.metrics
                    .queue_full
                    .with_label_values(&[&self.flow_label, &self.flow_tag])
                    .inc();
                Some(unsent)
            }
            Err(TrySendError::Closed((_, unsent))) => {
                self.error.store(true, Ordering::Release);
                self.metrics
                    .no_receiver
                    .with_label_values(&[&self.flow_label, &self.flow_tag])
                    .inc();
                Some(unsent)
            }
        }
    }

    fn clear(&self) {
        let (send_end, receive_end) = channel(self.queue_size.get());
        {
            let mut channel_ends = self.channel_ends.lock().unwrap();
            channel_ends.0 = send_end;
            channel_ends.1.update(receive_end);
        }
        self.metrics
            .queue_clear
            .with_label_values(&[&self.flow_label, &self.flow_tag])
            .inc();
    }
}

/// Send queue implementation
struct SendQueueReaderImpl {
    flow_label: String,
    flow_tag: String,
    receive_end_container: Arc<ReceiveEndContainer>,
    cur_receive_end: Option<ReceiveEnd>,
    error: Arc<AtomicBool>,
    metrics: SendQueueMetrics,
}

impl SendQueueReaderImpl {
    /// Receives a message with a given timeout. If timeout expires, returns
    /// None.
    async fn receive_with_timeout(
        receive_end: &mut ReceiveEnd,
        timeout: Duration,
    ) -> Option<(Instant, TransportPayload)> {
        let wait_for_entries = async move { receive_end.recv().await };
        let ret = timeout_at(Instant::now() + timeout, wait_for_entries).await;
        if ret.is_err() {
            // Return None on timeout.
            return None;
        }

        // Return None on sender disconnect as well.
        ret.unwrap()
    }

    /// Updates the receive ends
    fn update_cached_receive_end(&mut self) {
        if let Some(receive_end) = self.receive_end_container.take() {
            self.cur_receive_end = Some(receive_end);
            self.metrics
                .receive_end_updates
                .with_label_values(&[&self.flow_label, &self.flow_tag])
                .inc();
        }
    }
}

#[async_trait]
impl SendQueueReader for SendQueueReaderImpl {
    async fn dequeue(&mut self, bytes_limit: usize, timeout: Duration) -> Vec<DequeuedMessage> {
        // The channel end is looked up outside the loop. Any updates
        // to the receive end will be seen only in the next dequeue()
        // call.
        self.update_cached_receive_end();
        let cur_receive_end = self.cur_receive_end.as_mut().unwrap();

        let mut result = Vec::new();
        let mut time_left = timeout; // Initially set to heartbeat timeout.
        let mut removed = 0;
        let mut removed_bytes = 0;
        let mut batch_start_time = Instant::now();
        while let Some((enqueue_time, payload)) =
            Self::receive_with_timeout(cur_receive_end, time_left).await
        {
            self.metrics
                .queue_time_msec
                .with_label_values(&[&self.flow_label, &self.flow_tag])
                .observe(enqueue_time.elapsed().as_millis() as f64);
            removed += 1;
            removed_bytes += payload.0.len();

            let sender_error = if removed == 1 {
                // Return bool present in error and set error to false.
                self.error.fetch_and(false, Ordering::Acquire)
            } else {
                false
            };
            let msg = DequeuedMessage {
                payload,
                sender_error,
            };
            result.push(msg);

            if removed_bytes >= bytes_limit {
                break;
            }

            // bytes_limit not yet reached
            if removed == 1 {
                // Phase 1 over (heartbeat timeout), start phase 2 with
                // MAX_BATCHING_DURATION_MSEC
                time_left = Duration::from_millis(MAX_BATCHING_DURATION_MSEC);
                batch_start_time = Instant::now();
            } else {
                let batch_duration_msec = batch_start_time.elapsed().as_millis() as u64;
                if batch_duration_msec < MAX_BATCHING_DURATION_MSEC {
                    // Within MAX_BATCHING_DURATION_MSEC, try to batch more
                    time_left =
                        Duration::from_millis(MAX_BATCHING_DURATION_MSEC - batch_duration_msec);
                } else {
                    // Out of time, return what is gathered so far
                    break;
                }
            }
        }

        self.metrics
            .remove_count
            .with_label_values(&[&self.flow_label, &self.flow_tag])
            .inc_by(removed as u64);
        self.metrics
            .remove_bytes
            .with_label_values(&[&self.flow_label, &self.flow_tag])
            .inc_by(removed_bytes as u64);
        result
    }
}

/// Returns a map of flow_tag -> peer_ip for that flow.
pub(crate) fn get_flow_ips(
    node_record: &NodeRecord,
) -> Result<HashMap<FlowTag, String>, TransportErrorCode> {
    let mut ret = HashMap::new();
    for flow_endpoint in &node_record.p2p_flow_endpoints {
        let flow_tag = FlowTag::from(flow_endpoint.flow_tag);
        if ret.contains_key(&flow_tag) {
            return Err(TransportErrorCode::NodeRecordDuplicateFlowTag);
        }

        match &flow_endpoint.endpoint {
            Some(connection_endpoint) => ret.insert(flow_tag, connection_endpoint.ip_addr.clone()),
            None => return Err(TransportErrorCode::NodeRecordMissingConnectionEndpoint),
        };
    }

    Ok(ret)
}

/// Builds the flow label to use for metrics, from the IP address and the NodeId
pub(crate) fn get_flow_label(node_ip: &str, node_id: &NodeId) -> String {
    // 35: Includes the first 6 groups of 5 chars each + the 5 separators
    let prefix = node_id.to_string().chars().take(35).collect::<String>();
    return format!("{}_{}", node_ip, prefix);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_protobuf::registry::node::v1::{
        connection_endpoint::Protocol, ConnectionEndpoint, FlowEndpoint,
    };

    #[test]
    fn test_get_flow_ips() {
        let mut node_record: NodeRecord = Default::default();

        let ip_map = get_flow_ips(&node_record).unwrap();
        assert_eq!(ip_map.len(), 0);

        node_record.p2p_flow_endpoints.push(FlowEndpoint {
            flow_tag: 1000,
            endpoint: Some(ConnectionEndpoint {
                ip_addr: "10.0.0.1".to_string(),
                port: 100,
                protocol: Protocol::P2p1Tls13 as i32,
            }),
        });
        node_record.p2p_flow_endpoints.push(FlowEndpoint {
            flow_tag: 2000,
            endpoint: Some(ConnectionEndpoint {
                ip_addr: "20.0.0.1".to_string(),
                port: 200,
                protocol: Protocol::P2p1Tls13 as i32,
            }),
        });

        let ip_map = get_flow_ips(&node_record).unwrap();
        assert_eq!(ip_map.len(), 2);
        assert_eq!(
            *ip_map.get(&FlowTag::from(1000)).unwrap(),
            "10.0.0.1".to_string()
        );
        assert_eq!(
            *ip_map.get(&FlowTag::from(2000)).unwrap(),
            "20.0.0.1".to_string()
        );
    }

    #[test]
    fn test_get_flow_ips_duplicate_flow_tags() {
        let mut node_record: NodeRecord = Default::default();
        node_record.p2p_flow_endpoints.push(FlowEndpoint {
            flow_tag: 1000,
            endpoint: Some(ConnectionEndpoint {
                ip_addr: "10.0.0.1".to_string(),
                port: 100,
                protocol: Protocol::P2p1Tls13 as i32,
            }),
        });
        node_record.p2p_flow_endpoints.push(FlowEndpoint {
            flow_tag: 1000,
            endpoint: Some(ConnectionEndpoint {
                ip_addr: "20.0.0.1".to_string(),
                port: 200,
                protocol: Protocol::P2p1Tls13 as i32,
            }),
        });
        assert_eq!(
            get_flow_ips(&node_record),
            Err(TransportErrorCode::NodeRecordDuplicateFlowTag)
        );
    }

    #[test]
    fn test_get_flow_ips_missing_endpoint() {
        let mut node_record: NodeRecord = Default::default();
        node_record.p2p_flow_endpoints.push(FlowEndpoint {
            flow_tag: 1000,
            ..Default::default()
        });
        assert_eq!(
            get_flow_ips(&node_record),
            Err(TransportErrorCode::NodeRecordMissingConnectionEndpoint)
        );
    }
}
