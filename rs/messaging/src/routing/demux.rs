use crate::{
    message_routing::MessageRoutingMetrics, routing::stream_handler::StreamHandler,
    scheduling::valid_set_rule::ValidSetRule,
};
use ic_interfaces_certified_stream_store::CertifiedStreamStore;
use ic_logger::{ReplicaLogger, debug, trace};
use ic_replicated_state::ReplicatedState;
use ic_types::batch::BatchMessages;
use std::sync::Arc;

#[cfg(test)]
use mockall::automock;
use std::collections::BTreeMap;

#[cfg_attr(test, automock)]
pub(crate) trait Demux: Send {
    /// Process the provided payload. Splices off XNetMessages as appropriate
    /// and (attempts) to induct the messages contained in the payload as
    /// appropriate.
    fn process_payload(&self, state: ReplicatedState, messages: BatchMessages) -> ReplicatedState;
}

pub(crate) struct DemuxImpl<'a> {
    valid_set_rule: Box<dyn ValidSetRule + 'a>,
    stream_handler: Box<dyn StreamHandler + 'a>,
    certified_stream_store: Arc<dyn CertifiedStreamStore>,
    metrics: MessageRoutingMetrics,
    log: ReplicaLogger,
}

impl<'a> DemuxImpl<'a> {
    pub(crate) fn new(
        valid_set_rule: Box<dyn ValidSetRule + 'a>,
        stream_handler: Box<dyn StreamHandler + 'a>,
        certified_stream_store: Arc<dyn CertifiedStreamStore>,
        metrics: MessageRoutingMetrics,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            valid_set_rule,
            stream_handler,
            certified_stream_store,
            metrics,
            log,
        }
    }
}

impl Demux for DemuxImpl<'_> {
    fn process_payload(
        &self,
        state: ReplicatedState,
        batch_messages: BatchMessages,
    ) -> ReplicatedState {
        trace!(self.log, "Processing Payload");

        let mut decoded_slices = BTreeMap::new();
        for (subnet_id, certified_slice) in batch_messages.certified_stream_slices {
            let slice = self
                .certified_stream_store
                .decode_valid_certified_stream_slice(&certified_slice)
                .expect("failed to decode certified stream");
            decoded_slices.insert(subnet_id, slice);
            self.metrics
                .remote_certified_heights
                .with_label_values(&[&subnet_id.to_string()])
                .set(certified_slice.certification.height.get() as i64);
        }

        let mut state = self
            .stream_handler
            .process_stream_slices(state, decoded_slices);

        self.valid_set_rule
            .induct_messages(&mut state, batch_messages.signed_ingress_msgs);

        for response in batch_messages.bitcoin_adapter_responses.into_iter() {
            state.push_response_bitcoin(response).unwrap_or_else(|err| {
                debug!(
                    self.log,
                    "Error pushing the response from bitcoin adapter {}",
                    err.to_string()
                )
            });
        }

        state
    }
}
