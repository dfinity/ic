use crate::{
    message_routing::MessageRoutingMetrics, routing::stream_handler::StreamHandler,
    scheduling::valid_set_rule::ValidSetRule,
};
use ic_interfaces_certified_stream_store::CertifiedStreamStore;
use ic_logger::{debug, trace, ReplicaLogger};
use ic_replicated_state::ReplicatedState;
use ic_types::{batch::BatchMessages, messages::SignedIngressContent};
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

pub(crate) struct DemuxImpl<ValidSetRule_, StreamHandler_, CertifiedStreamStore_>
where
    ValidSetRule_: ValidSetRule,
    StreamHandler_: StreamHandler,
    CertifiedStreamStore_: CertifiedStreamStore,
{
    valid_set_rule: ValidSetRule_,
    stream_handler: StreamHandler_,
    certified_stream_store: Arc<CertifiedStreamStore_>,
    metrics: MessageRoutingMetrics,
    log: ReplicaLogger,
}

impl<'a, ValidSetRule_, StreamHandler_, CertifiedStreamStore_>
    DemuxImpl<ValidSetRule_, StreamHandler_, CertifiedStreamStore_>
where
    ValidSetRule_: ValidSetRule,
    StreamHandler_: StreamHandler,
    CertifiedStreamStore_: CertifiedStreamStore,
{
    pub(crate) fn new(
        valid_set_rule: ValidSetRule_,
        stream_handler: StreamHandler_,
        certified_stream_store: Arc<CertifiedStreamStore_>,
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

impl<'a, ValidSetRule_, StreamHandler_, CertifiedStreamStore_> Demux
    for DemuxImpl<ValidSetRule_, StreamHandler_, CertifiedStreamStore_>
where
    ValidSetRule_: ValidSetRule,
    StreamHandler_: StreamHandler,
    CertifiedStreamStore_: CertifiedStreamStore,
{
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

        let ingress_msgs: Vec<_> = batch_messages
            .signed_ingress_msgs
            .into_iter()
            .map(SignedIngressContent::from)
            .collect();

        self.valid_set_rule
            .induct_messages(&mut state, ingress_msgs);

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
