use crate::{routing::stream_handler::StreamHandler, scheduling::valid_set_rule::ValidSetRule};
use ic_interfaces::certified_stream_store::CertifiedStreamStore;
use ic_logger::{debug, trace, ReplicaLogger};
use ic_replicated_state::ReplicatedState;
use ic_types::{batch::BatchPayload, messages::SignedIngressContent};
use std::sync::Arc;

#[cfg(test)]
use mockall::automock;
use std::collections::BTreeMap;

#[cfg_attr(test, automock)]
pub(crate) trait Demux: Send {
    /// Process the provided payload. Splices off XNetMessages as appropriate
    /// and (attempts) to induct the messages contained in the payload as
    /// appropriate.
    fn process_payload(&self, state: ReplicatedState, payload: BatchPayload) -> ReplicatedState;
}

pub(crate) struct DemuxImpl<'a> {
    valid_set_rule: Box<dyn ValidSetRule + 'a>,
    stream_handler: Box<dyn StreamHandler + 'a>,
    certified_stream_store: Arc<dyn CertifiedStreamStore>,
    log: ReplicaLogger,
}

impl<'a> DemuxImpl<'a> {
    pub(crate) fn new(
        valid_set_rule: Box<dyn ValidSetRule + 'a>,
        stream_handler: Box<dyn StreamHandler + 'a>,
        certified_stream_store: Arc<dyn CertifiedStreamStore>,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            valid_set_rule,
            stream_handler,
            certified_stream_store,
            log,
        }
    }
}

impl<'a> Demux for DemuxImpl<'a> {
    fn process_payload(&self, state: ReplicatedState, payload: BatchPayload) -> ReplicatedState {
        trace!(self.log, "Processing Payload");

        let (signed_ingress_msgs, certified_stream_slices, bitcoin_adapter_responses) =
            payload.into_messages().unwrap_or_else(|err| {
                unreachable!(
                    "Failed to retrieve messages from validated batch payload: {:?}",
                    err
                )
            });

        let mut decoded_slices = BTreeMap::new();
        for (subnet_id, certified_slice) in certified_stream_slices {
            let slice = self
                .certified_stream_store
                .decode_valid_certified_stream_slice(&certified_slice)
                .expect("failed to decode certified stream");
            decoded_slices.insert(subnet_id, slice);
        }

        let mut state = self
            .stream_handler
            .process_stream_slices(state, decoded_slices);

        let ingress_msgs: Vec<_> = signed_ingress_msgs
            .into_iter()
            .map(SignedIngressContent::from)
            .collect();

        self.valid_set_rule
            .induct_messages(&mut state, ingress_msgs);

        for response in bitcoin_adapter_responses.into_iter() {
            state
                .push_response_bitcoin_testnet(response)
                .unwrap_or_else(|err| {
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
