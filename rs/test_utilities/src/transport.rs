use async_trait::*;
use ic_interfaces_transport::{AsyncTransportEventHandler, SendError, Transport};
use ic_protobuf::registry::node::v1::NodeRecord;
use ic_types::{
    transport::{FlowId, FlowTag, TransportErrorCode, TransportPayload, TransportStateChange},
    NodeId, RegistryVersion,
};
use mockall::*;
use std::sync::Arc;

mock! {
    pub Transport {}

    trait Transport {
        fn register_client(
            &self,
            event_handler: Arc<dyn AsyncTransportEventHandler>,
        ) -> Result<(), TransportErrorCode>;

        fn start_connections(
            &self,
            peer: &NodeId,
            record: &NodeRecord,
            registry_version: RegistryVersion,
        ) -> Result<(), TransportErrorCode>;

        fn stop_connections(
            &self,
            peer: &NodeId,
        ) -> Result<(), TransportErrorCode>;

        fn send(
            &self,
            peer: &NodeId,
            flow: FlowTag,
            message: TransportPayload,
        ) -> Result<(), TransportErrorCode>;

        fn clear_send_queues(
            &self,
            peer: &NodeId,
        );

        fn clear_send_queue(
            &self,
            peer: &NodeId,
            flow_tag: FlowTag,
        );
    }
}

mock! {
    pub TranportEventHandler {}
}

#[async_trait]
impl AsyncTransportEventHandler for MockTranportEventHandler {
    async fn send_message(
        &self,
        _flow: FlowId,
        _message: TransportPayload,
    ) -> Result<(), SendError> {
        Ok(())
    }
    async fn state_changed(&self, _state_change: TransportStateChange) {}
    async fn error(&self, _flow_id: FlowId, _error: TransportErrorCode) {}
}
