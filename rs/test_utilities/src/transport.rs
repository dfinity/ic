use ic_base_types::{NodeId, RegistryVersion};
use ic_interfaces_transport::{
    AsyncTransportEventHandler, FlowTag, Transport, TransportErrorCode, TransportPayload,
};
use ic_protobuf::registry::node::v1::NodeRecord;
use mockall::*;
use std::sync::Arc;

mock! {
    pub Transport {}

    trait Transport {
        fn set_event_handler(
            &self,
            event_handler: Arc<dyn AsyncTransportEventHandler>,
        );

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
    }
}

mock! {
    pub TranportEventHandler {}
}
