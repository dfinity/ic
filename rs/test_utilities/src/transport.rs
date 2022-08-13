use ic_base_types::{NodeId, RegistryVersion};
use ic_interfaces_transport::{
    FlowTag, Transport, TransportErrorCode, TransportEventHandler, TransportPayload,
};
use ic_protobuf::registry::node::v1::NodeRecord;
use mockall::*;

mock! {
    pub Transport {}

    trait Transport {
        fn set_event_handler(
            &self,
            event_handler: TransportEventHandler,
        );

        fn start_connection(
            &self,
            peer: &NodeId,
            record: &NodeRecord,
            registry_version: RegistryVersion,
        ) -> Result<(), TransportErrorCode>;

        fn stop_connection(
            &self,
            peer: &NodeId,
        );

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
