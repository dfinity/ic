use ic_base_types::{NodeId, RegistryVersion};
use ic_interfaces_transport::{
    FlowTag, Transport, TransportError, TransportEventHandler, TransportPayload,
};
use mockall::*;
use std::net::SocketAddr;

mock! {
    pub Transport {}

    trait Transport {
        fn set_event_handler(
            &self,
            event_handler: TransportEventHandler,
        );

        fn start_connection(
            &self,
            peer_id: &NodeId,
            peer_addr: SocketAddr,
            registry_version: RegistryVersion,
        ) -> Result<(), TransportError>;

        fn stop_connection(
            &self,
            peer: &NodeId,
        );

        fn send(
            &self,
            peer: &NodeId,
            flow: FlowTag,
            message: TransportPayload,
        ) -> Result<(), TransportError>;

        fn clear_send_queues(
            &self,
            peer: &NodeId,
        );
    }
}

mock! {
    pub TranportEventHandler {}
}
