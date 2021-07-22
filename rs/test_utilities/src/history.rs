use ic_interfaces::execution_environment::{
    IngressHistoryError, IngressHistoryReader, IngressHistoryWriter,
};
use ic_replicated_state::ReplicatedState;
use ic_types::{ingress::IngressStatus, messages::MessageId, Height};
use mockall::*;

mock! {
    pub IngressHistory {}

    trait IngressHistoryWriter {
        type State = ReplicatedState;

        fn set_status(
            &self,
            state: &mut ReplicatedState,
            message_id: MessageId,
            status: IngressStatus,
        );
    }

    trait IngressHistoryReader {
        fn get_latest_status(&self) -> Box<dyn Fn(&MessageId) -> IngressStatus>;

        fn get_status_at_height(
            &self,
            height: Height,
        ) -> Result<Box<dyn Fn(&MessageId) -> IngressStatus>, IngressHistoryError>;
    }
}
