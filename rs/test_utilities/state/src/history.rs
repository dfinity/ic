use ic_interfaces::execution_environment::{
    IngressHistoryError, IngressHistoryReader, IngressHistoryWriter,
};
use ic_replicated_state::ReplicatedState;
use ic_types::{Height, ingress::IngressStatus, messages::MessageId};
use mockall::*;
use std::sync::Arc;

mock! {
    pub IngressHistory {}

    impl IngressHistoryWriter  for IngressHistory {
        type State = ReplicatedState;

        fn set_status(
            &self,
            state: &mut ReplicatedState,
            message_id: MessageId,
            status: IngressStatus,
        ) -> Arc<IngressStatus>;
    }

    impl IngressHistoryReader for  IngressHistory {
        fn get_latest_status(&self) -> Box<dyn Fn(&MessageId) -> IngressStatus>;

        #[allow(clippy::type_complexity)]
        fn get_status_at_height(
            &self,
            height: Height,
        ) -> Result<Box<dyn Fn(&MessageId) -> IngressStatus>, IngressHistoryError>;
    }
}
