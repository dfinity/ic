use ic_interfaces::messaging::{
    MessageRouting, MessageRoutingError, XNetPayloadBuilder, XNetPayloadValidationError,
};
use ic_types::{
    Height, NumBytes,
    batch::{Batch, ValidationContext, XNetPayload},
};
use mockall::mock;
use std::sync::RwLock;

mock! {
    pub MessageRouting {}

    impl MessageRouting for MessageRouting {
        fn deliver_batch(& self, b: Batch) -> Result<(), MessageRoutingError>;
        fn expected_batch_height(&self) -> Height;
    }
}

/// Sync wrapper to allow shared modification. See [`RefMockStateManager`].
#[derive(Default)]
pub struct RefMockMessageRouting {
    pub mock: RwLock<MockMessageRouting>,
}

impl RefMockMessageRouting {
    pub fn get_mut(&self) -> std::sync::RwLockWriteGuard<'_, MockMessageRouting> {
        self.mock.write().unwrap()
    }
}

impl MessageRouting for RefMockMessageRouting {
    fn deliver_batch(&self, b: Batch) -> Result<(), MessageRoutingError> {
        self.mock.read().unwrap().deliver_batch(b)
    }
    fn expected_batch_height(&self) -> Height {
        self.mock.read().unwrap().expected_batch_height()
    }
}

mock! {
    pub XNetPayloadBuilder {}

    impl XNetPayloadBuilder for XNetPayloadBuilder{
        fn get_xnet_payload<'a>(
            &self,
            validation_context: &ValidationContext,
            past_payloads: &[&'a XNetPayload],
            byte_limit : NumBytes,
        ) -> (XNetPayload, NumBytes);

        fn validate_xnet_payload<'a>(
            &self,
            payload: &XNetPayload,
            validation_context: &ValidationContext,
            past_payloads: &[&'a XNetPayload]
        ) -> Result<NumBytes, XNetPayloadValidationError>;
    }
}
