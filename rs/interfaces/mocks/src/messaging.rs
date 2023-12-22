use ic_interfaces::messaging::{
    MessageRouting, MessageRoutingError, XNetPayloadBuilder, XNetPayloadValidationError,
};
use ic_types::{
    batch::{Batch, ValidationContext, XNetPayload},
    Height, NumBytes,
};
use mockall::mock;

mock! {
    pub MessageRouting {}

    impl MessageRouting for MessageRouting {
        fn deliver_batch(& self, b: Batch) -> Result<(), MessageRoutingError>;
        fn expected_batch_height(&self) -> Height;
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
