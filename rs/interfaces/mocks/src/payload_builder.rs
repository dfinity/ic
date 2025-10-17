use ic_interfaces::self_validating_payload::SelfValidatingPayloadBuilder;
use ic_types::{NumBytes, batch::ValidationContext};

use mockall::mock;

mock! {
    pub SelfValidatingPayloadBuilder {}

    impl SelfValidatingPayloadBuilder for SelfValidatingPayloadBuilder {
        fn get_self_validating_payload<'a>(
            &self,
            validation_context: &ValidationContext,
            past_payloads: &[&'a ic_types::batch::SelfValidatingPayload],
            byte_limit: NumBytes,
            priority: usize,
        ) -> (ic_types::batch::SelfValidatingPayload, NumBytes);

        fn validate_self_validating_payload<'a>(
            &self,
            payload: &ic_types::batch::SelfValidatingPayload,
            validation_context: &ValidationContext,
            past_payloads: &[&'a ic_types::batch::SelfValidatingPayload],
        ) -> Result<
            NumBytes,
            ic_interfaces::self_validating_payload::SelfValidatingPayloadValidationError,
        >;
    }
}
