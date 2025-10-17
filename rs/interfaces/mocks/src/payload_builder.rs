use ic_interfaces::{
    ingress_manager::IngressSelector, self_validating_payload::SelfValidatingPayloadBuilder,
    validation::ValidationResult,
};
use ic_types::{Height, NumBytes, batch::ValidationContext};

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

mock! {
   pub IngressSelector {}

   impl IngressSelector for IngressSelector {
     fn get_ingress_payload(
         &self,
         past_ingress: &dyn ic_interfaces::ingress_manager::IngressSetQuery,
         context: &ValidationContext,
         byte_limit: NumBytes,
     ) -> ic_types::batch::IngressPayload;

     fn validate_ingress_payload(
         &self,
         payload: &ic_types::batch::IngressPayload,
         past_ingress: &dyn ic_interfaces::ingress_manager::IngressSetQuery,
         context: &ValidationContext,
     ) -> ValidationResult<ic_interfaces::ingress_manager::IngressPayloadValidationError>;

     fn filter_past_payloads(
         &self,
         past_payloads: &[(Height, ic_types::Time, ic_types::consensus::Payload)],
         context: &ValidationContext,
     ) -> ic_types::ingress::IngressSets;

     fn request_purge_finalized_messages(&self, message_ids: Vec<ic_types::artifact::IngressMessageId>);
   }
}
