use ic_base_types::NumBytes;
use ic_interfaces::{
    batch_payload::{BatchPayloadBuilder, PastPayload, ProposalContext},
    consensus::PayloadValidationError,
    validation::ValidationResult,
};
use ic_types::{
    Height,
    batch::{ValidationContext, iterator_to_bytes},
};
use mockall::*;

mock! {
    pub BatchPayloadBuilder {}

    impl BatchPayloadBuilder for BatchPayloadBuilder {
        fn build_payload<'a>(
            &self,
            height: Height,
            max_size: NumBytes,
            past_payloads: &[PastPayload<'a>],
            context: &ValidationContext,
        ) -> Vec<u8>;

        fn validate_payload<'a>(
            &self,
            height: Height,
            proposal_context: &ProposalContext<'a>,
            payload: &[u8],
            past_payloads: &[PastPayload<'a>],
        ) -> ValidationResult<PayloadValidationError>;
    }
}

impl MockBatchPayloadBuilder {
    /// Expect the payload builder to only return empty payloads
    pub fn expect_noop(mut self) -> Self {
        self.expect_build_payload().return_const(vec![]);
        self.expect_validate_payload()
            .returning(|_, _, _, _| Ok(()));

        self
    }

    /// Expect the payload builder to return the serialized payload given by responses
    /// Returns always ok on validation
    pub fn with_responses<'a, A, M>(mut self, responses: &'a [A]) -> Self
    where
        A: 'a,
        M: prost::Message + From<&'a A>,
    {
        let response = iterator_to_bytes(
            responses
                .iter()
                .map(|response| <&A as Into<M>>::into(response)),
            NumBytes::new(4 * 1024 * 1024),
        );
        self.expect_build_payload().return_const(response);
        self.expect_validate_payload()
            .returning(|_, _, _, _| Ok(()));

        self
    }

    /// Expect the payload builder to return the serialized payload given by responses
    /// Returns always ok on validation
    pub fn with_response_and_max_size(
        mut self,
        response: Vec<u8>,
        expected_max_size: NumBytes,
    ) -> Self {
        self.expect_build_payload()
            .with(
                predicate::always(),
                predicate::eq(expected_max_size),
                predicate::always(),
                predicate::always(),
            )
            .return_const(response);
        self.expect_validate_payload()
            .returning(|_, _, _, _| Ok(()));

        self
    }
}
