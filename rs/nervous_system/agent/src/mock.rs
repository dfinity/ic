//! Ideally, we would use mockall to generate MockCallCanisters, but the
//! CallCanisters trait is a pretty sophisticated trait. As a result, trying to
//! make mockall generate a MockCallCanisters is maybe impossible. Therefore, we
//! have to hand-craft this MockCallCanisters. See ./mock/tests.rs for examples.

use super::*;
use candid::Encode;
use std::{cell::RefCell, collections::VecDeque};

pub struct MockCallCanisters {
    remaining_expected_calls: RefCell<VecDeque<ExpectedCall>>,
}

impl MockCallCanisters {
    pub fn new() -> Self {
        Self {
            remaining_expected_calls: RefCell::new(VecDeque::new()),
        }
    }

    pub fn expect_call<R: Request>(
        &self,
        canister_id: Principal,
        request: R,
        result: Result<R::Response, MockCallCanistersError>,
    ) {
        let request = request.payload().unwrap();
        let result = result.map(|response| Encode!(&response).unwrap());

        self.remaining_expected_calls
            .borrow_mut()
            .push_back(ExpectedCall {
                canister_id,
                request,
                result,
            });
    }
}

impl Default for MockCallCanisters {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::sealed::Sealed for MockCallCanisters {}

impl Drop for MockCallCanisters {
    fn drop(&mut self) {
        let calls = self.remaining_expected_calls.borrow();
        let len = calls.len();
        assert!(
            calls.is_empty(),
            "{len} expected calls were left over (i.e. were never made):\n{calls:#?}",
        );
    }
}

impl CallCanisters for MockCallCanisters {
    type Error = MockCallCanistersError;

    fn call<R: Request>(
        &self,
        canister_id: impl Into<Principal> + Send,
        request: R,
    ) -> impl Future<Output = Result<R::Response, Self::Error>> + Send {
        let canister_id: Principal = canister_id.into();
        let request: Vec<u8> = request.payload().unwrap();

        let next_expected_call = self
            .remaining_expected_calls
            .borrow_mut()
            .pop_front()
            .unwrap();

        let result =
            next_expected_call.get_return_value_or_panic::<R::Response>(canister_id, request);
        std::future::ready(result)
    }

    /// This could be implemented later, but for now, it's not needed.
    fn caller(&self) -> Result<Principal, Self::Error> {
        unimplemented!()
    }

    /// This could be implemented later, but for now, it's not needed.
    fn canister_info(
        &self,
        _canister_id: impl Into<Principal> + Send,
    ) -> impl Future<Output = Result<CanisterInfo, Self::Error>> + Send {
        // Normally, I'd use the unimplemented! macro, but that does not seem to
        // work here for some reason (bug??).
        panic!("Not implemented");
        #[allow(unreachable_code)]
        std::future::ready(Err(MockCallCanistersError("UNREACHABLE".to_string())))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct MockCallCanistersError(pub String);

impl std::error::Error for MockCallCanistersError {}

impl Display for MockCallCanistersError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ExpectedCall {
    canister_id: Principal,
    request: Vec<u8>,
    result: Result<Vec<u8>, MockCallCanistersError>,
}

impl ExpectedCall {
    fn get_return_value_or_panic<Response>(
        self,
        canister_id: Principal,
        request: Vec<u8>,
    ) -> Result<Response, MockCallCanistersError>
    where
        Response: CandidType + DeserializeOwned,
    {
        // Verify arguments.
        pretty_assertions::assert_eq!((canister_id, request), (self.canister_id, self.request),);

        self.result.map(|ok| candid::decode_one(&ok).unwrap())
    }
}

#[cfg(test)]
mod tests;
