use candid::{CandidType, Encode};
use serde::de::DeserializeOwned;

use crate::Request;

/// Implement a "null request" that can be used to call a canister method whose argument type is `null`.
pub struct NullRequest<T> {
    method_name: &'static str,
    update: bool,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: CandidType + DeserializeOwned> NullRequest<T> {
    pub fn new(method_name: &'static str, update: bool) -> Self {
        Self {
            method_name,
            update,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<T: CandidType + DeserializeOwned + Send> Request for NullRequest<T> {
    fn method(&self) -> &'static str {
        self.method_name
    }
    fn update(&self) -> bool {
        self.update
    }
    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        Encode!()
    }

    type Response = T;
}
