pub mod agent_impl;
pub mod nns;
mod null_request;
pub mod pocketic_impl;
pub mod sns;

use candid::{CandidType, Principal};
use serde::de::DeserializeOwned;
use std::fmt::Display;

// This is used to "seal" the CallCanisters trait so that it cannot be implemented outside of this crate.
// This is useful because it means we can modify the trait in the future without worrying about
// breaking backwards compatibility with implementations outside of this crate.
mod sealed {
    pub trait Sealed {}
}

/// An implementation of the request trait that is used internally by this crate.
/// It is separate from the one in ic_nervous_system_clients because that one makes certain simplifying assumptions
/// that are not valid for all requests made by this crate.
/// When in doubt, prefer implementing the trait in ic_nervous_system_clients over this one.
pub trait Request: Send {
    fn method(&self) -> &'static str;
    fn update(&self) -> bool;
    fn payload(&self) -> Result<Vec<u8>, candid::Error>;
    type Response: CandidType + DeserializeOwned;
}

impl<R: ic_nervous_system_clients::Request> Request for R {
    fn method(&self) -> &'static str {
        Self::METHOD
    }
    fn update(&self) -> bool {
        Self::UPDATE
    }
    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = <Self as ic_nervous_system_clients::Request>::Response;
}

pub trait CallCanisters: sealed::Sealed {
    type Error: Display + Send + std::error::Error + 'static;
    fn call<R: Request>(
        &self,
        canister_id: impl Into<Principal> + Send,
        request: R,
    ) -> impl std::future::Future<Output = Result<R::Response, Self::Error>> + Send;
}
