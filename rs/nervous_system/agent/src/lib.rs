use candid::{CandidType, Principal};
use serde::de::DeserializeOwned;
use std::collections::BTreeSet;
use std::fmt::Display;

pub mod agent_impl;
pub mod management_canister;
pub mod nns;
mod null_request;
pub mod pocketic_impl;
pub mod sns;

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

pub struct CanisterInfo {
    pub module_hash: Option<Vec<u8>>,
    pub controllers: BTreeSet<Principal>,
}

pub trait CallCanisters: sealed::Sealed {
    type Error: Display + Send + std::error::Error + 'static;

    fn caller(&self) -> Result<Principal, Self::Error>;

    fn call<R: Request>(
        &self,
        canister_id: impl Into<Principal> + Send,
        request: R,
    ) -> impl std::future::Future<Output = Result<R::Response, Self::Error>> + Send;

    fn canister_info(
        &self,
        canister_id: impl Into<Principal> + Send,
    ) -> impl std::future::Future<Output = Result<CanisterInfo, Self::Error>> + Send;
}
