mod agent_impl;
pub mod nns;
mod pocketic_impl;
pub mod sns;

use candid::Principal;
use ic_nervous_system_clients::Request;
use std::fmt::Display;

// This is used to "seal" the CallCanisters trait so that it cannot be implemented outside of this crate.
// This is useful because it means we can modify the trait in the future without worrying about
// breaking backwards compatibility with implementations outside of this crate.
mod sealed {
    pub trait Sealed {}
}

pub trait CallCanisters: sealed::Sealed {
    type Error: Display + Send + std::error::Error + 'static;
    fn call<R: Request>(
        &self,
        canister_id: impl Into<Principal> + Send,
        request: R,
    ) -> impl std::future::Future<Output = Result<R::Response, Self::Error>> + Send;
}
