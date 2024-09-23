mod agent_impl;
pub mod nns;
mod pocketic_impl;
pub mod sns;

use candid::Principal;
use ic_nervous_system_clients::Request;
use std::fmt::Display;

pub trait CallCanisters {
    type Error: Display + Send;
    fn call<R: Request>(
        &self,
        canister_id: impl Into<Principal> + Send,
        request: R,
    ) -> impl std::future::Future<Output = Result<R::Response, Self::Error>> + Send;
}
