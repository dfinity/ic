use candid::{CandidType, Principal};
use serde::de::DeserializeOwned;
use std::collections::BTreeSet;
use std::time::Duration;
use std::{fmt::Display, future::Future};

pub mod agent_impl;
pub mod helpers;
pub mod icrc2;
pub mod ledger;
pub mod management_canister;
pub mod mock;
pub mod nns;
mod null_request;
pub mod pocketic_impl;
mod registry;
pub mod sns;
#[cfg(feature = "test")]
pub mod state_machine_impl;

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

    /// See https://internetcomputer.org/docs/references/ic-interface-spec#http-interface
    fn effective_canister_id(&self) -> Option<Principal> {
        None
    }
    type Response: CandidType + DeserializeOwned + Send;
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
    ) -> impl Future<Output = Result<R::Response, Self::Error>> + Send;

    fn canister_info(
        &self,
        canister_id: impl Into<Principal> + Send,
    ) -> impl Future<Output = Result<CanisterInfo, Self::Error>> + Send;
}

pub trait AgentFor: sealed::Sealed {
    fn agent_for(&self, principal: impl Into<Principal>) -> impl CallCanisters;
}

// Functions that use 'call' need to be able
// to determine if a call to the canister failed due to the canister being stopped.
// Matching on a specific error outside of the trait implementation is not viable
// since the 'Error' type is different for each trait implementation and thus we can
// only match on specific implementations errors in the trait implementation directly.
//
// We're extending CallCanisters trait to allow this.
pub trait CallCanistersWithStoppedCanisterError: CallCanisters {
    fn is_canister_stopped_error(&self, err: &Self::Error) -> bool;
}

// This trait is used to abstract the ability to progress the network state
// since various scenarios may require waiting for certain action to happen
// after some period of time, e.g. NNS proposal to become adopted or SNS swap to become open.
//
// @rvem: I don't really like the name, but I didn't manage to come up with a better one for now.
pub trait ProgressNetwork: sealed::Sealed {
    fn progress(&self, duration: Duration) -> impl Future<Output = ()>;
}
