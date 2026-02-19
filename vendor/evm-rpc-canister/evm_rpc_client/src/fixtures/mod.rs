//! Basic unit tests utilities for the [`crate::EvmRpcClient`].
//!
//! Types and methods for this module are only available for non-canister architecture (non `wasm32`).

use crate::ClientBuilder;
use candid::CandidType;
use ic_canister_runtime::StubRuntime;

impl<R, C, P> ClientBuilder<R, C, P> {
    /// Set the runtime to a [`StubRuntime`].
    pub fn with_stub_runtime(self) -> ClientBuilder<StubRuntime, C, P> {
        self.with_runtime(|_runtime| StubRuntime::default())
    }

    /// Change the runtime to return the given stub response for all calls.
    pub fn with_stub_response<Out: CandidType>(
        self,
        stub_response: Out,
    ) -> ClientBuilder<StubRuntime, C, P> {
        self.with_stub_runtime().add_stub_response(stub_response)
    }
}

impl<C, P> ClientBuilder<StubRuntime, C, P> {
    /// Change the runtime to return the given stub response for all calls.
    pub fn add_stub_response<Out: CandidType>(
        self,
        stub_response: Out,
    ) -> ClientBuilder<StubRuntime, C, P> {
        self.with_runtime(|runtime| runtime.add_stub_response(stub_response))
    }
}
