#[cfg(test)]
mod tests;

use crate::{IcError, Runtime};
use async_trait::async_trait;
use candid::{utils::ArgumentEncoder, CandidType, Decode, Encode, Principal};
use serde::de::DeserializeOwned;
use std::sync::Arc;
use std::{collections::VecDeque, sync::Mutex};

/// An implementation of [`Runtime`] that returns pre-defined results from a queue.
/// This runtime is primarily intended for testing purposes.
///
/// # Examples
///
/// ```rust
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use candid::Principal;
/// use ic_canister_runtime::{IcError, Runtime, StubRuntime};
///
/// const PRINCIPAL: Principal = Principal::from_slice(&[0x9d, 0xf7, 0x01]);
/// const METHOD: &str = "method";
/// const ARGS: (&str,) = ("args",);
///
/// let runtime = StubRuntime::new()
///     .add_stub_response(1_u64)
///     .add_stub_response("two")
///     .add_stub_error(IcError::CallPerformFailed);
///
/// let result_1: Result<u64, IcError> = runtime
///     .update_call(PRINCIPAL, METHOD, ARGS, 0)
///     .await;
/// assert_eq!(result_1, Ok(1_u64));
///
/// let result_2: Result<String, IcError> = runtime
///     .query_call(PRINCIPAL, METHOD, ARGS)
///     .await;
/// assert_eq!(result_2, Ok("two".to_string()));
///
/// let result_3: Result<Option<u128>, IcError> = runtime
///     .query_call(PRINCIPAL, METHOD, ARGS)
///     .await;
/// assert_eq!(result_3, Err(IcError::CallPerformFailed));
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Default, Clone)]
pub struct StubRuntime {
    // Use a mutex so that this struct is Send and Sync
    #[allow(clippy::type_complexity)]
    call_results: Arc<Mutex<VecDeque<Result<Vec<u8>, IcError>>>>,
}

impl StubRuntime {
    /// Create a new empty [`StubRuntime`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Mutate the [`StubRuntime`] instance to add the given stub response.
    ///
    /// Panics if the stub response cannot be encoded using Candid.
    pub fn add_stub_response<Out: CandidType>(self, stub_response: Out) -> Self {
        let result = Encode!(&stub_response).expect("Failed to encode Candid stub response");
        self.call_results.try_lock().unwrap().push_back(Ok(result));
        self
    }

    /// Mutate the [`StubRuntime`] instance to add the given stub error.
    pub fn add_stub_error(self, stub_error: impl Into<IcError>) -> Self {
        self.call_results
            .try_lock()
            .unwrap()
            .push_back(Err(stub_error.into()));
        self
    }

    fn call<Out>(&self) -> Result<Out, IcError>
    where
        Out: CandidType + DeserializeOwned,
    {
        self.call_results
            .try_lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| panic!("No available call response"))
            .map(|bytes| Decode!(&bytes, Out).expect("Failed to decode Candid stub response"))
    }
}

#[async_trait]
impl Runtime for StubRuntime {
    async fn update_call<In, Out>(
        &self,
        _id: Principal,
        _method: &str,
        _args: In,
        _cycles: u128,
    ) -> Result<Out, IcError>
    where
        In: ArgumentEncoder + Send,
        Out: CandidType + DeserializeOwned,
    {
        self.call()
    }

    async fn query_call<In, Out>(
        &self,
        _id: Principal,
        _method: &str,
        _args: In,
    ) -> Result<Out, IcError>
    where
        In: ArgumentEncoder + Send,
        Out: CandidType + DeserializeOwned,
    {
        self.call()
    }
}
