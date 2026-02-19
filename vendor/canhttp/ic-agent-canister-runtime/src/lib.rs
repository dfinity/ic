//! Library that implements the [`ic_canister_runtime`](https://crates.io/crates/ic-canister-runtime)
//! crate's Runtime trait using [`ic-agent`](https://crates.io/crates/ic-agent).
//! This can be useful when, e.g., contacting a canister via ingress messages instead of via another
//! canister.

use async_trait::async_trait;
use candid::{decode_one, encode_args, utils::ArgumentEncoder, CandidType, Principal};
use ic_agent::{Agent, AgentError};
use ic_canister_runtime::{IcError, Runtime};
use ic_error_types::RejectCode;
use serde::de::DeserializeOwned;

/// Runtime for interacting with a canister through an [`ic_agent::Agent`].
/// This can be useful when, e.g., contacting a canister via ingress messages instead of via another
/// canister.
///
///
/// # Examples
///
/// Call the `make_http_post_request` endpoint on the example [`http_canister`].
/// ```rust, no_run
/// # #[allow(deref_nullptr)]
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use ic_agent::agent::Agent;
/// use ic_agent_canister_runtime::AgentRuntime;
/// use ic_canister_runtime::Runtime;
/// # use candid::Principal;
///
/// let agent = Agent::builder().build().expect("Failed to initialize agent");
/// let runtime = AgentRuntime::new(&agent);
/// # let canister_id = Principal::anonymous();
/// let http_request_result: String = runtime
///     .update_call(canister_id, "make_http_post_request", (), 0)
///     .await
///     .expect("Call to `http_canister` failed");
///
/// assert!(http_request_result.contains("Hello, World!"));
/// assert!(http_request_result.contains("\"X-Id\": \"42\""));
/// # Ok(())
/// # }
/// ```
///
/// [`http_canister`]: https://github.com/dfinity/canhttp/tree/main/examples/http_canister/
#[derive(Clone, Debug)]
pub struct AgentRuntime<'a> {
    agent: &'a Agent,
}

impl<'a> AgentRuntime<'a> {
    /// Create a new [`AgentRuntime`] with the given [`Agent`].
    pub fn new(agent: &'a Agent) -> Self {
        Self { agent }
    }
}

#[async_trait]
impl Runtime for AgentRuntime<'_> {
    async fn update_call<In, Out>(
        &self,
        id: Principal,
        method: &str,
        args: In,
        _cycles: u128,
    ) -> Result<Out, IcError>
    where
        In: ArgumentEncoder + Send,
        Out: CandidType + DeserializeOwned,
    {
        self.agent
            .update(&id, method)
            .with_arg(encode_args(args).unwrap_or_else(panic_when_encode_fails))
            .call_and_wait()
            .await
            .map_err(convert_agent_error)
            .and_then(decode_agent_response)
    }

    async fn query_call<In, Out>(
        &self,
        id: Principal,
        method: &str,
        args: In,
    ) -> Result<Out, IcError>
    where
        In: ArgumentEncoder + Send,
        Out: CandidType + DeserializeOwned,
    {
        self.agent
            .query(&id, method)
            .with_arg(encode_args(args).unwrap_or_else(panic_when_encode_fails))
            .call()
            .await
            .map_err(convert_agent_error)
            .and_then(decode_agent_response)
    }
}

fn decode_agent_response<Out>(result: Vec<u8>) -> Result<Out, IcError>
where
    Out: CandidType + DeserializeOwned,
{
    decode_one::<Out>(&result).map_err(|e| IcError::CandidDecodeFailed {
        message: e.to_string(),
    })
}

fn convert_agent_error(e: AgentError) -> IcError {
    if let AgentError::CertifiedReject { ref reject, .. } = e {
        if let Ok(code) = RejectCode::try_from(reject.reject_code as u64) {
            return IcError::CallRejected {
                code,
                message: reject.reject_message.clone(),
            };
        }
    }
    IcError::CallRejected {
        code: RejectCode::SysFatal,
        message: e.to_string(),
    }
}

fn panic_when_encode_fails(err: candid::error::Error) -> Vec<u8> {
    panic!("failed to encode args: {err}")
}
