use crate::{IcError, Runtime};
use async_trait::async_trait;
use candid::{decode_one, encode_args, utils::ArgumentEncoder, CandidType, Deserialize, Principal};
use ic_cdk::management_canister::CanisterId;
use ic_error_types::RejectCode;
use regex_lite::Regex;
use serde::de::DeserializeOwned;

/// Runtime wrapping another [`Runtime`] instance, where update calls are routed through a
/// [cycles wallet](https://github.com/dfinity/cycles-wallet) to attach cycles to them.
pub struct CyclesWalletRuntime<R> {
    runtime: R,
    cycles_wallet_canister_id: Principal,
}

impl<R> CyclesWalletRuntime<R> {
    /// Create a new [`CyclesWalletRuntime`] wrapping the given [`Runtime`] by routing update calls
    /// through the given cycles wallet to attach cycles.
    pub fn new(runtime: R, cycles_wallet_canister_id: Principal) -> Self {
        CyclesWalletRuntime {
            runtime,
            cycles_wallet_canister_id,
        }
    }

    /// Return a reference to the underlying runtime.
    pub fn get_runtime(&self) -> &R {
        &self.runtime
    }

    /// Modify the underlying runtime by applying a transformation function.
    ///
    /// The transformation does not necessarily produce a runtime of the same type.
    pub fn with_runtime<S, F: FnOnce(R) -> S>(self, transformation: F) -> CyclesWalletRuntime<S> {
        CyclesWalletRuntime {
            runtime: transformation(self.runtime),
            cycles_wallet_canister_id: self.cycles_wallet_canister_id,
        }
    }
}

#[async_trait]
impl<R: Runtime + Send + Sync> Runtime for CyclesWalletRuntime<R> {
    async fn update_call<In, Out>(
        &self,
        id: Principal,
        method: &str,
        args: In,
        cycles: u128,
    ) -> Result<Out, IcError>
    where
        In: ArgumentEncoder + Send,
        Out: CandidType + DeserializeOwned,
    {
        self.runtime
            .update_call::<(WalletCall128Args,), Result<WalletCall128Result, String>>(
                self.cycles_wallet_canister_id,
                "wallet_call128",
                (WalletCall128Args::new(id, method, args, cycles),),
                0,
            )
            .await
            .and_then(decode_cycles_wallet_response)
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
        self.runtime.query_call(id, method, args).await
    }
}

// Argument to the cycles wallet canister `wallet_call128` method.
#[derive(CandidType, Deserialize)]
struct WalletCall128Args {
    canister: Principal,
    method_name: String,
    #[serde(with = "serde_bytes")]
    args: Vec<u8>,
    cycles: u128,
}

impl WalletCall128Args {
    pub fn new<In: ArgumentEncoder>(
        canister_id: CanisterId,
        method: impl ToString,
        args: In,
        cycles: u128,
    ) -> Self {
        Self {
            canister: canister_id,
            method_name: method.to_string(),
            args: encode_args(args).unwrap_or_else(panic_when_encode_fails),
            cycles,
        }
    }
}

// Return type of the cycles wallet canister `wallet_call128` method.
#[derive(CandidType, Deserialize)]
struct WalletCall128Result {
    #[serde(with = "serde_bytes", rename = "return")]
    pub bytes: Vec<u8>,
}

// The cycles wallet canister formats the rejection code and error message from the target
// canister into a single string. Extract them back from the formatted string.
fn decode_cycles_wallet_response<Out>(
    result: Result<WalletCall128Result, String>,
) -> Result<Out, IcError>
where
    Out: CandidType + DeserializeOwned,
{
    match result {
        Ok(WalletCall128Result { bytes }) => {
            decode_one(&bytes).map_err(|e| IcError::CandidDecodeFailed {
                message: format!(
                    "failed to decode canister response as {}: {}",
                    std::any::type_name::<Out>(),
                    e
                ),
            })
        }
        Err(message) => {
            match Regex::new(r"^An error happened during the call: (\d+): (.*)$")
                .unwrap()
                .captures(&message)
            {
                Some(captures) => {
                    let (_, [code, message]) = captures.extract();
                    Err(IcError::CallRejected {
                        code: code.parse::<u64>().unwrap().try_into().unwrap(),
                        message: message.to_string(),
                    })
                }
                None => Err(IcError::CallRejected {
                    code: RejectCode::SysFatal,
                    message: message.to_string(),
                }),
            }
        }
    }
}

fn panic_when_encode_fails(err: candid::error::Error) -> Vec<u8> {
    panic!("failed to encode args: {err}")
}
