use crate::logs::DEBUG;
use async_trait::async_trait;
use candid::{CandidType, Encode, Principal};
use ic_canister_log::log;
use ic_cdk::call::{Call, CallFailed, OnewayError, RejectCode};
use ic_cdk::management_canister::{
    CanisterInstallMode, CanisterSettings, CanisterStatusArgs, CreateCanisterArgs,
    DepositCyclesArgs, InstallCodeArgs, StartCanisterArgs, StopCanisterArgs, canister_status,
    install_code, start_canister, stop_canister,
};
use serde::de::DeserializeOwned;
use std::fmt;
use std::fmt::Debug;

#[cfg(test)]
mod tests;

// TODO: extract to common crate since copied form ckETH

/// Represents an error from a management canister call, such as
/// `sign_with_ecdsa`.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct CallError {
    pub method: String,
    pub reason: Reason,
}

impl CallError {
    /// Returns the name of the method that resulted in this error.
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Returns the failure reason.
    pub fn reason(&self) -> &Reason {
        &self.reason
    }
}

impl fmt::Display for CallError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            fmt,
            "management call '{}' failed: {}",
            self.method, self.reason
        )
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
/// The reason for the management call failure.
pub enum Reason {
    /// The canister does not have enough cycles to submit the request.
    OutOfCycles,
    /// The call failed with an error.
    CanisterError(String),
    /// The management canister rejected the signature request (not enough
    /// cycles, the ECDSA subnet is overloaded, etc.).
    Rejected(String),
    /// The call failed with a transient error. Retrying may help.
    TransientInternalError(String),
    /// The call failed with a non-transient error. Retrying will not help.
    InternalError(String),
}

impl fmt::Display for Reason {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfCycles => write!(fmt, "the canister is out of cycles"),
            Self::CanisterError(msg) => write!(fmt, "canister error: {msg}"),
            Self::Rejected(msg) => {
                write!(fmt, "the management canister rejected the call: {msg}")
            }
            Reason::TransientInternalError(msg) => write!(fmt, "transient internal error: {msg}"),
            Reason::InternalError(msg) => write!(fmt, "internal error: {msg}"),
        }
    }
}

impl Reason {
    fn from_call_error(error: ic_cdk::call::Error) -> Self {
        use ic_cdk::call::Error;
        match error {
            Error::CallRejected(rejected) => Self::from_reject_code_message(
                rejected.reject_code(),
                rejected.raw_reject_code(),
                rejected.reject_message().to_string(),
            ),
            Error::InsufficientLiquidCycleBalance(_) => Self::OutOfCycles,
            Error::CallPerformFailed(_) => Self::InternalError("call_perform failed".to_string()),
            Error::CandidDecodeFailed(e) => {
                Self::InternalError(format!("candid decode failed: {e}"))
            }
        }
    }

    fn from_call_failed(failed: CallFailed) -> Self {
        match failed {
            CallFailed::CallRejected(rejected) => Self::from_reject_code_message(
                rejected.reject_code(),
                rejected.raw_reject_code(),
                rejected.reject_message().to_string(),
            ),
            CallFailed::InsufficientLiquidCycleBalance(_) => Self::OutOfCycles,
            CallFailed::CallPerformFailed(_) => {
                Self::InternalError("call_perform failed".to_string())
            }
        }
    }

    fn from_oneway_error(error: OnewayError) -> Self {
        match error {
            OnewayError::InsufficientLiquidCycleBalance(_) => Self::OutOfCycles,
            OnewayError::CallPerformFailed(_) => {
                Self::InternalError("call_perform failed".to_string())
            }
        }
    }

    fn from_reject_code_message(
        reject_code: Result<RejectCode, ic_cdk::call::UnrecognizedRejectCode>,
        raw_reject_code: u32,
        message: String,
    ) -> Self {
        match reject_code {
            Ok(RejectCode::SysTransient) => Self::TransientInternalError(message),
            Ok(RejectCode::CanisterError) => Self::CanisterError(message),
            Ok(RejectCode::CanisterReject) => Self::Rejected(message),
            Ok(code) => Self::InternalError(format!(
                "rejection code: {code:?}, rejection message: {message}"
            )),
            Err(_) => Self::InternalError(format!(
                "unrecognized rejection code: {raw_reject_code}, rejection message: {message}"
            )),
        }
    }
}

#[async_trait]
pub trait CanisterRuntime {
    /// Returns the canister id of the current canister.
    fn id(&self) -> Principal;

    /// Gets current timestamp, in nanoseconds since the epoch (1970-01-01)
    fn time(&self) -> u64;

    /// Set a global timer to make the system schedule a call to the exported `canister_global_timer` Wasm method after the specified time.
    /// The time must be provided as nanoseconds since 1970-01-01.
    /// See the [IC specification](https://internetcomputer.org/docs/current/references/ic-interface-spec#global-timer-1).
    fn global_timer_set(&self, timestamp: u64);

    /// Creates a new canister with the given cycles.
    async fn create_canister(
        &self,
        controllers: Vec<Principal>,
        cycles_for_canister_creation: u64,
    ) -> Result<Principal, CallError>;

    /// Stops the given canister.
    async fn stop_canister(&self, canister_id: Principal) -> Result<(), CallError>;

    /// Starts the given canister.
    async fn start_canister(&self, canister_id: Principal) -> Result<(), CallError>;

    /// Installs the given wasm module with the initialization arguments on the given canister.
    async fn install_code(
        &self,
        canister_id: Principal,
        wasm_module: Vec<u8>,
        arg: Vec<u8>,
    ) -> Result<(), CallError>;

    /// Upgrade the given canister without any upgrade arguments.
    async fn upgrade_canister(
        &self,
        canister_id: Principal,
        wasm_module: Vec<u8>,
    ) -> Result<(), CallError>;

    async fn canister_cycles(&self, canister_id: Principal) -> Result<u128, CallError>;

    fn send_cycles(&self, canister_id: Principal, cycles: u128) -> Result<(), CallError>;

    async fn call_canister<I, O>(
        &self,
        canister_id: Principal,
        method: &str,
        args: I,
    ) -> Result<O, CallError>
    where
        I: CandidType + Debug + Send + 'static,
        O: CandidType + DeserializeOwned + Debug + 'static;
}

#[derive(Copy, Clone)]
pub struct IcCanisterRuntime {}

#[async_trait]
impl CanisterRuntime for IcCanisterRuntime {
    fn id(&self) -> Principal {
        ic_cdk::api::canister_self()
    }

    fn time(&self) -> u64 {
        ic_cdk::api::time()
    }

    fn global_timer_set(&self, timestamp: u64) {
        ic0::global_timer_set(timestamp);
    }

    async fn create_canister(
        &self,
        controllers: Vec<Principal>,
        cycles_for_canister_creation: u64,
    ) -> Result<Principal, CallError> {
        // See https://internetcomputer.org/docs/current/references/ic-interface-spec#ic-create_canister
        assert!(
            controllers.len() <= 10,
            "BUG: too many controllers. Expected at most 10, got {}",
            controllers.len()
        );
        let payment = u128::from(cycles_for_canister_creation);
        // Mirrors the ic-cdk pre-flight check inside `Call::await`, which uses
        // `canister_liquid_cycle_balance` (i.e. excluding the freezing-threshold
        // reserve). Using the same liquid balance here avoids issuing a Call we
        // know will fail when the cycle balance is above `payment` but the
        // liquid balance is not.
        let balance = ic_cdk::api::canister_liquid_cycle_balance();
        if balance < payment {
            return Err(CallError {
                method: "create_canister".to_string(),
                reason: Reason::OutOfCycles,
            });
        }
        let create_args = CreateCanisterArgs {
            settings: Some(CanisterSettings {
                controllers: Some(controllers),
                ..Default::default()
            }),
        };
        let result = Call::unbounded_wait(Principal::management_canister(), "create_canister")
            .with_arg(&create_args)
            .with_cycles(payment)
            .await
            .map_err(|err| CallError {
                method: "create_canister".to_string(),
                reason: Reason::from_call_failed(err),
            })?
            .candid::<ic_cdk::management_canister::CreateCanisterResult>()
            .map_err(|err| CallError {
                method: "create_canister".to_string(),
                reason: Reason::InternalError(format!("candid decode failed: {err}")),
            })?;

        Ok(result.canister_id)
    }

    async fn stop_canister(&self, canister_id: Principal) -> Result<(), CallError> {
        stop_canister(&StopCanisterArgs { canister_id })
            .await
            .map_err(|err| CallError {
                method: "stop_canister".to_string(),
                reason: Reason::from_call_error(err),
            })
    }

    async fn start_canister(&self, canister_id: Principal) -> Result<(), CallError> {
        start_canister(&StartCanisterArgs { canister_id })
            .await
            .map_err(|err| CallError {
                method: "start_canister".to_string(),
                reason: Reason::from_call_error(err),
            })
    }

    async fn install_code(
        &self,
        canister_id: Principal,
        wasm_module: Vec<u8>,
        arg: Vec<u8>,
    ) -> Result<(), CallError> {
        install_code(&InstallCodeArgs {
            mode: CanisterInstallMode::Install,
            canister_id,
            wasm_module,
            arg,
        })
        .await
        .map_err(|err| CallError {
            method: "install_code".to_string(),
            reason: Reason::from_call_error(err),
        })
    }

    async fn upgrade_canister(
        &self,
        canister_id: Principal,
        wasm_module: Vec<u8>,
    ) -> Result<(), CallError> {
        install_code(&InstallCodeArgs {
            mode: CanisterInstallMode::Upgrade(None),
            canister_id,
            wasm_module,
            arg: Encode!(&()).unwrap(),
        })
        .await
        .map_err(|err| CallError {
            method: "install_code".to_string(),
            reason: Reason::from_call_error(err),
        })
    }

    async fn canister_cycles(&self, canister_id: Principal) -> Result<u128, CallError> {
        let result = canister_status(&CanisterStatusArgs { canister_id })
            .await
            .map_err(|err| CallError {
                method: "canister_status".to_string(),
                reason: Reason::from_call_error(err),
            })?;

        Ok(result.cycles.0.try_into().unwrap())
    }

    fn send_cycles(&self, canister_id: Principal, cycles: u128) -> Result<(), CallError> {
        Call::unbounded_wait(Principal::management_canister(), "deposit_cycles")
            .with_arg(&DepositCyclesArgs { canister_id })
            .with_cycles(cycles)
            .oneway()
            .map_err(|err| CallError {
                method: "send_cycles".to_string(),
                reason: Reason::from_oneway_error(err),
            })
    }

    async fn call_canister<I, O>(
        &self,
        canister_id: Principal,
        method: &str,
        args: I,
    ) -> Result<O, CallError>
    where
        I: CandidType + Debug + Send + 'static,
        O: CandidType + DeserializeOwned + Debug + 'static,
    {
        log!(
            DEBUG,
            "Calling canister '{}' with method '{}' and payload '{:?}'",
            canister_id,
            method,
            args
        );
        let res: Result<O, _> = Call::unbounded_wait(canister_id, method)
            .with_arg(&args)
            .await
            .map_err(|err| CallError {
                method: method.to_string(),
                reason: Reason::from_call_failed(err),
            })
            .and_then(|response| {
                response.candid::<O>().map_err(|err| CallError {
                    method: method.to_string(),
                    reason: Reason::InternalError(format!("candid decode failed: {err}")),
                })
            });
        log!(
            DEBUG,
            "Result of calling canister '{}' with method '{}' and payload '{:?}': {:?}",
            canister_id,
            method,
            args,
            res
        );
        res
    }
}
