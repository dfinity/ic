use crate::logs::DEBUG;
use async_trait::async_trait;
use candid::{CandidType, Encode, Principal};
use ic_base_types::PrincipalId;
use ic_canister_log::log;
use ic_cdk::api::call::RejectionCode;
use ic_management_canister_types::{
    CanisterIdRecord, CanisterInstallMode, CanisterSettingsArgsBuilder, CreateCanisterArgs,
    InstallCodeArgs,
};
use serde::de::DeserializeOwned;
use std::fmt;
use std::fmt::Debug;

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
            Self::CanisterError(msg) => write!(fmt, "canister error: {}", msg),
            Self::Rejected(msg) => {
                write!(fmt, "the management canister rejected the call: {}", msg)
            }
            Reason::TransientInternalError(msg) => write!(fmt, "transient internal error: {}", msg),
            Reason::InternalError(msg) => write!(fmt, "internal error: {}", msg),
        }
    }
}

impl Reason {
    fn from_reject(reject_code: RejectionCode, reject_message: String) -> Self {
        match reject_code {
            RejectionCode::SysTransient => Self::TransientInternalError(reject_message),
            RejectionCode::CanisterError => Self::CanisterError(reject_message),
            RejectionCode::CanisterReject => Self::Rejected(reject_message),
            RejectionCode::NoError
            | RejectionCode::SysFatal
            | RejectionCode::DestinationInvalid
            | RejectionCode::Unknown => Self::InternalError(format!(
                "rejection code: {:?}, rejection message: {}",
                reject_code, reject_message
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

impl IcCanisterRuntime {
    async fn call<I, O>(&self, method: &str, payment: u64, input: &I) -> Result<O, CallError>
    where
        I: CandidType,
        O: CandidType + DeserializeOwned,
    {
        let balance = ic_cdk::api::canister_balance128();
        if balance < payment as u128 {
            return Err(CallError {
                method: method.to_string(),
                reason: Reason::OutOfCycles,
            });
        }

        let res: Result<(O,), _> = ic_cdk::api::call::call_with_payment(
            Principal::management_canister(),
            method,
            (input,),
            payment,
        )
        .await;

        match res {
            Ok((output,)) => Ok(output),
            Err((code, msg)) => Err(CallError {
                method: method.to_string(),
                reason: Reason::from_reject(code, msg),
            }),
        }
    }
}

#[async_trait]
impl CanisterRuntime for IcCanisterRuntime {
    fn id(&self) -> Principal {
        ic_cdk::id()
    }

    fn time(&self) -> u64 {
        ic_cdk::api::time()
    }

    fn global_timer_set(&self, timestamp: u64) {
        // SAFETY: setting the global timer is always safe; it does not
        // mutate any canister memory.
        unsafe {
            ic0::global_timer_set(timestamp as i64);
        }
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
        let create_args = CreateCanisterArgs {
            settings: Some(
                CanisterSettingsArgsBuilder::new()
                    .with_controllers(controllers.into_iter().map(|p| p.into()).collect())
                    .build(),
            ),
            ..Default::default()
        };
        let result: CanisterIdRecord = self
            .call(
                "create_canister",
                cycles_for_canister_creation,
                &create_args,
            )
            .await?;

        Ok(result.get_canister_id().get().into())
    }

    async fn stop_canister(&self, canister_id: Principal) -> Result<(), CallError> {
        ic_cdk::api::management_canister::main::stop_canister(
            ic_cdk::api::management_canister::main::CanisterIdRecord { canister_id },
        )
        .await
        .map_err(|(code, msg)| CallError {
            method: "stop_canister".to_string(),
            reason: Reason::from_reject(code, msg),
        })
    }

    async fn start_canister(&self, canister_id: Principal) -> Result<(), CallError> {
        ic_cdk::api::management_canister::main::start_canister(
            ic_cdk::api::management_canister::main::CanisterIdRecord { canister_id },
        )
        .await
        .map_err(|(code, msg)| CallError {
            method: "start_canister".to_string(),
            reason: Reason::from_reject(code, msg),
        })
    }

    async fn install_code(
        &self,
        canister_id: Principal,
        wasm_module: Vec<u8>,
        arg: Vec<u8>,
    ) -> Result<(), CallError> {
        let install_code = InstallCodeArgs {
            mode: CanisterInstallMode::Install,
            canister_id: PrincipalId::from(canister_id),
            wasm_module,
            arg,
            compute_allocation: None,
            memory_allocation: None,
            sender_canister_version: None,
        };

        self.call("install_code", 0, &install_code).await?;

        Ok(())
    }

    async fn upgrade_canister(
        &self,
        canister_id: Principal,
        wasm_module: Vec<u8>,
    ) -> Result<(), CallError> {
        let install_code = InstallCodeArgs {
            mode: CanisterInstallMode::Upgrade,
            canister_id: PrincipalId::from(canister_id),
            wasm_module,
            arg: Encode!(&()).unwrap(),
            compute_allocation: None,
            memory_allocation: None,
            sender_canister_version: None,
        };

        self.call("install_code", 0, &install_code).await?;

        Ok(())
    }

    async fn canister_cycles(&self, canister_id: Principal) -> Result<u128, CallError> {
        let result = ic_cdk::api::management_canister::main::canister_status(
            ic_cdk::api::management_canister::main::CanisterIdRecord { canister_id },
        )
        .await
        .map_err(|(code, msg)| CallError {
            method: "canister_status".to_string(),
            reason: Reason::from_reject(code, msg),
        })?
        .0
        .cycles
        .0
        .try_into()
        .unwrap();

        Ok(result)
    }

    fn send_cycles(&self, canister_id: Principal, cycles: u128) -> Result<(), CallError> {
        #[derive(CandidType)]
        struct DepositCyclesArgs {
            canister_id: Principal,
        }

        ic_cdk::api::call::notify_with_payment128(
            Principal::management_canister(),
            "deposit_cycles",
            (DepositCyclesArgs { canister_id },),
            cycles,
        )
        .map_err(|reject_code| CallError {
            method: "send_cycles".to_string(),
            reason: Reason::from_reject(reject_code, String::default()),
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
        let res: Result<(O,), _> = ic_cdk::api::call::call(canister_id, method, (&args,)).await;
        log!(
            DEBUG,
            "Result of calling canister '{}' with method '{}' and payload '{:?}': {:?}",
            canister_id,
            method,
            args,
            res
        );

        match res {
            Ok((output,)) => Ok(output),
            Err((code, msg)) => Err(CallError {
                method: method.to_string(),
                reason: Reason::from_reject(code, msg),
            }),
        }
    }
}
