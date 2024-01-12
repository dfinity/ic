use crate::state::Wasm;
use candid::{CandidType, Principal};
use ic_base_types::PrincipalId;
use ic_cdk::api::call::RejectionCode;
use ic_ic00_types::{
    CanisterIdRecord, CanisterInstallMode, CanisterSettingsArgsBuilder, CreateCanisterArgs,
    InstallCodeArgs,
};
use serde::de::DeserializeOwned;
use std::fmt;

// TODO: extract to common crate since copied form ckETH

/// Represents an error from a management canister call, such as
/// `sign_with_ecdsa`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallError {
    method: String,
    reason: Reason,
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

#[derive(Debug, Clone, PartialEq, Eq)]
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

async fn call<I, O>(method: &str, payment: u64, input: &I) -> Result<O, CallError>
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

pub async fn create_canister(cycles_for_canister_creation: u64) -> Result<Principal, CallError> {
    let create_args = CreateCanisterArgs {
        settings: Some(
            CanisterSettingsArgsBuilder::new()
                .with_controllers(vec![ic_cdk::id().into()])
                .build(),
        ),
        ..Default::default()
    };
    let result: CanisterIdRecord = call(
        "create_canister",
        cycles_for_canister_creation,
        &create_args,
    )
    .await?;

    Ok(result.get_canister_id().get().into())
}

pub async fn install_code(
    canister_id: Principal,
    wasm_module: Wasm,
    arg: Vec<u8>,
) -> Result<(), CallError> {
    let install_code = InstallCodeArgs {
        mode: CanisterInstallMode::Install,
        canister_id: PrincipalId::from(canister_id),
        wasm_module: wasm_module.to_bytes(),
        arg,
        compute_allocation: None,
        memory_allocation: None,
        query_allocation: None,
        sender_canister_version: None,
    };

    call("install_code", 0, &install_code).await?;

    Ok(())
}
