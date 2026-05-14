use async_trait::async_trait;
use candid::{CandidType, Deserialize};
use ic_base_types::CanisterId;
use ic_cdk::call::{Call, CallFailed, InsufficientLiquidCycleBalance};
use std::sync::{Arc, Mutex};

#[derive(CandidType, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct MaturityModulation {
    pub current_value_permyriad: Option<i32>,
    pub updated_at_timestamp_seconds: Option<u64>,
}

#[derive(CandidType, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct GetMaturityModulationRequest {}

#[derive(CandidType, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct GetMaturityModulationResponse {
    pub maturity_modulation: Option<MaturityModulation>,
}

#[async_trait]
pub trait NnsGovernanceClient: Send + Sync {
    /// Fetch the current maturity modulation from NNS Governance, in permyriad
    /// (equivalent to basis points: 1/10,000). Returns `Ok(None)` if NNS
    /// Governance has not yet computed a value.
    async fn get_maturity_modulation(&self) -> Result<Option<i32>, String>;
}

pub struct RealNnsGovernanceClient {
    canister_id: CanisterId,
}

impl RealNnsGovernanceClient {
    pub fn new(canister_id: CanisterId) -> Self {
        Self { canister_id }
    }
}

#[async_trait]
impl NnsGovernanceClient for RealNnsGovernanceClient {
    async fn get_maturity_modulation(&self) -> Result<Option<i32>, String> {
        let response = Call::bounded_wait(self.canister_id.get().0, "get_maturity_modulation")
            .with_arg(GetMaturityModulationRequest {})
            .await
            .map_err(call_failed_to_string)?;

        let response: GetMaturityModulationResponse = response
            .candid()
            .map_err(|err| format!("Failed to decode get_maturity_modulation response: {err}"))?;

        Ok(response
            .maturity_modulation
            .and_then(|m| m.current_value_permyriad))
    }
}

fn call_failed_to_string(call_failed: CallFailed) -> String {
    match call_failed {
        CallFailed::InsufficientLiquidCycleBalance(InsufficientLiquidCycleBalance {
            available,
            required,
        }) => format!(
            "Insufficient liquid cycle balance to call NNS Governance: \
             available={available} vs. required={required}",
        ),
        CallFailed::CallPerformFailed(_) => {
            "The underlying ic0.call_perform operation returned a non-zero code.".to_string()
        }
        CallFailed::CallRejected(err) => {
            let code = err.reject_code().map(|code| code as i32).unwrap_or(-1);
            format!("Call rejected (code {code}): {}", err.reject_message())
        }
    }
}

/// A test fake that returns a configurable maturity modulation value.
///
/// The value is held behind an `Arc<Mutex<_>>` so that tests can clone the fake
/// (e.g., to keep a handle for later mutation) while it is owned by the
/// governance canister under test.
#[derive(Clone, Default)]
pub struct FakeNnsGovernanceClient {
    pub maturity_modulation: Arc<Mutex<i32>>,
}

impl FakeNnsGovernanceClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_maturity_modulation(maturity_modulation: i32) -> Self {
        Self {
            maturity_modulation: Arc::new(Mutex::new(maturity_modulation)),
        }
    }
}

#[async_trait]
impl NnsGovernanceClient for FakeNnsGovernanceClient {
    async fn get_maturity_modulation(&self) -> Result<Option<i32>, String> {
        Ok(Some(*self.maturity_modulation.lock().unwrap()))
    }
}
