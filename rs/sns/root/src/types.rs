use std::fmt::{self, Display, Formatter};

use async_trait::async_trait;
use ic_base_types::{CanisterId, PrincipalId};
use serde::{Deserialize, Serialize};

use crate::pb::v1::{
    register_extension_response, CanisterCallError, RegisterExtensionRequest,
    RegisterExtensionResponse,
};

/// A general trait for the environment in which governance is running.
#[async_trait]
pub trait Environment: Send + Sync {
    /// Returns the current time, in seconds since the epoch.
    fn now(&self) -> u64;

    /// Calls another canister. The return value indicates whether the call can be successfully
    /// initiated. If initiating the call is successful, the call could later be rejected by the
    /// remote canister. In CanisterEnv (the production implementation of this trait), to
    /// distinguish between whether the remote canister replies or rejects,
    /// set_proposal_execution_status is called (asynchronously). Therefore, the caller of
    /// call_canister should not call set_proposal_execution_status if call_canister returns Ok,
    /// because the call could fail later.
    async fn call_canister(
        &self,
        canister_id: CanisterId,
        method_name: &str,
        arg: Vec<u8>,
    ) -> get_open_ticket_response::Result<
        /* reply: */ Vec<u8>,
        (/* error_code: */ i32, /* message: */ String),
    >;
}

/// Different from the SnsCanisterType in SNS-W because it includes Dap
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub enum SnsCanisterType {
    Root,
    Governance,
    Ledger,
    Swap,
    Archive,
    Index,
    Dapp,
}

impl Display for SnsCanisterType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SnsCanisterType::Root => write!(f, "root"),
            SnsCanisterType::Governance => write!(f, "governance"),
            SnsCanisterType::Ledger => write!(f, "ledger"),
            SnsCanisterType::Swap => write!(f, "swap"),
            SnsCanisterType::Dapp => write!(f, "dapp"),
            SnsCanisterType::Archive => write!(f, "archive"),
            SnsCanisterType::Index => write!(f, "index"),
        }
    }
}

impl TryFrom<RegisterExtensionRequest> for PrincipalId {
    type Error = CanisterCallError;

    fn try_from(value: RegisterExtensionRequest) -> Result<Self, Self::Error> {
        let RegisterExtensionRequest { canister_id } = value;

        let Some(canister_id) = canister_id else {
            // RejectCode::DestinationInvalid
            let code = Some(3);
            let description = "RegisterExtensionRequest.canister_id must be set.".to_string();

            let err = CanisterCallError { code, description };

            return Err(err);
        };

        Ok(canister_id)
    }
}

impl From<Result<(), CanisterCallError>> for RegisterExtensionResponse {
    fn from(result: Result<(), CanisterCallError>) -> Self {
        use register_extension_response::{Ok, Result};
        match result {
            Ok(_) => RegisterExtensionResponse {
                result: Some(Result::Ok(Ok {})),
            },
            Err(err) => RegisterExtensionResponse {
                result: Some(Result::Err(err)),
            },
        }
    }
}
