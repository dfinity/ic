use crate::Request;
use sns_treasury_manager::{
    AuditTrail, AuditTrailRequest, BalancesRequest, DepositRequest, TreasuryManagerResult,
    WithdrawRequest,
};

impl Request for DepositRequest {
    fn method(&self) -> &'static str {
        "deposit"
    }

    fn update(&self) -> bool {
        true
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = TreasuryManagerResult;
}

impl Request for WithdrawRequest {
    fn method(&self) -> &'static str {
        "withdraw"
    }

    fn update(&self) -> bool {
        true
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = TreasuryManagerResult;
}

impl Request for BalancesRequest {
    fn method(&self) -> &'static str {
        "balances"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = TreasuryManagerResult;
}

impl Request for AuditTrailRequest {
    fn method(&self) -> &'static str {
        "audit_trail"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = AuditTrail;
}
