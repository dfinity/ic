use crate::CallCanisters;
use crate::Request;
use candid::{CandidType, Encode, Nat};
use ic_base_types::{CanisterId, PrincipalId};

#[derive(CandidType, Clone, Eq, PartialEq, Debug)]
struct WithdrawCyclesArg {
    pub to: PrincipalId,
}

impl Request for WithdrawCyclesArg {
    fn method(&self) -> &'static str {
        "withdraw_cycles"
    }

    fn update(&self) -> bool {
        true
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        Encode!(&self.to)
    }

    type Response = Nat;
}

pub async fn withdraw_cycles<C: CallCanisters>(
    agent: &C,
    store_canister_id: CanisterId,
    to: PrincipalId,
) -> Nat {
    agent
        .call(store_canister_id, WithdrawCyclesArg { to })
        .await
        .expect("Cannot withdraw cycles")
}
