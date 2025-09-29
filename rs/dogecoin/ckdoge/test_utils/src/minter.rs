use candid::{Decode, Encode, Principal};
use ic_ckdoge_minter::candid_api::{
    RetrieveDogeOk, RetrieveDogeWithApprovalArgs, RetrieveDogeWithApprovalError,
};
use ic_management_canister_types::CanisterId;
use pocket_ic::PocketIc;
use std::sync::Arc;

pub struct MinterCanister {
    pub(crate) env: Arc<PocketIc>,
    pub(crate) id: CanisterId,
}

impl MinterCanister {
    pub fn retrieve_doge_with_approval(
        &self,
        sender: Principal,
        args: &RetrieveDogeWithApprovalArgs,
    ) -> Result<RetrieveDogeOk, RetrieveDogeWithApprovalError> {
        let call_result = self
            .env
            .update_call(
                self.id,
                sender,
                "retrieve_doge_with_approval",
                Encode!(args).unwrap(),
            )
            .expect("BUG: failed to call retrieve_doge_with_approval");
        Decode!(&call_result, Result<RetrieveDogeOk, RetrieveDogeWithApprovalError>).unwrap()
    }
}
