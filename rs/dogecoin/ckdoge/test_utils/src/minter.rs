use candid::{Decode, Encode, Principal};
use ic_ckdoge_minter::UtxoStatus;
use ic_ckdoge_minter::candid_api::GetDogeAddressArgs;
use ic_ckdoge_minter::candid_api::{
    RetrieveDogeOk, RetrieveDogeWithApprovalArgs, RetrieveDogeWithApprovalError,
};
use ic_ckdoge_minter::{UpdateBalanceArgs, UpdateBalanceError};
use ic_management_canister_types::CanisterId;
use pocket_ic::{PocketIc, RejectResponse};
use std::sync::Arc;

pub struct MinterCanister {
    pub(crate) env: Arc<PocketIc>,
    pub(crate) id: CanisterId,
}

impl MinterCanister {
    pub fn update_call_retrieve_doge_with_approval(
        &self,
        sender: Principal,
        args: &RetrieveDogeWithApprovalArgs,
    ) -> Result<std::vec::Vec<u8>, RejectResponse> {
        self.env.update_call(
            self.id,
            sender,
            "retrieve_doge_with_approval",
            Encode!(args).unwrap(),
        )
    }

    pub fn retrieve_doge_with_approval(
        &self,
        sender: Principal,
        args: &RetrieveDogeWithApprovalArgs,
    ) -> Result<RetrieveDogeOk, RetrieveDogeWithApprovalError> {
        let call_result = self
            .update_call_retrieve_doge_with_approval(sender, args)
            .expect("BUG: failed to call retrieve_doge_with_approval");
        Decode!(&call_result, Result<RetrieveDogeOk, RetrieveDogeWithApprovalError>).unwrap()
    }

    pub fn update_call_get_doge_address(
        &self,
        sender: Principal,
        args: &GetDogeAddressArgs,
    ) -> Result<std::vec::Vec<u8>, RejectResponse> {
        self.env
            .update_call(self.id, sender, "get_doge_address", Encode!(args).unwrap())
    }

    pub fn get_doge_address(&self, sender: Principal, args: &GetDogeAddressArgs) -> String {
        let call_result = self
            .update_call_get_doge_address(sender, args)
            .expect("BUG: failed to call get_doge_address");
        Decode!(&call_result, String).unwrap()
    }

    pub fn update_balance(
        &self,
        sender: Principal,
        args: &UpdateBalanceArgs,
    ) -> Result<Vec<UtxoStatus>, UpdateBalanceError> {
        let call_result = self
            .update_call_update_balance(sender, args)
            .expect("BUG: failed to call update_balance");
        Decode!(&call_result, Result<Vec<UtxoStatus>, UpdateBalanceError>).unwrap()
    }

    pub fn update_call_update_balance(
        &self,
        sender: Principal,
        args: &UpdateBalanceArgs,
    ) -> Result<std::vec::Vec<u8>, RejectResponse> {
        self.env
            .update_call(self.id, sender, "update_balance", Encode!(args).unwrap())
    }
}
