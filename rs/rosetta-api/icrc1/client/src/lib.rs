use async_trait::async_trait;
use candid::utils::{ArgumentDecoder, ArgumentEncoder};
use candid::Principal;
use ic_icrc1::endpoints::{
    ApprovalDetails, ApproveTransferArg, ApproveTransferError, CommitTransferArg,
    CommitTransferError, RevokeApprovalError, TransferArg, TransferError, Value,
};
pub use ic_icrc1::Account;
use ic_icrc1::ApprovalId;
use ic_ledger_core::block::BlockHeight;

// Abstraction over the runtime. Implement this in terms of cdk call if you use
// the cdk or dfn_* if you use dfn_* call.
#[async_trait]
pub trait Runtime {
    async fn call<In, Out>(
        &self,
        id: Principal,
        method: &str,
        args: In,
    ) -> Result<Out, (i32, String)>
    where
        In: ArgumentEncoder + Send,
        Out: for<'a> ArgumentDecoder<'a>;
}

pub struct ICRC1Client<R: Runtime> {
    pub runtime: R,
    pub ledger_canister_id: Principal,
}

// Note (MP): you can check that the bindings are correct by running
// $ didc bind -t rs rs/rosetta-api/icrc1/ledger/icrc1.did
// The reason why we don't just generate the bindings is to avoid duplicating
// the in and out structures as we can use the ones defined in ic_icrc1::endpoints.

impl<R: Runtime> ICRC1Client<R> {
    pub async fn allowance(
        &self,
        approval_id: ApprovalId,
    ) -> Result<Option<ApprovalDetails>, (i32, String)> {
        self.runtime
            .call(self.ledger_canister_id, "icrc1_allowance", (approval_id,))
            .await
            .map(untuple)
    }

    pub async fn approve(
        &self,
        args: ApproveTransferArg,
    ) -> Result<Result<ApprovalId, ApproveTransferError>, (i32, String)> {
        self.runtime
            .call(self.ledger_canister_id, "icrc1_approveTransfer", (args,))
            .await
            .map(untuple)
    }

    pub async fn balance_of(&self, account: Account) -> Result<u64, (i32, String)> {
        self.runtime
            .call(self.ledger_canister_id, "icrc1_balanceOf", (account,))
            .await
            .map(untuple)
    }

    pub async fn commit_transfer(
        &self,
        args: CommitTransferArg,
    ) -> Result<Result<BlockHeight, CommitTransferError>, (i32, String)> {
        self.runtime
            .call(self.ledger_canister_id, "icrc1_commitTransfer", (args,))
            .await
            .map(untuple)
    }

    pub async fn decimals(&self) -> Result<u32, (i32, String)> {
        self.runtime
            .call(self.ledger_canister_id, "icrc1_decimals", ())
            .await
            .map(untuple)
    }

    pub async fn name(&self) -> Result<String, (i32, String)> {
        self.runtime
            .call(self.ledger_canister_id, "icrc1_name", ())
            .await
            .map(untuple)
    }

    pub async fn metadata(&self) -> Result<Vec<(String, Value)>, (i32, String)> {
        self.runtime
            .call(self.ledger_canister_id, "icrc1_metadata", ())
            .await
            .map(untuple)
    }

    pub async fn revoke_approval(
        &self,
        approval_id: ApprovalId,
    ) -> Result<Result<BlockHeight, RevokeApprovalError>, (i32, String)> {
        self.runtime
            .call(
                self.ledger_canister_id,
                "icrc1_revokeApproval",
                (approval_id,),
            )
            .await
            .map(untuple)
    }

    pub async fn symbol(&self) -> Result<String, (i32, String)> {
        self.runtime
            .call(self.ledger_canister_id, "icrc1_symbol", ())
            .await
            .map(untuple)
    }

    pub async fn total_supply(&self) -> Result<u64, (i32, String)> {
        self.runtime
            .call(self.ledger_canister_id, "icrc1_totalSupply", ())
            .await
            .map(untuple)
    }

    pub async fn transfer(
        &self,
        args: TransferArg,
    ) -> Result<Result<BlockHeight, TransferError>, (i32, String)> {
        self.runtime
            .call(self.ledger_canister_id, "icrc1_transfer", (args,))
            .await
            .map(untuple)
    }
}

// extract the element from an unary tuple
fn untuple<T>(t: (T,)) -> T {
    t.0
}
