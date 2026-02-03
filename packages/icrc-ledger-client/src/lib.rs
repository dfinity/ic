use async_trait::async_trait;
use candid::Principal;
use candid::types::number::Nat;
use candid::utils::{ArgumentDecoder, ArgumentEncoder};
use icrc_ledger_types::icrc::generic_metadata_value::MetadataValue as Value;
use icrc_ledger_types::icrc::metadata_key::MetadataKey;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::{BlockIndex, TransferArg, TransferError};
use icrc_ledger_types::icrc2::approve::{ApproveArgs, ApproveError};
use icrc_ledger_types::icrc2::transfer_from::{TransferFromArgs, TransferFromError};

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
// $ didc bind -t rs rs/ledger_suite/icrc1/ledger/ledger.did
// The reason why we don't just generate the bindings is to avoid duplicating
// the in and out structures as we can use the ones defined in ic_icrc1::endpoints.

impl<R: Runtime> ICRC1Client<R> {
    pub async fn balance_of(&self, account: Account) -> Result<Nat, (i32, String)> {
        self.runtime
            .call(self.ledger_canister_id, "icrc1_balance_of", (account,))
            .await
            .map(untuple)
    }

    pub async fn decimals(&self) -> Result<u8, (i32, String)> {
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

    pub async fn metadata(&self) -> Result<Vec<(MetadataKey, Value)>, (i32, String)> {
        self.runtime
            .call(self.ledger_canister_id, "icrc1_metadata", ())
            .await
            .map(untuple)
    }

    pub async fn symbol(&self) -> Result<String, (i32, String)> {
        self.runtime
            .call(self.ledger_canister_id, "icrc1_symbol", ())
            .await
            .map(untuple)
    }

    pub async fn total_supply(&self) -> Result<Nat, (i32, String)> {
        self.runtime
            .call(self.ledger_canister_id, "icrc1_total_supply", ())
            .await
            .map(untuple)
    }

    pub async fn fee(&self) -> Result<Nat, (i32, String)> {
        self.runtime
            .call(self.ledger_canister_id, "icrc1_fee", ())
            .await
            .map(untuple)
    }

    pub async fn minting_account(&self) -> Result<Option<Account>, (i32, String)> {
        self.runtime
            .call(self.ledger_canister_id, "icrc1_minting_account", ())
            .await
            .map(untuple)
    }

    pub async fn transfer(
        &self,
        args: TransferArg,
    ) -> Result<Result<BlockIndex, TransferError>, (i32, String)> {
        let result: Result<Nat, TransferError> = self
            .runtime
            .call(self.ledger_canister_id, "icrc1_transfer", (args,))
            .await
            .map(untuple)?;
        Ok(result)
    }

    pub async fn transfer_from(
        &self,
        args: TransferFromArgs,
    ) -> Result<Result<BlockIndex, TransferFromError>, (i32, String)> {
        let result: Result<Nat, TransferFromError> = self
            .runtime
            .call(self.ledger_canister_id, "icrc2_transfer_from", (args,))
            .await
            .map(untuple)?;
        Ok(result)
    }

    pub async fn approve(
        &self,
        args: ApproveArgs,
    ) -> Result<Result<BlockIndex, ApproveError>, (i32, String)> {
        let result: Result<Nat, ApproveError> = self
            .runtime
            .call(self.ledger_canister_id, "icrc2_approve", (args,))
            .await
            .map(untuple)?;
        Ok(result)
    }
}

// extract the element from an unary tuple
fn untuple<T>(t: (T,)) -> T {
    t.0
}
