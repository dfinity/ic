use async_trait::async_trait;
use candid::types::number::Nat;
use candid::utils::{ArgumentDecoder, ArgumentEncoder};
use candid::Principal;
use ic_icrc1::endpoints::{TransferArg, TransferError, Value};
pub use ic_icrc1::Account;
use ic_ledger_core::block::BlockHeight;
use num_traits::ToPrimitive;

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

/// Converts Nat to u64.
///
/// Note: our ICRC-1 ledger implementation is guaranteed to return values that
/// fit into u64.
fn nat_to_u64(n: Nat) -> u64 {
    n.0.to_u64().expect("nat does not fit into u64")
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
    pub async fn balance_of(&self, account: Account) -> Result<u64, (i32, String)> {
        self.runtime
            .call(self.ledger_canister_id, "icrc1_balance_of", (account,))
            .await
            .map(untuple)
            .map(nat_to_u64)
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

    pub async fn metadata(&self) -> Result<Vec<(String, Value)>, (i32, String)> {
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

    pub async fn total_supply(&self) -> Result<u64, (i32, String)> {
        self.runtime
            .call(self.ledger_canister_id, "icrc1_total_supply", ())
            .await
            .map(untuple)
            .map(nat_to_u64)
    }

    pub async fn fee(&self) -> Result<u64, (i32, String)> {
        self.runtime
            .call(self.ledger_canister_id, "icrc1_fee", ())
            .await
            .map(untuple)
            .map(nat_to_u64)
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
    ) -> Result<Result<BlockHeight, TransferError>, (i32, String)> {
        let result: Result<Nat, TransferError> = self
            .runtime
            .call(self.ledger_canister_id, "icrc1_transfer", (args,))
            .await
            .map(untuple)?;
        Ok(result.map(nat_to_u64))
    }
}

// extract the element from an unary tuple
fn untuple<T>(t: (T,)) -> T {
    t.0
}
