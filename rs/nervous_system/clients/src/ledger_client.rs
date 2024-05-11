use async_trait::async_trait;
use candid::{types::number::Nat, Principal};
use dfn_candid::{ArgumentDecoder, ArgumentEncoder};
use dfn_core::CanisterId;
use ic_base_types::PrincipalId;
use ic_ledger_core::{block::BlockIndex, Tokens};
pub use ic_nervous_system_common::ledger::ICRC1Ledger;
use ic_nervous_system_common::NervousSystemError;
use icrc_ledger_client::{ICRC1Client, Runtime};
use icrc_ledger_types::icrc1::{
    account::{Account, Subaccount},
    transfer::{Memo, TransferArg},
};
use num_traits::ToPrimitive;

// A ICRC1 client runtime that uses dfn_* functionalities
struct DfnRuntime {}

#[async_trait]
impl Runtime for DfnRuntime {
    async fn call<In, Out>(
        &self,
        id: Principal,
        method: &str,
        args: In,
    ) -> Result<Out, (i32, String)>
    where
        In: ArgumentEncoder + Send,
        Out: for<'a> ArgumentDecoder<'a>,
    {
        let principal_id = CanisterId::unchecked_from_principal(PrincipalId::from(id));
        dfn_core::api::call_with_cleanup(principal_id, method, dfn_candid::candid_multi_arity, args)
            .await
            .map_err(|(code, msg)| (code.unwrap_or_default(), msg))
    }
}

pub struct LedgerCanister {
    client: ICRC1Client<DfnRuntime>,
}

impl LedgerCanister {
    pub fn new(ledger_canister_id: CanisterId) -> Self {
        Self {
            client: ICRC1Client::<DfnRuntime> {
                runtime: DfnRuntime {},
                ledger_canister_id: ledger_canister_id.get().into(),
            },
        }
    }
}

#[async_trait]
impl ICRC1Ledger for LedgerCanister {
    async fn transfer_funds(
        &self,
        amount_e8s: u64,
        fee_e8s: u64,
        from_subaccount: Option<Subaccount>,
        to: Account,
        memo: u64,
    ) -> Result<BlockIndex, NervousSystemError> {
        let args = TransferArg {
            from_subaccount,
            to,
            fee: Some(Nat::from(fee_e8s)),
            created_at_time: None,
            amount: Nat::from(amount_e8s),
            memo: Some(Memo::from(memo)),
        };
        let res = self.client.transfer(args).await
            .map_err(|(code, msg)| {
                NervousSystemError::new_with_message(format!(
                    "Error calling method 'icrc1_transfer' of the icrc1 ledger canister. Code: {:?}. Message: {}",
                    code, msg
                ))
            })?;
        res.map_err(|err| {
            NervousSystemError::new_with_message(format!(
                "'icrc1_transfer' of the icrc1 ledger canister failed. Error: {:?}",
                err
            ))
        })
        .map(|n| n.0.to_u64().expect("nat does not fit into u64"))
    }

    async fn total_supply(&self) -> Result<Tokens, NervousSystemError> {
        self.client.total_supply().await
            .map(|n| Tokens::from_e8s(n.0.to_u64().expect("nat does not fit into u64")))
            .map_err(|(code, msg)| {
                NervousSystemError::new_with_message(
                    format!(
                        "Error calling method 'icrc1_total_supply' of the ledger canister. Code: {:?}. Message: {}",
                        code, msg
                    )
                )
            })
    }

    async fn account_balance(&self, account: Account) -> Result<Tokens, NervousSystemError> {
        self.client.balance_of(account).await
            .map(|n| Tokens::from_e8s(n.0.to_u64().expect("nat does not fit into u64")))
            .map_err(|(code, msg)| {
                NervousSystemError::new_with_message(
                    format!(
                        "Error calling method 'icrc1_balance_of' of the ledger canister. Code: {:?}. Message: {}",
                        code, msg
                    )
                )
            })
    }

    fn canister_id(&self) -> CanisterId {
        let principal_id = PrincipalId::from(self.client.ledger_canister_id);
        CanisterId::unchecked_from_principal(principal_id)
    }
}
