use async_trait::async_trait;
use candid::types::number::Nat;
use dfn_core::CanisterId;
use ic_base_types::PrincipalId;
use ic_ledger_core::{Tokens, block::BlockIndex};
pub use ic_nervous_system_canisters::ledger::ICRC1Ledger;
use ic_nervous_system_common::NervousSystemError;
use icrc_ledger_client::{ICRC1Client, Runtime};
use icrc_ledger_client_cdk::CdkRuntime;
use icrc_ledger_types::icrc2::approve::ApproveArgs;
use icrc_ledger_types::icrc3::blocks::{GetBlocksRequest, GetBlocksResult};
use icrc_ledger_types::{
    icrc1::{
        account::{Account, Subaccount},
        transfer::{Memo, TransferArg},
    },
    icrc2::approve::ApproveError,
};
use num_traits::ToPrimitive;

pub struct LedgerCanister {
    client: ICRC1Client<CdkRuntime>,
}

impl LedgerCanister {
    pub fn new(ledger_canister_id: CanisterId) -> Self {
        Self {
            client: ICRC1Client::<CdkRuntime> {
                runtime: CdkRuntime {},
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
                    "Error calling method 'icrc1_transfer' of the icrc1 ledger canister. Code: {code:?}. Message: {msg}"
                ))
            })?;
        res.map_err(|err| {
            NervousSystemError::new_with_message(format!(
                "'icrc1_transfer' of the icrc1 ledger canister failed. Error: {err:?}"
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
                        "Error calling method 'icrc1_total_supply' of the ledger canister. Code: {code:?}. Message: {msg}"
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
                        "Error calling method 'icrc1_balance_of' of the ledger canister. Code: {code:?}. Message: {msg}"
                    )
                )
            })
    }

    fn canister_id(&self) -> CanisterId {
        let principal_id = PrincipalId::from(self.client.ledger_canister_id);
        CanisterId::unchecked_from_principal(principal_id)
    }

    async fn icrc2_approve(
        &self,
        spender: Account,
        amount: u64,
        expires_at: Option<u64>,
        fee: u64,
        from_subaccount: Option<Subaccount>,
        expected_allowance: Option<u64>,
    ) -> Result<Nat, NervousSystemError> {
        let args = ApproveArgs {
            spender,
            amount: Nat::from(amount),
            expires_at,
            fee: Some(Nat::from(fee)),
            from_subaccount,
            memo: None,
            created_at_time: None,
            expected_allowance: expected_allowance.map(Nat::from),
        };

        let result: Result<Nat, ApproveError> = self
            .client
            .approve(args)
            .await
            .map_err(|(code, msg)| {
                NervousSystemError::new_with_message(format!(
                    "Error calling method 'icrc2_approve' of the icrc1 ledger canister. Code: {code:?}. Message: {msg}"
                ))
            })?;

        result.map_err(|err| {
            NervousSystemError::new_with_message(format!(
                "'icrc2_approve' of the icrc1 ledger canister failed. Error: {err:?}"
            ))
        })
    }

    async fn icrc3_get_blocks(
        &self,
        args: Vec<GetBlocksRequest>,
    ) -> Result<GetBlocksResult, NervousSystemError> {
        use candid::{CandidType, Deserialize};
        use serde::Serialize;

        #[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
        pub struct ICRC3GetBlocksArgs {
            pub start: Nat,
            pub length: Nat,
        }

        let result: Result<GetBlocksResult, (i32, String)> = self
            .client
            .runtime
            .call(
                self.canister_id().into(),
                "icrc3_get_blocks",
                (args
                    .iter()
                    .map(|arg| ICRC3GetBlocksArgs {
                        start: arg.start.clone(),
                        length: arg.length.clone(),
                    })
                    .collect::<Vec<_>>(),),
            )
            .await
            .map(|result: (GetBlocksResult,)| result.0);

        result.map_err(|(code, msg)| {
            NervousSystemError::new_with_message(format!("Error calling method 'icrc3_get_blocks' of the ledger canister. Code: {code:?}. Message: {msg}"))
        })
    }
}
