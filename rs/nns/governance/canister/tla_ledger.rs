use async_trait::async_trait;
use ic_base_types::CanisterId;
use ic_nervous_system_canisters::ledger::IcpLedger;
use ic_nervous_system_canisters::ledger::IcpLedgerCanister;
use ic_nervous_system_common::NervousSystemError;
use ic_nervous_system_runtime::Runtime;
use icp_ledger::{AccountIdentifier, Subaccount as IcpSubaccount, Tokens};
use icrc_ledger_types::icrc3::blocks::{GetBlocksRequest, GetBlocksResult};

#[cfg(feature = "tla")]
use ic_nns_governance::governance::tla::{
    self as tla, Destination, TLA_INSTRUMENTATION_STATE, ToTla, account_to_tla,
    opt_subaccount_to_tla,
};

#[cfg(feature = "tla")]
use tla_instrumentation_proc_macros::tla_function;

use ic_nns_governance::{tla_log_request, tla_log_response};
use std::collections::BTreeMap;

pub struct LoggingIcpLedgerCanister<Rt: Runtime>(IcpLedgerCanister<Rt>);

impl<Rt: Runtime + Send + Sync> LoggingIcpLedgerCanister<Rt> {
    pub fn new(id: CanisterId) -> Self {
        LoggingIcpLedgerCanister(IcpLedgerCanister::new(id))
    }
}

#[async_trait]
impl<Rt: Runtime + Send + Sync> IcpLedger for LoggingIcpLedgerCanister<Rt> {
    #[cfg_attr(feature = "tla", tla_function(force_async_fn = true))]
    async fn transfer_funds(
        &self,
        amount_e8s: u64,
        fee_e8s: u64,
        from_subaccount: Option<IcpSubaccount>,
        to: AccountIdentifier,
        memo: u64,
    ) -> Result<u64, NervousSystemError> {
        tla_log_request!(
            "WaitForTransfer",
            Destination::new("ledger"),
            "Transfer",
            tla::TlaValue::Record(BTreeMap::from([
                ("amount".to_string(), amount_e8s.to_tla_value()),
                ("fee".to_string(), fee_e8s.to_tla_value()),
                ("from".to_string(), opt_subaccount_to_tla(&from_subaccount)),
                ("to".to_string(), account_to_tla(to)),
            ]))
        );

        let result = self
            .0
            .transfer_funds(amount_e8s, fee_e8s, from_subaccount, to, memo)
            .await;

        tla_log_response!(
            Destination::new("ledger"),
            if result.is_err() {
                tla::TlaValue::Variant {
                    tag: "Fail".to_string(),
                    value: Box::new(tla::TlaValue::Constant("UNIT".to_string())),
                }
            } else {
                tla::TlaValue::Variant {
                    tag: "TransferOk".to_string(),
                    value: Box::new(tla::TlaValue::Constant("UNIT".to_string())),
                }
            }
        );

        result
    }

    async fn total_supply(&self) -> Result<Tokens, NervousSystemError> {
        self.0.total_supply().await
    }

    async fn account_balance(
        &self,
        account: AccountIdentifier,
    ) -> Result<Tokens, NervousSystemError> {
        tla_log_request!(
            "WaitForBalanceQuery",
            Destination::new("ledger"),
            "AccountBalance",
            tla::TlaValue::Record(BTreeMap::from([(
                "account".to_string(),
                account_to_tla(account)
            )]))
        );

        let result = self.0.account_balance(account).await;

        tla_log_response!(
            Destination::new("ledger"),
            match result {
                Ok(balance) => tla::TlaValue::Variant {
                    tag: "BalanceQueryOk".to_string(),
                    value: Box::new(balance.get_e8s().to_tla_value()),
                },
                _ => tla::TlaValue::Variant {
                    tag: "Fail".to_string(),
                    value: Box::new(tla::TlaValue::Constant("UNIT".to_string())),
                },
            }
        );

        result
    }

    fn canister_id(&self) -> CanisterId {
        self.0.canister_id()
    }

    async fn icrc2_approve(
        &self,
        _spender: icrc_ledger_types::icrc1::account::Account,
        _amount: u64,
        _expires_at: Option<u64>,
        _fee: u64,
        _from_subaccount: Option<icrc_ledger_types::icrc1::account::Subaccount>,
        _expected_allowance: Option<u64>,
    ) -> Result<candid::Nat, NervousSystemError> {
        Err(NervousSystemError {
            error_message: "Not Implemented".to_string(),
        })
    }

    async fn icrc3_get_blocks(
        &self,
        _args: Vec<GetBlocksRequest>,
    ) -> Result<GetBlocksResult, NervousSystemError> {
        Err(NervousSystemError {
            error_message: "Not Implemented".to_string(),
        })
    }
}
