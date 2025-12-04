use crate::events::MinterEventAssert;
use crate::{MAX_TIME_IN_QUEUE, NNS_ROOT_PRINCIPAL};
use candid::{Decode, Encode, Principal};
use canlog::LogEntry;
use ic_ckdoge_minter::{
    EstimateFeeArg, Event, EventType, Priority, Txid, UpdateBalanceArgs, UpdateBalanceError, Utxo,
    UtxoStatus,
    candid_api::{
        EstimateWithdrawalFeeError, GetDogeAddressArgs, MinterInfo, RetrieveDogeOk,
        RetrieveDogeStatus, RetrieveDogeStatusRequest, RetrieveDogeWithApprovalArgs,
        RetrieveDogeWithApprovalError, WithdrawalFee,
    },
    lifecycle::init::{MinterArg, UpgradeArgs},
};
use ic_management_canister_types::{CanisterId, CanisterStatusResult};
use ic_metrics_assert::{MetricsAssert, PocketIcHttpQuery};
use icrc_ledger_types::icrc1::account::Account;
use pocket_ic::common::rest::RawMessageId;
use pocket_ic::{PocketIc, RejectResponse};
use std::sync::Arc;
use std::time::Duration;

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
        let msg_id = self
            .submit_retrieve_doge_with_approval(sender, args)
            .expect("BUG: failed to call retrieve_doge_with_approval");
        self.env.await_call(msg_id)
    }
    pub fn submit_retrieve_doge_with_approval(
        &self,
        sender: Principal,
        args: &RetrieveDogeWithApprovalArgs,
    ) -> Result<RawMessageId, RejectResponse> {
        self.env.submit_call(
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

    pub fn get_known_utxos<A: Into<Account>>(&self, args: A) -> Vec<Utxo> {
        let Account { owner, subaccount } = args.into();
        let call_result = self
            .env
            .query_call(
                self.id,
                Principal::anonymous(),
                "get_known_utxos",
                Encode!(&UpdateBalanceArgs {
                    owner: Some(owner),
                    subaccount
                })
                .unwrap(),
            )
            .expect("BUG: failed to call get_known_utxos");
        Decode!(&call_result, Vec<Utxo>).unwrap()
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

    pub fn get_canister_status(&self) -> CanisterStatusResult {
        let call_result = self
            .env
            .update_call(
                self.id,
                Principal::anonymous(),
                "get_canister_status",
                Encode!().unwrap(),
            )
            .expect("BUG: failed to call get_canister_status");
        Decode!(&call_result, CanisterStatusResult).unwrap()
    }

    pub fn get_minter_info(&self) -> MinterInfo {
        let call_result = self
            .env
            .update_call(
                self.id,
                Principal::anonymous(),
                "get_minter_info",
                Encode!().unwrap(),
            )
            .expect("BUG: failed to call get_minter_info");
        Decode!(&call_result, MinterInfo).unwrap()
    }

    pub fn estimate_withdrawal_fee(
        &self,
        withdrawal_amount: u64,
    ) -> Result<WithdrawalFee, EstimateWithdrawalFeeError> {
        let call_result = self
            .env
            .query_call(
                self.id,
                Principal::anonymous(),
                "estimate_withdrawal_fee",
                Encode!(&EstimateFeeArg {
                    amount: Some(withdrawal_amount)
                })
                .unwrap(),
            )
            .expect("BUG: failed to call estimate_withdrawal_fee");
        Decode!(&call_result, Result<WithdrawalFee, EstimateWithdrawalFeeError>).unwrap()
    }

    pub fn retrieve_doge_status(&self, ledger_burn_index: u64) -> RetrieveDogeStatus {
        let call_result = self
            .env
            .query_call(
                self.id,
                Principal::anonymous(),
                "retrieve_doge_status",
                Encode!(&RetrieveDogeStatusRequest {
                    block_index: ledger_burn_index
                })
                .unwrap(),
            )
            .expect("BUG: failed to call retrieve_doge_status");
        Decode!(&call_result, RetrieveDogeStatus).unwrap()
    }

    pub fn self_check(&self) {
        let call_result = self
            .env
            .query_call(
                self.id,
                Principal::anonymous(),
                "self_check",
                Encode!().unwrap(),
            )
            .expect("BUG: failed to call self_check");
        Decode!(&call_result, Result<(), String>)
            .unwrap()
            .expect("BUG: minter self-check failed")
    }

    pub fn await_submitted_doge_transaction(&self, ledger_burn_index: u64) -> Txid {
        self.env
            .advance_time(MAX_TIME_IN_QUEUE + Duration::from_nanos(1));
        let status = self.await_doge_transaction_with_status(ledger_burn_index, |tx_status| {
            matches!(tx_status, RetrieveDogeStatus::Submitted { .. })
        });
        match status {
            RetrieveDogeStatus::Submitted { txid, .. } => txid,
            _ => unreachable!(),
        }
    }

    pub fn await_finalized_doge_transaction(&self, ledger_burn_index: u64) -> Txid {
        let status = self.await_doge_transaction_with_status(ledger_burn_index, |tx_status| {
            matches!(tx_status, RetrieveDogeStatus::Confirmed { .. })
        });
        match status {
            RetrieveDogeStatus::Confirmed { txid, .. } => txid,
            _ => unreachable!(),
        }
    }

    pub fn await_doge_transaction_with_status<F>(
        &self,
        ledger_burn_index: u64,
        filter: F,
    ) -> RetrieveDogeStatus
    where
        F: Fn(&RetrieveDogeStatus) -> bool,
    {
        let mut last_status = None;
        let max_ticks = 10;
        for _ in 0..max_ticks {
            let status = self.retrieve_doge_status(ledger_burn_index);
            if filter(&status) {
                return status;
            }
            last_status = Some(status);
            self.env.tick();
        }
        dbg!(self.get_logs());
        panic!("Unexpected transaction status in {max_ticks} ticks; last status {last_status:?}")
    }

    pub fn get_logs(&self) -> Vec<LogEntry<Priority>> {
        use ic_http_types::{HttpRequest, HttpResponse};

        let request = HttpRequest {
            method: "".to_string(),
            url: "/logs".to_string(),
            headers: vec![],
            body: vec![].into(),
        };
        let result = self
            .env
            .query_call(
                self.id,
                Principal::anonymous(),
                "http_request",
                Encode!(&request).unwrap(),
            )
            .expect("BUG: failed to call get_log");
        let response = Decode!(&result, HttpResponse).unwrap();
        serde_json::from_slice::<canlog::Log<Priority>>(&response.body)
            .expect("failed to parse ckBTC minter log")
            .entries
    }

    pub fn assert_that_events(&self) -> MinterEventAssert<EventType> {
        MinterEventAssert {
            events: self
                .get_all_events()
                .into_iter()
                .map(|e| e.payload)
                .collect(),
        }
    }

    pub fn assert_that_metrics(&self) -> MetricsAssert<&Self> {
        MetricsAssert::from_http_query(self)
    }

    pub fn get_all_events(&self) -> Vec<Event> {
        const FIRST_BATCH_SIZE: u64 = 100;
        let mut all_events = self.get_events(0, FIRST_BATCH_SIZE);
        loop {
            let events = self.get_events(all_events.len() as u64, 2_000);
            if !events.is_empty() {
                all_events.extend(events);
            } else {
                return all_events;
            }
        }
    }

    fn get_events(&self, start: u64, length: u64) -> Vec<Event> {
        use ic_ckdoge_minter::GetEventsArg;

        let call_result = self
            .env
            .query_call(
                self.id,
                Principal::anonymous(),
                "get_events",
                Encode!(&GetEventsArg { start, length }).unwrap(),
            )
            .expect("BUG: failed to call get_events");
        Decode!(&call_result, Vec<Event>).unwrap()
    }

    pub fn id(&self) -> CanisterId {
        self.id
    }

    pub fn upgrade(&self, upgrade_args: Option<UpgradeArgs>) {
        let minter_args = MinterArg::Upgrade(upgrade_args);
        self.env
            .upgrade_canister(
                self.id,
                crate::minter_wasm(),
                Encode!(&minter_args).unwrap(),
                Some(NNS_ROOT_PRINCIPAL),
            )
            .expect("BUG: failed to upgrade minter");
        // run immediate tasks after upgrade, like refreshing fee percentiles.
        self.env.tick();
    }
}

impl PocketIcHttpQuery for &MinterCanister {
    fn get_pocket_ic(&self) -> &pocket_ic::PocketIc {
        &self.env
    }
    fn get_canister_id(&self) -> candid::Principal {
        self.id
    }
}
