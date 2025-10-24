use crate::events::MinterEventAssert;
use candid::{Decode, Encode, Principal};
use canlog::LogEntry;
use ic_ckdoge_minter::Event;
use ic_ckdoge_minter::Priority;
use ic_ckdoge_minter::UtxoStatus;
use ic_ckdoge_minter::candid_api::{
    GetDogeAddressArgs, RetrieveDogeOk, RetrieveDogeStatus, RetrieveDogeWithApprovalArgs,
    RetrieveDogeWithApprovalError,
};
use ic_ckdoge_minter::{UpdateBalanceArgs, UpdateBalanceError};
use ic_management_canister_types::CanisterId;
use ic_metrics_assert::{MetricsAssert, PocketIcHttpQuery};
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
            .expect("BUg: failed to call retrieve_doge_status");
        Decode!(&call_result, RetrieveDogeStatus).unwrap()
    }

    pub fn await_doge_transaction(&self, ledger_burn_index: u64) -> Txid {
        self.env.advance_time(MAX_TIME_IN_QUEUE);
        let mut last_status = None;
        let max_ticks = 10;
        for _ in 0..max_ticks {
            let status = self.retrieve_doge_status(ledger_burn_index);
            match status {
                RetrieveDogeStatus::Submitted { txid } => {
                    return txid;
                }
                status => {
                    last_status = Some(status);
                    self.env.tick();
                }
            }
        }
        dbg!(self.get_logs());
        panic!(
            "the minter did not submit a transaction in {max_ticks} ticks; last status {last_status:?}"
        )
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

    pub fn assert_that_events(&self) -> MinterEventAssert {
        MinterEventAssert {
            events: self.get_all_events(),
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
}

impl PocketIcHttpQuery for &MinterCanister {
    fn get_pocket_ic(&self) -> &pocket_ic::PocketIc {
        &self.env
    }
    fn get_canister_id(&self) -> candid::Principal {
        self.id
    }
}
