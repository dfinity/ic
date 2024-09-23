use candid::{CandidType, Deserialize, Principal};
use ic_agent::Agent;
use ic_canisters_http_types::{HttpRequest, HttpResponse};
use ic_ckbtc_minter::queries::RetrieveBtcStatusRequest;
use ic_ckbtc_minter::state::eventlog::{Event, GetEventsArg};
use ic_ckbtc_minter::state::RetrieveBtcStatus;
use ic_ckbtc_minter::updates::{
    get_btc_address::GetBtcAddressArgs,
    retrieve_btc::{RetrieveBtcArgs, RetrieveBtcError, RetrieveBtcOk},
    update_balance::{UpdateBalanceArgs, UpdateBalanceError, UtxoStatus},
};
use icrc_ledger_types::icrc1::account::{Account, Subaccount};
use std::collections::BTreeMap;

#[derive(Debug)]
pub enum CkBtcMinterAgentError {
    AgentError(ic_agent::AgentError),
    CandidError(candid::Error),
}

impl From<ic_agent::AgentError> for CkBtcMinterAgentError {
    fn from(e: ic_agent::AgentError) -> Self {
        Self::AgentError(e)
    }
}

impl From<candid::Error> for CkBtcMinterAgentError {
    fn from(e: candid::Error) -> Self {
        Self::CandidError(e)
    }
}

/// Agent to make calls to the ckBTC minter.
#[derive(Clone)]
pub struct CkBtcMinterAgent {
    pub agent: Agent,
    pub minter_canister_id: Principal,
}

impl CkBtcMinterAgent {
    async fn update<Input, Output>(
        &self,
        method_name: impl Into<String>,
        arg: Input,
    ) -> Result<Output, CkBtcMinterAgentError>
    where
        Input: CandidType,
        Output: CandidType + for<'a> Deserialize<'a>,
    {
        Ok(candid::decode_one(
            &self
                .agent
                .update(&self.minter_canister_id, method_name)
                .with_arg(candid::encode_one(arg)?)
                .call_and_wait()
                .await?,
        )?)
    }

    async fn query<Input, Output>(
        &self,
        method_name: impl Into<String>,
        arg: Input,
    ) -> Result<Output, CkBtcMinterAgentError>
    where
        Input: CandidType,
        Output: CandidType + for<'a> Deserialize<'a>,
    {
        Ok(candid::decode_one(
            &self
                .agent
                .query(&self.minter_canister_id, method_name)
                .with_arg(candid::encode_one(arg)?)
                .call()
                .await?,
        )?)
    }

    pub async fn get_btc_address(
        &self,
        owner: Option<Principal>,
        subaccount: Option<Subaccount>,
    ) -> Result<String, CkBtcMinterAgentError> {
        self.update("get_btc_address", GetBtcAddressArgs { owner, subaccount })
            .await
    }

    pub async fn get_withdrawal_account(&self) -> Result<Account, CkBtcMinterAgentError> {
        self.update("get_withdrawal_account", ()).await
    }

    pub async fn retrieve_btc(
        &self,
        args: RetrieveBtcArgs,
    ) -> Result<Result<RetrieveBtcOk, RetrieveBtcError>, CkBtcMinterAgentError> {
        self.update("retrieve_btc", args).await
    }

    pub async fn update_balance(
        &self,
        args: UpdateBalanceArgs,
    ) -> Result<Result<Vec<UtxoStatus>, UpdateBalanceError>, CkBtcMinterAgentError> {
        self.update("update_balance", args).await
    }

    pub async fn retrieve_btc_status(
        &self,
        block_index: u64,
    ) -> Result<RetrieveBtcStatus, CkBtcMinterAgentError> {
        self.query(
            "retrieve_btc_status",
            RetrieveBtcStatusRequest { block_index },
        )
        .await
    }

    pub async fn distribute_kyt_fee(&self) -> Result<(), CkBtcMinterAgentError> {
        self.update("distribute_kyt_fee", ()).await
    }

    pub async fn get_events(
        &self,
        start: u64,
        length: u64,
    ) -> Result<Vec<Event>, CkBtcMinterAgentError> {
        self.query("get_events", GetEventsArg { start, length })
            .await
    }

    pub async fn get_metrics(&self) -> Result<HttpResponse, CkBtcMinterAgentError> {
        self.query(
            "http_request",
            HttpRequest {
                method: "GET".into(),
                url: "/metrics".into(),
                headers: vec![],
                body: Default::default(),
            },
        )
        .await
    }

    pub async fn get_metrics_map(&self) -> BTreeMap<String, Metric> {
        let metrics = self.get_metrics().await.unwrap();
        parse_metrics(std::str::from_utf8(&metrics.body.into_vec()).unwrap())
    }
}

/// Parse the fields that can be found in the metrics
fn parse_metrics(text: &str) -> BTreeMap<String, Metric> {
    let mut map = BTreeMap::new();
    for line in text.lines() {
        if let Some((key, value, ts)) = parse_metric(line) {
            let metric = map.entry(key).or_insert_with(Metric::default);
            metric.value = value;
            metric.timestamp = ts;
        }
    }
    map
}

fn parse_metric(line: &str) -> Option<(String, f64, i64)> {
    let mut parts = line.split_whitespace();
    if let Some(name) = parts.next() {
        if let Some(value) = parts.next() {
            if let Ok(value) = value.parse::<f64>() {
                if let Some(ts) = parts.next() {
                    if let Ok(ts) = ts.parse::<i64>() {
                        return Some((name.to_string(), value, ts));
                    }
                }
            }
        }
    }
    None
}

#[derive(Debug, Default)]
pub struct Metric {
    pub value: f64,
    pub timestamp: i64,
}
