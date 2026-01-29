use candid::{CandidType, Deserialize, Principal};
use ic_agent::Agent;
use ic_ckdoge_minter::{
    EstimateFeeArg, GetEventsArg, UpdateBalanceArgs, UpdateBalanceError, UtxoStatus,
    candid_api::{
        EstimateWithdrawalFeeError, GetDogeAddressArgs, RetrieveDogeOk, RetrieveDogeStatus,
        RetrieveDogeStatusRequest, RetrieveDogeWithApprovalArgs, RetrieveDogeWithApprovalError,
        WithdrawalFee,
    },
    event::CkDogeMinterEvent,
};
use ic_http_types::{HttpRequest, HttpResponse};
use icrc_ledger_types::icrc1::account::Subaccount;
use std::collections::BTreeMap;

#[derive(Debug)]
pub enum CkDogeMinterAgentError {
    AgentError(ic_agent::AgentError),
    CandidError(candid::Error),
}

impl From<ic_agent::AgentError> for CkDogeMinterAgentError {
    fn from(e: ic_agent::AgentError) -> Self {
        Self::AgentError(e)
    }
}

impl From<candid::Error> for CkDogeMinterAgentError {
    fn from(e: candid::Error) -> Self {
        Self::CandidError(e)
    }
}

/// Agent to make calls to the ckDOGE minter.
#[derive(Clone)]
pub struct CkDogeMinterAgent {
    pub agent: Agent,
    pub minter_canister_id: Principal,
}

impl CkDogeMinterAgent {
    async fn update<Input, Output>(
        &self,
        method_name: impl Into<String>,
        arg: Input,
    ) -> Result<Output, CkDogeMinterAgentError>
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
    ) -> Result<Output, CkDogeMinterAgentError>
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

    pub async fn get_doge_address(
        &self,
        owner: Option<Principal>,
        subaccount: Option<Subaccount>,
    ) -> Result<String, CkDogeMinterAgentError> {
        self.update("get_doge_address", GetDogeAddressArgs { owner, subaccount })
            .await
    }

    pub async fn retrieve_doge_with_approval(
        &self,
        args: RetrieveDogeWithApprovalArgs,
    ) -> Result<Result<RetrieveDogeOk, RetrieveDogeWithApprovalError>, CkDogeMinterAgentError> {
        self.update("retrieve_doge_with_approval", args).await
    }

    pub async fn update_balance(
        &self,
        args: UpdateBalanceArgs,
    ) -> Result<Result<Vec<UtxoStatus>, UpdateBalanceError>, CkDogeMinterAgentError> {
        self.update("update_balance", args).await
    }

    pub async fn retrieve_doge_status(
        &self,
        block_index: u64,
    ) -> Result<RetrieveDogeStatus, CkDogeMinterAgentError> {
        self.query(
            "retrieve_doge_status",
            RetrieveDogeStatusRequest { block_index },
        )
        .await
    }

    pub async fn estimate_withdrawal_fee(
        &self,
        amount: u64,
    ) -> Result<Result<WithdrawalFee, EstimateWithdrawalFeeError>, CkDogeMinterAgentError> {
        self.query(
            "estimate_withdrawal_fee",
            EstimateFeeArg {
                amount: Some(amount),
            },
        )
        .await
    }

    pub async fn get_events(
        &self,
        start: u64,
        length: u64,
    ) -> Result<Vec<CkDogeMinterEvent>, CkDogeMinterAgentError> {
        self.query("get_events", GetEventsArg { start, length })
            .await
    }

    pub async fn get_metrics(&self) -> Result<HttpResponse, CkDogeMinterAgentError> {
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
    if let Some(name) = parts.next()
        && let Some(value) = parts.next()
        && let Ok(value) = value.parse::<f64>()
        && let Some(ts) = parts.next()
        && let Ok(ts) = ts.parse::<i64>()
    {
        return Some((name.to_string(), value, ts));
    }
    None
}

#[derive(Debug, Default)]
pub struct Metric {
    pub value: f64,
    pub timestamp: i64,
}
