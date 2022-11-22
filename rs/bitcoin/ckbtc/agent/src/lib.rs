use candid::{CandidType, Deserialize, Principal};
use ic_agent::Agent;
use ic_ckbtc_minter::queries::RetrieveBtcStatusRequest;
use ic_ckbtc_minter::state::RetrieveBtcStatus;
use ic_ckbtc_minter::updates::{
    get_btc_address::GetBtcAddressArgs,
    get_withdrawal_account::GetWithdrawalAccountResult,
    retrieve_btc::{RetrieveBtcArgs, RetrieveBtcError, RetrieveBtcOk},
    update_balance::{UpdateBalanceArgs, UpdateBalanceError, UpdateBalanceResult},
};
use ic_icrc1::Subaccount;

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
        let waiter = garcon::Delay::builder()
            .throttle(std::time::Duration::from_millis(500))
            .timeout(std::time::Duration::from_secs(60 * 5))
            .build();

        Ok(candid::decode_one(
            &self
                .agent
                .update(&self.minter_canister_id, method_name)
                .with_arg(candid::encode_one(arg)?)
                .call_and_wait(waiter)
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
        subaccount: Option<Subaccount>,
    ) -> Result<String, CkBtcMinterAgentError> {
        self.update("get_btc_address", GetBtcAddressArgs { subaccount })
            .await
    }

    pub async fn get_withdrawal_account(
        &self,
    ) -> Result<GetWithdrawalAccountResult, CkBtcMinterAgentError> {
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
    ) -> Result<Result<UpdateBalanceResult, UpdateBalanceError>, CkBtcMinterAgentError> {
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
}
