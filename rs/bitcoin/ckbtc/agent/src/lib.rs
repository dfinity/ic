use candid::{Decode, Encode, Principal};
use ic_agent::Agent;
use ic_ckbtc_minter::updates::{
    get_btc_address::GetBtcAddressArgs,
    get_withdrawal_account::GetWithdrawalAccountResult,
    retrieve_btc::{RetrieveBtcArgs, RetrieveBtcErr, RetrieveBtcOk},
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
    async fn update<S: Into<String>>(
        &self,
        method_name: S,
        arg: &[u8],
    ) -> Result<Vec<u8>, CkBtcMinterAgentError> {
        let waiter = garcon::Delay::builder()
            .throttle(std::time::Duration::from_millis(500))
            .timeout(std::time::Duration::from_secs(60 * 5))
            .build();
        self.agent
            .update(&self.minter_canister_id, method_name)
            .with_arg(arg)
            .call_and_wait(waiter)
            .await
            .map_err(CkBtcMinterAgentError::AgentError)
    }

    pub async fn get_btc_address(
        &self,
        subaccount: Option<Subaccount>,
    ) -> Result<String, CkBtcMinterAgentError> {
        let args = GetBtcAddressArgs { subaccount };
        let args = &Encode!(&args)?;
        Ok(Decode!(
            &self.update("get_btc_address", args).await?,
            String
        )?)
    }

    pub async fn get_withdrawal_account(
        &self,
    ) -> Result<GetWithdrawalAccountResult, CkBtcMinterAgentError> {
        let args = ();
        let args = &Encode!(&args)?;
        Ok(Decode!(
            &self.update("get_withdrawal_account", args).await?,
            GetWithdrawalAccountResult
        )?)
    }

    pub async fn retrieve_btc(
        &self,
        args: RetrieveBtcArgs,
    ) -> Result<Result<RetrieveBtcOk, RetrieveBtcErr>, CkBtcMinterAgentError> {
        let args = &Encode!(&args)?;
        Ok(
            Decode!(&self.update("retrieve_btc", args).await?, Result<RetrieveBtcOk, RetrieveBtcErr>)?,
        )
    }

    pub async fn update_balance(
        &self,
        args: UpdateBalanceArgs,
    ) -> Result<Result<UpdateBalanceResult, UpdateBalanceError>, CkBtcMinterAgentError> {
        let args = &Encode!(&args)?;
        Ok(
            Decode!(&self.update("update_balance", args).await?, Result<UpdateBalanceResult, UpdateBalanceError>)?,
        )
    }
}
