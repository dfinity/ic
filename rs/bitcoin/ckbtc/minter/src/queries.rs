use candid::CandidType;
use serde::Deserialize;

#[derive(CandidType, Deserialize)]
pub struct RetrieveBtcStatusRequest {
    pub block_index: u64,
}

#[derive(CandidType, Deserialize)]
pub struct EstimateFeeArg {
    pub amount: Option<u64>,
}

#[derive(CandidType, Deserialize, Debug)]
pub struct WithdrawalFee {
    pub minter_fee: u64,
    pub bitcoin_fee: u64,
}
