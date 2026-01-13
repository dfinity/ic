use crate::{
    BitcoinAddress, BtcAddressCheckStatus, CanisterRuntime, CkDogeEventLogger,
    GetCurrentFeePercentilesRequest, GetUtxosRequest, GetUtxosResponse, Utxo,
    fees::DogecoinFeeEstimator,
    tx::{SignedRawTransaction, UnsignedTransaction},
};
use async_trait::async_trait;
use candid::Principal;
use ic_ckbtc_minter::{
    CheckTransactionResponse, ECDSAPublicKey, management::CallError, state::CkBtcMinterState,
    updates::update_balance::UpdateBalanceError,
};
use icrc_ledger_types::icrc1::{account::Account, transfer::Memo};
use mockall::mock;
use std::time::Duration;

mock! {
    #[derive(Debug)]
    pub CanisterRuntime {}

    #[async_trait]
    impl CanisterRuntime for CanisterRuntime {
        type Estimator = DogecoinFeeEstimator;
        type EventLogger = CkDogeEventLogger;
        fn caller(&self) -> Principal;
        fn id(&self) -> Principal;
        fn time(&self) -> u64;
        fn global_timer_set(&self, timestamp: u64);
        fn parse_address(&self, address: &str, network: ic_ckbtc_minter::Network) -> Result<BitcoinAddress, String>;
        fn block_time(&self, network: ic_ckbtc_minter::Network) -> Duration;
        fn derive_user_address(&self, state: &CkBtcMinterState, account: &Account) -> String;
        fn derive_minter_address(&self, state: &CkBtcMinterState) -> BitcoinAddress;
        fn derive_minter_address_str(&self, state: &CkBtcMinterState) -> String;
        fn refresh_fee_percentiles_frequency(&self) -> Duration;
        fn fee_estimator(&self, state: &CkBtcMinterState) -> DogecoinFeeEstimator;
        fn event_logger(&self) -> CkDogeEventLogger;
        async fn get_current_fee_percentiles(&self, request: &GetCurrentFeePercentilesRequest) -> Result<Vec<u64>, CallError>;
        async fn get_utxos(&self, request: &GetUtxosRequest) -> Result<GetUtxosResponse, CallError>;
        async fn check_transaction(&self, btc_checker_principal: Option<Principal>, utxo: &Utxo, cycle_payment: u128, ) -> Result<CheckTransactionResponse, CallError>;
        async fn mint_ckbtc(&self, amount: u64, to: Account, memo: Memo) -> Result<u64, UpdateBalanceError>;
        async fn sign_with_ecdsa(&self, key_name: String, derivation_path: Vec<Vec<u8>>, message_hash: [u8; 32]) -> Result<Vec<u8>, CallError>;
        async fn sign_transaction( &self, key_name: String, ecdsa_public_key: ECDSAPublicKey, unsigned_tx: UnsignedTransaction, accounts: Vec<Account>) -> Result<SignedRawTransaction, CallError>;
        async fn send_raw_transaction(&self, transaction: Vec<u8>, network: ic_ckbtc_minter::Network) -> Result<(), CallError>;
        async fn check_address( &self, btc_checker_principal: Option<Principal>, address: String) -> Result<BtcAddressCheckStatus, CallError>;
    }
}
