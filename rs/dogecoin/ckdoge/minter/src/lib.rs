use async_trait::async_trait;
use candid::Principal;
use ic_ckbtc_minter::{
    CanisterRuntime, CheckTransactionResponse, GetUtxosRequest, GetUtxosResponse, Network, Utxo,
    management::CallError, tx, updates::update_balance::UpdateBalanceError,
};
use icrc_ledger_types::icrc1::{account::Account, transfer::Memo};

pub mod candid_api;

#[derive(Copy, Clone)]
pub struct DogeCanisterRuntime {}

#[async_trait]
impl CanisterRuntime for DogeCanisterRuntime {
    async fn bitcoin_get_utxos(
        &self,
        _request: &GetUtxosRequest,
    ) -> Result<GetUtxosResponse, CallError> {
        todo!()
    }

    async fn check_transaction(
        &self,
        _btc_checker_principal: Principal,
        _utxo: &Utxo,
        _cycle_payment: u128,
    ) -> Result<CheckTransactionResponse, CallError> {
        unimplemented!(
            "No need to check Dogecoin transactions since there are no addresses on the OFAC list"
        );
    }

    async fn mint_ckbtc(
        &self,
        _amount: u64,
        _to: Account,
        _memo: Memo,
    ) -> Result<u64, UpdateBalanceError> {
        todo!()
    }

    async fn sign_with_ecdsa(
        &self,
        _key_name: String,
        _derivation_path: Vec<Vec<u8>>,
        _message_hash: [u8; 32],
    ) -> Result<Vec<u8>, CallError> {
        todo!()
    }

    async fn send_transaction(
        &self,
        _transaction: &tx::SignedTransaction,
        _network: Network,
    ) -> Result<(), CallError> {
        todo!()
    }
}
