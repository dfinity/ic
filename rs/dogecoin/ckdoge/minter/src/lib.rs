pub mod address;
pub mod candid_api;
pub mod lifecycle;
pub mod updates;

use crate::address::DogecoinAddress;
use crate::lifecycle::init::Network;
use async_trait::async_trait;
use candid::Principal;
use ic_ckbtc_minter::address::BitcoinAddress;
use ic_ckbtc_minter::state::CkBtcMinterState;
use ic_ckbtc_minter::updates::retrieve_btc::BtcAddressCheckStatus;
use ic_ckbtc_minter::{
    CanisterRuntime, CheckTransactionResponse, GetUtxosRequest, GetUtxosResponse, Utxo,
    management::CallError, tx, updates::update_balance::UpdateBalanceError,
};
use icrc_ledger_types::icrc1::{account::Account, transfer::Memo};

pub const DOGECOIN_CANISTER_RUNTIME: DogeCanisterRuntime = DogeCanisterRuntime {};

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
        _network: ic_ckbtc_minter::Network,
    ) -> Result<(), CallError> {
        todo!()
    }

    fn validate_config(&self, state: &CkBtcMinterState) {
        if state.check_fee > state.retrieve_btc_min_amount {
            ic_cdk::trap("check_fee cannot be greater than retrieve_btc_min_amount");
        }
        if state.check_fee != 0 {
            ic_cdk::trap("check_fee is non-zero but Dogecoin transactions are not checked");
        }
        if state.ecdsa_key_name.is_empty() {
            ic_cdk::trap("ecdsa_key_name is not set");
        }
    }

    fn parse_address(
        &self,
        address: &str,
        network: ic_ckbtc_minter::Network,
    ) -> Result<BitcoinAddress, String> {
        let doge_network = match network {
            ic_ckbtc_minter::Network::Mainnet => Network::Mainnet,
            ic_ckbtc_minter::Network::Testnet => Network::Testnet,
            ic_ckbtc_minter::Network::Regtest => Network::Regtest,
        };
        let doge_address =
            DogecoinAddress::parse(address, &doge_network).map_err(|e| e.to_string())?;

        // This conversion is a hack to use the same type of address as in RetrieveBtcRequest,
        // since this type is used both in the event logs (event `AcceptedRetrieveBtcRequest`)
        // and in the minter state (field `pending_retrieve_btc_requests`)
        Ok(match doge_address {
            DogecoinAddress::P2pkh(bytes) => BitcoinAddress::P2pkh(bytes),
            DogecoinAddress::P2sh(bytes) => BitcoinAddress::P2sh(bytes),
        })
    }

    async fn check_address(
        &self,
        _btc_checker_principal: Option<Principal>,
        _address: String,
    ) -> Result<BtcAddressCheckStatus, CallError> {
        // No OFAC checklist for Dogecoin addresses
        Ok(BtcAddressCheckStatus::Clean)
    }
}
