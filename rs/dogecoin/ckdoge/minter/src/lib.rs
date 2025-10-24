#[cfg(test)]
mod tests;

pub mod address;
pub mod candid_api;
pub mod lifecycle;
pub mod updates;

use crate::address::DogecoinAddress;
use crate::lifecycle::init::Network;
use async_trait::async_trait;
use candid::Principal;
use ic_ckbtc_minter::{
    CanisterRuntime, CheckTransactionResponse, GetCurrentFeePercentilesRequest, GetUtxosRequest,
    GetUtxosResponse, management::CallError, state::CkBtcMinterState, tx,
    updates::retrieve_btc::BtcAddressCheckStatus,
};
use icrc_ledger_types::icrc1::{account::Account, transfer::Memo};
use std::time::Duration;

use crate::dogecoin_canister::MillikoinuPerByte;
pub use dogecoin_canister::get_dogecoin_canister_id;
pub use ic_ckbtc_minter::{
    OutPoint, Page, Txid, Utxo,
    address::BitcoinAddress,
    logs::Priority,
    memo::{BurnMemo, MintMemo, encode as memo_encode},
    state::RetrieveBtcRequest,
    state::eventlog::{Event, EventType, GetEventsArg},
    updates::update_balance::{UpdateBalanceArgs, UpdateBalanceError, UtxoStatus},
};

pub const DOGECOIN_CANISTER_RUNTIME: DogeCanisterRuntime = DogeCanisterRuntime {};

#[derive(Copy, Clone)]
pub struct DogeCanisterRuntime {}

#[async_trait]
impl CanisterRuntime for DogeCanisterRuntime {
    fn refresh_fee_percentiles_frequency(&self) -> Duration {
        const SIX_MINUTES: Duration = Duration::from_secs(360);
        SIX_MINUTES
    }

    async fn get_current_fee_percentiles(
        &self,
        request: &GetCurrentFeePercentilesRequest,
    ) -> Result<Vec<MillikoinuPerByte>, CallError> {
        dogecoin_canister::dogecoin_get_fee_percentiles(request)
            .await
            .map_err(|err| CallError::from_cdk_call_error("dogecoin_get_fee_percentiles", err))
    }

    async fn get_utxos(&self, request: &GetUtxosRequest) -> Result<GetUtxosResponse, CallError> {
        dogecoin_canister::dogecoin_get_utxos(request)
            .await
            .map(GetUtxosResponse::from)
            .map_err(|err| CallError::from_cdk_call_error("dogecoin_get_utxos", err))
    }

    async fn check_transaction(
        &self,
        _btc_checker_principal: Option<Principal>,
        _utxo: &Utxo,
        _cycle_payment: u128,
    ) -> Result<CheckTransactionResponse, CallError> {
        // No OFAC checklist for Dogecoin addresses
        Ok(CheckTransactionResponse::Passed)
    }

    async fn mint_ckbtc(
        &self,
        amount: u64,
        to: Account,
        memo: Memo,
    ) -> Result<u64, UpdateBalanceError> {
        ic_ckbtc_minter::updates::update_balance::mint(amount, to, memo).await
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
    ) -> Result<BitcoinAddress, std::string::String> {
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

    fn derive_user_address(&self, state: &CkBtcMinterState, account: &Account) -> String {
        updates::account_to_p2pkh_address_from_state(state, account)
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

/// Similar to ic_cdk::bitcoin_canister but for Dogecoin
mod dogecoin_canister {
    use crate::Network;
    use candid::Principal;
    use ic_cdk::bitcoin_canister::{
        GetCurrentFeePercentilesRequest, GetUtxosRequest, GetUtxosResponse,
    };
    use ic_cdk::call::{Call, CallResult};

    /// Unit of Dogecoin transaction fee.
    ///
    /// This is the element in the [`dogecoin_get_fee_percentiles`] response.
    pub type MillikoinuPerByte = u64;

    pub async fn dogecoin_get_utxos(arg: &GetUtxosRequest) -> CallResult<GetUtxosResponse> {
        let canister_id = get_dogecoin_canister_id(&into_dogecoin_network(arg.network));
        // same cycles cost as for the Bitcoin canister
        let cycles = ic_cdk::bitcoin_canister::cost_get_utxos(arg);
        Ok(Call::bounded_wait(canister_id, "dogecoin_get_utxos")
            .with_arg(arg)
            .with_cycles(cycles)
            .await?
            .candid()?)
    }

    pub async fn dogecoin_get_fee_percentiles(
        arg: &GetCurrentFeePercentilesRequest,
    ) -> CallResult<Vec<MillikoinuPerByte>> {
        let canister_id = get_dogecoin_canister_id(&into_dogecoin_network(arg.network));
        // same cycles cost as for the Bitcoin canister
        let cycles = ic_cdk::bitcoin_canister::cost_get_current_fee_percentiles(arg);
        Ok(
            Call::bounded_wait(canister_id, "dogecoin_get_current_fee_percentiles")
                .with_arg(arg)
                .with_cycles(cycles)
                .await?
                .candid()?,
        )
    }

    /// Gets the canister ID of the Dogecoin canister for the specified network.
    pub fn get_dogecoin_canister_id(network: &Network) -> Principal {
        const MAINNET_ID: Principal = Principal::from_slice(&[0_u8, 0, 0, 0, 1, 160, 0, 7, 1, 1]); // "gordg-fyaaa-aaaan-aaadq-cai"
        const TESTNET_ID: Principal = Principal::from_slice(&[0, 0, 0, 0, 1, 160, 0, 8, 1, 1]); // "hd7hi-kqaaa-aaaan-aaaea-cai"
        const REGTEST_ID: Principal = Principal::from_slice(&[0, 0, 0, 0, 1, 160, 0, 8, 1, 1]); // "hd7hi-kqaaa-aaaan-aaaea-cai"

        match network {
            Network::Mainnet => MAINNET_ID,
            Network::Testnet => TESTNET_ID,
            Network::Regtest => REGTEST_ID,
        }
    }

    fn into_dogecoin_network(network: ic_cdk::bitcoin_canister::Network) -> Network {
        match network {
            ic_cdk::bitcoin_canister::Network::Mainnet => Network::Mainnet,
            ic_cdk::bitcoin_canister::Network::Testnet => Network::Testnet,
            ic_cdk::bitcoin_canister::Network::Regtest => Network::Regtest,
        }
    }
}
