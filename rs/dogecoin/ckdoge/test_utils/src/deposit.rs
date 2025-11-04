//! Helpers for the deposit flow, converting DOGE on Dogecoin into ckDOGE on ICP.
//!
//! General design guidelines:
//! * 1 public method for each user interaction.
//! * Helper struct with only 1 or 2 public methods for auto-completion to become trivial.
//! * Prefix in method's name (e.g. `minter_` or `dogecoin_`) indicates the involved component.
use crate::Setup;
use candid::Principal;
use ic_ckdoge_minter::candid_api::GetDogeAddressArgs;
use ic_ckdoge_minter::lifecycle::init::Network;
use ic_ckdoge_minter::{
    EventType, MintMemo, UpdateBalanceArgs, UpdateBalanceError, Utxo, UtxoStatus, memo_encode,
};
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::Memo;
use icrc_ledger_types::icrc3::transactions::Mint;
use std::cell::OnceCell;

pub struct RetrieveDepositAddressFlow<S> {
    setup: S,
}

impl<S> RetrieveDepositAddressFlow<S> {
    pub fn new(setup: S) -> Self {
        Self { setup }
    }

    pub fn minter_get_dogecoin_deposit_address<A: Into<Account>>(
        self,
        account: A,
    ) -> DogecoinDepositTransactionFlow<S>
    where
        S: AsRef<Setup>,
    {
        use std::str::FromStr;

        let account = account.into();
        let deposit_address = self.setup.as_ref().minter().get_doge_address(
            Principal::anonymous(),
            &GetDogeAddressArgs {
                owner: Some(account.owner),
                subaccount: account.subaccount,
            },
        );

        let network = self.setup.as_ref().network();
        let deposit_address = bitcoin::dogecoin::Address::from_str(&deposit_address)
            .expect("BUG: invalid Dogecoin address")
            .require_network(match network {
                Network::Mainnet => bitcoin::dogecoin::Network::Dogecoin,
                Network::Testnet => bitcoin::dogecoin::Network::Testnet,
                Network::Regtest => bitcoin::dogecoin::Network::Regtest,
            })
            .unwrap_or_else(|e| panic!("BUG: address is not valid for network {network}: {e}",));

        DogecoinDepositTransactionFlow {
            setup: self.setup,
            account,
            deposit_address,
            deposit_utxo: OnceCell::new(),
        }
    }
}

pub struct DogecoinDepositTransactionFlow<S> {
    setup: S,
    account: Account,
    deposit_address: bitcoin::dogecoin::Address,
    deposit_utxo: OnceCell<Utxo>,
}

impl<S> DogecoinDepositTransactionFlow<S>
where
    S: AsRef<Setup>,
{
    pub fn dogecoin_simulate_transaction(self, utxo: Utxo) -> Self {
        self.deposit_utxo
            .set(utxo.clone())
            .expect("BUG: simulate_transaction was called multiple times!");
        self.setup
            .as_ref()
            .dogecoin()
            .simulate_transaction(utxo, self.deposit_address.to_string());
        self
    }

    pub fn minter_update_balance(self) -> UpdateBalanceFlow<S> {
        let balance_before = self.setup.as_ref().ledger().icrc1_balance_of(self.account);
        let result = self.setup.as_ref().minter().update_balance(
            self.account.owner,
            &UpdateBalanceArgs {
                owner: Some(self.account.owner),
                subaccount: self.account.subaccount,
            },
        );

        UpdateBalanceFlow {
            setup: self.setup,
            account: self.account,
            balance_before,
            deposit_utxo: self.deposit_utxo.into_inner(),
            result,
        }
    }
}

pub struct UpdateBalanceFlow<S> {
    setup: S,
    account: Account,
    balance_before: u64,
    deposit_utxo: Option<Utxo>,
    result: Result<Vec<UtxoStatus>, UpdateBalanceError>,
}

impl<S> UpdateBalanceFlow<S>
where
    S: AsRef<Setup>,
{
    pub fn expect_mint(self) {
        let deposit_utxo = self.deposit_utxo.expect("BUG: missing deposit UTXO!");
        let minted_status: Vec<_> = self
            .result
            .expect("BUG: update_balance error")
            .into_iter()
            .filter_map(|status| match status {
                UtxoStatus::Minted {
                    block_index,
                    minted_amount,
                    utxo,
                } if utxo == deposit_utxo => Some((block_index, minted_amount)),
                _ => None,
            })
            .collect();
        assert_eq!(
            minted_status.len(),
            1,
            "BUG: expected exactly one mint for UTXO {:?}, but got {}",
            deposit_utxo,
            minted_status.len()
        );
        let (mint_index, minted_amount) = minted_status.into_iter().next().unwrap();
        assert_eq!(minted_amount, deposit_utxo.value);

        self.setup
            .as_ref()
            .ledger()
            .assert_that_transaction(mint_index)
            .equals_mint_ignoring_timestamp(Mint {
                amount: deposit_utxo.value.into(),
                to: self.account,
                memo: Some(Memo::from(memo_encode(&MintMemo::Convert {
                    txid: Some(deposit_utxo.outpoint.txid.as_ref()),
                    vout: Some(deposit_utxo.outpoint.vout),
                    kyt_fee: Some(0),
                }))),
                created_at_time: None,
                fee: None,
            });

        self.setup
            .as_ref()
            .minter()
            .assert_that_events()
            .contains_only_once_in_order(&[
                EventType::CheckedUtxoV2 {
                    utxo: deposit_utxo.clone(),
                    account: self.account,
                },
                EventType::ReceivedUtxos {
                    mint_txid: Some(0),
                    to_account: self.account,
                    utxos: vec![deposit_utxo],
                },
            ]);

        let balance_after = self.setup.as_ref().ledger().icrc1_balance_of(self.account);
        assert_eq!(balance_after - self.balance_before, minted_amount);
    }
}
