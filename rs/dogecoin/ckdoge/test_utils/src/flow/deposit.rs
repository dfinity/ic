use crate::{Setup, into_rust_dogecoin_network};
use candid::Principal;
use ic_ckdoge_minter::candid_api::GetDogeAddressArgs;
use ic_ckdoge_minter::{
    EventType, MintMemo, UpdateBalanceArgs, UpdateBalanceError, Utxo, UtxoStatus, memo_encode,
};
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::Memo;
use icrc_ledger_types::icrc3::transactions::Mint;

/// Entry point in the deposit flow.
///
/// Step 1: retrieve the deposit address on Dogecoin.
pub struct DepositFlowStart<S> {
    setup: S,
}

impl<S> DepositFlowStart<S> {
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
            .require_network(into_rust_dogecoin_network(network))
            .unwrap_or_else(|e| panic!("BUG: address is not valid for network {network}: {e}",));

        DogecoinDepositTransactionFlow {
            setup: self.setup,
            account,
            deposit_address,
        }
    }
}

/// Step 2: Deposit transaction on Dogecoin network.
pub struct DogecoinDepositTransactionFlow<S> {
    setup: S,
    account: Account,
    deposit_address: bitcoin::dogecoin::Address,
}

impl<S> DogecoinDepositTransactionFlow<S>
where
    S: AsRef<Setup>,
{
    pub fn dogecoin_simulate_transaction(self, deposit_utxo: Utxo) -> UpdateBalanceFlow<S> {
        self.setup
            .as_ref()
            .dogecoin()
            .push_utxo(deposit_utxo.clone(), self.deposit_address.to_string());

        UpdateBalanceFlow {
            setup: self.setup,
            account: self.account,
            deposit_utxo,
        }
    }
}

/// Step 3: call update balance on minter
pub struct UpdateBalanceFlow<S> {
    setup: S,
    account: Account,
    deposit_utxo: Utxo,
}

impl<S> UpdateBalanceFlow<S>
where
    S: AsRef<Setup>,
{
    pub fn minter_update_balance(self) -> DepositFlowEnd<S> {
        let balance_before = self.setup.as_ref().ledger().icrc1_balance_of(self.account);
        let result = self.setup.as_ref().minter().update_balance(
            self.account.owner,
            &UpdateBalanceArgs {
                owner: Some(self.account.owner),
                subaccount: self.account.subaccount,
            },
        );

        DepositFlowEnd {
            setup: self.setup,
            account: self.account,
            deposit_utxo: self.deposit_utxo,
            balance_before,
            result,
        }
    }
}

/// Verify the outcome of the deposit flow.
pub struct DepositFlowEnd<S> {
    setup: S,
    account: Account,
    balance_before: u64,
    deposit_utxo: Utxo,
    result: Result<Vec<UtxoStatus>, UpdateBalanceError>,
}

impl<S> DepositFlowEnd<S>
where
    S: AsRef<Setup>,
{
    pub fn expect_mint(self) {
        let minted_status: Vec<_> = self
            .result
            .expect("BUG: update_balance error")
            .into_iter()
            .filter_map(|status| match status {
                UtxoStatus::Minted {
                    block_index,
                    minted_amount,
                    utxo,
                } if utxo == self.deposit_utxo => Some((block_index, minted_amount)),
                _ => None,
            })
            .collect();
        assert_eq!(
            minted_status.len(),
            1,
            "BUG: expected exactly one mint for UTXO {:?}, but got {}",
            self.deposit_utxo,
            minted_status.len()
        );
        let (mint_index, minted_amount) = minted_status.into_iter().next().unwrap();
        assert_eq!(minted_amount, self.deposit_utxo.value);

        let known_utxos = self.setup.as_ref().minter().get_known_utxos(self.account);
        assert!(
            known_utxos.contains(&self.deposit_utxo),
            "BUG: missing deposit utxo {:?} in {known_utxos:?}",
            self.deposit_utxo
        );

        self.setup
            .as_ref()
            .ledger()
            .assert_that_transaction(mint_index)
            .equals_mint_ignoring_timestamp(Mint {
                amount: self.deposit_utxo.value.into(),
                to: self.account,
                memo: Some(Memo::from(memo_encode(&MintMemo::Convert {
                    txid: Some(self.deposit_utxo.outpoint.txid.as_ref()),
                    vout: Some(self.deposit_utxo.outpoint.vout),
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
                    utxo: self.deposit_utxo.clone(),
                    account: self.account,
                },
                EventType::ReceivedUtxos {
                    mint_txid: Some(mint_index),
                    to_account: self.account,
                    utxos: vec![self.deposit_utxo],
                },
            ]);

        let balance_after = self.setup.as_ref().ledger().icrc1_balance_of(self.account);
        assert_eq!(balance_after - self.balance_before, minted_amount);
    }
}
