use crate::dogecoin::DogecoinUsers;
use crate::{Setup, into_rust_dogecoin_network};
use bitcoin::hashes::Hash;
use candid::Principal;
use ic_ckdoge_minter::candid_api::GetDogeAddressArgs;
use ic_ckdoge_minter::{
    MintMemo, UpdateBalanceArgs, UpdateBalanceError, Utxo, UtxoStatus,
    event::CkDogeMinterEventType, memo_encode,
};
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::Memo;
use icrc_ledger_types::icrc3::transactions::Mint;
use std::collections::{BTreeMap, BTreeSet};

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
    pub fn dogecoin_simulate_transaction<I: IntoIterator<Item = Utxo>>(
        self,
        deposit_utxos: I,
    ) -> UpdateBalanceFlow<S> {
        let deposit_utxos: BTreeSet<_> = deposit_utxos.into_iter().collect();
        self.setup
            .as_ref()
            .dogecoin()
            .push_utxos(deposit_utxos.clone(), self.deposit_address.to_string());

        UpdateBalanceFlow {
            setup: self.setup,
            account: self.account,
            deposit_transactions: BTreeSet::default(),
        }
    }

    pub fn dogecoin_send_transaction<I: IntoIterator<Item = u64>>(
        self,
        amounts: I,
    ) -> UpdateBalanceFlow<S> {
        let dogecoind = self.setup.as_ref().dogecoind();
        let mut deposit_transactions = BTreeSet::new();
        for amount in amounts {
            let txid = dogecoind.send_transaction(
                &DogecoinUsers::DepositUser,
                &self.deposit_address,
                amount,
            );
            deposit_transactions.insert(txid);
        }

        UpdateBalanceFlow {
            setup: self.setup,
            account: self.account,
            deposit_transactions,
        }
    }
}

/// Step 3: call update balance on minter
pub struct UpdateBalanceFlow<S> {
    setup: S,
    account: Account,
    deposit_transactions: BTreeSet<bitcoin::Txid>,
}

impl<S> UpdateBalanceFlow<S>
where
    S: AsRef<Setup>,
{
    pub fn dogecoin_mine_blocks(self, num_blocks: impl Into<u64>) -> Self {
        self.setup
            .as_ref()
            .dogecoind()
            .mine_blocks(num_blocks.into());
        self
    }

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
            deposit_transactions: self.deposit_transactions,
            balance_before,
            result,
        }
    }
}

/// Verify the outcome of the deposit flow.
pub struct DepositFlowEnd<S> {
    setup: S,
    account: Account,
    balance_before: u128,
    deposit_transactions: BTreeSet<bitcoin::Txid>,
    result: Result<Vec<UtxoStatus>, UpdateBalanceError>,
}

impl<S> DepositFlowEnd<S>
where
    S: AsRef<Setup>,
{
    pub fn expect_mint(self) {
        let minted_status: BTreeMap<_, _> = self
            .result
            .expect("BUG: update_balance error")
            .into_iter()
            .filter_map(|status| match status {
                UtxoStatus::Minted {
                    block_index,
                    minted_amount,
                    utxo,
                } if self
                    .deposit_transactions
                    .contains(&bitcoin::Txid::from_byte_array(utxo.outpoint.txid.into())) =>
                {
                    Some((utxo, (block_index, minted_amount)))
                }
                _ => None,
            })
            .collect();
        let deposit_utxos = minted_status.keys().cloned().collect::<BTreeSet<_>>();
        assert_eq!(
            deposit_utxos
                .iter()
                .map(|utxo| bitcoin::Txid::from_byte_array(utxo.outpoint.txid.into()))
                .collect::<BTreeSet<_>>(),
            self.deposit_transactions,
            "BUG: unexpected UTXOs with status UtxoStatus::Minted"
        );

        let total_minted_amount = minted_status
            .iter()
            .map(|(_utxo, (_block_index, minted_amount))| *minted_amount as u128)
            .sum::<u128>();

        let known_utxos: BTreeSet<_> = self
            .setup
            .as_ref()
            .minter()
            .get_known_utxos(self.account)
            .into_iter()
            .collect();
        assert!(
            deposit_utxos.is_subset(&known_utxos),
            "BUG: missing deposit utxo {:?} in {known_utxos:?}",
            deposit_utxos
        );

        let expected_events: Vec<_> = minted_status
            .iter()
            .flat_map(|(utxo, (mint_index, _minted_amount))| {
                vec![
                    CkDogeMinterEventType::CheckedUtxo {
                        utxo: utxo.clone(),
                        account: self.account,
                    },
                    CkDogeMinterEventType::ReceivedUtxos {
                        mint_txid: Some(*mint_index),
                        to_account: self.account,
                        utxos: vec![utxo.clone()],
                    },
                ]
            })
            .collect();
        self.setup
            .as_ref()
            .minter()
            .assert_that_events()
            .contains_only_once_in_order(&expected_events);

        let mint_indexes: BTreeMap<_, _> = minted_status
            .iter()
            .map(|(utxo, (mint_index, minted_amount))| {
                (*mint_index, (utxo.clone(), *minted_amount))
            })
            .collect();
        let first_mint_index = *mint_indexes.first_key_value().unwrap().0;
        let last_mint_index = *mint_indexes.last_key_value().unwrap().0;
        assert_eq!(
            last_mint_index,
            first_mint_index + self.deposit_transactions.len() as u64 - 1,
            "Range of mint indexes on ledger is not continuous"
        );
        let expected_mints: Vec<_> = mint_indexes
            .into_iter()
            .map(|(_mint_index, (utxo, minted_amount))| Mint {
                amount: minted_amount.into(),
                to: self.account,
                memo: Some(Memo::from(memo_encode(&MintMemo::Convert {
                    txid: Some(utxo.outpoint.txid.as_ref()),
                    vout: Some(utxo.outpoint.vout),
                    kyt_fee: Some(0),
                }))),
                created_at_time: None,
                fee: None,
            })
            .collect();
        self.setup
            .as_ref()
            .ledger()
            .assert_that_transactions(first_mint_index..=last_mint_index)
            .equals_mint_ignoring_timestamp(&expected_mints);

        let balance_after = self.setup.as_ref().ledger().icrc1_balance_of(self.account);
        assert_eq!(balance_after - self.balance_before, total_minted_amount);
    }
}
