use crate::BLOCK_TIME;
use crate::MAX_TIME_IN_QUEUE;
use crate::MIN_CONFIRMATIONS;
use crate::{Setup, into_outpoint, parse_dogecoin_address};
use assert_matches::assert_matches;
use bitcoin::hashes::Hash;
use candid::{Decode, Principal};
use ic_bitcoin_canister_mock::{OutPoint, Utxo};
use ic_ckdoge_minter::candid_api::EstimateWithdrawalFeeError;
use ic_ckdoge_minter::event::RetrieveDogeRequest;
use ic_ckdoge_minter::fees::DogecoinFeeEstimator;
use ic_ckdoge_minter::{
    BurnMemo, MIN_RESUBMISSION_DELAY, Txid, WithdrawalReimbursementReason,
    address::DogecoinAddress,
    candid_api::{
        GetDogeAddressArgs, RetrieveDogeOk, RetrieveDogeStatus, RetrieveDogeWithApprovalError,
        WithdrawalFee,
    },
    event::CkDogeMinterEventType,
    memo_encode,
};
use icrc_ledger_types::{
    icrc1::{account::Account, transfer::Memo},
    icrc3::transactions::Burn,
};
use pocket_ic::{RejectResponse, common::rest::RawMessageId};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

/// Entry point in the withdrawal flow
///
/// Step 1: approve the minter to burn user's funds
pub struct WithdrawalFlowStart<S> {
    setup: S,
}

impl<S> WithdrawalFlowStart<S> {
    pub fn new(setup: S) -> Self {
        Self { setup }
    }

    pub fn ledger_approve_minter<A>(self, account: A, amount: u64) -> RetrieveDogeFlow<S>
    where
        A: Into<Account>,
        S: AsRef<Setup>,
    {
        let account = account.into();
        let _ledger_approval_index = self
            .setup
            .as_ref()
            .ledger()
            .icrc2_approve(account, amount, self.setup.as_ref().minter().id)
            .expect("BUG: failed to approve minter");

        RetrieveDogeFlow {
            setup: self.setup,
            account,
        }
    }
}

/// Step 2: Call `retrieve_doge_with_approval` on the minter
pub struct RetrieveDogeFlow<S> {
    setup: S,
    account: Account,
}

impl<S> RetrieveDogeFlow<S>
where
    S: AsRef<Setup>,
{
    pub fn minter_retrieve_doge_with_approval(
        self,
        withdrawal_amount: u64,
        address: impl Into<String>,
    ) -> ProcessWithdrawal<S> {
        use ic_ckdoge_minter::candid_api::RetrieveDogeWithApprovalArgs;

        let address = address.into();
        let Account { owner, subaccount } = self.account;
        let result = self
            .setup
            .as_ref()
            .minter()
            .submit_retrieve_doge_with_approval(
                owner,
                &RetrieveDogeWithApprovalArgs {
                    amount: withdrawal_amount,
                    from_subaccount: subaccount,
                    address: address.clone(),
                },
            );

        ProcessWithdrawal {
            setup: self.setup,
            account: self.account,
            withdrawal_amount,
            address,
            result,
        }
    }
}

/// Step 3: wait for the withdrawal to be processed by the minter
pub struct ProcessWithdrawal<S> {
    setup: S,
    account: Account,
    withdrawal_amount: u64,
    address: String,
    result: Result<RawMessageId, RejectResponse>,
}

impl<S> ProcessWithdrawal<S>
where
    S: AsRef<Setup>,
{
    pub fn expect_withdrawal_request_accepted(self) -> DogecoinWithdrawalTransactionFlow<S> {
        let balance_before = self.setup.as_ref().ledger().icrc1_balance_of(self.account);
        let withdrawal_fee = self
            .setup
            .as_ref()
            .minter()
            .estimate_withdrawal_fee(self.withdrawal_amount);

        let retrieve_doge_id = self
            .await_minter_response()
            .expect("BUG: withdrawal request was not accepted!");

        let address = DogecoinAddress::parse(&self.address, &self.setup.as_ref().network())
            .expect("BUG: minter accepted a withdrawal request with an invalid dogecoin address!");

        let minter = self.setup.as_ref().minter();
        assert_eq!(
            minter.retrieve_doge_status(retrieve_doge_id.block_index),
            RetrieveDogeStatus::Pending
        );
        minter
            .assert_that_events()
            .ignoring_timestamp()
            .contains_only_once_in_order(&[CkDogeMinterEventType::AcceptedRetrieveDogeRequest(
                RetrieveDogeRequest {
                    amount: self.withdrawal_amount,
                    address: address.clone(),
                    block_index: retrieve_doge_id.block_index,
                    received_at: 0, //not relevant
                    reimbursement_account: Some(self.account),
                },
            )]);

        let ledger = self.setup.as_ref().ledger();
        ledger
            .assert_that_transaction(retrieve_doge_id.block_index)
            .equals_burn_ignoring_timestamp(&[Burn {
                amount: self.withdrawal_amount.into(),
                from: self.account,
                spender: Some(minter.id().into()),
                memo: Some(Memo::from(memo_encode(&BurnMemo::Convert {
                    address: Some(&self.address),
                    kyt_fee: None,
                    status: None,
                }))),
                created_at_time: None,
                fee: None,
            }]);

        let balance_after = self.setup.as_ref().ledger().icrc1_balance_of(self.account);

        assert_eq!(balance_before - balance_after, self.withdrawal_amount);

        DogecoinWithdrawalTransactionFlow {
            setup: self.setup,
            withdrawal_amount: self.withdrawal_amount,
            address,
            retrieve_doge_id,
            account: self.account,
            withdrawal_fee,
        }
    }

    pub fn expect_error_matching<P>(self, matcher: P)
    where
        P: FnOnce(RetrieveDogeWithApprovalError) -> bool,
    {
        let err = self.await_minter_response().unwrap_err();
        assert!(matcher(err))
    }

    fn await_minter_response(&self) -> Result<RetrieveDogeOk, RetrieveDogeWithApprovalError> {
        let response = self
            .result
            .clone()
            .and_then(|msg_id| self.setup.as_ref().env.await_call(msg_id))
            .expect("BUG: call to retrieve_doge_with_approval failed");
        Decode!(&response, Result<RetrieveDogeOk, RetrieveDogeWithApprovalError>).unwrap()
    }
}

/// Step 4: wait for the Dogecoin transaction
pub struct DogecoinWithdrawalTransactionFlow<S> {
    setup: S,
    withdrawal_amount: u64,
    address: DogecoinAddress,
    retrieve_doge_id: RetrieveDogeOk,
    withdrawal_fee: Result<WithdrawalFee, EstimateWithdrawalFeeError>,
    account: Account,
}

impl<S> DogecoinWithdrawalTransactionFlow<S>
where
    S: AsRef<Setup>,
{
    pub fn dogecoin_await_transaction(self) -> WithdrawalFlowEnd<S> {
        let minter = self.setup.as_ref().minter();
        let txid = minter.await_submitted_doge_transaction(self.retrieve_doge_id.block_index);
        let mut mempool = self.setup.as_ref().dogecoin().mempool();
        let tx = mempool
            .remove(&txid)
            .expect("the mempool does not contain the withdrawal transaction");

        let (request_block_indices, change_amount, withdrawal_fee, used_utxos) = {
            let sent_tx_event = minter
                .assert_that_events()
                .extract_exactly_one(
                    |event| matches!(event, CkDogeMinterEventType::SentDogeTransaction {txid: sent_txid, ..} if sent_txid == &txid),
                );
            match sent_tx_event {
                CkDogeMinterEventType::SentDogeTransaction {
                    request_block_indices,
                    txid: _,
                    utxos,
                    change_output,
                    submitted_at: _,
                    fee_per_vbyte: _,
                    withdrawal_fee,
                    signed_tx: _,
                } => (
                    request_block_indices,
                    change_output.expect("BUG: missing change output").value,
                    withdrawal_fee.expect("BUG: missing withdrawal fee"),
                    utxos,
                ),
                _ => unreachable!(),
            }
        };
        assert_eq!(
            withdrawal_fee,
            self.withdrawal_fee.expect(
                "BUG: failed to estimate withdrawal fee, even though transaction is expected"
            ),
            "BUG: withdrawal fee from event does not match fees retrieved from endpoint"
        );
        assert!(request_block_indices.contains(&self.retrieve_doge_id.block_index));

        assert_uses_utxos(&tx, used_utxos.clone());
        let total_inputs: u64 = used_utxos.iter().map(|input| input.value).sum();

        let network = self.setup.as_ref().network();
        let minter = self.setup.as_ref().minter();
        let minter_address = self
            .setup
            .as_ref()
            .parse_dogecoin_address(minter.get_doge_address(
                Principal::anonymous(),
                &GetDogeAddressArgs {
                    owner: Some(minter.id()),
                    subaccount: None,
                },
            ));

        // expect at least 2 outputs:
        // 1) to beneficiary's address on Dogecoin
        // 2) to minter's address for the change output
        let outputs: BTreeMap<_, _> = tx
            .output
            .iter()
            .map(|output| (parse_dogecoin_address(network, output), output))
            .collect();
        assert_eq!(outputs.len(), tx.output.len());
        assert!(outputs.len() >= 2);

        let beneficiary_output = outputs
            .get(
                &self
                    .setup
                    .as_ref()
                    .parse_dogecoin_address(self.address.display(&network)),
            )
            .expect("BUG: missing output to beneficiary");
        assert_eq!(
            outputs
                .get(&minter_address)
                .expect("BUG: missing change output")
                .value
                .to_sat(),
            change_amount
        );

        let total_outputs: u64 = tx.output.iter().map(|output| output.value.to_sat()).sum();
        assert_eq!(total_inputs - total_outputs, withdrawal_fee.dogecoin_fee);
        let total_fee = withdrawal_fee.dogecoin_fee + withdrawal_fee.minter_fee;
        // Fee is shared across all outputs, excepted for the change output to the minter
        // There might be a one-off error due to sharing the fee evenly across the involved outputs.
        let fee_share_lower_bound = total_fee / (tx.output.len() as u64 - 1);
        let fee_share_upper_bound = fee_share_lower_bound + 1;
        let range = (self.withdrawal_amount - fee_share_upper_bound)
            ..=(self.withdrawal_amount - fee_share_lower_bound);
        assert!(range.contains(&beneficiary_output.value.to_sat()));

        WithdrawalFlowEnd {
            setup: self.setup,
            retrieve_doge_id: self.retrieve_doge_id,
            change_amount,
            minter_address,
            sent_transactions: vec![tx],
        }
    }

    pub fn minter_await_withdrawal_reimbursed(self, reason: WithdrawalReimbursementReason) {
        let ledger = self.setup.as_ref().ledger();
        let minter = self.setup.as_ref().minter();
        let balance_after_withdrawal = ledger.icrc1_balance_of(self.account);
        let withdrawal_id = self.retrieve_doge_id.block_index;

        assert_eq!(
            self.withdrawal_fee,
            Err(EstimateWithdrawalFeeError::AmountTooHigh),
            "BUG: the only reason for reimbursing a transaction is that the amount is so big that it requires too many UTXOs"
        );
        assert_eq!(
            minter.retrieve_doge_status(withdrawal_id),
            RetrieveDogeStatus::Pending
        );

        self.setup
            .as_ref()
            .env
            .advance_time(MAX_TIME_IN_QUEUE + Duration::from_nanos(1));
        let status = minter.await_doge_transaction_with_status(withdrawal_id, |tx_status| {
            matches!(tx_status, RetrieveDogeStatus::Reimbursed(_))
        });

        let mempool = self.setup.as_ref().dogecoin().mempool();
        assert_eq!(
            mempool.len(),
            0,
            "no transaction should appear when being reimbursed"
        );

        let reimbursement_block_index = withdrawal_id + 1;
        let reimbursement_amount =
            self.withdrawal_amount - DogecoinFeeEstimator::COST_OF_ONE_BILLION_CYCLES;
        assert_matches!(
            status,
            RetrieveDogeStatus::Reimbursed(reimbursement) if
            reimbursement.account == self.account &&
            reimbursement.amount == reimbursement_amount &&
            reimbursement.mint_block_index == reimbursement_block_index
        );

        minter
            .assert_that_events()
            .none_satisfy(|event| {
                matches!(
                    event,
                    CkDogeMinterEventType::SentDogeTransaction { .. }
                        | CkDogeMinterEventType::ReplacedDogeTransaction { .. }
                )
            })
            .contains_only_once_in_order(&[
                CkDogeMinterEventType::ScheduleWithdrawalReimbursement {
                    account: self.account,
                    amount: reimbursement_amount,
                    reason,
                    burn_block_index: withdrawal_id,
                },
                CkDogeMinterEventType::ReimbursedWithdrawal {
                    burn_block_index: withdrawal_id,
                    mint_block_index: reimbursement_block_index,
                },
            ]);

        assert_eq!(
            ledger.icrc1_balance_of(self.account),
            balance_after_withdrawal + reimbursement_amount
        );
    }
}

/// Step 5: wait for enough confirmations for the transaction to be considered finalized by the minter.
pub struct WithdrawalFlowEnd<S> {
    setup: S,
    retrieve_doge_id: RetrieveDogeOk,
    change_amount: u64,
    minter_address: bitcoin::dogecoin::Address,
    sent_transactions: Vec<bitcoin::Transaction>,
}

impl<S> WithdrawalFlowEnd<S>
where
    S: AsRef<Setup>,
{
    pub fn assert_sent_transactions<C>(self, check: C) -> Self
    where
        C: Fn(&[bitcoin::Transaction]),
    {
        check(&self.sent_transactions);
        self
    }

    pub fn minter_await_finalized_single_transaction(self) {
        assert_eq!(
            self.sent_transactions.len(),
            1,
            "BUG: expected exactly one transaction"
        );
        let sent_tx = self.sent_transactions.first().unwrap().compute_txid();
        self.finalize_transaction(sent_tx);
    }

    pub fn minter_await_finalized_transaction_by<F>(self, selector: F)
    where
        F: FnOnce(&[bitcoin::Transaction]) -> &bitcoin::Transaction,
    {
        let tx_to_finalize = selector(&self.sent_transactions);
        let txid_to_finalize = tx_to_finalize.compute_txid();
        self.finalize_transaction(txid_to_finalize);
    }

    fn finalize_transaction(self, txid: bitcoin::Txid) {
        use bitcoin::hashes::Hash;

        let minter = self.setup.as_ref().minter();
        self.setup
            .as_ref()
            .env
            .advance_time(MIN_CONFIRMATIONS * BLOCK_TIME + Duration::from_secs(1));
        let txid_bytes: [u8; 32] = txid.to_byte_array();
        self.setup.as_ref().dogecoin().push_utxo(
            Utxo {
                value: self.change_amount,
                height: 0,
                outpoint: OutPoint {
                    txid: txid_bytes.into(),
                    vout: 1,
                },
            },
            self.minter_address.to_string(),
        );

        assert_eq!(
            minter.await_finalized_doge_transaction(self.retrieve_doge_id.block_index),
            Txid::from(txid_bytes)
        );
        minter.assert_that_events().contains_only_once_in_order(&[
            CkDogeMinterEventType::ConfirmedDogeTransaction {
                txid: txid_bytes.into(),
            },
        ]);
        minter.self_check();
    }

    pub fn minter_await_resubmission(mut self) -> Self {
        assert!(
            !self.sent_transactions.is_empty(),
            "BUG: no transactions to resubmit"
        );
        let setup = self.setup.as_ref();
        let minter = setup.minter();
        let dogecoin = setup.dogecoin();
        let mempool_before = dogecoin.mempool();
        setup
            .env
            .advance_time(MIN_RESUBMISSION_DELAY + Duration::from_secs(1));
        let mut mempool_after =
            dogecoin.await_mempool(|mempool| mempool.len() > mempool_before.len());

        let old_transaction = self.sent_transactions.last().unwrap();
        let old_txid = Txid::from(old_transaction.compute_txid().to_byte_array());
        let new_txid = minter.await_submitted_doge_transaction(self.retrieve_doge_id.block_index);
        let _replaced_tx_event = minter
            .assert_that_events()
            .extract_exactly_one(
                |event| matches!(event,
                    CkDogeMinterEventType::ReplacedDogeTransaction {old_txid: event_old_txid, new_txid: event_new_txid, ..}
                    if event_old_txid == &old_txid && event_new_txid == &new_txid),
            );
        let new_tx = mempool_after
            .remove(&new_txid)
            .expect("BUG: did not find resubmit transaction");
        assert_replacement_transaction(old_transaction, &new_tx);
        self.sent_transactions.push(new_tx);
        self
    }
}

fn assert_replacement_transaction(old: &bitcoin::Transaction, new: &bitcoin::Transaction) {
    // In koinu/byte
    const MIN_RELAY_FEE_PER_BYTE: u64 = 10;

    fn input_utxos(tx: &bitcoin::Transaction) -> Vec<bitcoin::OutPoint> {
        tx.input.iter().map(|txin| txin.previous_output).collect()
    }

    fn output_script_pubkey(tx: &bitcoin::Transaction) -> BTreeSet<&bitcoin::script::ScriptBuf> {
        tx.output
            .iter()
            .map(|output| &output.script_pubkey)
            .collect()
    }

    assert_ne!(old.compute_txid(), new.compute_txid());
    assert_eq!(input_utxos(old), input_utxos(new));
    assert_eq!(output_script_pubkey(old), output_script_pubkey(new));

    let new_out_value = new.output.iter().map(|out| out.value.to_sat()).sum::<u64>();
    let prev_out_value = old.output.iter().map(|out| out.value.to_sat()).sum::<u64>();
    let relay_cost = new.total_size() as u64 * MIN_RELAY_FEE_PER_BYTE;

    assert!(
        new_out_value + relay_cost <= prev_out_value,
        "the transaction fees should have increased by at least {relay_cost}. prev out value: {prev_out_value}, new out value: {new_out_value}"
    );
}

pub fn assert_uses_utxos<I: IntoIterator<Item = Utxo>>(tx: &bitcoin::Transaction, utxos: I) {
    let tx_outpoints: BTreeSet<_> = tx.input.iter().map(|input| input.previous_output).collect();
    let expected_outpoints: BTreeSet<_> = utxos
        .into_iter()
        .map(|utxo| into_outpoint(utxo.outpoint))
        .collect();
    assert_eq!(tx_outpoints, expected_outpoints);
}
