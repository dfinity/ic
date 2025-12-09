use candid::Deserialize;
use ic_ckbtc_minter::state::CkBtcMinterState;
use ic_ckbtc_minter::state::eventlog::{
    CkBtcEventLogger, CkBtcMinterEvent, EventLogger, EventType, ReplayLogError,
};
use ic_ckbtc_minter::state::invariants::CheckInvariants;
use serde::Serialize;
use std::borrow::Cow;

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize, candid::CandidType)]
pub struct CkDogeMinterEvent {
    /// The canister time at which the minter generated this event.
    pub timestamp: Option<u64>,
    /// The event type.
    pub payload: CkDogeMinterEventType,
}

pub struct CkDogeEventLogger;

impl EventLogger for CkDogeEventLogger {
    type Event = CkDogeMinterEvent;

    fn record_event(&self, event: Self::Event) {
        ic_ckbtc_minter::storage::append_event(&event);
    }

    fn replay<I: CheckInvariants>(
        &self,
        mut events: impl Iterator<Item = Self::Event>,
    ) -> Result<CkBtcMinterState, ReplayLogError> {
        let state = match events.next() {
            Some(event) => match event.payload {
                CkDogeMinterEventType::Init(args) => {
                    CkBtcMinterState::from(ic_ckbtc_minter::lifecycle::init::InitArgs::from(args))
                }
                payload => {
                    return Err(ReplayLogError::InconsistentLog(format!(
                        "The first event is not Init: {payload:?}"
                    )));
                }
            },
            None => return Err(ReplayLogError::EmptyLog),
        };
        for event in events {
            match event.payload {
                CkDogeMinterEventType::Init(args) => {
                    return Err(ReplayLogError::InconsistentLog(format!(
                        "state re-initialization is not allowed: {args:?}"
                    )));
                }
                _ => todo!(),
            }
        }
        Ok(state)
    }

    fn events_iter(&self) -> impl Iterator<Item = Self::Event> {
        ic_ckbtc_minter::storage::EventIterator::new()
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize, candid::CandidType)]
pub enum CkDogeMinterEventType {
    /// Indicates the minter initialization with the specified arguments.
    /// Must be the first event in the event log.
    #[serde(rename = "init")]
    Init(crate::lifecycle::init::InitArgs),

    /// Indicates that the minter received new UTXOs to the specified account.
    /// The minter emits this event _after_ it minted ckBTC.
    #[serde(rename = "received_utxos")]
    ReceivedUtxos {
        /// The index of the transaction that mints ckBTC corresponding to the
        /// received UTXOs.
        #[serde(rename = "mint_txid")]
        #[serde(skip_serializing_if = "Option::is_none")]
        mint_txid: Option<u64>,
        /// That minter's account owning the UTXOs.
        #[serde(rename = "to_account")]
        to_account: Account,
        #[serde(rename = "utxos")]
        utxos: Vec<Utxo>,
    },

    /// Indicates that the minter accepted a new retrieve_btc request.
    /// The minter emits this event _after_ it burnt ckBTC.
    #[serde(rename = "accepted_retrieve_btc_request")]
    AcceptedRetrieveBtcRequest(RetrieveBtcRequest),

    /// Indicates that the minter removed a previous retrieve_btc request
    /// because the retrieval amount was not enough to cover the transaction
    /// fees.
    #[serde(rename = "removed_retrieve_btc_request")]
    RemovedRetrieveBtcRequest {
        #[serde(rename = "block_index")]
        block_index: u64,
    },

    /// Indicates that the minter sent out a new transaction to the Bitcoin
    /// network.
    #[serde(rename = "sent_transaction")]
    SentBtcTransaction {
        /// Block indices of retrieve_btc requests that caused the transaction.
        #[serde(rename = "requests")]
        request_block_indices: Vec<u64>,
        /// The Txid of the Bitcoin transaction.
        #[serde(rename = "txid")]
        txid: Txid,
        /// UTXOs used for the transaction.
        #[serde(rename = "utxos")]
        utxos: Vec<Utxo>,
        /// The output with the minter's change, if any.
        #[serde(rename = "change_output")]
        #[serde(skip_serializing_if = "Option::is_none")]
        change_output: Option<ChangeOutput>,
        /// The IC time at which the minter submitted the transaction.
        #[serde(rename = "submitted_at")]
        submitted_at: u64,
        /// The fee per vbyte (in millisatoshi) that we used for the transaction.
        #[serde(rename = "fee")]
        #[serde(skip_serializing_if = "Option::is_none")]
        fee_per_vbyte: Option<u64>,
        /// The total fee for this transaction
        #[serde(rename = "withdrawal_fee")]
        #[serde(skip_serializing_if = "Option::is_none")]
        withdrawal_fee: Option<WithdrawalFee>,
    },

    /// Indicates that the minter sent out a new transaction to replace an older transaction
    /// because the old transaction did not appear on the Bitcoin blockchain.
    #[serde(rename = "replaced_transaction")]
    ReplacedBtcTransaction {
        /// The Txid of the old Bitcoin transaction.
        #[serde(rename = "old_txid")]
        old_txid: Txid,
        /// The Txid of the new Bitcoin transaction.
        #[serde(rename = "new_txid")]
        new_txid: Txid,
        /// The output with the minter's change.
        #[serde(rename = "change_output")]
        change_output: ChangeOutput,
        /// The IC time at which the minter submitted the transaction.
        #[serde(rename = "submitted_at")]
        submitted_at: u64,
        /// The fee per vbyte (in millisatoshi) that we used for the transaction.
        #[serde(rename = "fee")]
        fee_per_vbyte: u64,
        /// The total fee for this transaction
        #[serde(rename = "withdrawal_fee")]
        #[serde(skip_serializing_if = "Option::is_none")]
        withdrawal_fee: Option<WithdrawalFee>,
        /// The reason why it was replaced
        reason: Option<ReplacedReason>,
        /// The UTXOs of the new transaction. If not available, we'll use the same
        /// UTXOs from the old transaction it replaces.
        #[serde(rename = "new_utxos")]
        #[serde(skip_serializing_if = "Option::is_none")]
        new_utxos: Option<Vec<Utxo>>,
    },

    /// Indicates that the minter received enough confirmations for a bitcoin
    /// transaction.
    #[serde(rename = "confirmed_transaction")]
    ConfirmedBtcTransaction {
        #[serde(rename = "txid")]
        txid: Txid,
    },

    #[serde(rename = "checked_utxo_v2")]
    CheckedUtxoV2 { utxo: Utxo, account: Account },

    /// Indicates a reimbursement.
    #[serde(rename = "schedule_withdrawal_reimbursement")]
    ScheduleWithdrawalReimbursement {
        /// The beneficiary.
        account: Account,
        /// The token amount to reimburse.
        amount: u64,
        /// The reason of the reimbursement.
        reason: WithdrawalReimbursementReason,
        /// The corresponding burn block on the ledger.
        burn_block_index: u64,
    },

    /// The minter unexpectedly panicked while processing a reimbursement.
    /// The reimbursement is quarantined to prevent any double minting and
    /// will not be processed without further manual intervention.
    #[serde(rename = "quarantined_withdrawal_reimbursement")]
    QuarantinedWithdrawalReimbursement {
        /// The burn block on the ledger for that withdrawal that should have been reimbursed
        burn_block_index: u64,
    },

    /// Indicates that a reimbursement has been executed.
    #[serde(rename = "reimbursed_withdrawal")]
    ReimbursedWithdrawal {
        /// The burn block on the ledger.
        burn_block_index: u64,
        /// The mint block on the ledger.
        mint_block_index: u64,
    },
}

impl ic_ckbtc_minter::storage::StorableEvent for CkDogeMinterEvent {
    fn to_bytes<'a>(&'a self) -> Cow<'a, [u8]> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(self, &mut buf).expect("failed to encode a minter event");
        Cow::Owned(buf)
    }
    fn from_bytes<'a>(bytes: Cow<'a, [u8]>) -> Self {
        ciborium::de::from_reader(bytes.as_ref()).expect("failed to decode a minter event")
    }
}

impl From<CkBtcMinterEvent> for CkDogeMinterEvent {
    fn from(CkBtcMinterEvent { timestamp, payload }: CkBtcMinterEvent) -> Self {
        CkDogeMinterEvent { timestamp, payload }
    }
}
