#[cfg(test)]
mod tests;

use crate::address::DogecoinAddress;
use candid::Deserialize;
use ic_ckbtc_minter::address::BitcoinAddress;
use ic_ckbtc_minter::queries::WithdrawalFee;
use ic_ckbtc_minter::state::eventlog::{
    CkBtcMinterEvent, EventLogger, EventType as CkBtcMinterEventType, ReplacedReason,
    ReplayLogError,
};
use ic_ckbtc_minter::state::invariants::CheckInvariants;
use ic_ckbtc_minter::state::{ChangeOutput, RetrieveBtcRequest};
use ic_ckbtc_minter::state::{CkBtcMinterState, SuspendedReason};
use ic_ckbtc_minter::{Txid, Utxo};
use icrc_ledger_types::icrc1::account::Account;
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
        events: impl Iterator<Item = Self::Event>,
    ) -> Result<CkBtcMinterState, ReplayLogError> {
        ic_ckbtc_minter::state::eventlog::CkBtcEventLogger
            .replay::<I>(events.map(CkBtcMinterEvent::from))
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

    /// Indicates the minter upgrade with specified arguments.
    #[serde(rename = "upgrade")]
    Upgrade(crate::lifecycle::upgrade::UpgradeArgs),

    /// Indicates that the minter received new UTXOs to the specified account.
    /// The minter emits this event _after_ it minted ckDOGE.
    #[serde(rename = "received_utxos")]
    ReceivedUtxos {
        /// The index of the transaction that mints ckDOGE corresponding to the
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

    #[serde(rename = "checked_utxo")]
    CheckedUtxo { utxo: Utxo, account: Account },

    /// Indicates that the minter accepted a new retrieve_doge request.
    /// The minter emits this event _after_ it burnt ckDOGE.
    #[serde(rename = "accepted_retrieve_doge_request")]
    AcceptedRetrieveDogeRequest(RetrieveDogeRequest),

    /// Indicates that the minter removed a previous retrieve_doge request
    /// because the retrieval amount was not enough to cover the transaction
    /// fees.
    #[serde(rename = "removed_retrieve_doge_request")]
    RemovedRetrieveDogeRequest {
        #[serde(rename = "block_index")]
        block_index: u64,
    },

    /// Indicates that the minter sent out a new transaction to the Dogecoin
    /// network.
    #[serde(rename = "sent_transaction")]
    SentDogeTransaction {
        /// Block indices of retrieve_doge requests that caused the transaction.
        #[serde(rename = "requests")]
        request_block_indices: Vec<u64>,
        /// The Txid of the Dogecoin transaction.
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
        /// The signed transaction bytes. Only for ConsolidateUtxosRequest.
        #[serde(rename = "signed_tx")]
        #[serde(skip_serializing_if = "Option::is_none")]
        signed_tx: Option<Vec<u8>>,
    },

    /// Indicates that the minter sent out a new transaction to replace an older transaction
    /// because the old transaction did not appear on the Dogecoin blockchain.
    #[serde(rename = "replaced_transaction")]
    ReplacedDogeTransaction {
        /// The Txid of the old Dogecoin transaction.
        #[serde(rename = "old_txid")]
        old_txid: Txid,
        /// The Txid of the new Dogecoin transaction.
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

    /// Indicates that the minter received enough confirmations for a dogecoin
    /// transaction.
    #[serde(rename = "confirmed_transaction")]
    ConfirmedDogeTransaction {
        #[serde(rename = "txid")]
        txid: Txid,
    },

    /// Indicates an UTXO is checked to be clean and pre-mint
    #[serde(rename = "checked_utxo_mint_unknown")]
    CheckedUtxoMintUnknown { account: Account, utxo: Utxo },

    /// Indicates a reimbursement.
    #[serde(rename = "schedule_withdrawal_reimbursement")]
    ScheduleWithdrawalReimbursement {
        /// The beneficiary.
        account: Account,
        /// The token amount to reimburse.
        amount: u64,
        /// The reason of the reimbursement.
        reason: ic_ckbtc_minter::reimbursement::WithdrawalReimbursementReason,
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
    /// Indicates that the minter consolidates UTXOs with transaction
    /// fee corresponding to burning ckbtc from the fee subaccount
    /// at the given ledger index.
    #[serde(rename = "created_consolidate_utxos_request")]
    CreatedConsolidateUtxosRequest(ConsolidateUtxosRequest),
}

/// A pending retrieve DOGE request
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize, candid::CandidType)]
pub struct RetrieveDogeRequest {
    /// The amount to convert to DOGE.
    /// The minter withdraws DOGE transfer fees from this amount.
    pub amount: u64,
    /// The destination DOGE address.
    pub address: DogecoinAddress,
    /// The BURN transaction index on the ledger.
    /// Serves as a unique request identifier.
    pub block_index: u64,
    /// The time at which the minter accepted the request.
    pub received_at: u64,
    /// The reimbursement_account of the retrieve_doge transaction.
    #[serde(rename = "reimbursement_account")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reimbursement_account: Option<Account>,
}

/// A pending utxo consolidation request
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize, candid::CandidType)]
pub struct ConsolidateUtxosRequest {
    /// The amount to consolidate.
    pub amount: u64,
    /// The destination Dogecoin address. It should always be the minter's address.
    pub address: DogecoinAddress,
    /// The BURN transaction index on the ledger.
    /// Serves as a unique request identifier.
    pub block_index: u64,
    /// The time at which the minter accepted the request.
    pub received_at: u64,
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
        CkDogeMinterEvent {
            timestamp,
            payload: payload.try_into().expect("BUG: when converting event type"),
        }
    }
}

impl From<CkDogeMinterEvent> for CkBtcMinterEvent {
    fn from(CkDogeMinterEvent { timestamp, payload }: CkDogeMinterEvent) -> Self {
        CkBtcMinterEvent {
            timestamp,
            payload: CkBtcMinterEventType::from(payload),
        }
    }
}

impl TryFrom<CkBtcMinterEventType> for CkDogeMinterEventType {
    type Error = String;
    fn try_from(event: CkBtcMinterEventType) -> Result<Self, Self::Error> {
        match event {
            CkBtcMinterEventType::Init(args) => {
                match (args.check_fee, args.btc_checker_principal) {
                    (Some(0), None) => Ok(()),
                    _ => Err(format!("BUG: unexpected checker for ckDOGE {args:?}")),
                }?;
                #[allow(deprecated)]
                match (args.kyt_fee, args.kyt_principal) {
                    (None, None) => Ok(()),
                    _ => Err(format!("BUG: unexpected KYT for ckDOGE {args:?}")),
                }?;
                Ok(CkDogeMinterEventType::Init(
                    crate::lifecycle::init::InitArgs::from(args),
                ))
            }
            CkBtcMinterEventType::Upgrade(args) => {
                #[allow(deprecated)]
                match (
                    args.check_fee,
                    args.kyt_fee,
                    args.btc_checker_principal,
                    args.kyt_principal,
                ) {
                    (None, None, None, None) => Ok(()),
                    _ => Err(format!(
                        "BUG: unexpected checker or KYT for ckDOGE {args:?}"
                    )),
                }?;
                Ok(CkDogeMinterEventType::Upgrade(
                    crate::lifecycle::upgrade::UpgradeArgs::from(args),
                ))
            }
            CkBtcMinterEventType::ReceivedUtxos {
                mint_txid,
                to_account,
                utxos,
            } => Ok(CkDogeMinterEventType::ReceivedUtxos {
                mint_txid,
                to_account,
                utxos,
            }),
            CkBtcMinterEventType::AcceptedRetrieveBtcRequest(request) => {
                match &request.kyt_provider {
                    None => {
                        let RetrieveBtcRequest {
                            amount,
                            address,
                            block_index,
                            received_at,
                            reimbursement_account,
                            kyt_provider: _,
                        } = request;
                        Ok(CkDogeMinterEventType::AcceptedRetrieveDogeRequest(
                            RetrieveDogeRequest {
                                amount,
                                address: bitcoin_to_dogecoin(address)?,
                                block_index,
                                received_at,
                                reimbursement_account,
                            },
                        ))
                    }
                    Some(provider) => Err(format!(
                        "BUG: Unexpected KYT provider {provider} for {request:?}"
                    )),
                }
            }
            CkBtcMinterEventType::RemovedRetrieveBtcRequest { block_index } => {
                Ok(CkDogeMinterEventType::RemovedRetrieveDogeRequest { block_index })
            }
            CkBtcMinterEventType::SentBtcTransaction {
                request_block_indices,
                txid,
                utxos,
                change_output,
                submitted_at,
                fee_per_vbyte,
                withdrawal_fee,
                signed_tx,
            } => Ok(CkDogeMinterEventType::SentDogeTransaction {
                request_block_indices,
                txid,
                utxos,
                change_output,
                submitted_at,
                fee_per_vbyte,
                withdrawal_fee,
                signed_tx,
            }),
            CkBtcMinterEventType::ReplacedBtcTransaction {
                old_txid,
                new_txid,
                change_output,
                submitted_at,
                fee_per_vbyte,
                withdrawal_fee,
                reason,
                new_utxos,
            } => Ok(CkDogeMinterEventType::ReplacedDogeTransaction {
                old_txid,
                new_txid,
                change_output,
                submitted_at,
                fee_per_vbyte,
                withdrawal_fee,
                reason,
                new_utxos,
            }),
            CkBtcMinterEventType::ConfirmedBtcTransaction { txid } => {
                Ok(CkDogeMinterEventType::ConfirmedDogeTransaction { txid })
            }
            CkBtcMinterEventType::CheckedUtxoV2 { utxo, account } => {
                Ok(CkDogeMinterEventType::CheckedUtxo { utxo, account })
            }

            CkBtcMinterEventType::CheckedUtxoMintUnknown { utxo, account } => {
                Ok(CkDogeMinterEventType::CheckedUtxoMintUnknown { utxo, account })
            }
            CkBtcMinterEventType::ScheduleWithdrawalReimbursement {
                account,
                amount,
                reason,
                burn_block_index,
            } => Ok(CkDogeMinterEventType::ScheduleWithdrawalReimbursement {
                account,
                amount,
                reason,
                burn_block_index,
            }),
            CkBtcMinterEventType::QuarantinedWithdrawalReimbursement { burn_block_index } => {
                Ok(CkDogeMinterEventType::QuarantinedWithdrawalReimbursement { burn_block_index })
            }
            CkBtcMinterEventType::ReimbursedWithdrawal {
                burn_block_index,
                mint_block_index,
            } => Ok(CkDogeMinterEventType::ReimbursedWithdrawal {
                burn_block_index,
                mint_block_index,
            }),

            CkBtcMinterEventType::SuspendedUtxo { reason, .. } => {
                let explanation = match reason {
                    SuspendedReason::ValueTooSmall => {
                        // TODO DEFI-2572: handle event when setting a minimum deposit amount.
                        "Unexpected ignored UTXO event since `check_fee` is null for ckDOGE"
                    }
                    SuspendedReason::Quarantined => {
                        "Unexpected quarantined UTXO event since ckDOGE does not check whether UTXOs are tainted"
                    }
                };
                Err(format!("{explanation}: {event:?}"))
            }
            CkBtcMinterEventType::CreatedConsolidateUtxosRequest(
                ic_ckbtc_minter::state::ConsolidateUtxosRequest {
                    amount,
                    address,
                    block_index,
                    received_at,
                },
            ) => Ok(CkDogeMinterEventType::CreatedConsolidateUtxosRequest(
                ConsolidateUtxosRequest {
                    amount,
                    address: bitcoin_to_dogecoin(address)?,
                    block_index,
                    received_at,
                },
            )),
            // Ignore deprecated events for Dogecoin
            #[allow(deprecated)]
            CkBtcMinterEventType::DistributedKytFee { .. }
            | CkBtcMinterEventType::CheckedUtxo { .. }
            | CkBtcMinterEventType::IgnoredUtxo { .. }
            | CkBtcMinterEventType::ReimbursedFailedDeposit { .. }
            | CkBtcMinterEventType::ScheduleDepositReimbursement { .. }
            | CkBtcMinterEventType::RetrieveBtcKytFailed { .. } => {
                Err(format!("unexpected deprecated event: {event:?}"))
            }
        }
    }
}

impl From<CkDogeMinterEventType> for CkBtcMinterEventType {
    fn from(event: CkDogeMinterEventType) -> Self {
        match event {
            CkDogeMinterEventType::Init(args) => CkBtcMinterEventType::Init(args.into()),
            CkDogeMinterEventType::Upgrade(args) => CkBtcMinterEventType::Upgrade(args.into()),
            CkDogeMinterEventType::ReceivedUtxos {
                mint_txid,
                to_account,
                utxos,
            } => CkBtcMinterEventType::ReceivedUtxos {
                mint_txid,
                to_account,
                utxos,
            },
            CkDogeMinterEventType::CheckedUtxo { utxo, account } => {
                CkBtcMinterEventType::CheckedUtxoV2 { utxo, account }
            }
            CkDogeMinterEventType::AcceptedRetrieveDogeRequest(RetrieveDogeRequest {
                amount,
                address,
                block_index,
                received_at,
                reimbursement_account,
            }) => CkBtcMinterEventType::AcceptedRetrieveBtcRequest(RetrieveBtcRequest {
                amount,
                address: dogecoin_to_bitcoin(address),
                block_index,
                received_at,
                kyt_provider: None,
                reimbursement_account,
            }),
            CkDogeMinterEventType::RemovedRetrieveDogeRequest { block_index } => {
                CkBtcMinterEventType::RemovedRetrieveBtcRequest { block_index }
            }
            CkDogeMinterEventType::SentDogeTransaction {
                request_block_indices,
                txid,
                utxos,
                change_output,
                submitted_at,
                fee_per_vbyte,
                withdrawal_fee,
                signed_tx,
            } => CkBtcMinterEventType::SentBtcTransaction {
                request_block_indices,
                txid,
                utxos,
                change_output,
                submitted_at,
                fee_per_vbyte,
                withdrawal_fee,
                signed_tx,
            },
            CkDogeMinterEventType::ReplacedDogeTransaction {
                old_txid,
                new_txid,
                change_output,
                submitted_at,
                fee_per_vbyte,
                withdrawal_fee,
                reason,
                new_utxos,
            } => CkBtcMinterEventType::ReplacedBtcTransaction {
                old_txid,
                new_txid,
                change_output,
                submitted_at,
                fee_per_vbyte,
                withdrawal_fee,
                reason,
                new_utxos,
            },
            CkDogeMinterEventType::ConfirmedDogeTransaction { txid } => {
                CkBtcMinterEventType::ConfirmedBtcTransaction { txid }
            }
            CkDogeMinterEventType::CheckedUtxoMintUnknown { account, utxo } => {
                CkBtcMinterEventType::CheckedUtxoMintUnknown { account, utxo }
            }
            CkDogeMinterEventType::ScheduleWithdrawalReimbursement {
                account,
                amount,
                reason,
                burn_block_index,
            } => CkBtcMinterEventType::ScheduleWithdrawalReimbursement {
                account,
                amount,
                reason,
                burn_block_index,
            },
            CkDogeMinterEventType::QuarantinedWithdrawalReimbursement { burn_block_index } => {
                CkBtcMinterEventType::QuarantinedWithdrawalReimbursement { burn_block_index }
            }
            CkDogeMinterEventType::ReimbursedWithdrawal {
                burn_block_index,
                mint_block_index,
            } => CkBtcMinterEventType::ReimbursedWithdrawal {
                burn_block_index,
                mint_block_index,
            },
            CkDogeMinterEventType::CreatedConsolidateUtxosRequest(ConsolidateUtxosRequest {
                amount,
                address,
                block_index,
                received_at,
            }) => CkBtcMinterEventType::CreatedConsolidateUtxosRequest(
                ic_ckbtc_minter::state::ConsolidateUtxosRequest {
                    amount,
                    address: dogecoin_to_bitcoin(address),
                    block_index,
                    received_at,
                },
            ),
        }
    }
}

fn bitcoin_to_dogecoin(address: BitcoinAddress) -> Result<DogecoinAddress, String> {
    match address {
        BitcoinAddress::P2wpkhV0(_) | BitcoinAddress::P2wshV0(_) | BitcoinAddress::P2trV1(_) => {
            Err(format!("BUG: unexpected address type {address:?}"))
        }
        BitcoinAddress::P2pkh(bytes) => Ok(DogecoinAddress::P2pkh(bytes)),
        BitcoinAddress::P2sh(bytes) => Ok(DogecoinAddress::P2sh(bytes)),
    }
}

fn dogecoin_to_bitcoin(address: DogecoinAddress) -> BitcoinAddress {
    match address {
        DogecoinAddress::P2pkh(bytes) => BitcoinAddress::P2pkh(bytes),
        DogecoinAddress::P2sh(bytes) => BitcoinAddress::P2sh(bytes),
    }
}
