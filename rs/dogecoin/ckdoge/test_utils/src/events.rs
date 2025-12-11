use crate::only_one;
use ic_ckdoge_minter::event::{CkDogeMinterEventType, RetrieveDogeRequest};
use std::collections::BTreeMap;
use std::fmt;

pub struct MinterEventAssert<E> {
    pub(crate) events: Vec<E>,
}

impl MinterEventAssert<CkDogeMinterEventType> {
    pub fn ignoring_timestamp(self) -> MinterEventAssert<IgnoreTimestamp> {
        MinterEventAssert {
            events: self.events.into_iter().map(IgnoreTimestamp::from).collect(),
        }
    }
}

impl<E> MinterEventAssert<E> {
    pub fn contains_only_once_in_order(self, expected_events: &[CkDogeMinterEventType]) -> Self
    where
        CkDogeMinterEventType: Into<E>,
        E: PartialEq + fmt::Debug,
    {
        let mut found_event_indexes = BTreeMap::new();
        for (index_expected_event, expected_event) in expected_events.iter().enumerate() {
            for (index_audit_event, audit_event) in self.events.iter().enumerate() {
                if audit_event == &expected_event.clone().into() {
                    assert_eq!(
                        found_event_indexes.insert(index_expected_event, index_audit_event),
                        None,
                        "Event {expected_event:?} occurs multiple times"
                    );
                }
            }
            assert!(
                found_event_indexes.contains_key(&index_expected_event),
                "Missing event {:?}. All events: {:?}",
                expected_event,
                self.events
            )
        }
        let audit_event_indexes = found_event_indexes.into_values().collect::<Vec<_>>();
        let sorted_audit_event_indexes = {
            let mut indexes = audit_event_indexes.clone();
            indexes.sort_unstable();
            indexes
        };
        assert_eq!(
            audit_event_indexes, sorted_audit_event_indexes,
            "Events were found in unexpected order. All events: {:?}",
            self.events
        );
        self
    }

    pub fn none_satisfy<P>(self, predicate: P) -> Self
    where
        P: Fn(&E) -> bool,
        E: fmt::Debug,
    {
        let unexpected = self.events.iter().find(|event| predicate(event));
        if let Some(unexpected) = unexpected {
            panic!("Unexpected event: {:?}", unexpected);
        }
        self
    }

    pub fn extract_exactly_one<P>(self, predicate: P) -> E
    where
        P: Fn(&E) -> bool,
        E: fmt::Debug,
    {
        only_one(self.events.into_iter().filter(|event| predicate(event)))
    }
}

/// Ignore fields related to timestamps.
#[derive(Debug)]
pub struct IgnoreTimestamp(CkDogeMinterEventType);

impl From<CkDogeMinterEventType> for IgnoreTimestamp {
    fn from(value: CkDogeMinterEventType) -> Self {
        Self(value)
    }
}

impl PartialEq for IgnoreTimestamp {
    fn eq(&self, rhs: &IgnoreTimestamp) -> bool {
        if self.0 == rhs.0 {
            return true;
        }
        match (&self.0, &rhs.0) {
            (
                CkDogeMinterEventType::SentDogeTransaction {
                    request_block_indices,
                    txid,
                    utxos,
                    change_output,
                    submitted_at: _,
                    fee_per_vbyte,
                    withdrawal_fee,
                },
                CkDogeMinterEventType::SentDogeTransaction {
                    request_block_indices: rhs_request_block_indices,
                    txid: rhs_txid,
                    utxos: rhs_utxos,
                    change_output: rhs_change_output,
                    submitted_at: _,
                    fee_per_vbyte: rhs_fee_per_vbyte,
                    withdrawal_fee: rhs_withdrawal_fee,
                },
            ) => {
                request_block_indices == rhs_request_block_indices
                    && txid == rhs_txid
                    && utxos == rhs_utxos
                    && change_output == rhs_change_output
                    && fee_per_vbyte == rhs_fee_per_vbyte
                    && withdrawal_fee == rhs_withdrawal_fee
            }

            (
                CkDogeMinterEventType::ReplacedDogeTransaction {
                    old_txid,
                    new_txid,
                    change_output,
                    submitted_at: _,
                    fee_per_vbyte,
                    withdrawal_fee,
                    reason,
                    new_utxos,
                },
                CkDogeMinterEventType::ReplacedDogeTransaction {
                    old_txid: rhs_old_txid,
                    new_txid: rhs_new_txid,
                    change_output: rhs_change_output,
                    submitted_at: _,
                    fee_per_vbyte: rhs_fee_per_vbyte,
                    withdrawal_fee: rhs_withdrawal_fee,
                    reason: rhs_reason,
                    new_utxos: rhs_new_utxos,
                },
            ) => {
                old_txid == rhs_old_txid
                    && new_txid == rhs_new_txid
                    && change_output == rhs_change_output
                    && fee_per_vbyte == rhs_fee_per_vbyte
                    && withdrawal_fee == rhs_withdrawal_fee
                    && reason == rhs_reason
                    && new_utxos == rhs_new_utxos
            }
            (
                CkDogeMinterEventType::AcceptedRetrieveDogeRequest(RetrieveDogeRequest {
                    amount,
                    address,
                    block_index,
                    received_at: _,
                    reimbursement_account,
                }),
                CkDogeMinterEventType::AcceptedRetrieveDogeRequest(RetrieveDogeRequest {
                    amount: rhs_amount,
                    address: rhs_address,
                    block_index: rhs_block_index,
                    received_at: _,
                    reimbursement_account: rhs_reimbursement_account,
                }),
            ) => {
                amount == rhs_amount
                    && address == rhs_address
                    && block_index == rhs_block_index
                    && reimbursement_account == rhs_reimbursement_account
            }
            (_, _) => false,
        }
    }
}
