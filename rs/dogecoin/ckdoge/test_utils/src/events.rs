use ic_ckdoge_minter::EventType;
use std::collections::BTreeMap;
use std::fmt;

pub struct MinterEventAssert<E> {
    pub(crate) events: Vec<E>,
}

impl MinterEventAssert<EventType> {
    pub fn ignoring_timestamp(self) -> MinterEventAssert<IgnoreTimestamp> {
        MinterEventAssert {
            events: self.events.into_iter().map(IgnoreTimestamp::from).collect(),
        }
    }
}

impl<E> MinterEventAssert<E> {
    pub fn contains_only_once_in_order(self, expected_events: &[EventType]) -> Self
    where
        EventType: Into<E>,
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
}

/// Ignore fields related to timestamps.
#[derive(Debug)]
pub struct IgnoreTimestamp(EventType);

impl From<EventType> for IgnoreTimestamp {
    fn from(value: EventType) -> Self {
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
                EventType::SentBtcTransaction {
                    request_block_indices,
                    txid,
                    utxos,
                    change_output,
                    submitted_at: _,
                    fee_per_vbyte,
                    withdrawal_fee,
                },
                EventType::SentBtcTransaction {
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
                EventType::ReplacedBtcTransaction {
                    old_txid,
                    new_txid,
                    change_output,
                    submitted_at: _,
                    fee_per_vbyte,
                    withdrawal_fee,
                    reason,
                    new_utxos,
                },
                EventType::ReplacedBtcTransaction {
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
            (_, _) => false,
        }
    }
}
