use crate::eth_rpc::Hash;
use crate::numeric::LedgerBurnIndex;
use crate::state::receipt_fetch::{
    INITIAL_RECEIPT_FETCH_WINDOW, MAX_RECEIPT_FETCH_WINDOW, MIN_RECEIPT_FETCH_WINDOW,
    ROUNDS_PER_ATTEMPT_WHILE_SKIPPING, ROUNDS_WITHOUT_READS_BEFORE_SKIPPING, ReceiptFetchCounters,
    ReceiptFetchWindow, RoundOutcome,
};
use std::collections::BTreeMap;

mod adaptation {
    use super::*;

    #[test]
    fn should_double_the_window_when_no_lookup_failed() {
        let mut window = window_of(1);

        for expected in [2, 4, 8, 16] {
            window.record_round(round(1, 0, 0));
            assert_eq!(window.window(), expected);
        }
    }

    #[test]
    fn should_not_grow_past_the_ceiling() {
        let mut window = window_of(16);

        window.record_round(round(3, 0, 0));
        assert_eq!(window.window(), MAX_RECEIPT_FETCH_WINDOW);

        window.record_round(round(3, 0, 0));
        assert_eq!(window.window(), MAX_RECEIPT_FETCH_WINDOW);
    }

    #[test]
    fn should_halve_the_window_when_some_lookups_failed() {
        let mut window = window_of(INITIAL_RECEIPT_FETCH_WINDOW);

        for expected in [5, 2, 1, 1] {
            window.record_round(round(1, 0, 1));
            assert_eq!(window.window(), expected);
        }
    }

    #[test]
    fn should_drop_to_the_floor_when_every_lookup_failed() {
        let mut window = window_of(MAX_RECEIPT_FETCH_WINDOW);

        window.record_round(round(0, 0, 7));

        assert_eq!(window.window(), MIN_RECEIPT_FETCH_WINDOW);
    }

    #[test]
    fn should_drop_to_the_floor_on_an_abandoned_round() {
        let mut window = window_of(MAX_RECEIPT_FETCH_WINDOW);
        let mut outcome = round(2, 0, 0);
        outcome.abandon();

        window.record_round(outcome);

        assert_eq!(window.window(), MIN_RECEIPT_FETCH_WINDOW);
    }

    #[test]
    fn should_count_an_abandoned_round() {
        let mut window = window_of(INITIAL_RECEIPT_FETCH_WINDOW);
        let mut outcome = round(2, 0, 0);
        outcome.abandon();

        window.record_round(outcome);

        assert_eq!(window.counters().abandoned_rounds, 1);
    }

    #[test]
    fn should_not_shrink_on_transactions_that_were_not_mined() {
        let mut window = window_of(INITIAL_RECEIPT_FETCH_WINDOW);

        window.record_round(round(1, 9, 0));

        assert_eq!(window.window(), MAX_RECEIPT_FETCH_WINDOW);
    }

    #[test]
    fn should_leave_the_window_alone_on_a_round_with_nothing_to_fetch() {
        let mut window = window_of(INITIAL_RECEIPT_FETCH_WINDOW);

        window.record_round(RoundOutcome::default());
        window.record_round_without_reads();

        assert_eq!(window.window(), INITIAL_RECEIPT_FETCH_WINDOW);
        assert_eq!(window.rounds_without_reads(), 1);
    }

    #[test]
    fn should_accumulate_what_the_lookups_returned() {
        let mut window = window_of(INITIAL_RECEIPT_FETCH_WINDOW);
        let mut outcome = round(1, 2, 3);
        outcome.record_stalled_id();

        window.record_round(outcome);
        window.record_round(outcome);

        assert_eq!(
            window.counters(),
            ReceiptFetchCounters {
                receipts: 2,
                not_mined: 4,
                failures: 6,
                stalled_ids: 2,
                abandoned_rounds: 0,
            }
        );
    }
}

mod selection {
    use super::*;

    #[test]
    fn should_select_nothing_when_nothing_is_pending() {
        let mut window = ReceiptFetchWindow::<LedgerBurnIndex>::default();

        assert_eq!(window.select_next_round(&BTreeMap::new()), BTreeMap::new());
        assert_eq!(window.cursor(), None);
    }

    #[test]
    fn should_select_every_transaction_of_the_ids_it_takes() {
        let pending = pending(&[(1, 3), (2, 1), (3, 2)]);
        let mut window = window_of(2);

        let selected = window.select_next_round(&pending);

        assert_eq!(ids_of(&selected), vec![id(1), id(2)]);
        assert_eq!(selected.len(), 4);
        assert_eq!(
            selected,
            pending
                .iter()
                .filter(|(_hash, id)| **id != LedgerBurnIndex::new(3))
                .map(|(hash, id)| (*hash, *id))
                .collect::<BTreeMap<_, _>>()
        );
    }

    #[test]
    fn should_not_split_the_transactions_of_one_id_across_rounds() {
        // A withdrawal resubmitted twice spans three hashes, of which at most one has a receipt.
        let pending = pending(&[(1, 3), (2, 3), (3, 3)]);
        let mut window = window_of(1);

        for expected in [id(1), id(2), id(3), id(1)] {
            let selected = window.select_next_round(&pending);
            assert_eq!(ids_of(&selected), vec![expected]);
            assert_eq!(selected.len(), 3);
        }
    }

    #[test]
    fn should_select_at_most_the_whole_pending_set() {
        let pending = pending(&[(1, 1), (2, 1)]);
        let mut window = window_of(MAX_RECEIPT_FETCH_WINDOW);

        let selected = window.select_next_round(&pending);

        assert_eq!(ids_of(&selected), vec![id(1), id(2)]);
        assert_eq!(window.cursor(), Some(id(2)));
    }
}

mod cursor {
    use super::*;

    #[test]
    fn should_walk_the_pending_set_round_after_round() {
        let pending = pending(&[(1, 1), (2, 1), (3, 1), (4, 1), (5, 1)]);
        let mut window = window_of(2);

        let rounds: Vec<_> = (0..4)
            .map(|_| {
                let selected = ids_of(&window.select_next_round(&pending));
                (selected, window.cursor())
            })
            .collect();

        assert_eq!(
            rounds,
            vec![
                (vec![id(1), id(2)], Some(id(2))),
                (vec![id(3), id(4)], Some(id(4))),
                // The third round takes the last id and wraps around to the first.
                (vec![id(1), id(5)], Some(id(1))),
                (vec![id(2), id(3)], Some(id(3))),
            ]
        );
    }

    #[test]
    fn should_resume_past_the_cursor_after_the_ids_around_it_finalized() {
        let mut window = window_of(2);

        window.select_next_round(&pending(&[(1, 1), (2, 1), (3, 1), (4, 1)]));
        assert_eq!(window.cursor(), Some(id(2)));

        let selected = window.select_next_round(&pending(&[(3, 1), (4, 1)]));

        assert_eq!(ids_of(&selected), vec![id(3), id(4)]);
        assert_eq!(window.cursor(), Some(id(4)));
    }

    #[test]
    fn should_wrap_around_when_the_cursor_is_past_everything_pending() {
        let mut window = window_of(2);

        window.select_next_round(&pending(&[(1, 1), (2, 1), (9, 1)]));
        assert_eq!(window.cursor(), Some(id(2)));

        let selected = window.select_next_round(&pending(&[(1, 1), (2, 1)]));

        assert_eq!(ids_of(&selected), vec![id(1), id(2)]);
    }

    #[test]
    fn should_leave_the_cursor_alone_on_a_round_that_selected_nothing() {
        let mut window = window_of(2);
        window.select_next_round(&pending(&[(1, 1), (2, 1)]));

        window.select_next_round(&BTreeMap::new());

        assert_eq!(window.cursor(), Some(id(2)));
    }
}

mod skipping {
    use super::*;

    #[test]
    fn should_attempt_every_round_below_the_threshold() {
        let mut window = ReceiptFetchWindow::<LedgerBurnIndex>::default();

        for _ in 0..ROUNDS_WITHOUT_READS_BEFORE_SKIPPING {
            assert!(!window.skip_round());
            window.record_round_without_reads();
        }
        assert!(!window.skip_round());
    }

    #[test]
    fn should_attempt_one_round_in_a_few_past_the_threshold() {
        let mut window = ReceiptFetchWindow::<LedgerBurnIndex>::default();
        for _ in 0..ROUNDS_WITHOUT_READS_BEFORE_SKIPPING {
            window.record_round_without_reads();
        }

        let mut attempted = 0;
        let rounds = 4 * ROUNDS_PER_ATTEMPT_WHILE_SKIPPING;
        for _ in 0..rounds {
            if !window.skip_round() {
                attempted += 1;
                window.record_round_without_reads();
            }
        }

        assert_eq!(attempted, rounds / ROUNDS_PER_ATTEMPT_WHILE_SKIPPING);
    }

    #[test]
    fn should_stop_skipping_once_a_round_read_the_chain() {
        let mut window = ReceiptFetchWindow::<LedgerBurnIndex>::default();
        for _ in 0..10 * ROUNDS_WITHOUT_READS_BEFORE_SKIPPING {
            window.record_round_without_reads();
        }
        assert!(window.skip_round());

        window.record_round(RoundOutcome::default());

        assert_eq!(window.rounds_without_reads(), 0);
        assert!(!window.skip_round());
    }
}

/// An outcome of a round whose lookups returned `receipts` receipts, `not_mined` transactions that
/// were not mined, and `failures` provider-level failures.
fn round(receipts: u32, not_mined: u32, failures: u32) -> RoundOutcome {
    let mut outcome = RoundOutcome::default();
    for _ in 0..receipts {
        outcome.record_receipt();
    }
    for _ in 0..not_mined {
        outcome.record_not_mined();
    }
    for _ in 0..failures {
        outcome.record_failure();
    }
    outcome
}

fn window_of(window: usize) -> ReceiptFetchWindow<LedgerBurnIndex> {
    ReceiptFetchWindow {
        window,
        ..Default::default()
    }
}

/// The pending transactions of the given ids, each with as many hashes as it was resubmitted.
fn pending(ids: &[(u8, u8)]) -> BTreeMap<Hash, LedgerBurnIndex> {
    ids.iter()
        .flat_map(|(id, transactions)| {
            (0..*transactions)
                .map(move |transaction| (hash(*id, transaction), LedgerBurnIndex::new(*id as u64)))
        })
        .collect()
}

fn ids_of(selected: &BTreeMap<Hash, LedgerBurnIndex>) -> Vec<LedgerBurnIndex> {
    let mut ids: Vec<_> = selected.values().copied().collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

fn id(id: u8) -> LedgerBurnIndex {
    LedgerBurnIndex::new(id as u64)
}

/// A hash whose bytes hide which id it belongs to, so that the hash order the pending set is keyed
/// by does not follow the id order the rounds walk.
fn hash(id: u8, transaction: u8) -> Hash {
    let mut bytes = [0_u8; 32];
    bytes[0] = id.wrapping_mul(37).wrapping_add(transaction);
    bytes[1] = id;
    bytes[2] = transaction;
    Hash(bytes)
}
