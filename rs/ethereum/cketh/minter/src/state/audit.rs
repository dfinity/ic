pub use super::event::{Event, EventType};
use super::State;
use crate::state::transactions::Reimbursed;
use crate::storage::{record_event, with_event_iter};

/// Updates the state to reflect the given state transition.
// public because it's used in tests since process_event
// requires canister infrastructure to retrieve time
pub fn apply_state_transition(state: &mut State, payload: &EventType) {
    match payload {
        EventType::Init(init_arg) => {
            panic!("state re-initialization is not allowed: {init_arg:?}");
        }
        EventType::Upgrade(upgrade_arg) => {
            state
                .upgrade(upgrade_arg.clone())
                .expect("applying upgrade event should succeed");
        }
        EventType::AcceptedDeposit(eth_event) => {
            state.record_event_to_mint(&eth_event.clone().into());
        }
        EventType::AcceptedErc20Deposit(eth_event) => {
            state.record_event_to_mint(&eth_event.clone().into());
        }
        EventType::InvalidDeposit {
            event_source,
            reason,
        } => {
            let _ = state.record_invalid_deposit(*event_source, reason.clone());
        }
        EventType::MintedCkEth {
            event_source,
            mint_block_index,
        } => {
            state.record_successful_mint(*event_source, *mint_block_index);
        }
        EventType::SyncedToBlock { block_number } => {
            state.last_scraped_block_number = *block_number;
        }
        EventType::AcceptedEthWithdrawalRequest(request) => {
            state
                .eth_transactions
                .record_withdrawal_request(request.clone());
        }
        EventType::CreatedTransaction {
            withdrawal_id,
            transaction,
        } => {
            state
                .eth_transactions
                .record_created_transaction(*withdrawal_id, transaction.clone());
        }
        EventType::SignedTransaction {
            withdrawal_id: _,
            transaction,
        } => {
            state
                .eth_transactions
                .record_signed_transaction(transaction.clone());
        }
        EventType::ReplacedTransaction {
            withdrawal_id: _,
            transaction,
        } => {
            state
                .eth_transactions
                .record_resubmit_transaction(transaction.clone());
        }
        EventType::FinalizedTransaction {
            withdrawal_id,
            transaction_receipt,
        } => {
            state.record_finalized_transaction(withdrawal_id, transaction_receipt);
        }
        EventType::ReimbursedEthWithdrawal(Reimbursed {
            withdrawal_id,
            reimbursed_in_block,
            reimbursed_amount: _,
            transaction_hash: _,
        }) => {
            state
                .eth_transactions
                .record_finalized_reimbursement(*withdrawal_id, *reimbursed_in_block);
        }
        EventType::SkippedBlock(block_number) => {
            state.record_skipped_block(*block_number);
        }
        EventType::AddedCkErc20Token(ckerc20_token) => {
            state.record_add_ckerc20_token(ckerc20_token.clone());
        }
    }
}

/// Records the given event payload in the event log and updates the state to reflect the change.
pub fn process_event(state: &mut State, payload: EventType) {
    apply_state_transition(state, &payload);
    record_event(payload);
}

/// Recomputes the minter state from the event log.
///
/// # Panics
///
/// This function panics if:
///   * The event log is empty.
///   * The first event in the log is not an Init event.
///   * One of the events in the log invalidates the minter's state invariants.
pub fn replay_events() -> State {
    with_event_iter(|mut iter| {
        let mut state = match iter.next().expect("the event log should not be empty") {
            Event {
                payload: EventType::Init(init_arg),
                ..
            } => State::try_from(init_arg).expect("state initialization should succeed"),
            other => panic!("the first event must be an Init event, got: {other:?}"),
        };
        for event in iter {
            apply_state_transition(&mut state, &event.payload);
        }
        state
    })
}
