pub use super::event::{Event, EventType};
use super::State;
use crate::storage::record_event;
use crate::transactions::Reimbursed;

/// Updates the state to reflect the given state transition.
fn apply_state_transition(state: &mut State, payload: &EventType) {
    match &payload {
        EventType::Init(init_arg) => {
            panic!("state re-initialization is not allowed: {init_arg:?}");
        }
        EventType::Upgrade(upgrade_arg) => {
            state
                .upgrade(upgrade_arg.clone())
                .expect("applying upgrade event should succeed");
        }
        EventType::AcceptedDeposit(eth_event) => {
            state.record_event_to_mint(eth_event.clone());
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
            state
                .eth_transactions
                .record_finalized_transaction(*withdrawal_id, transaction_receipt.clone());
        }
        EventType::ReimbursedEthWithdrawal(Reimbursed {
            withdrawal_id,
            reimbursed_in_block,
            reimbursed_amount: _,
        }) => {
            state
                .eth_transactions
                .record_finalized_reimbursement(*withdrawal_id, *reimbursed_in_block);
        }
    }
}

/// Records the given event payload in the event log and updates the state to reflect the change.
pub fn process_event(state: &mut State, payload: EventType) {
    apply_state_transition(state, &payload);
    record_event(payload);
}
