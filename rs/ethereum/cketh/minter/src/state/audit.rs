#[cfg(test)]
mod tests;

use super::State;
pub use super::event::{Event, EventType};
use crate::erc20::CkTokenSymbol;
use crate::state::eth_logs_scraping::LogScrapingId;
use crate::state::eth_logs_scraping::LogScrapingId::Erc20DepositWithoutSubaccount;
use crate::state::transactions::{Reimbursed, ReimbursementIndex, WithdrawalRequest};
use crate::storage::{record_event, with_event_iter};
use crate::time::TimeProvider;

/// Updates the state to reflect the given state transition.
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
        EventType::AcceptedErc20Deposit(erc20_event) => {
            state.record_event_to_mint(&erc20_event.clone().into());
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
            state.record_successful_mint(
                *event_source,
                &CkTokenSymbol::cketh_symbol_from_state(state).to_string(),
                *mint_block_index,
                None,
            );
        }
        EventType::MintedCkErc20 {
            event_source,
            mint_block_index,
            ckerc20_token_symbol,
            erc20_contract_address,
        } => {
            state.record_successful_mint(
                *event_source,
                ckerc20_token_symbol,
                *mint_block_index,
                Some(*erc20_contract_address),
            );
        }
        EventType::SyncedToBlock { block_number } => {
            state.log_scrapings.set_last_scraped_block_number(
                LogScrapingId::EthDepositWithoutSubaccount,
                *block_number,
            );
        }
        EventType::SyncedErc20ToBlock { block_number } => {
            state
                .log_scrapings
                .set_last_scraped_block_number(Erc20DepositWithoutSubaccount, *block_number);
        }
        EventType::AcceptedEthWithdrawalRequest(request) => {
            state
                .withdrawal_transactions
                .record_request(request.clone());
        }
        EventType::AcceptedSweeperFundingRequest(request) => {
            state.sweeper_funding.record_burn(request.withdrawal_amount);
            // Named explicitly: the payload converts to `CkEth` on its own, which would make the
            // funding reimbursable.
            state
                .withdrawal_transactions
                .record_request(WithdrawalRequest::SweeperFunding(request.clone()));
        }
        EventType::CreatedTransaction {
            withdrawal_id,
            transaction,
        } => {
            state
                .withdrawal_transactions
                .record_created_transaction(*withdrawal_id, transaction.clone());
        }
        EventType::SignedTransaction {
            withdrawal_id: _,
            transaction,
        } => {
            state
                .withdrawal_transactions
                .record_signed_transaction(transaction.clone());
        }
        EventType::ReplacedTransaction {
            withdrawal_id: _,
            transaction,
        } => {
            state
                .withdrawal_transactions
                .record_resubmit_transaction(transaction.clone());
        }
        EventType::FinalizedTransaction {
            withdrawal_id,
            transaction_receipt,
        } => {
            state.record_finalized_transaction(withdrawal_id, transaction_receipt);
        }
        EventType::AttestedDepositAddress { request, signature } => {
            state.record_attestation(request.clone(), signature.clone());
        }
        EventType::AuthorizedDepositAddress { request, signature } => {
            state
                .automatic_deposits
                .record_authorization(request.clone(), signature.clone());
        }
        EventType::AcceptedSweepRequest(request) => {
            state.next_sweep_id = request.id.next();
            state.automatic_deposits.record_sweep_scheduled(
                request.id,
                request.token,
                request.items.iter().map(|item| item.item.account),
            );
            state.update_sweeper_balance_upon_accepted_sweep(request);
            state
                .automatic_deposits
                .record_sweep_request(request.clone());
        }
        EventType::CreatedSweeperTransaction {
            sweep_id,
            transaction,
        } => {
            state
                .automatic_deposits
                .record_created_sweep_transaction(*sweep_id, transaction.clone());
        }
        EventType::SignedSweeperTransaction {
            sweep_id: _,
            transaction,
        } => {
            state
                .automatic_deposits
                .record_signed_sweep_transaction(transaction.clone());
        }
        EventType::ReplacedSweeperTransaction {
            sweep_id: _,
            transaction,
        } => {
            state
                .automatic_deposits
                .record_resubmit_sweep_transaction(transaction.clone());
        }
        EventType::FinalizedSweeperTransaction {
            sweep_id,
            transaction_receipt,
        } => {
            state.record_finalized_sweeper_transaction(sweep_id, transaction_receipt);
        }
        EventType::ReimbursedEthWithdrawal(Reimbursed {
            burn_in_block: withdrawal_id,
            reimbursed_in_block,
            reimbursed_amount: _,
            transaction_hash: _,
        }) => {
            state
                .withdrawal_transactions
                .record_finalized_reimbursement(
                    ReimbursementIndex::CkEth {
                        ledger_burn_index: *withdrawal_id,
                    },
                    *reimbursed_in_block,
                );
        }
        EventType::SkippedBlockForContract {
            contract_address,
            block_number,
        } => {
            state.record_skipped_block_for_contract(*contract_address, *block_number);
        }
        EventType::AddedCkErc20Token(ckerc20_token) => {
            state.record_add_ckerc20_token(ckerc20_token.clone());
        }
        EventType::AcceptedErc20WithdrawalRequest(request) => {
            state.record_erc20_withdrawal_request(request.clone())
        }
        EventType::ReimbursedErc20Withdrawal {
            cketh_ledger_burn_index,
            ckerc20_ledger_id,
            reimbursed,
        } => {
            state
                .withdrawal_transactions
                .record_finalized_reimbursement(
                    ReimbursementIndex::CkErc20 {
                        cketh_ledger_burn_index: *cketh_ledger_burn_index,
                        ledger_id: *ckerc20_ledger_id,
                        ckerc20_ledger_burn_index: reimbursed.burn_in_block,
                    },
                    reimbursed.reimbursed_in_block,
                );
        }
        EventType::FailedErc20WithdrawalRequest(cketh_reimbursement_request) => {
            state.withdrawal_transactions.record_reimbursement_request(
                ReimbursementIndex::CkEth {
                    ledger_burn_index: cketh_reimbursement_request.ledger_burn_index,
                },
                cketh_reimbursement_request.clone(),
            )
        }
        EventType::QuarantinedDeposit { event_source } => {
            state.record_quarantined_deposit(*event_source);
        }
        EventType::QuarantinedReimbursement { index } => {
            state
                .withdrawal_transactions
                .record_quarantined_reimbursement(index.clone());
        }
        EventType::SyncedDepositWithSubaccountToBlock { block_number } => {
            state.log_scrapings.set_last_scraped_block_number(
                LogScrapingId::EthOrErc20DepositWithSubaccount,
                *block_number,
            );
        }
        EventType::RegisteredDepositAddresses(registry) => {
            state.automatic_deposits.rebuild_watchlist(registry)
        }
        EventType::AutomaticDepositReceived(automatic_deposit) => state
            .automatic_deposits
            .record_automatic_deposit_received(automatic_deposit),
    }
}

/// Records the given event payload in the event log and updates the state to reflect the change.
pub fn process_event<T: TimeProvider>(state: &mut State, payload: EventType, time_provider: &T) {
    apply_state_transition(state, &payload);
    record_event(payload, time_provider);
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
    with_event_iter(|iter| replay_events_internal(iter))
}

fn replay_events_internal<T: IntoIterator<Item = Event>>(events: T) -> State {
    let mut events_iter = events.into_iter();
    let mut state = match events_iter
        .next()
        .expect("the event log should not be empty")
    {
        Event {
            payload: EventType::Init(init_arg),
            ..
        } => State::try_from(init_arg).expect("state initialization should succeed"),
        other => panic!("the first event must be an Init event, got: {other:?}"),
    };
    for event in events_iter {
        apply_state_transition(&mut state, &event.payload);
    }
    state
}
