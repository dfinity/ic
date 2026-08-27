use crate::numeric::BlockNumber;
use crate::state::audit::{EventType, apply_state_transition};
use crate::state::eth_logs_scraping::LogScrapings;
use crate::state::{State, read_state};
use crate::sweep::create_pending_sweeper_requests;
use crate::test_fixtures::mock::MockCanisterRuntime;
use crate::test_fixtures::{automatic_deposit, init_state, initial_state};

#[tokio::test]
async fn should_be_no_op_when_no_sweeper_contract() {
    let mut state = initial_state();
    state.sweeper_contract_address = None;
    init_state(state);
    let before = read_state(State::clone);

    create_pending_sweeper_requests(&mock()).await;

    assert_eq!(read_state(State::clone), before);
}

#[tokio::test]
async fn should_be_no_op_when_no_deposit_helper_contract() {
    let mut state = initial_state();
    state.log_scrapings = LogScrapings::new(BlockNumber::ONE);
    init_state(state);
    let before = read_state(State::clone);

    create_pending_sweeper_requests(&mock()).await;

    assert_eq!(read_state(State::clone), before);
}

#[tokio::test]
async fn should_leave_a_queued_deposit_untouched() {
    init_state(state_with_a_queued_deposit());
    let before = read_state(State::clone);

    create_pending_sweeper_requests(&mock()).await;

    assert_eq!(read_state(State::clone), before);
}

fn state_with_a_queued_deposit() -> State {
    let mut state = initial_state();
    apply_state_transition(
        &mut state,
        &EventType::AutomaticDepositReceived(automatic_deposit()),
    );
    assert_eq!(state.automatic_deposits.sweep_len(), 1);
    state
}

fn mock() -> MockCanisterRuntime {
    MockCanisterRuntime::new()
}
