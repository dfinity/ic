use crate::state::audit::{EventType, apply_state_transition};
use crate::state::{State, read_state};
use crate::sweep::create_pending_sweeper_requests;
use crate::test_fixtures::mock::MockCanisterRuntime;
use crate::test_fixtures::{automatic_deposit, init_state, initial_state};

#[tokio::test]
async fn should_leave_a_queued_deposit_untouched() {
    init_state(state_with_a_queued_deposit());
    let before = read_state(State::clone);

    create_pending_sweeper_requests(&MockCanisterRuntime::new()).await;

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
