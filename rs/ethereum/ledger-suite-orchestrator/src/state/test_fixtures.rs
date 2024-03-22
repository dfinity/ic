use crate::candid::InitArg;
use crate::state::State;

pub fn new_state() -> State {
    State::try_from(InitArg {
        more_controller_ids: vec![],
        minter_id: None,
        cycles_management: None,
    })
    .unwrap()
}
