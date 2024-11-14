use crate::state::CkBtcMinterState;

pub trait CheckInvariants {
    fn check_invariants(state: &CkBtcMinterState) -> Result<(), String>;
}

pub enum CheckInvariantsImpl {}

impl CheckInvariants for CheckInvariantsImpl {
    fn check_invariants(state: &CkBtcMinterState) -> Result<(), String> {
        todo!()
    }
}
