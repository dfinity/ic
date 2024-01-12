use crate::state::mutate_state;

//TODO re-use TimerGuard from ckETH.
#[derive(Debug, PartialEq, Eq)]
pub struct TimerGuard {}

#[derive(Debug, PartialEq, Eq)]
pub enum TimerGuardError {
    AlreadyProcessing,
}

impl TimerGuard {
    pub fn new() -> Result<Self, TimerGuardError> {
        mutate_state(|s| {
            if !s.maybe_set_timer_guard() {
                return Err(TimerGuardError::AlreadyProcessing);
            }
            Ok(Self {})
        })
    }
}

impl Drop for TimerGuard {
    fn drop(&mut self) {
        mutate_state(|s| {
            s.unset_timer_guard();
        });
    }
}
