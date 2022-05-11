///! State management module.
///!
///! The state is stored in the global thread-level variable `__STATE`.
///! This module provides utility functions to manage the state. Most
///! code should use those functions instead of touching `__STATE` directly.
use std::cell::RefCell;

thread_local! {
    static __STATE: RefCell<Option<CkBtcMinterState>> = RefCell::default();
}

/// The state of the ckBTC Minter.
///
/// Every piece of state of the Minter should be stored as field of this struct.
#[derive(Clone, Debug)]
pub struct CkBtcMinterState {}

/// Take the current state.
///
/// After calling this function the state won't be initialized anymore.
/// Panics if there is no state.
pub fn take_state<F, R>(f: F) -> R
where
    F: FnOnce(CkBtcMinterState) -> R,
{
    __STATE.with(|s| f(s.take().expect("State not initialized!")))
}

/// Mutates (part of) the current state using `f`.
///
/// Panics if there is no state.
pub fn mutate_state<F, R>(f: F) -> R
where
    F: FnOnce(&mut CkBtcMinterState) -> R,
{
    __STATE.with(|s| f(s.borrow_mut().as_mut().expect("State not initialized!")))
}

/// Read (part of) the current state using `f`.
///
/// Panics if there is no state.
pub fn read_state<F, R>(f: F) -> R
where
    F: FnOnce(&CkBtcMinterState) -> R,
{
    __STATE.with(|s| f(s.borrow().as_ref().expect("State not initialized!")))
}

/// Replaces the current state.
pub fn replace_state(state: CkBtcMinterState) {
    __STATE.with(|s| {
        *s.borrow_mut() = Some(state);
    });
}
