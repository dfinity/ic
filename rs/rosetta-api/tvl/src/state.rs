use ic_base_types::PrincipalId;
use std::cell::RefCell;

pub struct TvlState {
    pub governance_principal: PrincipalId,
    pub xrc_principal: PrincipalId,
    pub update_period: u64,
    pub last_ts_icp_price: u64,
    pub last_ts_icp_locked: u64,
}

thread_local! {
    static __STATE: RefCell<Option<TvlState>> = RefCell::new(None);
}

/// Mutates (part of) the current state using `f`.
///
/// Panics if there is no state.
pub fn mutate_state<F, R>(f: F) -> R
where
    F: FnOnce(&mut TvlState) -> R,
{
    __STATE.with(|s| f(s.borrow_mut().as_mut().expect("State not initialized!")))
}

/// Read (part of) the current state using `f`.
///
/// Panics if there is no state.
pub fn read_state<F, R>(f: F) -> R
where
    F: FnOnce(&TvlState) -> R,
{
    __STATE.with(|s| f(s.borrow().as_ref().expect("State not initialized!")))
}

/// Replaces the current state.
pub fn replace_state(state: TvlState) {
    __STATE.with(|s| {
        *s.borrow_mut() = Some(state);
    });
}
