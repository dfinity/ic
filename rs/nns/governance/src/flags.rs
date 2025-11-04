use std::cell::Cell;

thread_local! {
    static ARE_PERFORMANCE_BASED_REWARDS_ENABLED: Cell<bool> = const { Cell::new(false) };
}

pub(crate) fn are_performance_based_rewards_enabled() -> bool {
    ARE_PERFORMANCE_BASED_REWARDS_ENABLED.get()
}
