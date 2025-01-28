use crate::storage::{Timestamp, LAST_SALT_NS, SALT, SALT_SIZE};
use crate::time::delay_till_next_month;
use getrandom::getrandom;
use ic_cdk::api::time;
use ic_cdk_macros::{init, post_upgrade, query};
use ic_cdk_timers::set_timer;
use salt_api::{GetSaltResponse, InitArg, SaltGenerationStrategy, SaltResponse};

// Sets an execution timer (delayed future task) and returns immediately.
fn reschedule_salt_generation(strategy: SaltGenerationStrategy) {
    match strategy {
        SaltGenerationStrategy::StartOfMonth => {
            let delay = delay_till_next_month(time());
            set_timer(delay, || {
                regenerate_salt();
                // Function is called recursively to schedule next execution
                reschedule_salt_generation(strategy);
            });
        }
    }
}

// Run when the canister is first installed
#[init]
fn init(init_arg: InitArg) {
    // Generate salt on the very first init or based on the provided argument.
    if !is_salt_init() || init_arg.regenerate_now {
        regenerate_salt();
    }
    // Start salt generation schedule based on the argument.
    if let Some(strategy) = init_arg.salt_generation_strategy {
        reschedule_salt_generation(strategy);
    }
}

// Run every time a canister is upgraded
#[post_upgrade]
fn post_upgrade(init_arg: InitArg) {
    // Run the same initialization logic
    init(init_arg);
}

#[query]
fn get_salt() -> GetSaltResponse {
    let salt = get_salt_metadata();
    Ok(SaltResponse {
        salt: salt.0,
        salt_id: salt.1,
    })
}

fn is_salt_init() -> bool {
    SALT.with(|cell| cell.borrow().get(&())).is_some()
        && LAST_SALT_NS.with(|cell| cell.borrow().get(&())).is_some()
}

fn get_salt_metadata() -> (Vec<u8>, Timestamp) {
    let salt = SALT
        .with(|cell| cell.borrow().get(&()))
        .expect("salt was not initialized correctly");
    // TODO: use ms or secs.
    let salt_id = LAST_SALT_NS
        .with(|cell| cell.borrow_mut().insert((), time()))
        .expect("salt was not initialized correctly");
    (salt, salt_id)
}

fn regenerate_salt() {
    let mut buf = [0u8; SALT_SIZE];
    getrandom(&mut buf).expect("failed to generate random bytes");
    SALT.with(|cell| {
        cell.borrow_mut().insert((), buf.to_vec());
    });
    LAST_SALT_NS.with(|cell| cell.borrow_mut().insert((), time()));
}
