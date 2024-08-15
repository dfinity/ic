use candid::candid_method;
use ic_cdk_macros::init;
use std::time::Duration;

#[init]
#[candid_method(init)]
fn init() {
    ic_cdk_timers::set_timer_interval(Duration::from_secs(1), || ic_cdk::spawn(async {}));
}

fn main() {}

#[cfg(test)]
candid::export_service!();
