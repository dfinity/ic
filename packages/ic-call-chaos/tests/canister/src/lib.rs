#[cfg(feature = "use_call_chaos")]
use ic_call_chaos::{
    set_policy as call_chaos_set_policy, AllowAll, AllowEveryOther, Call, DenyAll, WithProbability,
};
use ic_cdk::api::canister_self;
#[cfg(not(feature = "use_call_chaos"))]
use ic_cdk::call::Call;
use ic_cdk::call::CallFailed;
use ic_cdk::update;

static mut PINGS: u32 = 1;

#[update]
pub async fn call_ping(times: u32) -> (u32, u32, u32) {
    unsafe {
        PINGS = 0;
    }

    let mut succeeded = 0_u32;
    let mut failed = 0_u32;

    for _i in 0..times {
        let curr_time = ic_cdk::api::time();
        match Call::bounded_wait(canister_self(), "ping").await {
            Ok(_) => succeeded += 1,
            Err(CallFailed::CallRejected(_)) => {
                let new_time = ic_cdk::api::time();
                assert!(
                    new_time > curr_time,
                    "Time didn't move even though we got an asynchronous rejection: {} and {}",
                    curr_time,
                    new_time
                );
                failed += 1
            }
            Err(_) => failed += 1,
        }
    }

    assert!(
        succeeded + failed == times,
        "All calls should have succeeded so far!"
    );

    let nr_pings = unsafe { PINGS };
    (succeeded, failed, nr_pings)
}

#[update]
pub async fn ping() {
    unsafe {
        PINGS += 1;
    }
}

#[cfg(feature = "use_call_chaos")]
#[update]
pub async fn set_policy(policy: String) {
    match policy.as_str() {
        "AllowAll" => call_chaos_set_policy(AllowAll::default()),
        "AllowEveryOther" => call_chaos_set_policy(AllowEveryOther::default()),
        "DenyAll" => call_chaos_set_policy(DenyAll::default()),
        "WithProbability" => call_chaos_set_policy(WithProbability::new(0.5, 1337, true)),
        _ => panic!("Unknown policy"),
    }
}

pub fn main() {}
