use ic_cdk::{init, println, update};
use std::time::Duration;

#[init]
fn canister_init() {
    println!("Playground Canister Init!");
}

#[update]
async fn test() {
    println!("Playground test was called");
    ic_cdk::spawn(async move {
        let _: () = ic_cdk::call(ic_cdk::api::id(), "test_2", ()).await.unwrap();
    });
    ic_cdk_timers::set_timer(Duration::from_millis(0), || {
        println!("Timer call worked!");
    });
    println!("Playground test - spawns were called");
    panic!("Panic at the disco!");
}

#[update]
async fn test_2() {
    println!("Playground canister test_2 was called");
}

fn main() {}
