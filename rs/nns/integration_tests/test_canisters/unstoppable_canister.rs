use dfn_core::println;
use ic_base_types::CanisterId;
use std::time::Duration;

#[unsafe(export_name = "canister_init")]
fn canister_init() {
    println!("Unstoppable Canister Init!");
    ic_cdk_timers::set_timer(Duration::from_millis(10), async {
        let future = async {
            println!("Unstoppable canister loop is starting...");

            loop {
                interrupt().await;
            }
        };
        dfn_core::api::futures::spawn(future);
    });
}

async fn interrupt() {
    use ic_nervous_system_clients::{
        canister_id_record::CanisterIdRecord, canister_status::CanisterStatusResult,
    };

    let _unused: Result<CanisterStatusResult, _> = dfn_core::api::call(
        CanisterId::ic_00(), // Call the management (virtual) canister.
        "canister_status",
        dfn_candid::candid_one,
        CanisterIdRecord::from(dfn_core::api::id()),
    )
    .await;
}

fn main() {}
