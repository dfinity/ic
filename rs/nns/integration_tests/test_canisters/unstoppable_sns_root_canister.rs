use async_trait::async_trait;
use dfn_candid::{CandidOne, candid_one};
use dfn_core::{over_async, over_init, println};
use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_clients::management_canister_client::ManagementCanisterClientImpl;
use ic_nervous_system_common::NANO_SECONDS_PER_SECOND;
use ic_nervous_system_runtime::{CdkRuntime, Runtime};
use ic_sns_root::{
    ArchiveInfo, GetSnsCanistersSummaryRequest, GetSnsCanistersSummaryResponse,
    LedgerCanisterClient,
    pb::v1::{CanisterCallError, SnsRootCanister},
    types::Environment,
};
use std::{cell::RefCell, time::Duration};

type CanisterRuntime = CdkRuntime;

struct CanisterEnvironment {}

#[async_trait]
impl Environment for CanisterEnvironment {
    fn now(&self) -> u64 {
        ic_cdk::api::time() / NANO_SECONDS_PER_SECOND
    }

    async fn call_canister(
        &self,
        canister_id: CanisterId,
        method_name: &str,
        arg: Vec<u8>,
    ) -> Result<Vec<u8>, (i32, String)> {
        CanisterRuntime::call_bytes_with_cleanup(canister_id, method_name, &arg).await
    }
}

thread_local! {
    static STATE: RefCell<SnsRootCanister> = RefCell::new(Default::default());
}

#[unsafe(export_name = "canister_init")]
fn canister_init() {
    println!("Unstoppable Canister Init!");

    over_init(|CandidOne(arg)| {
        STATE.with(move |state| {
            let mut state = state.borrow_mut();
            *state = arg;
        });
    });

    ic_cdk_timers::set_timer(Duration::from_millis(10), || {
        let future = async {
            println!("Unstoppable canister loop is starting...");

            loop {
                interrupt().await;
            }
        };
        dfn_core::api::futures::spawn(future);
    });
}

#[unsafe(export_name = "canister_update get_sns_canisters_summary")]
fn get_sns_canisters_summary() {
    over_async(
        candid_one,
        |request: GetSnsCanistersSummaryRequest| async move {
            get_sns_canisters_summary_impl(request).await
        },
    )
}

struct NoopLedgerClient;

#[async_trait]
impl LedgerCanisterClient for NoopLedgerClient {
    async fn archives(&self) -> Result<Vec<ArchiveInfo>, CanisterCallError> {
        todo!()
    }
}

async fn get_sns_canisters_summary_impl(
    _request: GetSnsCanistersSummaryRequest,
) -> GetSnsCanistersSummaryResponse {
    let canister_env = CanisterEnvironment {};
    let ledger_client = NoopLedgerClient;

    SnsRootCanister::get_sns_canisters_summary(
        &STATE,
        &ManagementCanisterClientImpl::<CanisterRuntime>::new(None),
        &ledger_client,
        &canister_env,
        false,
        PrincipalId(ic_cdk::api::canister_self()),
    )
    .await
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
