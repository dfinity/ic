use ic_cdk::{init, post_upgrade, update};
use ic_ckbtc_minter::state::eventlog::EventType;
use ic_ckbtc_minter::tasks::{TaskType, schedule_now};
use ic_ckdoge_minter::{
    DOGECOIN_CANISTER_RUNTIME,
    candid_api::{RetrieveDogeOk, RetrieveDogeWithApprovalArgs, RetrieveDogeWithApprovalError},
    lifecycle::init::MinterArg,
};

#[init]
fn init(args: MinterArg) {
    match args {
        MinterArg::Init(args) => {
            let args = ic_ckbtc_minter::lifecycle::init::InitArgs::from(args);
            ic_ckbtc_minter::storage::record_event(
                EventType::Init(args.clone()),
                &DOGECOIN_CANISTER_RUNTIME,
            );
            ic_ckbtc_minter::lifecycle::init::init(args, &DOGECOIN_CANISTER_RUNTIME);
            setup_tasks();

            #[cfg(feature = "self_check")]
            ok_or_die(check_invariants())
        }
    }
}

fn setup_tasks() {
    schedule_now(TaskType::ProcessLogic(true), &DOGECOIN_CANISTER_RUNTIME);
    schedule_now(TaskType::RefreshFeePercentiles, &DOGECOIN_CANISTER_RUNTIME);
}

#[post_upgrade]
fn post_upgrade() {
    todo!("XC-495")
}

#[update]
async fn retrieve_doge_with_approval(
    args: RetrieveDogeWithApprovalArgs,
) -> Result<RetrieveDogeOk, RetrieveDogeWithApprovalError> {
    check_anonymous_caller();
    let result = ic_ckbtc_minter::updates::retrieve_btc::retrieve_btc_with_approval(args.into())
        .await
        .map(RetrieveDogeOk::from)
        .map_err(RetrieveDogeWithApprovalError::from);
    check_postcondition(result)
}

fn check_anonymous_caller() {
    if ic_cdk::api::msg_caller() == candid::Principal::anonymous() {
        panic!("anonymous caller not allowed")
    }
}

fn check_postcondition<T>(t: T) -> T {
    #[cfg(feature = "self_check")]
    ok_or_die(check_invariants());
    t
}

#[cfg(feature = "self_check")]
fn ok_or_die(result: Result<(), String>) {
    if let Err(msg) = result {
        ic_cdk::println!("{}", msg);
        ic_cdk::trap(&msg);
    }
}

/// Checks that ckDOGE minter state internally consistent.
#[cfg(feature = "self_check")]
fn check_invariants() -> Result<(), String> {
    use ic_ckbtc_minter::{
        state::{eventlog::replay, invariants::CheckInvariantsImpl, read_state},
        storage,
    };

    read_state(|s| {
        s.check_invariants()?;

        let events: Vec<_> = storage::events().collect();
        let recovered_state = replay::<CheckInvariantsImpl>(events.clone().into_iter())
            .unwrap_or_else(|e| panic!("failed to replay log {events:?}: {e:?}"));

        recovered_state.check_invariants()?;

        // A running timer can temporarily violate invariants.
        if !s.is_timer_running {
            s.check_semantically_eq(&recovered_state)?;
        }

        Ok(())
    })
}

fn main() {}

#[test]
fn check_candid_interface_compatibility() {
    use candid_parser::utils::{CandidSource, service_equal};

    candid::export_service!();

    let new_interface = __export_service();

    // check the public interface against the actual one
    let old_interface = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("ckdoge_minter.did");
    let old_interface_content = std::fs::read_to_string(&old_interface)
        .unwrap_or_else(|e| panic!("Failed to read interface file {:?}: {}", old_interface, e));

    service_equal(
        CandidSource::Text(&new_interface),
        CandidSource::File(&old_interface),
    )
    .unwrap_or_else(|e| {
        panic!(
            "New interface {new_interface} is not equal to old interface {old_interface_content}: {e}",
        )
    });
}
