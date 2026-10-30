use candid::{CandidType, Decode, Encode, Nat, Principal};
use common::{
    STARTING_CYCLES_PER_CANISTER, account, index_ng_wasm, install_icrc3_test_ledger_with_wasm,
    install_index_ng, run_rounds_until, status,
};
use ic_base_types::{CanisterId, PrincipalId};
use ic_icrc1_index_ng::{IndexArg, InitArg, UpgradeArg};
use ic_icrc1_test_utils::icrc3::BlockBuilder;
use ic_ledger_suite_state_machine_helpers::{add_block, set_icrc3_enabled};
use ic_state_machine_tests::{StateMachine, StateMachineBuilder};
use icrc_ledger_types::icrc::generic_value::ICRC3Value;
use std::time::Duration;

mod common;

#[cfg(not(feature = "u256-tokens"))]
type Tokens = ic_icrc1_tokens_u64::U64;
#[cfg(feature = "u256-tokens")]
type Tokens = ic_icrc1_tokens_u256::U256;

#[derive(CandidType)]
struct OldInitArg {
    ledger_id: Principal,
    retrieve_blocks_from_ledger_interval_seconds: Option<u64>,
    min_retrieve_blocks_from_ledger_interval_seconds: Option<u64>,
    max_retrieve_blocks_from_ledger_interval_seconds: Option<u64>,
}

#[derive(CandidType)]
struct OldUpgradeArg {
    ledger_id: Option<Principal>,
}

#[derive(CandidType)]
enum OldIndexArg {
    Init(OldInitArg),
    Upgrade(OldUpgradeArg),
}

fn test_env() -> StateMachine {
    StateMachineBuilder::new().build()
}

fn install_controllable_ledger(env: &StateMachine) -> CanisterId {
    let path = std::env::var("IC_ICRC3_POKE_TEST_LEDGER_WASM_PATH").unwrap();
    install_icrc3_test_ledger_with_wasm(env, std::fs::read(path).unwrap())
}

fn setup(
    interval: u64,
    allowed_poke_callers: Option<Option<Vec<Principal>>>,
) -> (StateMachine, CanisterId, CanisterId) {
    let env = test_env();
    let ledger = install_controllable_ledger(&env);
    set_icrc3_enabled(&env, ledger, !cfg!(feature = "icrc3_disabled"));
    let index = install_index_ng(
        &env,
        InitArg {
            ledger_id: ledger.into(),
            #[allow(deprecated)]
            retrieve_blocks_from_ledger_interval_seconds: None,
            min_retrieve_blocks_from_ledger_interval_seconds: Some(interval),
            max_retrieve_blocks_from_ledger_interval_seconds: Some(interval),
            allowed_poke_callers,
        },
    );
    (env, ledger, index)
}

fn run_rounds(env: &StateMachine) {
    for _ in 0..10 {
        env.tick();
    }
}

fn advance_time_and_run_rounds(env: &StateMachine, seconds: u64) {
    env.advance_time(Duration::from_secs(seconds));
    run_rounds(env);
}

fn count(env: &StateMachine, ledger: CanisterId) -> u64 {
    Decode!(
        &env.query(ledger, "block_request_count", Encode!().unwrap())
            .unwrap()
            .bytes(),
        u64
    )
    .unwrap()
}

fn notify(env: &StateMachine, ledger: CanisterId, index: CanisterId) {
    // This returns only the sender's submission result, not an index reply.
    env.execute_ingress(
        ledger,
        "send_poke",
        Encode!(&Principal::from(index)).unwrap(),
    )
    .unwrap();
    run_rounds(env);
}

fn ingress(env: &StateMachine, index: CanisterId, caller: PrincipalId) {
    // A no-application-reply ingress may be rejected after executing. Observe
    // effects separately instead of awaiting or asserting an application reply.
    env.send_ingress(caller, index, "poke", Encode!().unwrap());
    run_rounds(env);
}

fn hold(env: &StateMachine, ledger: CanisterId, enabled: bool) {
    env.execute_ingress(ledger, "hold_block_responses", Encode!(&enabled).unwrap())
        .unwrap();
}

fn release_one(env: &StateMachine, ledger: CanisterId) {
    env.execute_ingress(ledger, "release_block_response", Encode!().unwrap())
        .unwrap();
}

fn upgrade(env: &StateMachine, index: CanisterId, policy: Option<Option<Vec<Principal>>>) {
    let arg = IndexArg::Upgrade(UpgradeArg {
        ledger_id: None,
        #[allow(deprecated)]
        retrieve_blocks_from_ledger_interval_seconds: None,
        min_retrieve_blocks_from_ledger_interval_seconds: None,
        max_retrieve_blocks_from_ledger_interval_seconds: None,
        allowed_poke_callers: policy,
    });
    env.upgrade_canister(index, index_ng_wasm(), Encode!(&arg).unwrap())
        .unwrap();
}

#[test]
fn poke_preserves_deadline_and_busy_callback_preserves_one_polling_chain() {
    let (env, ledger, index) = setup(100, Some(None));
    let mint = BlockBuilder::new(0, 0)
        .mint(account(1, 0), Tokens::from(100_u64))
        .build();
    add_block(&env, ledger, &mint).unwrap();

    // The fixture captures the response before holding it. The transfer below
    // therefore requires the pending poke to make a second ledger request.
    hold(&env, ledger, true);
    notify(&env, ledger, index);
    assert_eq!(count(&env, ledger), 1);
    assert_eq!(status(&env, index).num_blocks_synced, Nat::from(0_u64));
    let transfer = BlockBuilder::new(1, 1)
        .with_fee(Tokens::from(1_u64))
        .transfer(account(1, 0), account(2, 0), Tokens::from(20_u64))
        .build();
    add_block(&env, ledger, &transfer).unwrap();
    notify(&env, ledger, index);
    ingress(&env, index, PrincipalId::new_anonymous());
    notify(&env, ledger, index);
    assert_eq!(count(&env, ledger), 1, "busy pokes do not overlap");

    release_one(&env, ledger);
    run_rounds_until(&env, || count(&env, ledger) == 2);
    assert_eq!(count(&env, ledger), 2, "busy pokes coalesce into one pass");
    assert_eq!(status(&env, index).num_blocks_synced, Nat::from(1_u64));
    let balance = env
        .query(index, "icrc1_balance_of", Encode!(&account(2, 0)).unwrap())
        .unwrap()
        .bytes();
    assert_eq!(Decode!(&balance, Nat).unwrap(), Nat::from(0_u64));

    // The follow-up has started but its response has not been applied yet. A
    // new poke during it must request one more pass after this one completes.
    ingress(&env, index, PrincipalId::new_anonymous());
    release_one(&env, ledger);
    run_rounds_until(&env, || count(&env, ledger) == 3);
    release_one(&env, ledger);
    run_rounds_until(&env, || status(&env, index).num_blocks_synced == 2_u64);
    hold(&env, ledger, false);
    assert_eq!(count(&env, ledger), 3, "the newer poke adds one pass");
    advance_time_and_run_rounds(&env, 99); // before the original deadline
    assert_eq!(count(&env, ledger), 3);

    // Hold another poke across the original automatic deadline. The scheduled
    // callback must rearm exactly one ordinary polling chain, while pending poke
    // work is serviced separately after the held pass releases the shared guard.
    hold(&env, ledger, true);
    notify(&env, ledger, index);
    assert_eq!(count(&env, ledger), 4);
    notify(&env, ledger, index);
    ingress(&env, index, PrincipalId::new_anonymous());
    advance_time_and_run_rounds(&env, 1); // t=100: scheduled callback meets the busy guard
    assert_eq!(count(&env, ledger), 4);
    notify(&env, ledger, index);
    hold(&env, ledger, false);
    run_rounds_until(&env, || count(&env, ledger) == 5);
    run_rounds(&env);
    assert_eq!(count(&env, ledger), 5, "busy pokes leave one follow-up");
    advance_time_and_run_rounds(&env, 99);
    assert_eq!(count(&env, ledger), 5);
    advance_time_and_run_rounds(&env, 1);
    assert_eq!(count(&env, ledger), 6);
    advance_time_and_run_rounds(&env, 100);
    assert_eq!(count(&env, ledger), 7, "exactly one polling chain remains");
    assert_eq!(status(&env, index).num_blocks_synced, Nat::from(2_u64));
    let balance = env
        .query(index, "icrc1_balance_of", Encode!(&account(2, 0)).unwrap())
        .unwrap()
        .bytes();
    assert_eq!(Decode!(&balance, Nat).unwrap(), Nat::from(20_u64));
}

#[test]
fn poke_policy_and_upgrade_compatibility() {
    let listed = PrincipalId::new_user_test_id(42);
    for (policy, expected_requests) in [
        (None, 0),
        (Some(Some(vec![])), 0),
        (Some(Some(vec![listed.0])), 1),
    ] {
        let (env, ledger, index) = setup(100, policy);
        ingress(&env, index, PrincipalId::new_anonymous());
        assert_eq!(count(&env, ledger), 0);
        ingress(&env, index, listed);
        assert_eq!(count(&env, ledger), expected_requests);
    }

    let old_env = test_env();
    let old_ledger = install_controllable_ledger(&old_env);
    set_icrc3_enabled(&old_env, old_ledger, !cfg!(feature = "icrc3_disabled"));
    let old_index = old_env
        .install_canister_with_cycles(
            index_ng_wasm(),
            Encode!(&OldIndexArg::Init(OldInitArg {
                ledger_id: old_ledger.into(),
                retrieve_blocks_from_ledger_interval_seconds: None,
                min_retrieve_blocks_from_ledger_interval_seconds: Some(100),
                max_retrieve_blocks_from_ledger_interval_seconds: Some(100),
            }))
            .unwrap(),
            None,
            ic_types_cycles::Cycles::new(STARTING_CYCLES_PER_CANISTER),
        )
        .unwrap();
    ingress(&old_env, old_index, listed);
    assert_eq!(
        count(&old_env, old_ledger),
        0,
        "old init payload without a policy disables poke"
    );

    let (env, ledger, index) = setup(100, Some(None));
    let anonymous = PrincipalId::new_anonymous();
    ingress(&env, index, anonymous); // anonymous public access
    assert_eq!(count(&env, ledger), 1);
    notify(&env, ledger, index);
    assert_eq!(count(&env, ledger), 2);

    upgrade(&env, index, Some(Some(vec![ledger.into(), listed.0])));
    ingress(&env, index, anonymous);
    ingress(&env, index, PrincipalId::new_user_test_id(43));
    assert_eq!(count(&env, ledger), 2);
    notify(&env, ledger, index); // the forwarding canister is the immediate caller
    assert_eq!(count(&env, ledger), 3);
    advance_time_and_run_rounds(&env, 1);
    ingress(&env, index, listed);
    assert_eq!(count(&env, ledger), 4);

    env.run_until_completion(20);
    env.upgrade_canister(index, index_ng_wasm(), Encode!().unwrap())
        .unwrap();
    ingress(&env, index, anonymous);
    assert_eq!(
        count(&env, ledger),
        4,
        "no-argument upgrade preserves restriction"
    );
    notify(&env, ledger, index);
    assert_eq!(count(&env, ledger), 5, "listed caller survives upgrade");
    // Independently encoded old argument omits the new field entirely.
    env.upgrade_canister(
        index,
        index_ng_wasm(),
        Encode!(&OldIndexArg::Upgrade(OldUpgradeArg { ledger_id: None })).unwrap(),
    )
    .unwrap();
    ingress(&env, index, anonymous);
    assert_eq!(count(&env, ledger), 5, "old payload preserves restriction");
    notify(&env, ledger, index);
    assert_eq!(
        count(&env, ledger),
        6,
        "old payload preserves listed caller"
    );

    for (policy, expected) in [
        (Some(Some(vec![])), 6),
        (Some(None), 7),
        (Some(Some(vec![anonymous.0])), 8),
        (Some(Some(vec![ledger.into()])), 8),
        (None, 8),
    ] {
        upgrade(&env, index, policy);
        ingress(&env, index, anonymous);
        assert_eq!(count(&env, ledger), expected);
    }
    // Restore public access, poke immediately before the automatic deadline,
    // and show that ordinary polling still runs on that deadline.
    upgrade(&env, index, Some(None));
    advance_time_and_run_rounds(&env, 99);
    ingress(&env, index, anonymous);
    let before = count(&env, ledger);
    advance_time_and_run_rounds(&env, 1);
    assert_eq!(count(&env, ledger), before + 1);
}

#[test]
fn failed_poke_releases_guard_and_never_retries_or_skips() {
    let (env, ledger, index) = setup(100, Some(None));
    add_block(&env, ledger, &ICRC3Value::Text("invalid block".into())).unwrap();
    advance_time_and_run_rounds(&env, 1);
    notify(&env, ledger, index);
    env.run_until_completion(20);
    assert_eq!(count(&env, ledger), 1);
    ingress(&env, index, PrincipalId::new_anonymous());
    assert_eq!(count(&env, ledger), 2, "error released the shared guard");
    advance_time_and_run_rounds(&env, 98);
    assert_eq!(count(&env, ledger), 2);
    advance_time_and_run_rounds(&env, 1); // original automatic wakeup also fails, stopping its chain
    assert_eq!(count(&env, ledger), 3);
    advance_time_and_run_rounds(&env, 102); // includes any accidental retries at t=101/102/200
    assert_eq!(count(&env, ledger), 3);
    notify(&env, ledger, index); // independent attempt after automatic stop
    assert_eq!(count(&env, ledger), 4);
    advance_time_and_run_rounds(&env, 100);
    assert_eq!(
        count(&env, ledger),
        4,
        "poke must not restart the stopped chain"
    );
    assert_eq!(status(&env, index).num_blocks_synced, Nat::from(0_u64));
}
