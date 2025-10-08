use assert_matches::assert_matches;
use candid::{Decode, Encode};
use ic_nervous_system_proto::pb::v1::Timers;
use ic_nns_test_utils::sns_wasm::{
    build_swap_sns_wasm, create_modified_sns_wasm, ensure_sns_wasm_gzipped,
};
use ic_sns_swap::pb::v1::{GetStateRequest, GetStateResponse, Swap};
use ic_sns_wasm::pb::v1::SnsWasm;
use ic_state_machine_tests::StateMachine;
use ic_types::{CanisterId, PrincipalId};
use pretty_assertions::assert_eq;
use std::str::FromStr;

/// This function redacts the `timers` field, as they are not supposed to match before and after
/// an upgrade. As the in-code documentation suggests, the `timers` field contains "information
/// about the timers that perform periodic tasks of this Swap canister." This information includes,
/// in particular, the last time timers were initialized, reset, and executed. Or course, this is
/// time-sensitive and upgrade-sensitive.
fn redact_timers(swap_state: &mut GetStateResponse) {
    if let Some(swap) = swap_state.swap.as_mut() {
        swap.timers = None
    }
}

fn get_state(
    state_machine: &StateMachine,
    swap_canister_id: CanisterId,
    sns_name: &str,
) -> GetStateResponse {
    // A little hack to ensure out of cycles does not cause spurious test
    // failures. Such failures are considered spurious, because we are not
    // testing anything to do with cycles. We are just trying to verify that
    // upgrades will work.
    state_machine.add_cycles(swap_canister_id, 100e12 as u128);

    let args = Encode!(&GetStateRequest {}).unwrap();
    let state_before_upgrade = state_machine
        .execute_ingress(swap_canister_id, "get_state", args)
        .unwrap_or_else(|err| panic!("Unable to get state of {sns_name}'s Swap canister: {err}",));
    Decode!(&state_before_upgrade.bytes(), GetStateResponse).unwrap()
}

fn upgrade_swap_to_tip_of_master(
    state_machine: &StateMachine,
    swap_canister_id: CanisterId,
    swap_wasm: SnsWasm,
    sns_name: &str,
) {
    let swap_upgrade_arg = Encode!().unwrap();

    state_machine
        .upgrade_canister(swap_canister_id, swap_wasm.wasm, swap_upgrade_arg)
        .unwrap_or_else(|err| panic!("Cannot upgrade {sns_name}'s Swap canister: {err}"));
}

/// Returns the pre-upgrade and post-upgrade states of the Swap.
fn run_upgrade_for_swap(
    state_machine: &StateMachine,
    swap_canister_id: CanisterId,
    swap_wasm: SnsWasm,
    sns_name: &str,
) -> (GetStateResponse, GetStateResponse) {
    let swap_pre_state = get_state(state_machine, swap_canister_id, sns_name);

    upgrade_swap_to_tip_of_master(state_machine, swap_canister_id, swap_wasm, sns_name);

    let swap_post_state = get_state(state_machine, swap_canister_id, sns_name);

    (swap_pre_state, swap_post_state)
}

fn run_test_for_swap(state_machine: &StateMachine, swap_canister_id: &str, sns_name: &str) {
    let swap_canister_id =
        CanisterId::unchecked_from_principal(PrincipalId::from_str(swap_canister_id).unwrap());

    let swap_wasm_1 = ensure_sns_wasm_gzipped(build_swap_sns_wasm());
    let swap_wasm_2 = create_modified_sns_wasm(&swap_wasm_1, Some(42));
    assert_ne!(swap_wasm_1, swap_wasm_2);

    // Experiment I: Upgrade from golden version to the tip of this branch.
    {
        let (mut swap_pre_state, mut swap_post_state) =
            run_upgrade_for_swap(state_machine, swap_canister_id, swap_wasm_1, sns_name);

        // Ensure the timers are not going to be scheduled for this Swap.
        assert_matches!(
            swap_post_state.swap,
            Some(Swap {
                timers: Some(Timers {
                    requires_periodic_tasks: Some(false),
                    ..
                }),
                ..
            })
        );

        // Timers need to be redacted as they are expected to change due to the upgrade.
        redact_timers(&mut swap_post_state);
        redact_timers(&mut swap_pre_state);

        // Otherwise, the states before and after the migration should match.
        assert_eq!(
            swap_pre_state, swap_post_state,
            "Experiment I: Swap state mismatch detected for {} ",
            sns_name
        );
    }

    // Experiment II: Upgrade again to test the pre-upgrade hook.
    {
        let (swap_pre_state, swap_post_state) =
            run_upgrade_for_swap(state_machine, swap_canister_id, swap_wasm_2, sns_name);

        // Nothing to redact in this case; we've just upgraded a recent version to its modified version.

        assert_eq!(
            swap_pre_state, swap_post_state,
            "Experiment II: Swap state mismatch detected for {}",
            sns_name
        );
    }
}

#[test]
fn golden_state_swap_upgrade_twice() {
    // Ideally, we would try to upgrade all SNS canisters (not just swap). For
    // now, we only check these canisters. One slight difficulty of this is
    // determining which SNSs are still "active".
    let snses_under_test = [
        ("vuqiy-liaaa-aaaaq-aabiq-cai", "BOOM DAO"),
        ("iuhw5-siaaa-aaaaq-aadoq-cai", "CYCLES-TRANSFER-STATION"),
        ("uc3qt-6yaaa-aaaaq-aabnq-cai", "Catalyze"),
        ("n223b-vqaaa-aaaaq-aadsa-cai", "DOGMI"),
        ("xhply-dqaaa-aaaaq-aabga-cai", "DecideAI DAO"),
        ("zcdfx-6iaaa-aaaaq-aaagq-cai", "Dragginz"),
        ("grlys-pqaaa-aaaaq-aacoa-cai", "ELNA AI"),
        ("bcl3g-3aaaa-aaaaq-aac5a-cai", "EstateDAO"),
        ("t7z6p-ryaaa-aaaaq-aab7q-cai", "Gold DAO"),
        ("4f5dx-pyaaa-aaaaq-aaa3q-cai", "ICGhost"),
        ("habgn-xyaaa-aaaaq-aaclq-cai", "ICLighthouse DAO"),
        ("lwslc-cyaaa-aaaaq-aadfq-cai", "ICPCC DAO LLC"),
        ("ch7an-giaaa-aaaaq-aacwq-cai", "ICPSwap"),
        ("c424i-4qaaa-aaaaq-aacua-cai", "ICPanda DAO"),
        ("mzwsh-biaaa-aaaaq-aaduq-cai", "ICVC"),
        ("7sppf-6aaaa-aaaaq-aaata-cai", "Kinic"),
        ("kv6ce-waaaa-aaaaq-aadda-cai", "Motoko"),
        ("f25or-jiaaa-aaaaq-aaceq-cai", "Neutrinite"),
        ("q2nfe-mqaaa-aaaaq-aabua-cai", "Nuance"),
        ("jxl73-gqaaa-aaaaq-aadia-cai", "ORIGYN"),
        ("2hx64-daaaa-aaaaq-aaana-cai", "OpenChat"),
        ("dkred-jaaaa-aaaaq-aacra-cai", "OpenFPL"),
        ("qils5-aaaaa-aaaaq-aabxa-cai", "SONIC"),
        ("rmg5p-zaaaa-aaaaq-aabra-cai", "Seers"),
        ("hshru-3iaaa-aaaaq-aaciq-cai", "Sneed"),
        ("ezrhx-5qaaa-aaaaq-aacca-cai", "TRAX"),
        ("ipcky-iqaaa-aaaaq-aadma-cai", "WaterNeuron"),
        ("6eexo-lqaaa-aaaaq-aaawa-cai", "YRAL"),
        ("a2cof-vaaaa-aaaaq-aacza-cai", "Yuku DAO"),
    ];

    let state_machine =
        ic_nns_test_utils_golden_nns_state::new_state_machine_with_golden_sns_state_or_panic();

    for (swap_canister_id, sns_name) in snses_under_test {
        run_test_for_swap(&state_machine, swap_canister_id, sns_name);
    }
}
