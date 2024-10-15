use candid::{Decode, Encode};
use ic_nns_test_utils::sns_wasm::{
    build_swap_sns_wasm, create_modified_sns_wasm, ensure_sns_wasm_gzipped,
};
use ic_sns_swap::pb::v1::{DerivedState, GetStateRequest, GetStateResponse, Swap};
use ic_sns_wasm::pb::v1::SnsWasm;
use ic_state_machine_tests::StateMachine;
use ic_types::{CanisterId, PrincipalId};
use std::str::FromStr;

// TODO[NNS1-3386]: Remove this function once all existing Swaps are upgraded.
fn redact_unavailable_swap_fields(swap_state: &mut GetStateResponse) {
    // The following fields were added to the swap state later than some of the Swap canisters'
    // last upgrade. These fields will become available after those canisters are upgraded.
    {
        let swap = swap_state.swap.clone().unwrap();
        swap_state.swap = Some(Swap {
            timers: None,
            direct_participation_icp_e8s: None,
            neurons_fund_participation_icp_e8s: None,
            ..swap
        });
    }

    // The following fields were added to the derived state later than some of the Swap canisters'
    // last upgrade. These fields will become available after those canisters are upgraded.
    {
        let derived = swap_state.derived.clone().unwrap();
        swap_state.derived = Some(DerivedState {
            direct_participant_count: None,
            cf_participant_count: None,
            cf_neuron_count: None,
            direct_participation_icp_e8s: None,
            neurons_fund_participation_icp_e8s: None,
            ..derived
        });
    }
}

fn get_state(
    state_machine: &StateMachine,
    swap_canister_id: CanisterId,
    sns_name: &str,
) -> GetStateResponse {
    let args = Encode!(&GetStateRequest {}).unwrap();
    let state_before_upgrade = state_machine
        .execute_ingress(swap_canister_id, "get_state", args)
        .expect(&format!(
            "Unable to get state of {}'s Swap canister",
            sns_name
        ));
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
        .expect(&format!("Cannot upgrade {}'s Swap canister", sns_name));
}

/// Returns the pre-upgrade and post-upgrade states of the Swap.
fn run_upgrade_for_swap(
    state_machine: &StateMachine,
    swap_canister_id: CanisterId,
    swap_wasm: SnsWasm,
    sns_name: &str,
) -> (GetStateResponse, GetStateResponse) {
    let swap_pre_state = get_state(&state_machine, swap_canister_id, sns_name);

    upgrade_swap_to_tip_of_master(&state_machine, swap_canister_id, swap_wasm, sns_name);

    let swap_post_state = get_state(&state_machine, swap_canister_id, sns_name);

    (swap_pre_state, swap_post_state)
}

fn run_test_for_swap(swap_canister_id: &str, sns_name: &str) {
    let swap_canister_id =
        CanisterId::unchecked_from_principal(PrincipalId::from_str(swap_canister_id).unwrap());

    let state_machine =
        ic_nns_test_utils_golden_nns_state::new_state_machine_with_golden_sns_state_or_panic();

    let swap_wasm_1 = ensure_sns_wasm_gzipped(build_swap_sns_wasm());
    let swap_wasm_2 = create_modified_sns_wasm(&swap_wasm_1, Some(42));
    assert_ne!(swap_wasm_1, swap_wasm_2);

    // Experiment I: Upgrade from golden version to the tip of this branch.
    {
        let (swap_pre_state, mut swap_post_state) =
            run_upgrade_for_swap(&state_machine, swap_canister_id, swap_wasm_1, sns_name);

        // Some fields need to be redacted as they were introduced after some Swaps were created.
        redact_unavailable_swap_fields(&mut swap_post_state);

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
            run_upgrade_for_swap(&state_machine, swap_canister_id, swap_wasm_2, sns_name);

        // Nothing to redact in this case; we've just upgraded a recent version to its modified version.

        assert_eq!(
            swap_pre_state, swap_post_state,
            "Experiment II: Swap state mismatch detected for {}",
            sns_name
        );
    }
}

#[test]
fn upgrade_downgrade_swap_boom_dao() {
    run_test_for_swap("vuqiy-liaaa-aaaaq-aabiq-cai", "BOOM DAO");
}

#[test]
fn upgrade_downgrade_swap_cycles_transfer_station() {
    run_test_for_swap("iuhw5-siaaa-aaaaq-aadoq-cai", "CYCLES-TRANSFER-STATION");
}

#[test]
fn upgrade_downgrade_swap_catalyze() {
    run_test_for_swap("uc3qt-6yaaa-aaaaq-aabnq-cai", "Catalyze");
}

#[test]
fn upgrade_downgrade_swap_dogmi() {
    run_test_for_swap("n223b-vqaaa-aaaaq-aadsa-cai", "DOGMI");
}

#[test]
fn upgrade_downgrade_swap_decideai_dao() {
    run_test_for_swap("xhply-dqaaa-aaaaq-aabga-cai", "DecideAI DAO");
}

#[test]
fn upgrade_downgrade_swap_dragginz() {
    run_test_for_swap("zcdfx-6iaaa-aaaaq-aaagq-cai", "Dragginz");
}

#[test]
fn upgrade_downgrade_swap_elna_ai() {
    run_test_for_swap("grlys-pqaaa-aaaaq-aacoa-cai", "ELNA AI");
}

#[test]
fn upgrade_downgrade_swap_estatedao() {
    run_test_for_swap("bcl3g-3aaaa-aaaaq-aac5a-cai", "EstateDAO");
}

#[test]
fn upgrade_downgrade_swap_gold_dao() {
    run_test_for_swap("t7z6p-ryaaa-aaaaq-aab7q-cai", "Gold DAO");
}

#[test]
fn upgrade_downgrade_swap_icghost() {
    run_test_for_swap("4f5dx-pyaaa-aaaaq-aaa3q-cai", "ICGhost");
}

#[test]
fn upgrade_downgrade_swap_iclighthouse_dao() {
    run_test_for_swap("habgn-xyaaa-aaaaq-aaclq-cai", "ICLighthouse DAO");
    
}
#[test]
fn upgrade_downgrade_swap_icpcc_dao_llc() {
    run_test_for_swap("lwslc-cyaaa-aaaaq-aadfq-cai", "ICPCC DAO LLC");
}

#[test]
fn upgrade_downgrade_swap_icpswap() {
    run_test_for_swap("ch7an-giaaa-aaaaq-aacwq-cai", "ICPSwap");
}

#[test]
fn upgrade_downgrade_swap_icpanda_dao() {
    run_test_for_swap("c424i-4qaaa-aaaaq-aacua-cai", "ICPanda DAO");
}

#[test]
fn upgrade_downgrade_swap_icvc() {
    run_test_for_swap("mzwsh-biaaa-aaaaq-aaduq-cai", "ICVC");
}

#[test]
fn upgrade_downgrade_swap_juno_build() {
    run_test_for_swap("mlqf6-nyaaa-aaaaq-aadxq-cai", "Juno Build");
}

#[test]
fn upgrade_downgrade_swap_kinic() {
    run_test_for_swap("7sppf-6aaaa-aaaaq-aaata-cai", "Kinic");
}

#[test]
fn upgrade_downgrade_swap_mora_dao() {
    run_test_for_swap("khyv5-2qaaa-aaaaq-aadaa-cai", "MORA DAO");
}

#[test]
fn upgrade_downgrade_swap_motoko() {
    run_test_for_swap("kv6ce-waaaa-aaaaq-aadda-cai", "Motoko");
}

#[test]
fn upgrade_downgrade_swap_neutrinite() {
    run_test_for_swap("f25or-jiaaa-aaaaq-aaceq-cai", "Neutrinite");
}

#[test]
fn upgrade_downgrade_swap_nuance() {
    run_test_for_swap("q2nfe-mqaaa-aaaaq-aabua-cai", "Nuance");
}

#[test]
fn upgrade_downgrade_swap_origyn() {
    run_test_for_swap("jxl73-gqaaa-aaaaq-aadia-cai", "ORIGYN");
}

#[test]
fn upgrade_downgrade_swap_openchat() {
    run_test_for_swap("2hx64-daaaa-aaaaq-aaana-cai", "OpenChat");
}

#[test]
fn upgrade_downgrade_swap_openfpl() {
    run_test_for_swap("dkred-jaaaa-aaaaq-aacra-cai", "OpenFPL");
}

#[test]
fn upgrade_downgrade_swap_sonic() {
    run_test_for_swap("qils5-aaaaa-aaaaq-aabxa-cai", "SONIC");
}

#[test]
fn upgrade_downgrade_swap_seers() {
    run_test_for_swap("rmg5p-zaaaa-aaaaq-aabra-cai", "Seers");
}

#[test]
fn upgrade_downgrade_swap_sneed() {
    run_test_for_swap("hshru-3iaaa-aaaaq-aaciq-cai", "Sneed");
}

#[test]
fn upgrade_downgrade_swap_trax() {
    run_test_for_swap("ezrhx-5qaaa-aaaaq-aacca-cai", "TRAX");
}

#[test]
fn upgrade_downgrade_swap_waterneuron() {
    run_test_for_swap("ipcky-iqaaa-aaaaq-aadma-cai", "WaterNeuron");
}

#[test]
fn upgrade_downgrade_swap_yral() {
    run_test_for_swap("6eexo-lqaaa-aaaaq-aaawa-cai", "YRAL");
}

#[test]
fn upgrade_downgrade_swap_yuku_dao() {
    run_test_for_swap("a2cof-vaaaa-aaaaq-aacza-cai", "Yuku DAO");
}
