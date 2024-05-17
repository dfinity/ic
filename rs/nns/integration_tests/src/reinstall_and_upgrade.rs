use candid::Encode;
use canister_test::{Canister, Project, Wasm};
use dfn_candid::candid_one;
use ic_canister_client_sender::Sender;
use ic_management_canister_types::CanisterInstallMode;
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_2_OWNER_KEYPAIR, TEST_NEURON_2_OWNER_PRINCIPAL,
};
use ic_nns_common::types::{NeuronId, UpdateIcpXdrConversionRatePayload};
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, LIFELINE_CANISTER_ID};
use ic_nns_governance::{
    init::TEST_NEURON_2_ID,
    pb::v1::{Governance as GovernanceProto, NnsFunction},
};
use ic_nns_gtc::{
    der_encode,
    pb::v1::{AccountState, Gtc as GtcProto},
    test_constants::{TEST_IDENTITY_1, TEST_IDENTITY_2, TEST_IDENTITY_3, TEST_IDENTITY_4},
};
use ic_nns_test_utils::{
    common::{NnsInitPayloads, NnsInitPayloadsBuilder},
    governance::{
        bump_gzip_timestamp, get_pending_proposals, reinstall_nns_canister_by_proposal,
        submit_external_update_proposal, upgrade_nns_canister_by_proposal,
        upgrade_nns_canister_with_arg_by_proposal, upgrade_root_canister_by_proposal,
    },
    itest_helpers::{state_machine_test_on_nns_subnet, NnsCanisters},
};
use icp_ledger::{LedgerCanisterInitPayload, LedgerCanisterPayload, Tokens};
use lifeline::LIFELINE_CANISTER_WASM;
use prost::Message;
use std::{collections::HashMap, path::PathBuf, sync::Arc};

/// Seed Round (SR) neurons are released over 48 months in the following tests
const SR_MONTHS_TO_RELEASE: u8 = 48;
/// Early Contributor Tokenholder (ECT) neurons are released over 12 months in
/// the following tests
const ECT_MONTHS_TO_RELEASE: u8 = 12;
const TEST_SR_ACCOUNTS: &[(&str, u32); 2] = &[
    (TEST_IDENTITY_1.gtc_address, 1200),
    (TEST_IDENTITY_3.gtc_address, 14500),
];
const TEST_ECT_ACCOUNTS: &[(&str, u32); 2] = &[
    (TEST_IDENTITY_2.gtc_address, 8544),
    (TEST_IDENTITY_4.gtc_address, 3789),
];

#[test]
fn test_reinstall_and_upgrade_canisters_canonical_ordering() {
    state_machine_test_on_nns_subnet(|runtime| async move {
        let init_state = construct_init_state();
        let nns_canisters = NnsCanisters::set_up(&runtime, init_state.clone()).await;

        for CanisterInstallInfo {
            wasm,
            use_root,
            canister,
            init_payload,
            mode,
        } in get_nns_canister_wasm(&nns_canisters, init_state).into_iter()
        {
            if use_root {
                if mode == CanisterInstallMode::Upgrade {
                    println!("[Update] Canister: {:?}", canister.canister_id());
                    if canister.canister_id() == LIFELINE_CANISTER_ID {
                        let arg: Vec<String> = vec![];
                        upgrade_nns_canister_with_arg_by_proposal(
                            canister,
                            &nns_canisters.governance,
                            &nns_canisters.root,
                            bump_gzip_timestamp(&wasm),
                            Encode!(&arg).unwrap(),
                        )
                        .await;
                    } else {
                        upgrade_nns_canister_by_proposal(
                            canister,
                            &nns_canisters.governance,
                            &nns_canisters.root,
                            true,
                            // Method fails if wasm stays the same
                            bump_gzip_timestamp(&wasm),
                            None,
                        )
                        .await;
                    }
                } else if mode == CanisterInstallMode::Reinstall {
                    println!("[Reinstall] Canister: {:?}", canister.canister_id());
                    reinstall_nns_canister_by_proposal(
                        canister,
                        &nns_canisters.governance,
                        &nns_canisters.root,
                        wasm,
                        init_payload,
                    )
                    .await;
                }
            } else {
                // Root Upgrade via Lifeline
                upgrade_root_canister_by_proposal(
                    &nns_canisters.governance,
                    &nns_canisters.root,
                    wasm,
                )
                .await;
            }
        }

        Ok(())
    });
}

#[test]
fn test_reinstall_and_upgrade_canisters_with_state_changes() {
    state_machine_test_on_nns_subnet(|runtime| async move {
        let init_state = construct_init_state();
        let nns_canisters = NnsCanisters::set_up(&runtime, init_state.clone()).await;

        make_changes_to_state(&nns_canisters).await;
        assert!(check_changes_to_state(&nns_canisters).await);

        submit_external_update_proposal(
            &nns_canisters.governance,
            Sender::from_keypair(&TEST_NEURON_2_OWNER_KEYPAIR),
            NeuronId(TEST_NEURON_2_ID),
            // Random proposal type
            NnsFunction::IcpXdrConversionRate,
            // Payload itself doesn't matter
            UpdateIcpXdrConversionRatePayload {
                data_source: "".to_string(),
                timestamp_seconds: 1,
                xdr_permyriad_per_icp: 100,
                reason: None,
            },
            "<proposal created by test_reinstall_and_upgrade_canisters_with_state_changes>"
                .to_string(),
            "".to_string(),
        )
        .await;
        // Should have 1 pending proposal
        let pending_proposals = get_pending_proposals(&nns_canisters.governance).await;
        assert_eq!(pending_proposals.len(), 1);

        let canister_install_info: Vec<CanisterInstallInfo> =
            get_nns_canister_wasm(&nns_canisters, init_state);

        // Reinstall
        for CanisterInstallInfo {
            wasm,
            use_root,
            canister,
            init_payload,
            mode,
        } in canister_install_info.clone().into_iter()
        {
            if mode == CanisterInstallMode::Reinstall && use_root {
                reinstall_nns_canister_by_proposal(
                    canister,
                    &nns_canisters.governance,
                    &nns_canisters.root,
                    wasm,
                    init_payload,
                )
                .await;
            }
        }

        // Changes should have been reverted
        assert!(!check_changes_to_state(&nns_canisters).await);

        // Should have 0 pending proposals
        let pending_proposals = get_pending_proposals(&nns_canisters.governance).await;
        assert_eq!(pending_proposals.len(), 0);

        // Redo changes for upgrade
        make_changes_to_state(&nns_canisters).await;

        submit_external_update_proposal(
            &nns_canisters.governance,
            Sender::from_keypair(&TEST_NEURON_2_OWNER_KEYPAIR),
            NeuronId(TEST_NEURON_2_ID),
            // Random proposal type
            NnsFunction::IcpXdrConversionRate,
            // Payload itself doesn't matter
            UpdateIcpXdrConversionRatePayload {
                data_source: "".to_string(),
                timestamp_seconds: 1,
                xdr_permyriad_per_icp: 100,
                reason: None,
            },
            "<proposal created by test_reinstall_and_upgrade_canisters_with_state_changes>"
                .to_string(),
            "".to_string(),
        )
        .await;
        // Should have 1 pending proposal
        let pending_proposals = get_pending_proposals(&nns_canisters.governance).await;
        assert_eq!(pending_proposals.len(), 1);

        // Upgrade
        for CanisterInstallInfo {
            wasm,
            use_root,
            canister,
            init_payload,
            mode,
        } in canister_install_info
        {
            if mode == CanisterInstallMode::Upgrade {
                if use_root {
                    upgrade_nns_canister_by_proposal(
                        canister,
                        &nns_canisters.governance,
                        &nns_canisters.root,
                        false,
                        wasm,
                        Some(init_payload),
                    )
                    .await;
                } else {
                    // Root Upgrade via Lifeline
                    upgrade_root_canister_by_proposal(
                        &nns_canisters.governance,
                        &nns_canisters.root,
                        wasm,
                    )
                    .await;
                }
            }
        }

        // Should still have 1 pending proposal
        let pending_proposals = get_pending_proposals(&nns_canisters.governance).await;
        assert_eq!(pending_proposals.len(), 1);

        // Check that changes have persisted
        assert!(check_changes_to_state(&nns_canisters).await);

        Ok(())
    });
}

fn encode_init_state(init_state: NnsInitPayloads) -> Vec<Vec<u8>> {
    let ledger_init_vec = Encode!(&init_state.ledger).unwrap();
    let mut gtc_init_vec = Vec::new();
    GtcProto::encode(&init_state.genesis_token, &mut gtc_init_vec).unwrap();
    let cmc_init_vec = Encode!(&init_state.cycles_minting).unwrap();
    let lifeline_init_vec = Encode!(&init_state.lifeline).unwrap();
    let mut governance_init_vec = Vec::new();
    GovernanceProto::encode(&init_state.governance, &mut governance_init_vec).unwrap();
    let root_init_vec = Encode!(&init_state.root).unwrap();
    let registry_init_vec = Encode!(&init_state.registry).unwrap();

    vec![
        ledger_init_vec,
        gtc_init_vec,
        cmc_init_vec,
        lifeline_init_vec,
        governance_init_vec,
        root_init_vec,
        registry_init_vec,
    ]
}

#[derive(Clone)]
struct CanisterInstallInfo<'a> {
    wasm: Wasm,
    use_root: bool,
    canister: &'a Canister<'a>,
    init_payload: Vec<u8>,
    mode: CanisterInstallMode,
}

/// Returns a struct of each NNS canister's WASM, whether it is upgraded through
/// the Root canister, its installed canister, and its initial payload, in the
/// canonical ordering.
fn get_nns_canister_wasm<'a>(
    nns_canisters: &'a NnsCanisters,
    init_state: NnsInitPayloads,
) -> Vec<CanisterInstallInfo<'a>> {
    let encoded_init_state = encode_init_state(init_state);
    vec![
        CanisterInstallInfo {
            wasm: bump_gzip_timestamp(&Project::cargo_bin_maybe_from_env("ledger-canister", &[])),
            use_root: true,
            canister: &nns_canisters.ledger,
            init_payload: encoded_init_state[0].clone(),
            mode: CanisterInstallMode::Reinstall,
        },
        CanisterInstallInfo {
            wasm: Project::cargo_bin_maybe_from_env("ledger-canister", &[]),
            use_root: true,
            canister: &nns_canisters.ledger,
            init_payload: Encode!(&LedgerCanisterPayload::Upgrade(None)).unwrap(),
            mode: CanisterInstallMode::Upgrade,
        },
        CanisterInstallInfo {
            wasm: bump_gzip_timestamp(&Project::cargo_bin_maybe_from_env(
                "genesis-token-canister",
                &[],
            )),
            use_root: true,
            canister: &nns_canisters.genesis_token,
            init_payload: encoded_init_state[1].clone(),
            mode: CanisterInstallMode::Reinstall,
        },
        CanisterInstallInfo {
            wasm: Project::cargo_bin_maybe_from_env("genesis-token-canister", &[]),
            use_root: true,
            canister: &nns_canisters.genesis_token,
            init_payload: encoded_init_state[1].clone(),
            mode: CanisterInstallMode::Upgrade,
        },
        CanisterInstallInfo {
            wasm: bump_gzip_timestamp(&Project::cargo_bin_maybe_from_env(
                "cycles-minting-canister",
                &[],
            )),
            use_root: true,
            canister: &nns_canisters.cycles_minting,
            init_payload: encoded_init_state[2].clone(),
            mode: CanisterInstallMode::Reinstall,
        },
        CanisterInstallInfo {
            wasm: Project::cargo_bin_maybe_from_env("cycles-minting-canister", &[]),
            use_root: true,
            canister: &nns_canisters.cycles_minting,
            init_payload: encoded_init_state[2].clone(),
            mode: CanisterInstallMode::Upgrade,
        },
        CanisterInstallInfo {
            wasm: bump_gzip_timestamp(&Wasm::from_bytes(LIFELINE_CANISTER_WASM)),
            use_root: true,
            canister: &nns_canisters.lifeline,
            init_payload: encoded_init_state[3].clone(),
            mode: CanisterInstallMode::Reinstall,
        },
        CanisterInstallInfo {
            wasm: Wasm::from_bytes(LIFELINE_CANISTER_WASM),
            use_root: true,
            canister: &nns_canisters.lifeline,
            init_payload: encoded_init_state[3].clone(),
            mode: CanisterInstallMode::Upgrade,
        },
        CanisterInstallInfo {
            wasm: bump_gzip_timestamp(&Project::cargo_bin_maybe_from_env(
                "governance-canister",
                &[],
            )),
            use_root: true,
            canister: &nns_canisters.governance,
            init_payload: encoded_init_state[4].clone(),
            mode: CanisterInstallMode::Reinstall,
        },
        CanisterInstallInfo {
            wasm: Project::cargo_bin_maybe_from_env("governance-canister", &[]),
            use_root: true,
            canister: &nns_canisters.governance,
            init_payload: encoded_init_state[4].clone(),
            mode: CanisterInstallMode::Upgrade,
        },
        CanisterInstallInfo {
            wasm: bump_gzip_timestamp(&Project::cargo_bin_maybe_from_env("root-canister", &[])),
            use_root: false,
            canister: &nns_canisters.root,
            init_payload: encoded_init_state[5].clone(),
            mode: CanisterInstallMode::Reinstall,
        },
        CanisterInstallInfo {
            wasm: Project::cargo_bin_maybe_from_env("root-canister", &[]),
            use_root: false,
            canister: &nns_canisters.root,
            init_payload: encoded_init_state[5].clone(),
            mode: CanisterInstallMode::Upgrade,
        },
        CanisterInstallInfo {
            wasm: bump_gzip_timestamp(&Project::cargo_bin_maybe_from_env("registry-canister", &[])),
            use_root: true,
            canister: &nns_canisters.registry,
            init_payload: encoded_init_state[6].clone(),
            mode: CanisterInstallMode::Reinstall,
        },
        CanisterInstallInfo {
            wasm: Project::cargo_bin_maybe_from_env("registry-canister", &[]),
            use_root: true,
            canister: &nns_canisters.registry,
            init_payload: encoded_init_state[6].clone(),
            mode: CanisterInstallMode::Upgrade,
        },
    ]
}

async fn make_changes_to_state(nns_canisters: &NnsCanisters<'_>) {
    // GTC change: have TEST_IDENTITY_1 donate their neurons
    let sign_cmd = move |msg: &[u8]| Ok(TEST_IDENTITY_1.sign(msg));
    let sender = Sender::ExternalHsm {
        pub_key: der_encode(&TEST_IDENTITY_1.public_key()),
        sign: Arc::new(sign_cmd),
    };
    let donate_account_response: Result<Result<(), String>, String> = nns_canisters
        .genesis_token
        .update_from_sender(
            "donate_account",
            candid_one,
            TEST_IDENTITY_1.public_key_hex.to_string(),
            &sender,
        )
        .await;
    assert!(donate_account_response.unwrap().is_ok());
}

async fn check_changes_to_state(nns_canisters: &NnsCanisters<'_>) -> bool {
    // GTC change: Assert that TEST_IDENTITY_1 has donated their neurons
    let sign_cmd = move |msg: &[u8]| Ok(TEST_IDENTITY_1.sign(msg));
    let sender = Sender::ExternalHsm {
        pub_key: der_encode(&TEST_IDENTITY_1.public_key()),
        sign: Arc::new(sign_cmd),
    };
    let get_account_response: Result<Result<AccountState, String>, String> = nns_canisters
        .genesis_token
        .update_from_sender(
            "get_account",
            candid_one,
            TEST_IDENTITY_1.gtc_address.to_string(),
            &sender,
        )
        .await;
    let account_after_donation = get_account_response.unwrap().unwrap();

    account_after_donation.has_donated
}

fn construct_init_state() -> NnsInitPayloads {
    let mut nns_init_payload_builder = NnsInitPayloadsBuilder::new();

    // Initialize the ledger with an account for a user
    let mut ledger_init_state = HashMap::new();
    ledger_init_state.insert(
        (*TEST_NEURON_2_OWNER_PRINCIPAL).into(),
        Tokens::from_tokens(1000).unwrap(),
    );
    nns_init_payload_builder.ledger = LedgerCanisterInitPayload::builder()
        .minting_account(GOVERNANCE_CANISTER_ID.into())
        .initial_values(ledger_init_state)
        .build()
        .unwrap();

    nns_init_payload_builder
        .genesis_token
        .genesis_timestamp_seconds = 1;
    nns_init_payload_builder.genesis_token.sr_months_to_release = Some(SR_MONTHS_TO_RELEASE);
    nns_init_payload_builder.genesis_token.ect_months_to_release = Some(ECT_MONTHS_TO_RELEASE);
    nns_init_payload_builder
        .genesis_token
        .add_sr_neurons(TEST_SR_ACCOUNTS);
    nns_init_payload_builder
        .genesis_token
        .add_ect_neurons(TEST_ECT_ACCOUNTS);

    nns_init_payload_builder
        .genesis_token
        .donate_account_recipient_neuron_id = Some(NeuronId(TEST_NEURON_2_ID).into());

    let csv_file = match std::env::var("NEURON_CSV_PATH") {
        Ok(v) => PathBuf::from(v),
        Err(_) => PathBuf::from("src/neurons.csv"),
    };
    nns_init_payload_builder
        .governance
        .with_test_neurons()
        .add_all_neurons_from_csv_file(&csv_file);

    // The registry checks invariants when it is upgraded
    nns_init_payload_builder.with_initial_invariant_compliant_mutations();

    nns_init_payload_builder.build()
}
