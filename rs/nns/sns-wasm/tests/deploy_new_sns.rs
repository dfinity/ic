use crate::common::EXPECTED_SNS_CREATION_FEE;
use candid::{Decode, Encode};
use canister_test::{Canister, Project, Runtime, Wasm};
use common::set_up_state_machine_with_nns;
use dfn_candid::candid_one;
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_crypto_sha2::Sha256;
use ic_interfaces_registry::RegistryClient;
use ic_nervous_system_clients::canister_status::CanisterStatusResultV2;
use ic_nervous_system_clients::canister_status::CanisterStatusType::Running;
use ic_nervous_system_common::ONE_TRILLION;
use ic_nervous_system_proto::pb::v1::Canister as NervousSystemProtoCanister;
use ic_nns_constants::{
    GOVERNANCE_CANISTER_ID, ROOT_CANISTER_ID, SNS_WASM_CANISTER_ID,
    SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    itest_helpers::{
        local_test_on_nns_subnet, set_up_universal_canister_with_cycles,
        try_call_with_cycles_via_universal_canister, NnsCanisters,
    },
    sns_wasm, state_test_helpers,
    state_test_helpers::{set_controllers, set_up_universal_canister, update_with_sender},
};
use ic_protobuf::registry::subnet::v1::SubnetListRecord;
use ic_registry_keys::make_subnet_list_record_key;
use ic_sns_init::pb::v1::{DappCanisters, SnsInitPayload};
use ic_sns_root::{CanisterSummary, GetSnsCanistersSummaryRequest, GetSnsCanistersSummaryResponse};
use ic_sns_swap::pb::v1::GetCanisterStatusRequest;
use ic_sns_wasm::pb::v1::{
    AddWasmRequest, DappCanistersTransferResult, DeployNewSnsRequest, DeployNewSnsResponse,
    SnsCanisterIds, SnsCanisterType, SnsWasm, SnsWasmError,
};
use ic_test_utilities::{
    types::ids::canister_test_id, universal_canister::UNIVERSAL_CANISTER_WASM,
};
use ic_types::Cycles;
use registry_canister::mutations::common::decode_registry_value;
use std::convert::TryFrom;

pub mod common;

#[test]
fn test_canisters_are_created_and_installed_legacy() {
    // Keeping a test on ReplicaTests for performance comparison
    local_test_on_nns_subnet(|runtime| async move {
        let fake_registry_client = match runtime {
            Runtime::Remote(_) => {
                panic!("Cannot run this test on Runtime::Remote at this time");
            }
            Runtime::Local(ref r) => r.registry_client.clone(),
        };

        // The id the universal canister created below will have.
        let universal_canister_id = CanisterId::from_u64(11);

        let subnet_list_record = decode_registry_value::<SubnetListRecord>(
            fake_registry_client
                .get_value(
                    &make_subnet_list_record_key(),
                    fake_registry_client.get_latest_version(),
                )
                .unwrap()
                .unwrap(),
        );
        let system_subnet_id = SubnetId::new(
            PrincipalId::try_from(subnet_list_record.subnets.get(0).unwrap()).unwrap(),
        );

        let nns_init_payload = NnsInitPayloadsBuilder::new()
            .with_initial_invariant_compliant_mutations()
            .with_test_neurons()
            .with_sns_dedicated_subnets(vec![system_subnet_id])
            .with_sns_wasm_allowed_principals(vec![universal_canister_id.into()])
            .build();
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        let sns_wasm = &nns_canisters.sns_wasms;

        let root_wasm = Project::cargo_bin_maybe_from_env("sns-root-canister", &[]);
        let root_hash = Sha256::hash(&root_wasm.clone().bytes()).to_vec();
        let request = AddWasmRequest {
            wasm: Some(SnsWasm {
                wasm: root_wasm.clone().bytes(),
                canister_type: SnsCanisterType::Root.into(),
            }),
            hash: root_hash.clone(),
        };
        nns_canisters.add_wasm(request).await;

        let governance_wasm = Project::cargo_bin_maybe_from_env("sns-governance-canister", &[]);
        let governance_hash = Sha256::hash(&governance_wasm.clone().bytes()).to_vec();
        let request = AddWasmRequest {
            wasm: Some(SnsWasm {
                wasm: governance_wasm.clone().bytes(),
                canister_type: SnsCanisterType::Governance.into(),
            }),
            hash: governance_hash.clone(),
        };
        nns_canisters.add_wasm(request).await;

        let ledger_wasm = Project::cargo_bin_maybe_from_env("ic-icrc1-ledger", &[]);
        let ledger_hash = Sha256::hash(&ledger_wasm.clone().bytes()).to_vec();
        let request = AddWasmRequest {
            wasm: Some(SnsWasm {
                wasm: ledger_wasm.clone().bytes(),
                canister_type: SnsCanisterType::Ledger.into(),
            }),
            hash: ledger_hash.clone(),
        };
        nns_canisters.add_wasm(request).await;

        let swap_wasm = Project::cargo_bin_maybe_from_env("sns-swap-canister", &[]);
        let swap_hash = Sha256::hash(&swap_wasm.clone().bytes()).to_vec();
        let request = AddWasmRequest {
            wasm: Some(SnsWasm {
                wasm: swap_wasm.clone().bytes(),
                canister_type: SnsCanisterType::Swap.into(),
            }),
            hash: swap_hash.clone(),
        };

        nns_canisters.add_wasm(request).await;

        let archive_wasm = Project::cargo_bin_maybe_from_env("ic-icrc1-archive", &[]);
        let archive_hash = Sha256::hash(&archive_wasm.clone().bytes()).to_vec();
        let request = AddWasmRequest {
            wasm: Some(SnsWasm {
                wasm: archive_wasm.clone().bytes(),
                canister_type: SnsCanisterType::Archive.into(),
            }),
            hash: archive_hash.clone(),
        };

        nns_canisters.add_wasm(request).await;

        let index_wasm = Project::cargo_bin_maybe_from_env("ic-icrc1-index", &[]);
        let index_hash = Sha256::hash(&index_wasm.clone().bytes()).to_vec();
        let request = AddWasmRequest {
            wasm: Some(SnsWasm {
                wasm: index_wasm.clone().bytes(),
                canister_type: SnsCanisterType::Index.into(),
            }),
            hash: index_hash.clone(),
        };
        nns_canisters.add_wasm(request).await;

        // This canister will have id = universal_canister_id.
        // It has to be set up after the other canisters.
        let wallet_canister =
            set_up_universal_canister_with_cycles(&runtime, 2 * EXPECTED_SNS_CREATION_FEE).await;

        let result = try_call_with_cycles_via_universal_canister(
            &wallet_canister,
            sns_wasm,
            "deploy_new_sns",
            Encode!(&DeployNewSnsRequest {
                sns_init_payload: Some(SnsInitPayload::with_valid_legacy_values_for_testing())
            })
            .unwrap(),
            EXPECTED_SNS_CREATION_FEE,
        )
        .await
        .unwrap();

        let response = Decode!(&result, DeployNewSnsResponse).unwrap();

        // SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 1 is the ID of the wallet canister
        let root_canister_id = canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 2);
        let governance_canister_id = canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 3);
        let ledger_canister_id = canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 4);
        let swap_canister_id = canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 5);
        let index_canister_id = canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 6);

        assert_eq!(
            response,
            DeployNewSnsResponse {
                subnet_id: Some(system_subnet_id.get()),
                canisters: Some(SnsCanisterIds {
                    governance: Some(governance_canister_id.get()),
                    root: Some(root_canister_id.get()),
                    ledger: Some(ledger_canister_id.get()),
                    swap: Some(swap_canister_id.get()),
                    index: Some(index_canister_id.get()),
                }),
                error: None,
                dapp_canisters_transfer_result: Some(DappCanistersTransferResult {
                    restored_dapp_canisters: vec![],
                    sns_controlled_dapp_canisters: vec![],
                    nns_controlled_dapp_canisters: vec![],
                }),
            }
        );

        let canisters_returned = response.canisters.unwrap();
        let root_canister_principal = canisters_returned.root.unwrap();
        let swap_canister_principal = canisters_returned.swap.unwrap();

        let mut root_canister =
            Canister::new(&runtime, CanisterId::new(root_canister_principal).unwrap());
        root_canister.set_wasm(root_wasm.bytes());

        let response: GetSnsCanistersSummaryResponse = root_canister
            .update_(
                "get_sns_canisters_summary",
                candid_one,
                GetSnsCanistersSummaryRequest {
                    update_canister_list: None,
                },
            )
            .await
            .unwrap();

        // We know from a successful response that the init_payload is in fact sent correctly
        // through CanisterApiImpl::install_wasm, since governance has to know root canister_id
        // in order to respond to root's request for its own status from governance
        // more detailed coverage of the initialization parameters is done through unit tests

        // Assert that the canisters are installed in the same configuration that our response
        // told us above and controllers and installed wasms are correct
        let root_canister_summary = response.root_canister_summary();
        assert_eq!(root_canister_summary.canister_id(), root_canister_id.get());
        assert_eq!(root_canister_summary.status().status(), Running);
        assert_eq!(
            root_canister_summary.status().controllers(),
            vec![governance_canister_id.get()]
        );
        assert_eq!(
            root_canister_summary.status().module_hash().unwrap(),
            root_hash
        );

        let governance_canister_summary = response.governance_canister_summary();
        assert_eq!(
            governance_canister_summary.canister_id(),
            governance_canister_id.get()
        );
        assert_eq!(governance_canister_summary.status().status(), Running);
        assert_eq!(
            governance_canister_summary.status().controllers(),
            vec![root_canister_id.get()]
        );
        assert_eq!(
            governance_canister_summary.status().module_hash().unwrap(),
            governance_hash
        );

        let ledger_canister_summary = response.ledger_canister_summary();
        assert_eq!(
            ledger_canister_summary.canister_id(),
            ledger_canister_id.get()
        );
        assert_eq!(ledger_canister_summary.status().status(), Running);
        assert_eq!(
            ledger_canister_summary.status().controllers(),
            vec![root_canister_id.get()]
        );
        assert_eq!(
            ledger_canister_summary.status().module_hash().unwrap(),
            ledger_hash
        );

        let index_canister_summary = response.index_canister_summary();
        assert_eq!(
            index_canister_summary.canister_id(),
            index_canister_id.get()
        );
        assert_eq!(index_canister_summary.status().status(), Running);
        assert_eq!(
            index_canister_summary.status().controllers(),
            vec![root_canister_id.get()]
        );
        assert_eq!(
            index_canister_summary.status().module_hash().unwrap(),
            index_hash
        );

        let mut swap_canister =
            Canister::new(&runtime, CanisterId::new(swap_canister_principal).unwrap());
        swap_canister.set_wasm(swap_wasm.bytes());

        // Check Swap status
        let response: CanisterStatusResultV2 = swap_canister
            .update_(
                "get_canister_status",
                candid_one,
                GetCanisterStatusRequest {},
            )
            .await
            .unwrap();

        assert_eq!(response.controllers(), vec![ROOT_CANISTER_ID.get()]);

        // After a caller (on the SNS-WASM whitelist) calls deploy_new_sns, the caller is removed
        // from the whitelist.
        let result = try_call_with_cycles_via_universal_canister(
            &wallet_canister,
            sns_wasm,
            "deploy_new_sns",
            Encode!(&DeployNewSnsRequest {
                sns_init_payload: Some(SnsInitPayload::with_valid_values_for_testing())
            })
            .unwrap(),
            EXPECTED_SNS_CREATION_FEE,
        )
        .await
        .unwrap();

        let response = Decode!(&result, DeployNewSnsResponse).unwrap();
        let expected_error = SnsWasmError {
            message: "Caller is not in allowed principals list. Cannot deploy an sns.".to_string(),
        };
        assert_eq!(response.error, Some(expected_error));

        Ok(())
    });
}

/// There are not many tests we can deterministically create at this level
/// to simulate failure without creating more sophisticated test harnesses that let us
/// simulate failures executing basic IC00 operations
#[test]
fn test_deploy_cleanup_on_wasm_install_failure_legacy() {
    // The canister id the wallet canister will have.
    let wallet_canister_id = CanisterId::from_u64(11);

    state_test_helpers::reduce_state_machine_logging_unless_env_set();
    let machine = set_up_state_machine_with_nns(vec![wallet_canister_id.into()]);

    // Enough cycles one SNS deploy
    let wallet_canister = state_test_helpers::set_up_universal_canister(
        &machine,
        Some(Cycles::new(EXPECTED_SNS_CREATION_FEE)),
    );

    sns_wasm::add_real_wasms_to_sns_wasms(&machine);
    // we add a wasm that will fail with the given payload on installation
    let bad_wasm = SnsWasm {
        wasm: Wasm::from_bytes(UNIVERSAL_CANISTER_WASM).bytes(),
        canister_type: SnsCanisterType::Governance.into(),
    };
    sns_wasm::add_wasm_via_proposal(&machine, bad_wasm);

    let response = sns_wasm::deploy_new_sns(
        &machine,
        wallet_canister,
        SNS_WASM_CANISTER_ID,
        SnsInitPayload::with_valid_legacy_values_for_testing(),
        EXPECTED_SNS_CREATION_FEE,
    );

    // SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 1 is the ID of the wallet canister
    let root = canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 2);
    let governance = canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 3);
    let ledger = canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 4);
    let swap = canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 5);
    let index = canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 6);

    assert_eq!(
        response,
        DeployNewSnsResponse {
            subnet_id: Some(machine.get_subnet_ids().first().unwrap().get()),
            canisters: Some(SnsCanisterIds {
                root: Some(root.get()),
                ledger: Some(ledger.get()),
                governance: Some(governance.get()),
                swap: Some(swap.get()),
                index: Some(index.get()),
            }),
            // Because of the invalid WASM above (i.e. universal canister) which does not understand
            // the governance init payload, this fails.
            error: Some(SnsWasmError {
                message: "Error installing Governance WASM: Failed to install WASM on canister qvhpv-4qaaa-aaaaa-aaagq-cai: \
                error code 5: Canister qvhpv-4qaaa-aaaaa-aaagq-cai trapped explicitly: \
                did not find blob on stack"
                    .to_string()
            }),
            dapp_canisters_transfer_result: Some(DappCanistersTransferResult {
                restored_dapp_canisters: vec![],
                sns_controlled_dapp_canisters: vec![],
                nns_controlled_dapp_canisters: vec![],
            }),
        }
    );

    // 5_000_000_000_000 cycles are burned creating the canisters before the failure
    assert_eq!(
        machine.cycle_balance(wallet_canister),
        EXPECTED_SNS_CREATION_FEE - 5 * (ONE_TRILLION as u128)
    );

    // No canisters should exist above SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 1 (+1 for the wallet
    // canister) because we deleted those canisters
    assert!(!machine.canister_exists(canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 2)));
    assert!(!machine.canister_exists(canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 3)));
    assert!(!machine.canister_exists(canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 4)));
    assert!(!machine.canister_exists(canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 5)));
    assert!(!machine.canister_exists(canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 6)));
}

#[test]
fn test_deploy_adds_cycles_to_target_canisters_legacy() {
    // The canister id the wallet canister will have.
    let wallet_canister_id = CanisterId::from_u64(11);

    state_test_helpers::reduce_state_machine_logging_unless_env_set();
    let machine = set_up_state_machine_with_nns(vec![wallet_canister_id.into()]);

    // Enough cycles one SNS deploy
    let wallet_canister = state_test_helpers::set_up_universal_canister(
        &machine,
        Some(Cycles::new(EXPECTED_SNS_CREATION_FEE)),
    );

    sns_wasm::add_dummy_wasms_to_sns_wasms(&machine, None);
    // we add a wasm that will fail with the given payload on installation

    let response = sns_wasm::deploy_new_sns(
        &machine,
        wallet_canister,
        SNS_WASM_CANISTER_ID,
        SnsInitPayload::with_valid_legacy_values_for_testing(),
        EXPECTED_SNS_CREATION_FEE,
    );

    // SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 1 is the ID of the wallet canister
    let root = canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 2);
    let governance = canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 3);
    let ledger = canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 4);
    let swap = canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 5);
    let index = canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 6);

    assert_eq!(
        response,
        DeployNewSnsResponse {
            subnet_id: Some(machine.get_subnet_ids()[0].get()),
            canisters: Some(SnsCanisterIds {
                root: Some(*root.get_ref()),
                ledger: Some(*ledger.get_ref()),
                governance: Some(*governance.get_ref()),
                swap: Some(*swap.get_ref()),
                index: Some(*index.get_ref()),
            }),
            error: None,
            dapp_canisters_transfer_result: Some(DappCanistersTransferResult {
                restored_dapp_canisters: vec![],
                sns_controlled_dapp_canisters: vec![],
                nns_controlled_dapp_canisters: vec![],
            }),
        }
    );

    // All cycles should have been used and none refunded.
    assert_eq!(machine.cycle_balance(wallet_canister), 0);

    let sixth_cycles = EXPECTED_SNS_CREATION_FEE / 6;

    for canister_id in &[root, governance, swap, index] {
        assert!(machine.canister_exists(*canister_id));
        assert_eq!(machine.cycle_balance(*canister_id), sixth_cycles)
    }

    assert!(machine.canister_exists(ledger));
    assert_eq!(machine.cycle_balance(ledger), sixth_cycles * 2);
}

#[test]
fn test_deploy_sns_and_transfer_dapps() {
    // Setup the state machine
    state_test_helpers::reduce_state_machine_logging_unless_env_set();
    let machine = set_up_state_machine_with_nns(vec![]);

    // Add cycles to the SNS-W canister to deploy the SNS
    machine.add_cycles(SNS_WASM_CANISTER_ID, 200 * ONE_TRILLION as u128);

    // Add the Wasms of the SNS canisters to SNS-W
    sns_wasm::add_real_wasms_to_sns_wasms(&machine);

    // Create a dapp_canister and add NNS Root as a controller of it
    let dapp_canister = set_up_universal_canister(&machine, None);
    set_controllers(
        &machine,
        PrincipalId::new_anonymous(),
        dapp_canister,
        vec![ROOT_CANISTER_ID.get()],
    );

    // Add the dapp to the SnsInitPayload
    let sns_init_payload = SnsInitPayload {
        dapp_canisters: Some(DappCanisters {
            canisters: vec![NervousSystemProtoCanister {
                id: Some(dapp_canister.get()),
            }],
        }),
        ..SnsInitPayload::with_valid_values_for_testing()
    };

    // Call the code under test
    let response = sns_wasm::deploy_new_sns(
        &machine,
        GOVERNANCE_CANISTER_ID,
        SNS_WASM_CANISTER_ID,
        sns_init_payload,
        0,
    );

    // SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 1 is the ID of the wallet canister
    let root_canister_id = canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 2);
    let governance_canister_id = canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 3);
    let ledger_canister_id = canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 4);
    let swap_canister_id = canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 5);
    let index_canister_id = canister_test_id(SNS_WASM_CANISTER_INDEX_IN_NNS_SUBNET + 6);

    assert_eq!(
        response,
        DeployNewSnsResponse {
            subnet_id: Some(machine.get_subnet_id().get()),
            canisters: Some(SnsCanisterIds {
                governance: Some(governance_canister_id.get()),
                root: Some(root_canister_id.get()),
                ledger: Some(ledger_canister_id.get()),
                swap: Some(swap_canister_id.get()),
                index: Some(index_canister_id.get()),
            }),
            error: None,
            dapp_canisters_transfer_result: Some(DappCanistersTransferResult {
                restored_dapp_canisters: vec![],
                nns_controlled_dapp_canisters: vec![],
                sns_controlled_dapp_canisters: vec![NervousSystemProtoCanister::new(
                    dapp_canister.get()
                )],
            }),
        }
    );

    let canisters_returned = response.canisters.unwrap();
    let root_canister_principal = canisters_returned.root.unwrap();

    let response: GetSnsCanistersSummaryResponse = update_with_sender(
        &machine,
        CanisterId::new(root_canister_principal).unwrap(),
        "get_sns_canisters_summary",
        candid_one,
        GetSnsCanistersSummaryRequest {
            update_canister_list: None,
        },
        PrincipalId::new_anonymous(),
    )
    .unwrap();

    assert_eq!(response.dapps.len(), 1);
    let &CanisterSummary {
        canister_id: actual_dapp_canister,
        status: _,
    } = response.dapps.first().unwrap();

    assert_eq!(actual_dapp_canister, Some(dapp_canister.get()));
}
