use candid::{Nat, Principal};
use canister_test::{Canister, Runtime};
use ic_base_types::PrincipalId;
use ic_canister_client_sender::Sender;
use ic_ledger_core::Tokens;
use ic_nervous_system_common_test_keys::{TEST_USER1_KEYPAIR, TEST_USER2_KEYPAIR};
use ic_nns_constants::SNS_WASM_CANISTER_ID;
use ic_sns_governance::{
    pb::v1::{
        proposal::Action, ManageLedgerParameters, NervousSystemParameters, NeuronId,
        NeuronPermissionList, NeuronPermissionType, Proposal, ProposalId,
    },
    types::{DEFAULT_TRANSFER_FEE, ONE_YEAR_SECONDS},
};
use ic_sns_test_utils::{
    icrc1,
    itest_helpers::{
        compile_rust_canister, install_rust_canister_with_memory_allocation,
        local_test_on_sns_subnet, SnsCanisters, SnsTestsInitPayloadBuilder, LEDGER_BINARY_NAME,
        SNS_WASM_BINARY_NAME,
    },
    SNS_MAX_CANISTER_MEMORY_ALLOCATION_IN_BYTES,
};
use ic_sns_wasm::{
    init::SnsWasmCanisterInitPayload,
    pb::v1::{add_wasm_response, AddWasmRequest, AddWasmResponse, SnsCanisterType, SnsWasm},
};
use icrc_ledger_types::icrc1::{account::Account, transfer::TransferArg};

#[test]
fn test_manage_ledger_parameters_change_transfer_fee() {
    local_test_on_sns_subnet(|runtime| async move {
        // set sns
        let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);

        let system_params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
            .with_ledger_account(
                user.get_principal_id().0.into(),
                Tokens::from_tokens(1000).unwrap(),
            )
            .with_nervous_system_parameters(system_params)
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        // set up sns-wasm canister
        set_up_sns_wasm_canister_for_manage_ledger_parameters_proposals(&runtime).await;

        // create neuron
        let neuron_id: NeuronId = sns_canisters
            .stake_and_claim_neuron(&user, Some(ONE_YEAR_SECONDS as u32))
            .await;
        let subaccount = neuron_id
            .subaccount()
            .expect("Error creating the subaccount");

        // change ledger transfer_fee with the ManageLedgerParameters proposal
        let new_fee = 34;

        let proposal_id: ProposalId = sns_canisters
            .make_proposal(
                &user,
                &subaccount,
                Proposal {
                    title: "ManageLedgerParameters".to_string(),
                    action: Some(Action::ManageLedgerParameters(ManageLedgerParameters {
                        transfer_fee: Some(new_fee),
                        ..Default::default()
                    })),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        let pd = sns_canisters
            .await_proposal_execution_or_failure(&proposal_id)
            .await;
        println!("change ledger fee proposal data: {:?}", pd);

        // check that the fee on the ledger has changed.
        assert!(icrc1::fee(&sns_canisters.ledger).await.unwrap() != DEFAULT_TRANSFER_FEE.get_e8s());
        assert!(icrc1::fee(&sns_canisters.ledger).await.unwrap() == new_fee);

        // try making transfers using the new fee and the old fee.
        icrc1::transfer(
            &sns_canisters.ledger,
            &user,
            TransferArg {
                amount: Nat::from(5),
                fee: Some(Nat::from(new_fee)),
                from_subaccount: None,
                to: Account {
                    owner: Principal::management_canister(),
                    subaccount: None,
                },
                memo: None,
                created_at_time: None,
            },
        )
        .await
        .expect("This transfer with the new fee must succeed");

        icrc1::transfer(
            &sns_canisters.ledger,
            &user,
            TransferArg {
                amount: Nat::from(5),
                fee: Some(Nat::from(DEFAULT_TRANSFER_FEE.get_e8s())),
                from_subaccount: None,
                to: Account {
                    owner: Principal::management_canister(),
                    subaccount: None,
                },
                memo: None,
                created_at_time: None,
            },
        )
        .await
        .expect_err("This transfer with the old fee must fail.");

        let nervous_system_parameters_with_new_fee: NervousSystemParameters = sns_canisters
            .governance
            .query_("get_nervous_system_parameters", dfn_candid::candid_one, ())
            .await
            .unwrap();

        assert_eq!(
            nervous_system_parameters_with_new_fee.transaction_fee_e8s,
            Some(new_fee)
        );

        Ok(())
    })
}

#[test]
fn test_manage_ledger_parameters_change_fee_collector() {
    local_test_on_sns_subnet(|runtime| async move {
        // set sns
        let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);

        let system_params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
            .with_ledger_account(
                user.get_principal_id().0.into(),
                Tokens::from_tokens(1000).unwrap(),
            )
            .with_nervous_system_parameters(system_params)
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        // set up sns-wasm canister
        set_up_sns_wasm_canister_for_manage_ledger_parameters_proposals(&runtime).await;

        // create neuron
        let neuron_id: NeuronId = sns_canisters
            .stake_and_claim_neuron(&user, Some(ONE_YEAR_SECONDS as u32))
            .await;
        let subaccount = neuron_id
            .subaccount()
            .expect("Error creating the subaccount");

        // choose a new fee_collector
        let new_fee_collector = Account {
            owner: Sender::from_keypair(&TEST_USER2_KEYPAIR)
                .get_principal_id()
                .0,
            subaccount: None,
        };
        // check that a transfer does not send the fee to the new_fee_collector before the proposal
        icrc1::transfer(
            &sns_canisters.ledger,
            &user,
            TransferArg {
                amount: Nat::from(5),
                fee: Some(Nat::from(DEFAULT_TRANSFER_FEE.get_e8s())),
                from_subaccount: None,
                to: Account {
                    owner: Principal::management_canister(),
                    subaccount: None,
                },
                memo: None,
                created_at_time: None,
            },
        )
        .await
        .unwrap();

        assert_eq!(
            icrc1::balance_of(&sns_canisters.ledger, new_fee_collector,)
                .await
                .unwrap(),
            0
        );

        // change the sns-ledger's fee_collector with the ManageLedgerParameters proposal
        let proposal_id: ProposalId = sns_canisters
            .make_proposal(
                &user,
                &subaccount,
                Proposal {
                    title: "ManageLedgerParameters".to_string(),
                    action: Some(Action::ManageLedgerParameters(ManageLedgerParameters {
                        set_fee_collector: Some(new_fee_collector.into()),
                        ..Default::default()
                    })),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        let pd = sns_canisters
            .await_proposal_execution_or_failure(&proposal_id)
            .await;
        println!("change fee collector proposal data: {:?}", pd);
        // check that a transfer does send the fee to the new fee_collector now.
        icrc1::transfer(
            &sns_canisters.ledger,
            &user,
            TransferArg {
                amount: Nat::from(5),
                fee: Some(Nat::from(DEFAULT_TRANSFER_FEE.get_e8s())),
                from_subaccount: None,
                to: Account {
                    owner: Principal::management_canister(),
                    subaccount: None,
                },
                memo: None,
                created_at_time: None,
            },
        )
        .await
        .unwrap();

        assert_eq!(
            icrc1::balance_of(&sns_canisters.ledger, new_fee_collector,)
                .await
                .unwrap(),
            DEFAULT_TRANSFER_FEE.get_e8s()
        );

        Ok(())
    })
}

async fn set_up_sns_wasm_canister_for_manage_ledger_parameters_proposals(
    runtime: &Runtime,
) -> Canister<'_> {
    let mut sns_wasm_canister = runtime
        .create_canister_with_specified_id(
            Some(100_000_000_000_000),
            Some(SNS_WASM_CANISTER_ID.get()),
        )
        .await
        .unwrap();

    install_rust_canister_with_memory_allocation(
        &mut sns_wasm_canister,
        SNS_WASM_BINARY_NAME,
        &[],
        Some(
            candid::encode_one(SnsWasmCanisterInitPayload {
                sns_subnet_ids: vec![PrincipalId::default().into()],
                access_controls_enabled: false,
                allowed_principals: vec![],
            })
            .unwrap(),
        ),
        SNS_MAX_CANISTER_MEMORY_ALLOCATION_IN_BYTES,
    )
    .await;

    let ledger_wasm = compile_rust_canister(LEDGER_BINARY_NAME, &[]).await;
    let ledger_wasm_hash = ledger_wasm.sha256_hash().to_vec();
    let add_wasm_response: AddWasmResponse = sns_wasm_canister
        .update_(
            "add_wasm",
            dfn_candid::candid_one,
            AddWasmRequest {
                hash: ledger_wasm_hash.clone(),
                wasm: Some(SnsWasm {
                    wasm: ledger_wasm.bytes(),
                    canister_type: SnsCanisterType::Ledger.into(),
                }),
            },
        )
        .await
        .unwrap();
    match add_wasm_response.result.unwrap() {
        add_wasm_response::Result::Hash(b) => {
            assert_eq!(ledger_wasm_hash, b);
        }
        add_wasm_response::Result::Error(e) => {
            panic!("Error calling add_wasm on the sns-wasm-canister. {:?}", e);
        }
    }

    sns_wasm_canister
}
