use assert_matches::assert_matches;
use candid::{Decode, Encode, Nat};
use canister_test::Canister;
use cycles_minting_canister::{
    CanisterSettingsArgs, ChangeSubnetTypeAssignmentArgs, CreateCanister, CreateCanisterError,
    IcpXdrConversionRateCertifiedResponse, NotifyCreateCanister, NotifyError, NotifyErrorCode,
    NotifyMintCyclesArg, NotifyMintCyclesSuccess, NotifyTopUp, SubnetListWithType,
    SubnetTypesToSubnetsResponse, UpdateSubnetTypeArgs, BAD_REQUEST_CYCLES_PENALTY,
    MEMO_CREATE_CANISTER, MEMO_MINT_CYCLES, MEMO_TOP_UP_CANISTER,
};
use dfn_candid::candid_one;
use dfn_protobuf::protobuf;
use ic_canister_client_sender::Sender;
use ic_ledger_core::tokens::{CheckedAdd, CheckedSub};
// TODO(EXC-1687): remove temporary alias `Ic00CanisterSettingsArgs`.
use ic_management_canister_types::{
    CanisterIdRecord, CanisterInfoResponse, CanisterSettingsArgs as Ic00CanisterSettingsArgs,
    CanisterSettingsArgsBuilder, CanisterStatusResultV2,
};
use ic_nervous_system_clients::canister_status::CanisterStatusResult;
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR, TEST_USER1_KEYPAIR, TEST_USER1_PRINCIPAL,
    TEST_USER2_PRINCIPAL, TEST_USER3_PRINCIPAL,
};
use ic_nns_common::types::{NeuronId, ProposalId, UpdateIcpXdrConversionRatePayload};
use ic_nns_constants::{
    CYCLES_LEDGER_CANISTER_ID, CYCLES_MINTING_CANISTER_ID, GOVERNANCE_CANISTER_ID,
    LEDGER_CANISTER_INDEX_IN_NNS_SUBNET, ROOT_CANISTER_ID,
};
use ic_nns_governance_api::pb::v1::{NnsFunction, ProposalStatus};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    governance::{submit_external_update_proposal, wait_for_final_state},
    itest_helpers::{state_machine_test_on_nns_subnet, NnsCanisters},
    neuron_helpers::get_neuron_1,
    state_test_helpers::{
        cmc_set_default_authorized_subnetworks, set_up_universal_canister, setup_cycles_ledger,
        setup_nns_canisters, state_machine_builder_for_nns_tests, update_with_sender,
    },
};
use ic_state_machine_tests::{StateMachine, WasmResult};
use ic_test_utilities::universal_canister::{call_args, wasm};
use ic_types::{CanisterId, Cycles, PrincipalId};
use ic_types_test_utils::ids::subnet_test_id;
use icp_ledger::{
    tokens_from_proto, AccountBalanceArgs, AccountIdentifier, BlockIndex, CyclesResponse, Memo,
    NotifyCanisterArgs, SendArgs, Subaccount, Tokens, TransferArgs, TransferError,
    DEFAULT_TRANSFER_FEE,
};
use icrc_ledger_types::icrc1::account::Account;
use std::time::Duration;

/// Test that the CMC's `icp_xdr_conversion_rate` can be updated via Governance
/// proposal.
#[test]
fn test_set_icp_xdr_conversion_rate() {
    state_machine_test_on_nns_subnet(|runtime| async move {
        let nns_init_payload = NnsInitPayloadsBuilder::new()
            .with_initial_invariant_compliant_mutations()
            .with_test_neurons()
            .build();
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        let payload = UpdateIcpXdrConversionRatePayload {
            data_source: "test_set_icp_xdr_conversion_rate".to_string(),
            timestamp_seconds: 1665782922,
            xdr_permyriad_per_icp: 200,
            reason: None,
        };

        set_icp_xdr_conversion_rate(&nns_canisters, payload).await;

        Ok(())
    });
}

async fn set_icp_xdr_conversion_rate(
    nns: &NnsCanisters<'_>,
    payload: UpdateIcpXdrConversionRatePayload,
) {
    let proposal_id: ProposalId = submit_external_update_proposal(
        &nns.governance,
        Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        NeuronId(TEST_NEURON_1_ID),
        NnsFunction::IcpXdrConversionRate,
        payload.clone(),
        "<proposal created by set_icp_xdr_conversion_rate>".to_string(),
        "".to_string(),
    )
    .await;

    // Wait for the proposal to be accepted and executed.
    assert_eq!(
        wait_for_final_state(&nns.governance, proposal_id)
            .await
            .status(),
        ProposalStatus::Executed
    );

    let response: IcpXdrConversionRateCertifiedResponse = nns
        .cycles_minting
        .query_("get_icp_xdr_conversion_rate", candid_one, ())
        .await
        .unwrap();

    assert_eq!(response.data.timestamp_seconds, payload.timestamp_seconds);
    assert_eq!(
        response.data.xdr_permyriad_per_icp,
        payload.xdr_permyriad_per_icp
    );
}

/// Test that we can top-up the Governance canister with cycles when the CMC has
/// a set exchange rate
#[test]
fn test_cmc_mints_cycles_when_cmc_has_exchange_rate() {
    state_machine_test_on_nns_subnet(|runtime| async move {
        let account = AccountIdentifier::new(*TEST_USER1_PRINCIPAL, None);
        let icpts = Tokens::new(100, 0).unwrap();

        // The CMC subaccount to send ICP to. In this test we try to top-up an existing
        // canister, and Governance is simply a convenient pre-existing canister.
        let subaccount: Subaccount = GOVERNANCE_CANISTER_ID.get_ref().into();

        let nns_init_payload = NnsInitPayloadsBuilder::new()
            .with_initial_invariant_compliant_mutations()
            .with_test_neurons()
            .with_ledger_account(account, icpts)
            .build();

        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        let payload = UpdateIcpXdrConversionRatePayload {
            data_source: "test_set_icp_xdr_conversion_rate".to_string(),
            timestamp_seconds: 1665782922,
            xdr_permyriad_per_icp: 20_000,
            reason: None,
        };

        set_icp_xdr_conversion_rate(&nns_canisters, payload).await;

        let governance_status_initial: CanisterStatusResult = nns_canisters
            .root
            .update_(
                "canister_status",
                candid_one,
                CanisterIdRecord::from(GOVERNANCE_CANISTER_ID),
            )
            .await
            .unwrap();
        let governance_cycles_initial = governance_status_initial.cycles;

        // Top-up the Governance canister
        let cycles_response = send_cycles(
            icpts,
            &nns_canisters.ledger,
            MEMO_TOP_UP_CANISTER,
            &subaccount,
        )
        .await;

        match cycles_response {
            CyclesResponse::ToppedUp(_) => (),
            _ => panic!("Failed to top up canister"),
        }

        // Assert that the correct amount of TEST_USER1's ICP was used to create cycles
        let final_balance: Tokens = nns_canisters
            .ledger
            .query_from_sender(
                "account_balance_pb",
                protobuf,
                AccountBalanceArgs { account },
                &Sender::from_keypair(&TEST_USER1_KEYPAIR),
            )
            .await
            .map(tokens_from_proto)
            .unwrap();

        let mut expected_final_balance = icpts;
        expected_final_balance = expected_final_balance
            .checked_sub(&Tokens::new(10, 0).unwrap())
            .unwrap();
        expected_final_balance = expected_final_balance
            .checked_sub(
                &DEFAULT_TRANSFER_FEE
                    .checked_add(&DEFAULT_TRANSFER_FEE)
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(final_balance, expected_final_balance);

        let governance_status_final: CanisterStatusResult = nns_canisters
            .root
            .update_(
                "canister_status",
                candid_one,
                CanisterIdRecord::from(GOVERNANCE_CANISTER_ID),
            )
            .await
            .unwrap();
        let governance_cycles_final = governance_status_final.cycles;

        // Assert that the expected amount of cycles were added to governance.
        assert_eq!(
            governance_cycles_final - governance_cycles_initial,
            Nat::from(20000000000000u64)
        );

        Ok(())
    });
}

/// Sends 10 ICP from `TEST_USER1_PRINCIPAL`s Ledger account to the given
/// subaccount of the CMC, which then, depending on `memo`, either tries to
/// create a canister (aka a "cycles wallet") or top-up the canister whose
/// `CanisterId` corresponds to `subaccount`.
async fn send_cycles(
    initial_icpts: Tokens,
    ledger: &Canister<'_>,
    memo: Memo,
    subaccount: &Subaccount,
) -> CyclesResponse {
    let account = AccountIdentifier::new(*TEST_USER1_PRINCIPAL, None);

    let initial_balance: Tokens = ledger
        .query_from_sender(
            "account_balance_pb",
            protobuf,
            AccountBalanceArgs { account },
            &Sender::from_keypair(&TEST_USER1_KEYPAIR),
        )
        .await
        .map(tokens_from_proto)
        .unwrap();

    assert_eq!(initial_balance, initial_icpts);

    let send_args = SendArgs {
        memo,
        amount: Tokens::new(10, 0).unwrap(),
        fee: DEFAULT_TRANSFER_FEE,
        from_subaccount: None,
        to: AccountIdentifier::new(CYCLES_MINTING_CANISTER_ID.get(), Some(*subaccount)),
        created_at_time: None,
    };

    let block_height: BlockIndex = ledger
        .update_from_sender(
            "send_dfx",
            candid_one,
            send_args.clone(),
            &Sender::from_keypair(&TEST_USER1_KEYPAIR),
        )
        .await
        .unwrap();

    let after_send_balance: Tokens = ledger
        .query_from_sender(
            "account_balance_pb",
            protobuf,
            AccountBalanceArgs { account },
            &Sender::from_keypair(&TEST_USER1_KEYPAIR),
        )
        .await
        .map(tokens_from_proto)
        .unwrap();

    let mut expected_balance = initial_icpts;
    expected_balance = expected_balance
        .checked_sub(&Tokens::new(10, 0).unwrap())
        .unwrap();
    expected_balance = expected_balance.checked_sub(&DEFAULT_TRANSFER_FEE).unwrap();
    assert_eq!(after_send_balance, expected_balance);

    let notify_args = NotifyCanisterArgs::new_from_send(
        &send_args,
        block_height,
        CYCLES_MINTING_CANISTER_ID,
        Some(*subaccount),
    )
    .unwrap();

    let cycles_response: CyclesResponse = ledger
        .update_from_sender(
            "notify_dfx",
            candid_one,
            notify_args.clone(),
            &Sender::from_keypair(&TEST_USER1_KEYPAIR),
        )
        .await
        .unwrap();

    cycles_response
}

fn canister_status(
    machine: &StateMachine,
    sender: PrincipalId,
    target: CanisterId,
) -> Result<CanisterStatusResultV2, String> {
    update_with_sender(
        machine,
        CanisterId::ic_00(),
        "canister_status",
        candid_one,
        &CanisterIdRecord::from(target),
        sender,
    )
}

fn canister_info(
    machine: &StateMachine,
    universal_canister: CanisterId,
    target: CanisterId,
) -> CanisterInfoResponse {
    let canister_info = wasm()
        .call_with_cycles(
            CanisterId::ic_00(),
            "canister_info",
            call_args().other_side(Encode!(&CanisterIdRecord::from(target)).unwrap()),
            0_u128.into(),
        )
        .build();

    if let WasmResult::Reply(res) = machine
        .execute_ingress(universal_canister, "update", canister_info)
        .unwrap()
    {
        Decode!(&res, CanisterInfoResponse).unwrap()
    } else {
        panic!("canister_info failed")
    }
}

/// Test notify_create_canister with different canister settings
#[test]
fn test_cmc_notify_create_with_settings() {
    let account = AccountIdentifier::new(*TEST_USER1_PRINCIPAL, None);
    let icpts = Tokens::new(100, 0).unwrap();
    let neuron = get_neuron_1();

    let state_machine = state_machine_builder_for_nns_tests().build();
    let nns_init_payloads = NnsInitPayloadsBuilder::new()
        .with_test_neurons()
        .with_ledger_account(account, icpts)
        .build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    let subnet_id = state_machine.get_subnet_id();
    cmc_set_default_authorized_subnetworks(
        &state_machine,
        vec![subnet_id],
        neuron.principal_id,
        neuron.neuron_id,
    );
    let universal_canister = set_up_universal_canister(&state_machine, Some(u128::MAX.into()));

    //default settings
    let canister = notify_create_canister(&state_machine, None);
    let status = canister_status(&state_machine, *TEST_USER1_PRINCIPAL, canister).unwrap();
    assert_eq!(status.controllers(), vec![*TEST_USER1_PRINCIPAL]);
    assert_eq!(status.compute_allocation(), 0);
    assert_eq!(status.memory_allocation(), 0);
    assert_eq!(status.freezing_threshold(), 2592000);

    //specify single controller
    let canister = notify_create_canister(
        &state_machine,
        Some(
            CanisterSettingsArgsBuilder::new()
                // TEST_USER1 creates the canister, so to check it didn't default to the caller we use TEST_USER2
                .with_controllers(vec![*TEST_USER2_PRINCIPAL])
                .build(),
        ),
    );
    let status = canister_status(&state_machine, *TEST_USER2_PRINCIPAL, canister).unwrap();
    assert_eq!(status.controllers(), vec![*TEST_USER2_PRINCIPAL]);
    assert_eq!(status.compute_allocation(), 0);
    assert_eq!(status.memory_allocation(), 0);
    assert_eq!(status.freezing_threshold(), 2592000);

    //specify multiple controllers
    let mut specified_controllers = vec![
        *TEST_USER1_PRINCIPAL,
        *TEST_USER2_PRINCIPAL,
        *TEST_USER3_PRINCIPAL,
    ];
    specified_controllers.sort();
    let canister = notify_create_canister(
        &state_machine,
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_controllers(specified_controllers.clone())
                .build(),
        ),
    );
    let status = canister_status(&state_machine, *TEST_USER1_PRINCIPAL, canister).unwrap();
    let mut canister_controllers = status.controllers();
    canister_controllers.sort();
    assert_eq!(specified_controllers, canister_controllers);
    assert_eq!(status.compute_allocation(), 0);
    assert_eq!(status.memory_allocation(), 0);
    assert_eq!(status.freezing_threshold(), 2592000);

    //specify no controller
    let canister = notify_create_canister(
        &state_machine,
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_controllers(vec![])
                .build(),
        ),
    );
    let info = canister_info(&state_machine, universal_canister, canister);
    assert!(info.controllers().is_empty());

    //specify compute allocation
    let canister = notify_create_canister(
        &state_machine,
        Some(dbg!(CanisterSettingsArgsBuilder::new()
            .with_compute_allocation(7)
            .build())),
    );
    let status = dbg!(canister_status(&state_machine, *TEST_USER1_PRINCIPAL, canister).unwrap());
    assert_eq!(status.controllers(), vec![*TEST_USER1_PRINCIPAL]);
    assert_eq!(status.compute_allocation(), 7);
    assert_eq!(status.memory_allocation(), 0);
    assert_eq!(status.freezing_threshold(), 2592000);

    //specify freezing threshold
    let canister = notify_create_canister(
        &state_machine,
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_freezing_threshold(7)
                .build(),
        ),
    );
    let status = canister_status(&state_machine, *TEST_USER1_PRINCIPAL, canister).unwrap();
    assert_eq!(status.controllers(), vec![*TEST_USER1_PRINCIPAL]);
    assert_eq!(status.compute_allocation(), 0);
    assert_eq!(status.memory_allocation(), 0);
    assert_eq!(status.freezing_threshold(), 7);

    //specify memory allocation
    let canister = notify_create_canister(
        &state_machine,
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_memory_allocation(7)
                .build(),
        ),
    );
    let status = canister_status(&state_machine, *TEST_USER1_PRINCIPAL, canister).unwrap();
    assert_eq!(status.controllers(), vec![*TEST_USER1_PRINCIPAL]);
    assert_eq!(status.compute_allocation(), 0);
    assert_eq!(status.memory_allocation(), 7);
    assert_eq!(status.freezing_threshold(), 2592000);
}

fn canister_cycles_balance(
    state_machine: &StateMachine,
    canister: CanisterId,
    controller: PrincipalId,
) -> u128 {
    canister_status(state_machine, controller, canister)
        .unwrap()
        .cycles()
}

#[test]
fn test_cmc_create_canister_refunds() {
    let account = AccountIdentifier::new(*TEST_USER1_PRINCIPAL, None);
    let icpts = Tokens::new(100, 0).unwrap();
    let neuron = get_neuron_1();

    let state_machine = state_machine_builder_for_nns_tests().build();
    let nns_init_payloads = NnsInitPayloadsBuilder::new()
        .with_test_neurons()
        .with_ledger_account(account, icpts)
        .build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    let subnet_id = state_machine.get_subnet_id();
    cmc_set_default_authorized_subnetworks(
        &state_machine,
        vec![subnet_id],
        neuron.principal_id,
        neuron.neuron_id,
    );
    let cmc_cycles_balance = || {
        canister_cycles_balance(
            &state_machine,
            CYCLES_MINTING_CANISTER_ID,
            ROOT_CANISTER_ID.get(),
        )
    };

    assert_eq!(cmc_cycles_balance(), 0);

    let universal_canister = set_up_universal_canister(&state_machine, Some(u128::MAX.into()));

    let uc_cycles_balance = || state_machine.cycle_balance(universal_canister);

    //default settings
    let canister = cmc_create_canister_with_cycles(
        &state_machine,
        universal_canister,
        None,
        None,
        10_000_000_000_000,
    )
    .unwrap();
    let status = canister_status(&state_machine, universal_canister.get(), canister).unwrap();
    assert_eq!(status.controllers(), vec![universal_canister.get()]);

    // We minted, then used, then accepted some cycles.
    assert_eq!(cmc_cycles_balance(), 10_000_000_000_000);
    assert_eq!(uc_cycles_balance(), u128::MAX - 10_000_000_000_000);

    // Create canister on non-existing subnet type
    let error = cmc_create_canister_with_cycles(
        &state_machine,
        universal_canister,
        None,
        Some("fake_subnet_type".to_string()),
        10_000_000_000_000,
    )
    .unwrap_err();

    assert_eq!(
        error,
        CreateCanisterError::Refunded {
            refund_amount: 9_999_900_000_000,
            create_error: "Provided subnet type fake_subnet_type does not exist".to_string()
        }
    );

    assert_eq!(cmc_cycles_balance(), 10_000_100_000_000);
    assert_eq!(uc_cycles_balance(), u128::MAX - 10_000_100_000_000);

    println!("{:?}", error);

    //default settings
    let canister = cmc_create_canister_with_cycles(
        &state_machine,
        universal_canister,
        None,
        None,
        11_000_000_000_000,
    )
    .unwrap();
    let status = canister_status(&state_machine, universal_canister.get(), canister).unwrap();
    assert_eq!(status.controllers(), vec![universal_canister.get()]);

    assert_eq!(cmc_cycles_balance(), 11_000_000_000_000);
    assert_eq!(uc_cycles_balance(), u128::MAX - 21_000_100_000_000);
}

/// Test create_canister with different canister settings
#[test]
fn test_cmc_cycles_create_with_settings() {
    let account = AccountIdentifier::new(*TEST_USER1_PRINCIPAL, None);
    let icpts = Tokens::new(100, 0).unwrap();
    let neuron = get_neuron_1();

    let state_machine = state_machine_builder_for_nns_tests().build();
    let nns_init_payloads = NnsInitPayloadsBuilder::new()
        .with_test_neurons()
        .with_ledger_account(account, icpts)
        .build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    let subnet_id = state_machine.get_subnet_id();
    cmc_set_default_authorized_subnetworks(
        &state_machine,
        vec![subnet_id],
        neuron.principal_id,
        neuron.neuron_id,
    );
    let universal_canister = set_up_universal_canister(&state_machine, Some(u128::MAX.into()));

    //default settings
    let canister = cmc_create_canister_with_cycles(
        &state_machine,
        universal_canister,
        None,
        None,
        10_000_000_000_000,
    )
    .unwrap();
    let status = canister_status(&state_machine, universal_canister.get(), canister).unwrap();
    assert_eq!(status.controllers(), vec![universal_canister.get()]);
    assert_eq!(status.compute_allocation(), 0);
    assert_eq!(status.memory_allocation(), 0);
    assert_eq!(status.freezing_threshold(), 2592000);

    //specify single controller
    let canister = cmc_create_canister_with_cycles(
        &state_machine,
        universal_canister,
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_controllers(vec![*TEST_USER1_PRINCIPAL])
                .build(),
        ),
        None,
        10_000_000_000_000,
    )
    .unwrap();
    let status = canister_status(&state_machine, *TEST_USER1_PRINCIPAL, canister).unwrap();
    assert_eq!(status.controllers(), vec![*TEST_USER1_PRINCIPAL]);
    assert_eq!(status.compute_allocation(), 0);
    assert_eq!(status.memory_allocation(), 0);
    assert_eq!(status.freezing_threshold(), 2592000);

    //specify multiple controllers
    let mut specified_controllers = vec![
        *TEST_USER1_PRINCIPAL,
        *TEST_USER2_PRINCIPAL,
        *TEST_USER3_PRINCIPAL,
    ];
    specified_controllers.sort();
    let canister = cmc_create_canister_with_cycles(
        &state_machine,
        universal_canister,
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_controllers(specified_controllers.clone())
                .build(),
        ),
        None,
        10_000_000_000_000,
    )
    .unwrap();
    let status = canister_status(&state_machine, *TEST_USER1_PRINCIPAL, canister).unwrap();
    let mut canister_controllers = status.controllers();
    canister_controllers.sort();
    assert_eq!(specified_controllers, canister_controllers);
    assert_eq!(status.compute_allocation(), 0);
    assert_eq!(status.memory_allocation(), 0);
    assert_eq!(status.freezing_threshold(), 2592000);

    //specify no controller
    let canister = cmc_create_canister_with_cycles(
        &state_machine,
        universal_canister,
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_controllers(vec![])
                .build(),
        ),
        None,
        10_000_000_000_000,
    )
    .unwrap();
    let info = canister_info(&state_machine, universal_canister, canister);
    assert!(info.controllers().is_empty());

    //specify compute allocation
    let canister = cmc_create_canister_with_cycles(
        &state_machine,
        universal_canister,
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_controllers(vec![*TEST_USER1_PRINCIPAL])
                .with_compute_allocation(7)
                .build(),
        ),
        None,
        10_000_000_000_000,
    )
    .unwrap();
    let status = canister_status(&state_machine, *TEST_USER1_PRINCIPAL, canister).unwrap();
    assert_eq!(status.controllers(), vec![*TEST_USER1_PRINCIPAL]);
    assert_eq!(status.compute_allocation(), 7);
    assert_eq!(status.memory_allocation(), 0);
    assert_eq!(status.freezing_threshold(), 2592000);

    //specify freezing threshold
    let canister = cmc_create_canister_with_cycles(
        &state_machine,
        universal_canister,
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_controllers(vec![*TEST_USER1_PRINCIPAL])
                .with_freezing_threshold(7)
                .build(),
        ),
        None,
        10_000_000_000_000,
    )
    .unwrap();
    let status = canister_status(&state_machine, *TEST_USER1_PRINCIPAL, canister).unwrap();
    assert_eq!(status.controllers(), vec![*TEST_USER1_PRINCIPAL]);
    assert_eq!(status.compute_allocation(), 0);
    assert_eq!(status.memory_allocation(), 0);
    assert_eq!(status.freezing_threshold(), 7);

    //specify memory allocation
    let canister = cmc_create_canister_with_cycles(
        &state_machine,
        universal_canister,
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_controllers(vec![*TEST_USER1_PRINCIPAL])
                .with_memory_allocation(7)
                .build(),
        ),
        None,
        10_000_000_000_000,
    )
    .unwrap();
    let status = canister_status(&state_machine, *TEST_USER1_PRINCIPAL, canister).unwrap();
    assert_eq!(status.controllers(), vec![*TEST_USER1_PRINCIPAL]);
    assert_eq!(status.compute_allocation(), 0);
    assert_eq!(status.memory_allocation(), 7);
    assert_eq!(status.freezing_threshold(), 2592000);

    let universal_status = canister_status(
        &state_machine,
        PrincipalId::new_anonymous(),
        universal_canister,
    )
    .unwrap();
    let universal_cycles = universal_status.cycles();

    // Creating a canister with obviously too few cycles returns all cycles to the caller
    let error =
        cmc_create_canister_with_cycles(&state_machine, universal_canister, None, None, 100)
            .unwrap_err();
    let CreateCanisterError::Refunded {
        create_error,
        refund_amount: 100,
    } = error
    else {
        panic!("Refund failed: {:?}", error)
    };
    assert!(create_error.contains("Insufficient cycles attached"));
    assert_eq!(
        universal_cycles,
        canister_status(
            &state_machine,
            PrincipalId::new_anonymous(),
            universal_canister
        )
        .unwrap()
        .cycles()
    );

    // Refund works when requesting a non-existent subnet type but charges some penalty
    let error = cmc_create_canister_with_cycles(
        &state_machine,
        universal_canister,
        None,
        Some("fake_subnet_type".to_string()),
        10_000_000_000_000,
    )
    .unwrap_err();
    let CreateCanisterError::Refunded {
        refund_amount,
        create_error,
    } = error
    else {
        panic!("Refund failed: {:?}", error)
    };
    assert!(create_error.contains("subnet type fake_subnet_type does not exist"));
    assert_eq!(
        refund_amount,
        10_000_000_000_000 - BAD_REQUEST_CYCLES_PENALTY,
        "Refund was not BAD_REQUEST_CYCLES_PENALTY smaller than initial send amount"
    );
    assert_eq!(
        universal_cycles - BAD_REQUEST_CYCLES_PENALTY,
        canister_status(
            &state_machine,
            PrincipalId::new_anonymous(),
            universal_canister
        )
        .unwrap()
        .cycles(),
        "Penalty was not BAD_REQUEST_CYCLES_PENALTY"
    );
}

fn send_transfer(env: &StateMachine, arg: &TransferArgs) -> Result<BlockIndex, TransferError> {
    let ledger = CanisterId::from_u64(LEDGER_CANISTER_INDEX_IN_NNS_SUBNET);
    let from = *TEST_USER1_PRINCIPAL;
    Decode!(
        &env.execute_ingress_as(
            from,
            ledger,
            "transfer",
            Encode!(arg)
            .unwrap()
        )
        .expect("failed to transfer funds")
        .bytes(),
        Result<BlockIndex, TransferError>
    )
    .expect("failed to decode transfer response")
}

/// Sends 10 ICP from `TEST_USER1_PRINCIPAL`s Ledger account to the given
/// subaccount of the CMC, which then tries to create a canister with the provided settings.
fn notify_create_canister(
    state_machine: &StateMachine,
    settings: Option<Ic00CanisterSettingsArgs>,
) -> CanisterId {
    let transfer_args = TransferArgs {
        memo: MEMO_CREATE_CANISTER,
        amount: Tokens::new(10, 0).unwrap(),
        fee: Tokens::from_e8s(10_000),
        from_subaccount: None,
        to: AccountIdentifier::new(
            CYCLES_MINTING_CANISTER_ID.get(),
            Some(Subaccount::from(&TEST_USER1_PRINCIPAL.clone())),
        )
        .to_address(),
        created_at_time: None,
    };

    let block_index = send_transfer(state_machine, &transfer_args).expect("transfer failed");
    #[allow(deprecated)]
    let notify_args = NotifyCreateCanister {
        block_index,
        controller: *TEST_USER1_PRINCIPAL,
        subnet_type: None,
        subnet_selection: None,
        settings: settings.map(CanisterSettingsArgs::from),
    };

    if let WasmResult::Reply(res) = state_machine
        .execute_ingress_as(
            *TEST_USER1_PRINCIPAL,
            CYCLES_MINTING_CANISTER_ID,
            "notify_create_canister",
            Encode!(&notify_args).unwrap(),
        )
        .unwrap()
    {
        Decode!(&res, Result<CanisterId, NotifyError>)
            .unwrap()
            .expect("notify_create failed")
    } else {
        panic!("notify rejected")
    }
}

/// Sends `amount` ICP from `TEST_USER1_PRINCIPAL`s ledger account to the given
/// subaccount of the CMC, which then tries to mint cycles with the provided settings.
fn notify_mint_cycles(
    state_machine: &StateMachine,
    amount: Tokens,
    to_subaccount: Option<[u8; 32]>,
    deposit_memo: Option<Vec<u8>>,
) -> Result<NotifyMintCyclesSuccess, NotifyError> {
    let transfer_args = TransferArgs {
        memo: MEMO_MINT_CYCLES,
        amount,
        fee: Tokens::from_e8s(10_000),
        from_subaccount: None,
        to: AccountIdentifier::new(
            CYCLES_MINTING_CANISTER_ID.get(),
            Some(Subaccount::from(&TEST_USER1_PRINCIPAL.clone())),
        )
        .to_address(),
        created_at_time: None,
    };

    let block_index = send_transfer(state_machine, &transfer_args).expect("transfer failed");
    let notify_args = NotifyMintCyclesArg {
        block_index,
        to_subaccount,
        deposit_memo,
    };

    if let WasmResult::Reply(res) = state_machine
        .execute_ingress_as(
            *TEST_USER1_PRINCIPAL,
            CYCLES_MINTING_CANISTER_ID,
            "notify_mint_cycles",
            Encode!(&notify_args).unwrap(),
        )
        .unwrap()
    {
        Decode!(&res, Result<NotifyMintCyclesSuccess, NotifyError>).unwrap()
    } else {
        panic!("notify rejected")
    }
}

fn cycles_ledger_balance_of(state_machine: &StateMachine, account: Account) -> u128 {
    if let WasmResult::Reply(res) = state_machine
        .execute_ingress(
            CYCLES_LEDGER_CANISTER_ID,
            "icrc1_balance_of",
            Encode!(&account).unwrap(),
        )
        .unwrap()
    {
        Decode!(&res, u128).unwrap()
    } else {
        panic!("icrc1_balance_of rejected")
    }
}

fn cmc_create_canister_with_cycles(
    state_machine: &StateMachine,
    universal_canister: CanisterId,
    settings: Option<Ic00CanisterSettingsArgs>,
    subnet_type: Option<String>,
    cycles: u128,
) -> Result<CanisterId, CreateCanisterError> {
    #[allow(deprecated)]
    let create_args = Encode!(&CreateCanister {
        settings: settings.map(CanisterSettingsArgs::from),
        subnet_type,
        subnet_selection: None,
    })
    .unwrap();

    let create_canister = wasm()
        .call_with_cycles(
            CYCLES_MINTING_CANISTER_ID,
            "create_canister",
            call_args().other_side(create_args),
            cycles.into(),
        )
        .build();

    if let WasmResult::Reply(res) = state_machine
        .execute_ingress(universal_canister, "update", create_canister)
        .unwrap()
    {
        Decode!(&res, Result<CanisterId, CreateCanisterError>).unwrap()
    } else {
        panic!("create_canister rejected")
    }
}

async fn update_subnet_type(nns: &NnsCanisters<'_>, payload: UpdateSubnetTypeArgs) {
    let proposal_id: ProposalId = submit_external_update_proposal(
        &nns.governance,
        Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        NeuronId(TEST_NEURON_1_ID),
        NnsFunction::UpdateSubnetType,
        payload.clone(),
        "<proposal created by update_subnet_type>".to_string(),
        "".to_string(),
    )
    .await;

    // Wait for the proposal to be accepted and executed.
    assert_eq!(
        wait_for_final_state(&nns.governance, proposal_id)
            .await
            .status(),
        ProposalStatus::Executed
    );
}

#[test]
fn test_update_subnet_type() {
    state_machine_test_on_nns_subnet(|runtime| async move {
        let nns_init_payload = NnsInitPayloadsBuilder::new()
            .with_initial_invariant_compliant_mutations()
            .with_test_neurons()
            .build();
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        let payload = UpdateSubnetTypeArgs::Add("Fiduciary".to_string());

        update_subnet_type(&nns_canisters, payload).await;

        let response: SubnetTypesToSubnetsResponse = nns_canisters
            .cycles_minting
            .query_("get_subnet_types_to_subnets", candid_one, ())
            .await
            .unwrap();
        assert_eq!(
            response,
            SubnetTypesToSubnetsResponse {
                data: vec![("Fiduciary".to_string(), vec![])]
            }
        );

        Ok(())
    });
}

async fn change_subnet_type_assignment(
    nns: &NnsCanisters<'_>,
    payload: ChangeSubnetTypeAssignmentArgs,
) {
    let proposal_id: ProposalId = submit_external_update_proposal(
        &nns.governance,
        Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        NeuronId(TEST_NEURON_1_ID),
        NnsFunction::ChangeSubnetTypeAssignment,
        payload.clone(),
        "<proposal created by change_subnet_type_assignment>".to_string(),
        "".to_string(),
    )
    .await;

    // Wait for the proposal to be accepted and executed.
    assert_eq!(
        wait_for_final_state(&nns.governance, proposal_id)
            .await
            .status(),
        ProposalStatus::Executed
    );
}

#[test]
fn test_change_subnet_type_assignment() {
    state_machine_test_on_nns_subnet(|runtime| async move {
        let nns_init_payload = NnsInitPayloadsBuilder::new()
            .with_initial_invariant_compliant_mutations()
            .with_test_neurons()
            .build();
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        let type1 = "Type1".to_string();
        let type2 = "Type2".to_string();
        update_subnet_type(&nns_canisters, UpdateSubnetTypeArgs::Add(type1.clone())).await;
        update_subnet_type(&nns_canisters, UpdateSubnetTypeArgs::Add(type2.clone())).await;

        let subnet1 = subnet_test_id(0);
        let subnet2 = subnet_test_id(1);
        let subnet3 = subnet_test_id(2);

        let payload = ChangeSubnetTypeAssignmentArgs::Add(SubnetListWithType {
            subnets: vec![subnet1, subnet2],
            subnet_type: type1.clone(),
        });
        change_subnet_type_assignment(&nns_canisters, payload).await;

        let payload = ChangeSubnetTypeAssignmentArgs::Add(SubnetListWithType {
            subnets: vec![subnet3],
            subnet_type: type2.clone(),
        });
        change_subnet_type_assignment(&nns_canisters, payload).await;

        let response: SubnetTypesToSubnetsResponse = nns_canisters
            .cycles_minting
            .query_("get_subnet_types_to_subnets", candid_one, ())
            .await
            .unwrap();
        assert_eq!(
            response,
            SubnetTypesToSubnetsResponse {
                data: vec![
                    (type1.clone(), vec![subnet1, subnet2]),
                    (type2.clone(), vec![subnet3])
                ]
            }
        );

        let payload = ChangeSubnetTypeAssignmentArgs::Remove(SubnetListWithType {
            subnets: vec![subnet2],
            subnet_type: type1.clone(),
        });
        change_subnet_type_assignment(&nns_canisters, payload).await;

        let response: SubnetTypesToSubnetsResponse = nns_canisters
            .cycles_minting
            .query_("get_subnet_types_to_subnets", candid_one, ())
            .await
            .unwrap();
        assert_eq!(
            response,
            SubnetTypesToSubnetsResponse {
                data: vec![(type1, vec![subnet1]), (type2, vec![subnet3])]
            }
        );

        Ok(())
    });
}

#[test]
fn cmc_notify_mint_cycles() {
    let account = AccountIdentifier::new(*TEST_USER1_PRINCIPAL, None);
    let main_account = Account {
        owner: (*TEST_USER1_PRINCIPAL).into(),
        subaccount: None,
    };
    let icpts = Tokens::new(100, 0).unwrap();

    let state_machine = state_machine_builder_for_nns_tests().build();
    let nns_init_payloads = NnsInitPayloadsBuilder::new()
        .with_test_neurons()
        .with_ledger_account(account, icpts)
        .build();
    setup_nns_canisters(&state_machine, nns_init_payloads);
    setup_cycles_ledger(&state_machine);
    assert_eq!(cycles_ledger_balance_of(&state_machine, main_account), 0);

    // default notify_mint_cycles
    notify_mint_cycles(
        &state_machine,
        Tokens::new(1, 0).unwrap(),
        main_account.subaccount,
        Some(vec![1u8; 32]),
    )
    .unwrap();
    assert_eq!(
        cycles_ledger_balance_of(&state_machine, main_account),
        100_000_000_000_000
    );

    // to subaccount
    let subaccount_1 = Account {
        owner: (*TEST_USER1_PRINCIPAL).into(),
        subaccount: Some([1; 32]),
    };
    notify_mint_cycles(
        &state_machine,
        Tokens::new(2, 0).unwrap(),
        subaccount_1.subaccount,
        None,
    )
    .unwrap();
    assert_eq!(
        cycles_ledger_balance_of(&state_machine, subaccount_1),
        200_000_000_000_000
    );

    // insufficient amount
    let notify_mint_result =
        notify_mint_cycles(&state_machine, Tokens::new(0, 1).unwrap(), None, None).unwrap_err();
    let NotifyError::Refunded {
        reason,
        block_index,
    } = notify_mint_result
    else {
        panic!("Not refunded.")
    };
    assert!(reason.contains(
        "The requested amount 1000000 to be deposited is less than the cycles ledger fee"
    ));
    assert_eq!(block_index, None); // Amount too small to refund

    // bad memo
    let transfer_args = TransferArgs {
        memo: icp_ledger::Memo(0x5214), // wrong memo
        amount: Tokens::new(3, 0).unwrap(),
        fee: Tokens::from_e8s(10_000),
        from_subaccount: None,
        to: AccountIdentifier::new(
            CYCLES_MINTING_CANISTER_ID.get(),
            Some(Subaccount::from(&TEST_USER1_PRINCIPAL.clone())),
        )
        .to_address(),
        created_at_time: None,
    };
    let block_index = send_transfer(&state_machine, &transfer_args).expect("transfer failed");
    let notify_args = NotifyMintCyclesArg {
        block_index,
        to_subaccount: None,
        deposit_memo: None,
    };
    let WasmResult::Reply(res) = state_machine
        .execute_ingress_as(
            *TEST_USER1_PRINCIPAL,
            CYCLES_MINTING_CANISTER_ID,
            "notify_mint_cycles",
            Encode!(&notify_args).unwrap(),
        )
        .unwrap()
    else {
        panic!("notify rejected")
    };
    assert_matches!(
        Decode!(&res, Result<NotifyMintCyclesSuccess, NotifyError>).unwrap(),
        Err(NotifyError::InvalidTransaction(_))
    );

    // double notify
    let transfer_args = TransferArgs {
        memo: MEMO_MINT_CYCLES,
        amount: Tokens::new(5, 0).unwrap(),
        fee: Tokens::from_e8s(10_000),
        from_subaccount: None,
        to: AccountIdentifier::new(
            CYCLES_MINTING_CANISTER_ID.get(),
            Some(Subaccount::from(&TEST_USER1_PRINCIPAL.clone())),
        )
        .to_address(),
        created_at_time: None,
    };
    let block_index = send_transfer(&state_machine, &transfer_args).expect("transfer failed");
    let notify_args = NotifyMintCyclesArg {
        block_index,
        to_subaccount: None,
        deposit_memo: None,
    };
    let WasmResult::Reply(res) = state_machine
        .execute_ingress_as(
            *TEST_USER1_PRINCIPAL,
            CYCLES_MINTING_CANISTER_ID,
            "notify_mint_cycles",
            Encode!(&notify_args).unwrap(),
        )
        .unwrap()
    else {
        panic!("notify rejected")
    };
    let Ok(NotifyMintCyclesSuccess {
        block_index,
        minted,
        balance,
    }) = Decode!(&res, Result<NotifyMintCyclesSuccess, NotifyError>).unwrap()
    else {
        panic!("failed to mint cycles");
    };
    let WasmResult::Reply(res) = state_machine
        .execute_ingress_as(
            *TEST_USER1_PRINCIPAL,
            CYCLES_MINTING_CANISTER_ID,
            "notify_mint_cycles",
            Encode!(&notify_args).unwrap(),
        )
        .unwrap()
    else {
        panic!("notify rejected")
    };
    let Ok(NotifyMintCyclesSuccess {
        block_index: block_index_duplicate,
        minted: minted_duplicate,
        balance: balance_duplicate,
    }) = Decode!(&res, Result<NotifyMintCyclesSuccess, NotifyError>).unwrap()
    else {
        panic!("failed to mint cycles");
    };
    assert_eq!(block_index, block_index_duplicate);
    assert_eq!(minted, minted_duplicate);
    assert_eq!(balance, balance_duplicate);

    // Deposit memo is too long.
    let transfer_args = TransferArgs {
        memo: MEMO_MINT_CYCLES,
        amount: Tokens::new(3, 0).unwrap(),
        fee: Tokens::from_e8s(10_000),
        from_subaccount: None,
        to: AccountIdentifier::new(
            CYCLES_MINTING_CANISTER_ID.get(),
            Some(Subaccount::from(&TEST_USER1_PRINCIPAL.clone())),
        )
        .to_address(),
        created_at_time: None,
    };
    let block_index = send_transfer(&state_machine, &transfer_args).expect("transfer failed");
    let notify_args = NotifyMintCyclesArg {
        block_index,
        to_subaccount: None,
        deposit_memo: Some(vec![0; 100]),
    };
    let WasmResult::Reply(res) = state_machine
        .execute_ingress_as(
            *TEST_USER1_PRINCIPAL,
            CYCLES_MINTING_CANISTER_ID,
            "notify_mint_cycles",
            Encode!(&notify_args).unwrap(),
        )
        .unwrap()
    else {
        panic!("notify rejected")
    };
    let response = Decode!(&res, Result<NotifyMintCyclesSuccess, NotifyError>).unwrap();
    match response {
        Err(NotifyError::Other {
            error_code,
            error_message,
        }) => {
            assert_eq!(error_code, NotifyErrorCode::DepositMemoTooLong as u64);
            assert!(error_message.contains("exceeds the maximum length"));
        }
        _ => panic!("Unexpected response: {:?}", response),
    }
}

/// Sends `amount` ICP from `TEST_USER1_PRINCIPAL`s ledger account to the given
/// subaccount of the CMC, which then tries to top up the canister.
fn notify_top_up(
    state_machine: &StateMachine,
    canister_id: CanisterId,
    amount: Tokens,
) -> Result<Cycles, NotifyError> {
    let transfer_args = TransferArgs {
        memo: MEMO_TOP_UP_CANISTER,
        amount,
        fee: Tokens::from_e8s(10_000),
        from_subaccount: None,
        to: AccountIdentifier::new(
            CYCLES_MINTING_CANISTER_ID.get(),
            Some(Subaccount::from(&canister_id.get())),
        )
        .to_address(),
        created_at_time: None,
    };

    let block_index = send_transfer(state_machine, &transfer_args).expect("transfer failed");
    let notify_args = NotifyTopUp {
        block_index,
        canister_id,
    };

    if let WasmResult::Reply(res) = state_machine
        .execute_ingress_as(
            *TEST_USER1_PRINCIPAL,
            CYCLES_MINTING_CANISTER_ID,
            "notify_top_up",
            Encode!(&notify_args).unwrap(),
        )
        .unwrap()
    {
        Decode!(&res, Result<Cycles, NotifyError>).unwrap()
    } else {
        panic!("notify rejected")
    }
}

fn total_cycles_minted(state_machine: &StateMachine) -> u64 {
    use prost::Message;

    if let WasmResult::Reply(res) = state_machine
        .query(CYCLES_MINTING_CANISTER_ID, "total_cycles_minted", vec![])
        .unwrap()
    {
        u64::decode(&res[..]).unwrap()
    } else {
        panic!("total_cycles_minted rejected")
    }
}

#[test]
fn cmc_notify_top_up_valid() {
    let account = AccountIdentifier::new(*TEST_USER1_PRINCIPAL, None);
    let icpts = Tokens::new(100, 0).unwrap();

    let state_machine = state_machine_builder_for_nns_tests().build();
    let nns_init_payloads = NnsInitPayloadsBuilder::new()
        .with_test_neurons()
        .with_ledger_account(account, icpts)
        .build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    let total_minted_before = total_cycles_minted(&state_machine);
    let cycles = notify_top_up(
        &state_machine,
        GOVERNANCE_CANISTER_ID,
        Tokens::new(1, 0).unwrap(),
    )
    .unwrap();
    let total_minted_after = total_cycles_minted(&state_machine);

    assert_eq!(cycles, Cycles::new(100_000_000_000_000u128));
    assert_eq!(
        total_minted_after - total_minted_before,
        100_000_000_000_000
    );
}

#[test]
fn cmc_notify_top_up_invalid() {
    let account = AccountIdentifier::new(*TEST_USER1_PRINCIPAL, None);
    let icpts = Tokens::new(100, 0).unwrap();
    let invalid_canister_id = CanisterId::from_u64(123_456_789);

    let state_machine = state_machine_builder_for_nns_tests().build();
    let nns_init_payloads = NnsInitPayloadsBuilder::new()
        .with_test_neurons()
        .with_ledger_account(account, icpts)
        .build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    let total_minted_before = total_cycles_minted(&state_machine);
    let error = notify_top_up(
        &state_machine,
        invalid_canister_id,
        Tokens::new(1, 0).unwrap(),
    )
    .unwrap_err();
    let total_minted_after = total_cycles_minted(&state_machine);
    assert_matches!(error, NotifyError::Refunded { .. });
    assert_eq!(
        total_minted_after - total_minted_before,
        100_000_000_000_000
    );

    let total_minted_before = total_cycles_minted(&state_machine);
    let error = notify_top_up(
        &state_machine,
        invalid_canister_id,
        Tokens::new(1, 0).unwrap(),
    )
    .unwrap_err();
    let total_minted_after = total_cycles_minted(&state_machine);
    assert_matches!(error, NotifyError::Refunded { .. });
    assert_eq!(total_minted_after - total_minted_before, 0);
}

#[test]
fn cmc_notify_top_up_rate_limited() {
    let account = AccountIdentifier::new(*TEST_USER1_PRINCIPAL, None);
    let icpts = Tokens::new(1_000, 0).unwrap();
    let state_machine = state_machine_builder_for_nns_tests().build();
    let nns_init_payloads = NnsInitPayloadsBuilder::new()
        .with_test_neurons()
        .with_ledger_account(account, icpts)
        .build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    // First top-up should succeed since it's 30P - less than the 50P/hr limit.
    let cycles = notify_top_up(
        &state_machine,
        GOVERNANCE_CANISTER_ID,
        Tokens::new(300, 0).unwrap(),
    )
    .unwrap();
    assert_eq!(cycles, Cycles::new(30_000_000_000_000_000u128));

    // Second top-up should also succeed after 1 hour.
    state_machine.advance_time(Duration::from_secs(4000));
    let cycles = notify_top_up(
        &state_machine,
        GOVERNANCE_CANISTER_ID,
        Tokens::new(300, 0).unwrap(),
    )
    .unwrap();
    assert_eq!(cycles, Cycles::new(30_000_000_000_000_000u128));

    // Third top-up should fail since the rate limit is 50P cycles per hour, and less than an hour
    // has passed.
    state_machine.advance_time(Duration::from_secs(3000));
    let error = notify_top_up(
        &state_machine,
        GOVERNANCE_CANISTER_ID,
        Tokens::new(300, 0).unwrap(),
    )
    .unwrap_err();
    assert_matches!(error, NotifyError::Refunded { reason, .. } if reason.contains("try again later"));
}

#[test]
fn cmc_notify_top_up_not_rate_limited_by_invalid_top_up() {
    let good_account = AccountIdentifier::new(*TEST_USER1_PRINCIPAL, None);
    let good_account_icpts = Tokens::new(10, 0).unwrap();
    let bad_account = AccountIdentifier::new(*TEST_USER2_PRINCIPAL, None);
    let bad_account_icpts = Tokens::new(1, 0).unwrap();

    let state_machine = state_machine_builder_for_nns_tests().build();
    let nns_init_payloads = NnsInitPayloadsBuilder::new()
        .with_test_neurons()
        .with_ledger_accounts(vec![
            (good_account, good_account_icpts),
            (bad_account, bad_account_icpts),
        ])
        .build();
    setup_nns_canisters(&state_machine, nns_init_payloads);
    let non_existing_canister_id = CanisterId::from_u64(123_456_789);

    // First make sure topping up 400T cylces on a valid canister works.
    let cycles = notify_top_up(
        &state_machine,
        GOVERNANCE_CANISTER_ID,
        Tokens::new(4, 0).unwrap(),
    )
    .unwrap();
    assert_eq!(cycles, Cycles::new(400_000_000_000_000u128));

    // Advance time by 1 hour to make sure the rate limit is reset.
    state_machine.advance_time(Duration::from_secs(60 * 60));

    // Now the attack begines - the bad account sends 0.69 tokens per 5 seconds to the non-existing
    // canister, which makes it 69T * 12 * 60 = 49.68P cycles per hour, close to the 50P limit,
    // while getting the 0.69 tokens back each time (the account only has 1 token in the
    // begingging).
    for _ in 0..(12 * 60) {
        let error = notify_top_up(
            &state_machine,
            non_existing_canister_id,
            Tokens::from_e8s(69_000_000),
        )
        .unwrap_err();
        assert_matches!(error, NotifyError::Refunded { .. });
        state_machine.advance_time(Duration::from_secs(5));
    }

    // Now the good account tries to top up 400T cycles on the governance canister again, which
    // should still succeed.
    let cycles = notify_top_up(
        &state_machine,
        GOVERNANCE_CANISTER_ID,
        Tokens::new(4, 0).unwrap(),
    )
    .unwrap();
    assert_eq!(cycles, Cycles::new(400_000_000_000_000u128));
}
