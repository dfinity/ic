use assert_matches::assert_matches;
use candid::{Decode, Encode, Nat, Principal};
use canister_test::Canister;
use cycles_minting_canister::{
    AuthorizedSubnetsResponse, BAD_REQUEST_CYCLES_PENALTY, ChangeSubnetTypeAssignmentArgs,
    CreateCanister, CreateCanisterError, MEANINGFUL_MEMOS, MEMO_CREATE_CANISTER, MEMO_MINT_CYCLES,
    MEMO_TOP_UP_CANISTER, NotifyCreateCanister, NotifyError, NotifyErrorCode, NotifyMintCyclesArg,
    NotifyMintCyclesSuccess, NotifyTopUp, SubnetListWithType, SubnetTypesToSubnetsResponse,
    UpdateSubnetTypeArgs,
};
use dfn_candid::candid_one;
use dfn_protobuf::protobuf;
use ic_canister_client_sender::Sender;
use ic_ledger_core::tokens::CheckedSub;
// TODO(NNS1-3249): remove temporary alias `Ic00CanisterSettingsArgs`.
use ic_management_canister_types_private::{
    CanisterIdRecord, CanisterInfoResponse, CanisterSettingsArgs as Ic00CanisterSettingsArgs,
    CanisterSettingsArgsBuilder, CanisterStatusResultV2, EnvironmentVariable,
};
use ic_nervous_system_clients::canister_status::CanisterStatusResult;
use ic_nervous_system_common::{E8, ONE_MONTH_SECONDS, ONE_TRILLION};
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR, TEST_USER1_KEYPAIR, TEST_USER1_PRINCIPAL,
    TEST_USER2_PRINCIPAL, TEST_USER3_PRINCIPAL,
};
use ic_nns_common::types::{NeuronId, ProposalId};
use ic_nns_constants::{
    CYCLES_LEDGER_CANISTER_ID, CYCLES_MINTING_CANISTER_ID, GOVERNANCE_CANISTER_ID,
    LEDGER_CANISTER_ID, LEDGER_CANISTER_INDEX_IN_NNS_SUBNET, ROOT_CANISTER_ID,
    SUBNET_RENTAL_CANISTER_ID,
};
use ic_nns_governance_api::{NnsFunction, ProposalStatus};
use ic_nns_test_utils::state_test_helpers::cmc_set_authorized_subnetworks_for_principal;
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    governance::{submit_external_update_proposal, wait_for_final_state},
    itest_helpers::{NnsCanisters, state_machine_test_on_nns_subnet},
    neuron_helpers::get_neuron_1,
    state_test_helpers::{
        cmc_set_default_authorized_subnetworks, icrc1_balance, icrc1_transfer,
        set_up_universal_canister, setup_cycles_ledger, setup_nns_canisters,
        state_machine_builder_for_nns_tests, update_with_sender,
    },
};
use ic_state_machine_tests::{StateMachine, WasmResult};
use ic_test_utilities::universal_canister::{call_args, wasm};
use ic_test_utilities_metrics::fetch_int_gauge_vec;
use ic_types::{CanisterId, Cycles, PrincipalId};
use ic_types_test_utils::ids::subnet_test_id;
use icp_ledger::{
    AccountBalanceArgs, AccountIdentifier, BlockIndex, DEFAULT_TRANSFER_FEE, Memo, SendArgs,
    Subaccount, Tokens, TransferArgs, TransferError, tokens_from_proto,
};
use icrc_ledger_types::icrc1::{self, account::Account};
use maplit::btreemap;
use serde_bytes::ByteBuf;
use std::time::Duration;

const CYCLES_LEDGER_FEE: u128 = 100_000_000;
const CYCLES_MINTING_LIMIT: u128 = 150e15 as u128;

// per month
const SUBNET_RENTAL_CYCLES_MINTING_LIMIT: u128 = 500e15 as u128;

/// Test that we can top-up the Governance canister with cycles when the CMC has
/// a set exchange rate
#[test]
fn test_cmc_mints_cycles_when_cmc_has_exchange_rate() {
    state_machine_test_on_nns_subnet(|runtime| async move {
        let account = AccountIdentifier::new(*TEST_USER1_PRINCIPAL, None);
        let icpts = Tokens::new(100, 0).unwrap();

        // In this test we try to top-up an existing canister, and Governance is simply a
        // convenient pre-existing canister.
        let canister_to_top_up = GOVERNANCE_CANISTER_ID.get();

        let nns_init_payload = NnsInitPayloadsBuilder::new()
            .with_initial_invariant_compliant_mutations()
            .with_test_neurons()
            .with_ledger_account(account, icpts)
            .build();

        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

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
        top_up_canister(
            icpts,
            &nns_canisters.ledger,
            &nns_canisters.cycles_minting,
            MEMO_TOP_UP_CANISTER,
            CanisterId::unchecked_from_principal(canister_to_top_up),
        )
        .await
        .expect("Failed to top up canister");

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
            .checked_sub(&DEFAULT_TRANSFER_FEE)
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
            Nat::from(1000000000000000u64)
        );

        Ok(())
    });
}

/// Sends 10 ICP from `TEST_USER1_PRINCIPAL`s Ledger account to the given
/// subaccount of the CMC, which then tries to top-up the canister whose
/// `CanisterId` corresponds to `canister_to_top_up`.
async fn top_up_canister(
    initial_icpts: Tokens,
    ledger: &Canister<'_>,
    cycles_minting: &Canister<'_>,
    memo: Memo,
    canister_to_top_up: CanisterId,
) -> Result<Cycles, NotifyError> {
    let account = AccountIdentifier::new(*TEST_USER1_PRINCIPAL, None);
    let subaccount: Subaccount = canister_to_top_up.get_ref().into();

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
        to: AccountIdentifier::new(CYCLES_MINTING_CANISTER_ID.get(), Some(subaccount)),
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

    let notify_args = NotifyTopUp {
        block_index: block_height,
        canister_id: canister_to_top_up,
    };

    let cycles_response: Result<Cycles, NotifyError> = cycles_minting
        .update_from_sender(
            "notify_top_up",
            candid_one,
            notify_args,
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
        CanisterIdRecord::from(target),
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
            0_u128,
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
    assert_eq!(status.environment_variables(), vec![]);

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
    assert_eq!(status.environment_variables(), vec![]);

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
    assert_eq!(status.environment_variables(), vec![]);

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
        Some(dbg!(
            CanisterSettingsArgsBuilder::new()
                .with_compute_allocation(7)
                .build()
        )),
    );
    let status = dbg!(canister_status(&state_machine, *TEST_USER1_PRINCIPAL, canister).unwrap());
    assert_eq!(status.controllers(), vec![*TEST_USER1_PRINCIPAL]);
    assert_eq!(status.compute_allocation(), 7);
    assert_eq!(status.memory_allocation(), 0);
    assert_eq!(status.freezing_threshold(), 2592000);
    assert_eq!(status.environment_variables(), vec![]);

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
    assert_eq!(status.environment_variables(), vec![]);

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
    assert_eq!(status.environment_variables(), vec![]);

    //specify environment variables
    let env_vars = vec![EnvironmentVariable {
        name: "TEST_ENV_VAR".to_string(),
        value: "TEST_ENV_VAR_VALUE".to_string(),
    }];
    let canister = notify_create_canister(
        &state_machine,
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_environment_variables(env_vars.clone())
                .build(),
        ),
    );
    let status = canister_status(&state_machine, *TEST_USER1_PRINCIPAL, canister).unwrap();
    assert_eq!(status.controllers(), vec![*TEST_USER1_PRINCIPAL]);
    assert_eq!(status.compute_allocation(), 0);
    assert_eq!(status.memory_allocation(), 0);
    assert_eq!(status.freezing_threshold(), 2592000);
    assert_eq!(status.environment_variables(), env_vars);
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
    assert_eq!(status.environment_variables(), vec![]);

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
    assert_eq!(status.environment_variables(), vec![]);

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
    assert_eq!(status.environment_variables(), vec![]);

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
    assert_eq!(status.environment_variables(), vec![]);

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
    assert_eq!(status.environment_variables(), vec![]);

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
    assert_eq!(status.environment_variables(), vec![]);

    //specify environment variables
    let env_vars = vec![EnvironmentVariable {
        name: "TEST_ENV_VAR".to_string(),
        value: "TEST_ENV_VAR_VALUE".to_string(),
    }];
    let canister = cmc_create_canister_with_cycles(
        &state_machine,
        universal_canister,
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_controllers(vec![*TEST_USER1_PRINCIPAL])
                .with_environment_variables(env_vars.clone())
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
    assert_eq!(status.environment_variables(), env_vars);

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
        panic!("Refund failed: {error:?}")
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
    } = error;

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

#[test]
fn test_cmc_automatically_refunds_when_memo_is_garbage() {
    // Step 1: Prepare the world.

    // USER1 has some ICP (in their default subaccount).
    let account_identifier = AccountIdentifier::new(*TEST_USER1_PRINCIPAL, None);
    let initial_balance = Tokens::new(100, 0).unwrap();
    let state_machine = state_machine_builder_for_nns_tests().build();
    let nns_init_payloads = NnsInitPayloadsBuilder::new()
        .with_ledger_account(account_identifier, initial_balance)
        .build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    let assert_canister_statuses_fixed = |test_phase| {
        assert_eq!(
            btreemap! {
                btreemap! { "status".to_string() => "running".to_string() } => 17,
                btreemap! { "status".to_string() => "stopped".to_string() } => 0,
                btreemap! { "status".to_string() => "stopping".to_string() } => 0,
            },
            fetch_int_gauge_vec(
                state_machine.metrics_registry(),
                "replicated_state_registered_canisters"
            ),
            "{test_phase}",
        );
    };
    // This will be called again later to verify that no canisters were added.
    // Here, we just make sure that assert_canister_statuses_fixed has a correct
    // understanding of how many canisters there are originally.
    assert_canister_statuses_fixed("start");

    let assert_balance = |nominal_amount_tokens: u64, fee_count: u64, test_phase: &str| {
        let observed_balance = icrc1_balance(
            &state_machine,
            LEDGER_CANISTER_ID,
            Account {
                owner: Principal::from(*TEST_USER1_PRINCIPAL),
                subaccount: None,
            },
        );

        let total_fees = Tokens::new(0, fee_count * 10_000).unwrap();
        let expected_balance = Tokens::new(nominal_amount_tokens, 0)
            .unwrap()
            .checked_sub(&total_fees)
            .unwrap();
        assert_eq!(observed_balance, expected_balance, "{test_phase}");
    };
    // This is more to gain confidence that assert_balance works; there is very
    // little risk that USER1's balance is not 100.
    assert_balance(100, 0, "start");

    // Step 2: Run code under test.

    // Step 2.1: Send ICP from USER1 to CMC, but use a garbage memo. Even though
    // the problem is created here, it is not detected until later.

    let garbage_memo = [0xEF, 0xBE, 0xAD, 0xDE, 0, 0, 0, 0]; // little endian 0x_DEAD_BEEF
    assert!(!MEANINGFUL_MEMOS.contains(&Memo(u64::from_le_bytes(garbage_memo))));
    let transfer_arg = icrc1::transfer::TransferArg {
        to: icrc1::account::Account {
            owner: Principal::from(CYCLES_MINTING_CANISTER_ID.get()),
            subaccount: Some(Subaccount::from(&TEST_USER1_PRINCIPAL.clone()).0),
        },
        amount: Nat::from(10 * E8),
        fee: Some(Nat::from(10_000_u64)),

        // Here, the "bomb is being planted".
        memo: Some(icrc1::transfer::Memo(ByteBuf::from(garbage_memo))),

        from_subaccount: None, // source from USER1's the default subaccount
        created_at_time: None,
    };
    let create_canister_block_index = icrc1_transfer(
        &state_machine,
        LEDGER_CANISTER_ID,
        *TEST_USER1_PRINCIPAL,
        transfer_arg.clone(),
    )
    .expect("transfer failed");
    assert_balance(90, 1, "ICP sent to CMC");

    // This is to make it so that CMC has more ICP. That way, when we later try
    // to duplicate the automatic refund, we can verify that CMC refrains from
    // sending back more ICP.
    let transfer_arg = icrc1::transfer::TransferArg {
        amount: Nat::from(50 * E8),
        ..transfer_arg
    };
    let _red_herring = icrc1_transfer(
        &state_machine,
        LEDGER_CANISTER_ID,
        *TEST_USER1_PRINCIPAL,
        transfer_arg,
    )
    .expect("transfer failed");
    // Balance has gone down by 10 + 10 (plus fees). Later, we will see balance
    // go back up, but only by 10 (minus fee).
    assert_balance(40, 2, "additional red herring ICP sent to CMC");

    // Step 2.2: Ask CMC to create a canister using the ICP that was just sent
    // to it (from USER1). This is where it is noticed (by CMC) that USER1 did
    // something wrong. Many requests are sent concurrently to verify that
    // journaling/locking/deduplication works.
    #[allow(deprecated)]
    let notify_create_canister = Encode!(&NotifyCreateCanister {
        block_index: create_canister_block_index,
        controller: *TEST_USER1_PRINCIPAL,

        // Nothing fancy.
        subnet_type: None,
        subnet_selection: None,
        settings: None,
    })
    .unwrap();
    let results = (0..100)
        .map(|_i| {
            // Launch (another) notify_create_canister call, but crucially, do
            // NOT wait for it to complete. That takes place a little further
            // down.
            state_machine
                .send_ingress_safe(
                    *TEST_USER1_PRINCIPAL,
                    CYCLES_MINTING_CANISTER_ID,
                    "notify_create_canister",
                    notify_create_canister.clone(),
                )
                .unwrap()
        })
        // It might seem silly to call collect, and then immediately after that
        // call into_iter, but this is to ensure that await_ingress is not
        // called until after ALL send_ingress_safe calls are made.
        .collect::<Vec<_>>()
        .into_iter()
        .map(|message_id| {
            let result = state_machine.await_ingress(message_id, 500).unwrap();

            let result = match result {
                WasmResult::Reply(ok) => ok,
                _ => panic!("{result:?}"),
            };

            Decode!(&result, Result<CanisterId, NotifyError>).unwrap()
        })
        .collect::<Vec<_>>();

    // Step 3: Verify results.

    // Step 3.1: Verify that no canisters were created.
    assert_canister_statuses_fixed("end");

    // Step 3.2: Inspect USER1's balance.
    // Verify that CMC sent 10 ICP back to USER1 (minus fee, ofc). Here, we
    // also see that CMC refrained from refunding the same transfer more
    // than once, even though multiple its notify_create_canister method was
    // called a couple of times.
    assert_balance(50, 3, "end");

    // Step 3.3: Verify that CMC returned Err.

    // Step 3.3.1: Filter out Err(Processing), and freak out if there are any Ok.
    let mut errs = results
        .into_iter()
        .filter_map(|result| match result {
            Err(NotifyError::Processing) => None,
            Ok(_) => panic!("{result:?}"),
            Err(err) => Some(err),
        })
        .collect::<Vec<NotifyError>>();

    // Step 3.3.2: Assert that all errs are the same.
    let last_err = errs.pop().unwrap();
    assert!(
        errs.iter().all(|other_err| other_err == &last_err),
        "{last_err:?}\nvs.\n{errs:#?}",
    );
    assert!(
        errs.len() >= 2, // If errs is empty, then the previous assert is trivial.
        "{}: {:#?}",
        errs.len(),
        errs,
    );
    // I tried cranking up the concurrent calls, but I could never get
    // Processing to occur. That is, this would always print concurrency - 1.
    println!("errs.len() == {}", errs.len());

    // Step 3.3.3: Verify that the errors are of the right type. This depends on
    // whether automatic refund is enabled. If so, then they errs should be
    // Refunded; otherwise, they should be InvalidTransaction.
    //
    // (Most of the code here is for inspecting the reason.)
    match &last_err {
        NotifyError::Refunded {
            reason,
            block_index: refund_block_index,
        } => {
            // There should be a block_index.
            refund_block_index.as_ref().unwrap();

            // Inspect reason.
            let lower_reason = reason.to_lowercase();
            for key_word in ["memo", "0xdeadbeef", "does not correspond", "offer"] {
                assert!(
                    lower_reason.contains(key_word),
                    r#""{key_word}" not in {last_err:?}"#
                );
            }
        }

        _ => panic!("{last_err:?}"),
    };
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
        settings,
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
        settings,
        subnet_type,
        subnet_selection: None,
    })
    .unwrap();

    let create_canister = wasm()
        .call_with_cycles(
            CYCLES_MINTING_CANISTER_ID,
            "create_canister",
            call_args().other_side(create_args),
            cycles,
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
            .status,
        ProposalStatus::Executed as i32
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
            .status,
        ProposalStatus::Executed as i32
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
        100_000_000_000_000 - CYCLES_LEDGER_FEE
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
        200_000_000_000_000 - CYCLES_LEDGER_FEE
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
    let result = Decode!(&res, Result<NotifyMintCyclesSuccess, NotifyError>).unwrap();
    let reason = match &result {
        Err(NotifyError::Refunded {
            reason,
            block_index: _,
        }) => reason,
        _ => panic!("{result:?}"),
    };

    let reason = reason.to_lowercase();
    for key_word in ["memo", "transfer", "correspond", "offer"] {
        assert!(
            reason.contains(key_word),
            "{key_word} not in reason of {result:?}"
        );
    }

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
}

#[test]
fn cmc_notify_mint_cycles_deposit_memo_too_long() {
    let account = AccountIdentifier::new(*TEST_USER1_PRINCIPAL, None);
    let icpts = Tokens::new(10, 0).unwrap();

    let state_machine = state_machine_builder_for_nns_tests().build();
    let nns_init_payloads = NnsInitPayloadsBuilder::new()
        .with_test_neurons()
        .with_ledger_account(account, icpts)
        .build();
    // We deliberately not set up the cycles ledger here to make sure it is not called.
    setup_nns_canisters(&state_machine, nns_init_payloads);

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
        deposit_memo: Some(vec![0; 33]),
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
        _ => panic!("Unexpected response: {response:?}"),
    }
}

fn notify_top_up_as(
    state_machine: &StateMachine,
    canister_id: CanisterId,
    amount: Tokens,
    caller: PrincipalId,
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
            caller,
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

/// Sends `amount` ICP from `TEST_USER1_PRINCIPAL`s ledger account to the given
/// subaccount of the CMC, which then tries to top up the canister.
fn notify_top_up(
    state_machine: &StateMachine,
    canister_id: CanisterId,
    amount: Tokens,
) -> Result<Cycles, NotifyError> {
    notify_top_up_as(state_machine, canister_id, amount, *TEST_USER1_PRINCIPAL)
}

fn total_cycles_minted(state_machine: &StateMachine) -> Nat {
    if let WasmResult::Reply(res) = state_machine
        .query(CYCLES_MINTING_CANISTER_ID, "total_cycles_minted", vec![])
        .unwrap()
    {
        Decode!(&res, Nat).unwrap()
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
        100_000_000_000_000u64
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
        100_000_000_000_000u64
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
    assert_eq!(total_minted_after - total_minted_before, 0u64);
}

#[test]
fn cmc_notify_top_up_rate_limited() {
    let state_machine = state_machine_builder_for_nns_tests().build();

    let account = AccountIdentifier::new(*TEST_USER1_PRINCIPAL, None);
    // The only requirement here is to have sufficient funds. Other than that,
    // the precise number here does not matter.
    let balance = Tokens::new(1e6 as u64, 0).unwrap();
    let nns_init_payloads = NnsInitPayloadsBuilder::new()
        .with_test_neurons()
        .with_ledger_account(account, balance)
        .build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    // First top-up should succeed since it's 90P - less than the 150P/hr limit.
    let cycles = notify_top_up(
        &state_machine,
        GOVERNANCE_CANISTER_ID,
        Tokens::new(900, 0).unwrap(),
    )
    .unwrap();
    assert_eq!(cycles, Cycles::new(90e15 as u128));

    // Second top-up should also succeed after 1 hour.
    state_machine.advance_time(Duration::from_secs(4000));
    let cycles = notify_top_up(
        &state_machine,
        GOVERNANCE_CANISTER_ID,
        Tokens::new(900, 0).unwrap(),
    )
    .unwrap();
    assert_eq!(cycles, Cycles::new(90e15 as u128));

    // Third top-up should fail since the rate limit is 150e15 cycles per hour,
    // and less than an hour has passed.
    state_machine.advance_time(Duration::from_secs(3000));
    let error = notify_top_up(
        &state_machine,
        GOVERNANCE_CANISTER_ID,
        Tokens::new(900, 0).unwrap(),
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

    // First make sure topping up 400T cycles on a valid canister works.
    let cycles = notify_top_up(
        &state_machine,
        GOVERNANCE_CANISTER_ID,
        Tokens::new(4, 0).unwrap(),
    )
    .unwrap();
    assert_eq!(cycles, Cycles::new(400_000_000_000_000u128));

    // Advance time by 1 hour to make sure the rate limit is reset.
    state_machine.advance_time(Duration::from_secs(60 * 60));

    // Now the attack begins - the bad account sends 0.69 tokens per 5 seconds to the non-existing
    // canister, which makes it 207T * 12 * 60 = 149.04P cycles per hour, close to the 150P limit,
    // while getting the 0.69 tokens back each time (the account only has 1 token in the
    // beginning).
    for _ in 0..(12 * 60) {
        let error = notify_top_up(
            &state_machine,
            non_existing_canister_id,
            Tokens::from_e8s(207_000_000),
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

#[test]
fn test_cmc_subnet_rental_topups_use_separate_limit() {
    let state_machine = state_machine_builder_for_nns_tests().build();

    let unprivilieged_user_account = AccountIdentifier::new(*TEST_USER1_PRINCIPAL, None);
    let subnet_rental_canister_account =
        AccountIdentifier::new(SUBNET_RENTAL_CANISTER_ID.get(), None);
    // The only requirement here is to have sufficient funds to run the test. Other than that,
    // the precise number here does not matter.
    let balance = Tokens::new(1e6 as u64, 0).unwrap();
    let nns_init_payloads = NnsInitPayloadsBuilder::new()
        .with_test_neurons()
        .with_ledger_account(subnet_rental_canister_account, balance)
        .with_ledger_account(unprivilieged_user_account, balance)
        .build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    // Conversion rate in tests is 100 XDR per ICP, and cycles cost 1 XDR per trillion cycles.
    // To get the ICP needed to mint maximum cycles, we divide by 1 trillion and then by 100.
    let subnet_rental_limit_cost_icp =
        SUBNET_RENTAL_CYCLES_MINTING_LIMIT as u64 / ONE_TRILLION / 100;
    let base_limit_cost_icp = CYCLES_MINTING_LIMIT as u64 / ONE_TRILLION / 100;

    // First top-up should succeed as it's 500,000T cycles, which is at the limit for SRC.
    let cycles = notify_top_up_as(
        &state_machine,
        SUBNET_RENTAL_CANISTER_ID,
        Tokens::new(subnet_rental_limit_cost_icp, 0).unwrap(),
        SUBNET_RENTAL_CANISTER_ID.get(),
    )
    .unwrap();
    assert_eq!(cycles, Cycles::new(SUBNET_RENTAL_CYCLES_MINTING_LIMIT));

    // Second top up should fail.
    let cycles = notify_top_up_as(
        &state_machine,
        SUBNET_RENTAL_CANISTER_ID,
        Tokens::new(1, 0).unwrap(),
        SUBNET_RENTAL_CANISTER_ID.get(),
    )
    .unwrap_err();
    assert_matches!(cycles, NotifyError::Refunded { reason, .. } if reason.contains("try again later"));

    // Next topups

    // Third top-up should succeed since it uses a different limit.
    let cycles = notify_top_up(
        &state_machine,
        GOVERNANCE_CANISTER_ID,
        Tokens::new(base_limit_cost_icp, 0).unwrap(),
    )
    .unwrap();
    assert_eq!(cycles, Cycles::new(CYCLES_MINTING_LIMIT));

    // Fourth top-up should fail since the rate limit is 150e15 cycles per hour,
    // and less than an hour has passed.
    let error = notify_top_up(
        &state_machine,
        GOVERNANCE_CANISTER_ID,
        Tokens::new(base_limit_cost_icp, 0).unwrap(),
    )
    .unwrap_err();
    assert_matches!(error, NotifyError::Refunded { reason, .. } if reason.contains("try again later"));

    // Advance time by 1 hour, to show base limit is reset, but the SRC limit is not

    state_machine.advance_time(Duration::from_secs(4000));
    // Fifth top-up should succeed since the base limit is reset.
    let cycles = notify_top_up(
        &state_machine,
        GOVERNANCE_CANISTER_ID,
        Tokens::new(base_limit_cost_icp, 0).unwrap(),
    )
    .unwrap();
    assert_eq!(cycles, Cycles::new(CYCLES_MINTING_LIMIT));

    // Another attempt to top up the SRC should still fail
    let error = notify_top_up_as(
        &state_machine,
        SUBNET_RENTAL_CANISTER_ID,
        Tokens::new(1, 0).unwrap(),
        SUBNET_RENTAL_CANISTER_ID.get(),
    )
    .unwrap_err();
    assert_matches!(error, NotifyError::Refunded { reason, .. } if reason.contains("try again later"));

    // Advance time by 1 month, show you can now mint again to SRC
    state_machine.advance_time(Duration::from_secs(ONE_MONTH_SECONDS));

    // Finally, another top-up from the Subnet Rental Canister should succeed
    let cycles = notify_top_up_as(
        &state_machine,
        SUBNET_RENTAL_CANISTER_ID,
        Tokens::new(subnet_rental_limit_cost_icp, 0).unwrap(),
        SUBNET_RENTAL_CANISTER_ID.get(),
    )
    .unwrap();
    assert_eq!(cycles, Cycles::new(SUBNET_RENTAL_CYCLES_MINTING_LIMIT));
}

#[test]
fn test_cmc_set_and_get_authorized_subnets() {
    let account = AccountIdentifier::new(*TEST_USER1_PRINCIPAL, None);
    let icpts = Tokens::new(100, 0).unwrap();
    let neuron = get_neuron_1();

    let state_machine = state_machine_builder_for_nns_tests().build();
    let nns_init_payloads = NnsInitPayloadsBuilder::new()
        .with_test_neurons()
        .with_ledger_account(account, icpts)
        .build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    let default_subnets = state_machine
        .execute_ingress(
            CYCLES_MINTING_CANISTER_ID,
            "get_default_subnets",
            candid::encode_one(()).unwrap(),
        )
        .unwrap();
    let decoded = Decode!(default_subnets.bytes().as_slice(), Vec<PrincipalId>).unwrap();
    assert!(decoded.is_empty());

    let authorized_subnets_response = state_machine
        .execute_ingress(
            CYCLES_MINTING_CANISTER_ID,
            "get_principals_authorized_to_create_canisters_to_subnets",
            candid::encode_one(()).unwrap(),
        )
        .unwrap();
    let authorized_for_sam = Decode!(
        &authorized_subnets_response.bytes().as_slice(),
        AuthorizedSubnetsResponse
    )
    .unwrap();
    assert_eq!(authorized_for_sam.data.len(), 0);

    let subnet_id = state_machine.get_subnet_id();
    cmc_set_default_authorized_subnetworks(
        &state_machine,
        vec![subnet_id],
        neuron.principal_id,
        neuron.neuron_id,
    );

    let default_subnets = state_machine
        .execute_ingress(
            CYCLES_MINTING_CANISTER_ID,
            "get_default_subnets",
            candid::encode_one(()).unwrap(),
        )
        .unwrap();
    let decoded = Decode!(default_subnets.bytes().as_slice(), Vec<PrincipalId>).unwrap();
    assert!(decoded.len() == 1);

    let authorized_subnets_response = state_machine
        .execute_ingress(
            CYCLES_MINTING_CANISTER_ID,
            "get_principals_authorized_to_create_canisters_to_subnets",
            candid::encode_one(()).unwrap(),
        )
        .unwrap();
    let authorized_subnets_response = Decode!(
        &authorized_subnets_response.bytes().as_slice(),
        AuthorizedSubnetsResponse
    )
    .unwrap();
    assert_eq!(authorized_subnets_response.data.len(), 0);

    let bob = PrincipalId::new_user_test_id(1010101);
    cmc_set_authorized_subnetworks_for_principal(
        &state_machine,
        Some(bob),
        vec![subnet_id],
        neuron.principal_id,
        neuron.neuron_id,
    );

    let authorized_subnets_response = state_machine
        .execute_ingress(
            CYCLES_MINTING_CANISTER_ID,
            "get_principals_authorized_to_create_canisters_to_subnets",
            candid::encode_one(()).unwrap(),
        )
        .unwrap();
    let mut authorized_subnets_response = Decode!(
        &authorized_subnets_response.bytes().as_slice(),
        AuthorizedSubnetsResponse
    )
    .unwrap();
    assert_eq!(authorized_subnets_response.data.len(), 1);
    assert_eq!(
        authorized_subnets_response.data.pop(),
        Some((bob, vec![subnet_id]))
    );
}
