use candid::{CandidType, Decode, Encode};
use canister_test::Project;
use ic_base_types::{CanisterId, PrincipalId};
use ic_ic00_types::{CanisterInstallMode, CanisterSettingsArgs, UpdateSettingsArgs};
use ic_icrc1::Account;
use ic_ledger_core::Tokens;
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_OWNER_PRINCIPAL, TEST_USER1_PRINCIPAL, TEST_USER2_PRINCIPAL,
};
use ic_nns_common::pb::v1 as nns_common_pb;
use ic_nns_constants::{
    GOVERNANCE_CANISTER_ID as NNS_GOVERNANCE_CANISTER_ID,
    LEDGER_CANISTER_ID as ICP_LEDGER_CANISTER_ID, ROOT_CANISTER_ID as NNS_ROOT_CANISTER_ID,
};
use ic_nns_governance::pb::v1::{
    manage_neuron::{self, RegisterVote},
    manage_neuron_response, proposal, ManageNeuron, ManageNeuronResponse, Proposal,
    SetSnsTokenSwapOpenTimeWindow, Vote,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder, ids::TEST_NEURON_1_ID, state_test_helpers::setup_nns_canisters,
};
use ic_sns_governance::pb::v1::{ListNeurons, ListNeuronsResponse};
use ic_sns_init::SnsCanisterInitPayloads;
use ic_sns_root::{
    pb::v1::{RegisterDappCanisterRequest, RegisterDappCanisterResponse},
    CanisterIdRecord, CanisterStatusResultV2,
};
use ic_sns_swap::pb::v1::{
    self as swap_pb, set_dapp_controllers_call_result, RefreshSnsTokensRequest,
    SetDappControllersCallResult, SetDappControllersResponse, SetOpenTimeWindowRequest, TimeWindow,
};
use ic_sns_test_utils::itest_helpers::{populate_canister_ids, SnsTestsInitPayloadBuilder};
use ic_state_machine_tests::StateMachine;
use ic_types::ingress::WasmResult;
use lazy_static::lazy_static;
use ledger_canister::{
    AccountIdentifier, BinaryAccountBalanceArgs as AccountBalanceArgs, Memo, TransferArgs,
    DEFAULT_TRANSFER_FEE,
};

const SECONDS_PER_DAY: u64 = 24 * 60 * 60;

/// 10^8
const E8: u64 = 1_0000_0000;

lazy_static! {
    static ref TEST_USER2_ORIGINAL_BALANCE_ICP: Tokens = Tokens::from_tokens(100).unwrap();
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SnsCanisterType {
    Ledger,
    Root,
    Governance,
    Swap,
}

impl SnsCanisterType {
    fn get_wasm(self) -> Vec<u8> {
        let features = [];
        Project::cargo_bin_maybe_from_env(self.bin_name(), &features).bytes()
    }

    fn bin_name(self) -> &'static str {
        use SnsCanisterType::*;
        match self {
            Ledger => "ic-icrc1-ledger",

            Root => "sns-root-canister",
            Governance => "sns-governance-canister",
            Swap => "sns-swap-canister",
        }
    }
}

fn init_canister(
    state_machine: &mut StateMachine,
    canister_id: CanisterId,
    sns_canister_type: SnsCanisterType,
    init_argument: &impl CandidType,
) {
    let init_argument = Encode!(init_argument).unwrap();
    state_machine
        .install_wasm_in_mode(
            canister_id,
            CanisterInstallMode::Install,
            sns_canister_type.get_wasm(),
            init_argument,
        )
        .unwrap();
}

fn set_controllers(
    state_machine: &mut StateMachine,
    sender: PrincipalId,
    target: CanisterId,
    controllers: Vec<PrincipalId>,
) {
    let request = Encode!(&UpdateSettingsArgs {
        canister_id: target.into(),
        settings: CanisterSettingsArgs::new(None, Some(controllers), None, None, None,),
    })
    .unwrap();

    state_machine
        .execute_ingress_as(sender, CanisterId::ic_00(), "update_settings", request)
        .unwrap();
}

fn canister_status(
    state_machine: &mut StateMachine,
    sender: PrincipalId,
    request: &CanisterIdRecord,
) -> CanisterStatusResultV2 {
    let request = Encode!(&request).unwrap();
    let result = state_machine
        .execute_ingress_as(sender, CanisterId::ic_00(), "canister_status", request)
        .unwrap();
    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!("get_state was rejected by the swap canister: {:#?}", reject)
        }
    };
    Decode!(&result, CanisterStatusResultV2).unwrap()
}

struct Scenario {
    configuration: SnsCanisterInitPayloads,

    root_canister_id: CanisterId,
    governance_canister_id: CanisterId,
    ledger_canister_id: CanisterId,
    swap_canister_id: CanisterId,
    dapp_canister_id: CanisterId,
}

impl Scenario {
    /// Step 1: Creates canisters, but does not install code into them.
    ///
    /// Installation is performed separately using the init_all_canisters method.
    ///
    /// These two operations are performed separately in order to allow the user
    /// to customize the canisters. This can be done by modifying
    /// self.configuration before calling init_all_canisters.
    ///
    /// self.configuration is initialized with "bare-bones" values. More
    /// precisely, it builds upon SnsTestsInitPayloadBuilder::new().build(), but
    /// this makes two enhancements:
    ///
    ///   1. The swap canister is funded (with 10 SNS tokens).
    ///   2. The canister_id fields are populated.
    ///
    /// The dapp canister is owned by TEST_USER1.
    pub fn new(state_machine: &mut StateMachine) -> Self {
        let create_canister = || state_machine.create_canister(/* settings= */ None);

        let root_canister_id = create_canister();
        let governance_canister_id = create_canister();
        let ledger_canister_id = create_canister();
        let swap_canister_id = create_canister();
        let dapp_canister_id = create_canister();

        set_controllers(
            state_machine,
            PrincipalId::new_anonymous(),
            root_canister_id,
            vec![governance_canister_id.into()],
        );
        set_controllers(
            state_machine,
            PrincipalId::new_anonymous(),
            governance_canister_id,
            vec![root_canister_id.into()],
        );
        set_controllers(
            state_machine,
            PrincipalId::new_anonymous(),
            ledger_canister_id,
            vec![root_canister_id.into()],
        );
        set_controllers(
            state_machine,
            PrincipalId::new_anonymous(),
            swap_canister_id,
            vec![NNS_ROOT_CANISTER_ID.into(), swap_canister_id.into()],
        );
        set_controllers(
            state_machine,
            PrincipalId::new_anonymous(),
            dapp_canister_id,
            vec![*TEST_USER1_PRINCIPAL],
        );

        // Construct base configuration.
        let account_identifiers = vec![Account {
            owner: swap_canister_id.into(),
            subaccount: None,
        }];
        let mut configuration = SnsTestsInitPayloadBuilder::new()
            .with_ledger_accounts(account_identifiers, Tokens::from_tokens(10).unwrap())
            .build();
        populate_canister_ids(
            root_canister_id,
            governance_canister_id,
            ledger_canister_id,
            swap_canister_id,
            &mut configuration,
        );

        Self {
            root_canister_id,
            governance_canister_id,
            ledger_canister_id,
            swap_canister_id,
            dapp_canister_id,
            configuration,
        }
    }

    /// Installs respective wasms into respective canisters, using the
    /// corresponding init payload, of course.
    ///
    /// (The dapp canister is not touched).
    pub fn init_all_canisters(&self, state_machine: &mut StateMachine) {
        init_canister(
            state_machine,
            self.root_canister_id,
            SnsCanisterType::Root,
            &self.configuration.root,
        );
        init_canister(
            state_machine,
            self.governance_canister_id,
            SnsCanisterType::Governance,
            &self.configuration.governance,
        );
        init_canister(
            state_machine,
            self.ledger_canister_id,
            SnsCanisterType::Ledger,
            &self.configuration.ledger,
        );
        init_canister(
            state_machine,
            self.swap_canister_id,
            SnsCanisterType::Swap,
            &self.configuration.swap,
        );
    }
}

/// Serves as a fixture (factory) for the tests in this file. (The previous
/// stuff is generic to any SNS test; whereas, this is specifc to swap.)
///
/// Configures, creates, and inits the following canisters:
///   1. NNS
///   2. SNS
///   3. dapp
///
/// Begins a swap.
///
/// TEST_USER2 has 100 ICP that he can use to buy into the swap.
fn begin_swap(state_machine: &mut StateMachine) -> (Scenario, TimeWindow) {
    // Give TEST_USER2 some ICP so that he can buy into the swap.
    let test_user2_principal_id: PrincipalId = *TEST_USER2_PRINCIPAL;
    let nns_init_payloads = NnsInitPayloadsBuilder::new()
        .with_ledger_account(
            test_user2_principal_id.into(),
            *TEST_USER2_ORIGINAL_BALANCE_ICP,
        )
        .with_test_neurons()
        .build();
    let neuron_id_to_principal_id: Vec<(u64, PrincipalId)> = nns_init_payloads
        .governance
        .neurons
        .iter()
        .map(|(id, neuron)| (*id, neuron.controller.unwrap()))
        .collect();
    assert_eq!(
        neuron_id_to_principal_id.len(),
        3,
        "{:#?}",
        neuron_id_to_principal_id
    );
    setup_nns_canisters(state_machine, nns_init_payloads);

    // Create, configure, and init canisters.
    let mut scenario = Scenario::new(state_machine);
    // Fill in more swap parameters.
    {
        let swap = &mut scenario.configuration.swap;

        // Succeed as soon as 10 ICP has been raised.
        swap.max_icp_e8s = 10 * E8;
        // Still succeed if 2 ICP has been raised, but only after the open time
        // window has passed.
        swap.min_icp_e8s = 2 * E8;

        // We need at least one participant, but they can contribute whatever
        // amount they want (subject to max_icp_e8s for the whole swap).
        swap.min_participants = 1;
        swap.min_participant_icp_e8s = 1;
        swap.max_participant_icp_e8s = swap.max_icp_e8s;

        // In case of failure, restore TEST_USER1 as the controller of the dapp.
        swap.fallback_controller_principal_ids = vec![TEST_USER1_PRINCIPAL.to_string()];

        assert!(swap.is_valid(), "{:#?}", swap);
    }
    scenario.init_all_canisters(state_machine);

    // TEST_USER1 relinquishes control of the dapp to SNS root (and tells SNS root about it).
    set_controllers(
        state_machine,
        *TEST_USER1_PRINCIPAL,
        scenario.dapp_canister_id,
        vec![scenario.root_canister_id.into()],
    );
    sns_root_register_dapp_canister(
        state_machine,
        scenario.root_canister_id,
        &RegisterDappCanisterRequest {
            canister_id: Some(scenario.dapp_canister_id.into()),
        },
    );

    // Let swap know that it has SNS tokens.
    state_machine
        .execute_ingress(
            scenario.swap_canister_id,
            "refresh_sns_tokens",
            Encode!(&RefreshSnsTokensRequest {}).unwrap(),
        )
        .unwrap();

    // Propose that a swap be scheduled to start 3 days from now, and last for
    // 10 days.
    let start_timestamp_seconds = state_machine
        .time()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3 * SECONDS_PER_DAY;
    let end_timestamp_seconds = start_timestamp_seconds + 10 * SECONDS_PER_DAY;
    let open_time_window = TimeWindow {
        start_timestamp_seconds,
        end_timestamp_seconds,
    };
    let neuron_id = nns_common_pb::NeuronId {
        id: TEST_NEURON_1_ID,
    };
    let response = nns_governance_make_proposal(
        state_machine,
        *TEST_NEURON_1_OWNER_PRINCIPAL, // sender
        neuron_id,
        &Proposal {
            title: Some("Schedule SNS Token Sale".to_string()),
            summary: "".to_string(),
            url: "".to_string(),
            action: Some(proposal::Action::SetSnsTokenSwapOpenTimeWindow(
                SetSnsTokenSwapOpenTimeWindow {
                    swap_canister_id: Some(scenario.swap_canister_id.into()),
                    request: Some(SetOpenTimeWindowRequest {
                        open_time_window: Some(open_time_window),
                    }),
                },
            )),
        },
    );
    let proposal_id = response
        .proposal_id
        .unwrap_or_else(|| panic!("Response did not contain a proposal_id: {:#?}", response));

    // Vote for the proposal.
    for (neuron_id, principal_id) in neuron_id_to_principal_id {
        // Skip TEST_NEURON_1, since it, being the proposer, automatically voted in favor already.
        if neuron_id == TEST_NEURON_1_ID {
            continue;
        }

        state_machine
            .execute_ingress_as(
                principal_id,
                NNS_GOVERNANCE_CANISTER_ID,
                "manage_neuron",
                Encode!(&ManageNeuron {
                    id: Some(nns_common_pb::NeuronId { id: neuron_id }),
                    command: Some(manage_neuron::Command::RegisterVote(RegisterVote {
                        proposal: Some(proposal_id),
                        vote: Vote::Yes as i32,
                    })),
                    neuron_id_or_subaccount: None
                })
                .unwrap(),
            )
            .unwrap();
    }

    // Advance time so that the swap is open.
    state_machine.set_time(
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(start_timestamp_seconds + 1),
    );

    // Make sure that the swap is now open.
    {
        let result = swap_get_state(
            state_machine,
            scenario.swap_canister_id,
            &swap_pb::GetStateRequest {},
        )
        .swap
        .unwrap()
        .state
        .unwrap();

        assert_eq!(
            result.lifecycle(),
            swap_pb::Lifecycle::Open,
            "{:#?}",
            result
        );
    }

    (scenario, open_time_window)
}

#[test]
fn swap_lifecycle_happy() {
    // Step 1: Prepare the world.
    let mut state_machine = StateMachine::new();
    let (scenario, _open_time_window) = begin_swap(&mut state_machine);

    // Step 2: Run code under test.

    // Make the swap an immediate success by having TEST_USER2 participate.
    // First, they must transfer funds to the swap canister under the
    // appropriate subaccount...
    participate_in_swap(
        &mut state_machine,
        scenario.swap_canister_id,
        *TEST_USER2_PRINCIPAL,
        Tokens::from_tokens(10).unwrap(),
    );

    // Make sure the swap reached the Committed state.
    {
        let result = swap_get_state(
            &mut state_machine,
            scenario.swap_canister_id,
            &swap_pb::GetStateRequest {},
        )
        .swap
        .unwrap()
        .state
        .unwrap();

        assert_eq!(
            result.lifecycle(),
            swap_pb::Lifecycle::Committed,
            "{:#?}",
            result
        );
    }

    // Execute the swap.
    let finalize_swap_response = {
        let result = state_machine
            .execute_ingress(
                scenario.swap_canister_id,
                "finalize_swap",
                Encode!(&swap_pb::FinalizeSwapRequest {}).unwrap(),
            )
            .unwrap();
        let result: Vec<u8> = match result {
            WasmResult::Reply(reply) => reply,
            WasmResult::Reject(reject) => panic!(
                "finalize_swap call was rejected by swap canister: {:#?}",
                reject
            ),
        };
        Decode!(&result, swap_pb::FinalizeSwapResponse).unwrap()
    };

    // Step 3: Inspect results.

    assert_eq!(
        finalize_swap_response,
        swap_pb::FinalizeSwapResponse {
            sweep_icp: Some(swap_pb::SweepResult {
                success: 1,
                failure: 0,
                skipped: 0,
            }),
            sweep_sns: Some(swap_pb::SweepResult {
                success: 1,
                failure: 0,
                skipped: 0,
            }),
            create_neuron: Some(swap_pb::SweepResult {
                success: 1,
                failure: 0,
                skipped: 0,
            }),
            sns_governance_normal_mode_enabled: Some(swap_pb::SetModeCallResult {
                possibility: None
            }),
            set_dapp_controllers_result: None,
        }
    );

    // SNS governance should get the ICP.
    {
        let observed_balance = ledger_account_balance(
            &mut state_machine,
            ICP_LEDGER_CANISTER_ID,
            &AccountBalanceArgs {
                account: AccountIdentifier::new(scenario.governance_canister_id.into(), None)
                    .to_address(),
            },
        );
        let expected_balance = (Tokens::from_tokens(10).unwrap() - DEFAULT_TRANSFER_FEE).unwrap();
        assert_eq!(observed_balance, expected_balance);
    }

    // TEST_USER2 should receive the SNS tokens, but in the form a neuron.
    {
        let observed_neurons = sns_governance_list_neurons(
            &mut state_machine,
            scenario.governance_canister_id,
            &ListNeurons::default(),
        )
        .neurons;

        assert_eq!(observed_neurons.len(), 1, "{:#?}", observed_neurons);
        let observed_neuron = &observed_neurons[0];

        // Inspect the neuron.
        assert_eq!(
            observed_neuron.maturity_e8s_equivalent, 0,
            "{:#?}",
            observed_neuron,
        );
        assert_eq!(
            observed_neuron.cached_neuron_stake_e8s,
            10 * E8
                - scenario
                    .configuration
                    .governance
                    .parameters
                    .as_ref()
                    .unwrap()
                    .transaction_fee_e8s
                    .unwrap(),
            "{:#?}",
            observed_neuron
        );
        assert_eq!(observed_neuron.neuron_fees_e8s, 0, "{:#?}", observed_neuron);
    }
}

#[test]
fn swap_lifecycle_sad() {
    // Step 1: Prepare the world.
    let mut state_machine = StateMachine::new();
    let (scenario, open_time_window) = begin_swap(&mut state_machine);

    // Step 2: Run code under test.

    // TEST_USER2 participates, but not enough for the swap to succeed, even
    // after the open time window has passed.  First, they must transfer funds
    // to the swap canister under the appropriate subaccount...
    participate_in_swap(
        &mut state_machine,
        scenario.swap_canister_id,
        *TEST_USER2_PRINCIPAL,
        Tokens::from_tokens(1).unwrap(),
    );

    // Make sure the swap is still in the Open state.
    {
        let result = swap_get_state(
            &mut state_machine,
            scenario.swap_canister_id,
            &swap_pb::GetStateRequest {},
        )
        .swap
        .unwrap()
        .state
        .unwrap();

        assert_eq!(
            result.lifecycle(),
            swap_pb::Lifecycle::Open,
            "{:#?}",
            result
        );
    }

    // Advance time well into the future so that the swap fails due to no participants.
    state_machine.set_time(
        std::time::UNIX_EPOCH
            + std::time::Duration::from_secs(open_time_window.end_timestamp_seconds + 1),
    );

    // Make sure the swap reached the Aborted state.
    {
        let result = swap_get_state(
            &mut state_machine,
            scenario.swap_canister_id,
            &swap_pb::GetStateRequest {},
        )
        .swap
        .unwrap()
        .state
        .unwrap();

        assert_eq!(
            result.lifecycle(),
            swap_pb::Lifecycle::Aborted,
            "{:#?}",
            result
        );
    }

    // Execute the swap.
    let finalize_swap_response = {
        let result = state_machine
            .execute_ingress(
                scenario.swap_canister_id,
                "finalize_swap",
                Encode!(&swap_pb::FinalizeSwapRequest {}).unwrap(),
            )
            .unwrap();
        let result: Vec<u8> = match result {
            WasmResult::Reply(reply) => reply,
            WasmResult::Reject(reject) => panic!(
                "finalize_swap call was rejected by swap canister: {:#?}",
                reject
            ),
        };
        Decode!(&result, swap_pb::FinalizeSwapResponse).unwrap()
    };

    // Step 3: Inspect results.

    assert_eq!(
        finalize_swap_response,
        swap_pb::FinalizeSwapResponse {
            sweep_icp: Some(swap_pb::SweepResult {
                success: 1,
                failure: 0,
                skipped: 0,
            }),
            sweep_sns: None,
            create_neuron: None,
            sns_governance_normal_mode_enabled: None,
            set_dapp_controllers_result: Some(SetDappControllersCallResult {
                possibility: Some(set_dapp_controllers_call_result::Possibility::Ok(
                    SetDappControllersResponse {
                        failed_updates: vec![],
                    }
                )),
            }),
        }
    );

    // TEST_USER2 (the participant) should get their ICP back (less two transfer fees).
    {
        let observed_balance = ledger_account_balance(
            &mut state_machine,
            ICP_LEDGER_CANISTER_ID,
            &AccountBalanceArgs {
                account: AccountIdentifier::new(*TEST_USER2_PRINCIPAL, None).to_address(),
            },
        );
        let expected_balance = ((*TEST_USER2_ORIGINAL_BALANCE_ICP - DEFAULT_TRANSFER_FEE).unwrap()
            - DEFAULT_TRANSFER_FEE)
            .unwrap();
        assert_eq!(observed_balance, expected_balance);
    }

    // There should be no SNS neurons.
    {
        let observed_neurons = sns_governance_list_neurons(
            &mut state_machine,
            scenario.governance_canister_id,
            &ListNeurons::default(),
        )
        .neurons;
        assert_eq!(observed_neurons, vec![]);
    }

    // Finally, dapp should once again return to the (exclusive) control of TEST_USER1.
    {
        let dapp_canister_status = canister_status(
            &mut state_machine,
            *TEST_USER1_PRINCIPAL,
            &scenario.dapp_canister_id.into(),
        );
        assert_eq!(
            dapp_canister_status.controllers(),
            vec![*TEST_USER1_PRINCIPAL],
        );
    }
}

fn participate_in_swap(
    state_machine: &mut StateMachine,
    swap_canister_id: CanisterId,
    participant_principal_id: PrincipalId,
    amount: Tokens,
) {
    // First, transfer ICP to swap. Needs to go into a special subaccount...
    let subaccount = ledger_canister::Subaccount(ic_sns_swap::swap::principal_to_subaccount(
        &participant_principal_id,
    ));
    let request = Encode!(&TransferArgs {
        memo: Memo(0),
        amount,
        fee: DEFAULT_TRANSFER_FEE,
        from_subaccount: None,
        to: AccountIdentifier::new(swap_canister_id.into(), Some(subaccount)).to_address(),
        created_at_time: None,
    })
    .unwrap();
    state_machine
        .execute_ingress_as(
            participant_principal_id,
            ICP_LEDGER_CANISTER_ID,
            "transfer",
            request,
        )
        .unwrap();
    // ... then, swap must be notified about that transfer.
    state_machine
        .execute_ingress(
            swap_canister_id,
            "refresh_buyer_tokens",
            Encode!(&swap_pb::RefreshBuyerTokensRequest {
                buyer: participant_principal_id.to_string(),
            })
            .unwrap(),
        )
        .unwrap();
}

fn nns_governance_make_proposal(
    state_machine: &mut StateMachine,
    sender: PrincipalId,
    neuron_id: nns_common_pb::NeuronId,
    proposal: &Proposal,
) -> manage_neuron_response::MakeProposalResponse {
    let result = state_machine
        .execute_ingress_as(
            sender,
            NNS_GOVERNANCE_CANISTER_ID,
            "manage_neuron",
            Encode!(&ManageNeuron {
                id: Some(neuron_id),
                command: Some(manage_neuron::Command::MakeProposal(Box::new(
                    proposal.clone()
                ))),
                neuron_id_or_subaccount: None
            })
            .unwrap(),
        )
        .unwrap();

    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Failed to make proposal: {:#?}", s),
    };

    let result = Decode!(&result, ManageNeuronResponse).unwrap();
    match result.command {
        Some(manage_neuron_response::Command::MakeProposal(response)) => response,
        _ => panic!("Response was not of type MakeProposal: {:#?}", result),
    }
}

fn sns_root_register_dapp_canister(
    state_machine: &mut StateMachine,
    target_canister_id: CanisterId,
    request: &RegisterDappCanisterRequest,
) -> RegisterDappCanisterResponse {
    let result = state_machine
        .execute_ingress(
            target_canister_id,
            "register_dapp_canister",
            Encode!(&request).unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!(
                "register_dapp_canister was rejected by the swap canister: {:#?}",
                reject
            )
        }
    };
    Decode!(&result, RegisterDappCanisterResponse).unwrap()
}

fn sns_governance_list_neurons(
    state_machine: &mut StateMachine,
    sns_governance_canister_id: CanisterId,
    request: &ListNeurons,
) -> ListNeuronsResponse {
    let result = state_machine
        .execute_ingress(
            sns_governance_canister_id,
            "list_neurons",
            Encode!(&request).unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!("get_state was rejected by the swap canister: {:#?}", reject)
        }
    };
    Decode!(&result, ListNeuronsResponse).unwrap()
}

fn ledger_account_balance(
    state_machine: &mut StateMachine,
    ledger_canister_id: CanisterId,
    request: &AccountBalanceArgs,
) -> Tokens {
    let result = state_machine
        .execute_ingress(
            ledger_canister_id,
            "account_balance",
            Encode!(&request).unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!("get_state was rejected by the swap canister: {:#?}", reject)
        }
    };
    Decode!(&result, Tokens).unwrap()
}

fn swap_get_state(
    state_machine: &mut StateMachine,
    swap_canister_id: CanisterId,
    request: &swap_pb::GetStateRequest,
) -> swap_pb::GetStateResponse {
    let result = state_machine
        .execute_ingress(swap_canister_id, "get_state", Encode!(request).unwrap())
        .unwrap();
    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!("get_state was rejected by the swap canister: {:#?}", reject)
        }
    };
    Decode!(&result, swap_pb::GetStateResponse).unwrap()
}
