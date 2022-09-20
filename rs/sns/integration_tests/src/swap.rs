use candid::{types::number::Nat, CandidType, Decode, Encode};
use canister_test::Project;
use ic_base_types::{CanisterId, PrincipalId};
use ic_ic00_types::{CanisterInstallMode, CanisterSettingsArgs, UpdateSettingsArgs};
use ic_icrc1::Account;
use ic_ledger_core::Tokens;
use ic_nervous_system_common::ledger::compute_neuron_staking_subaccount_bytes;
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_OWNER_PRINCIPAL, TEST_USER1_PRINCIPAL, TEST_USER2_PRINCIPAL,
};
use ic_nns_common::pb::v1 as nns_common_pb;
use ic_nns_constants::{
    GOVERNANCE_CANISTER_ID as NNS_GOVERNANCE_CANISTER_ID,
    LEDGER_CANISTER_ID as ICP_LEDGER_CANISTER_ID, ROOT_CANISTER_ID as NNS_ROOT_CANISTER_ID,
};
use ic_nns_governance::pb::v1::{
    self as nns_governance_pb,
    manage_neuron::{self, RegisterVote},
    manage_neuron_response, proposal, ManageNeuron, OpenSnsTokenSwap, Proposal, Vote,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder, ids::TEST_NEURON_1_ID, state_test_helpers,
    state_test_helpers::setup_nns_canisters,
};
use ic_sns_governance::pb::v1::{self as sns_governance_pb, ListNeurons, ListNeuronsResponse};
use ic_sns_init::SnsCanisterInitPayloads;
use ic_sns_root::{
    pb::v1::{RegisterDappCanisterRequest, RegisterDappCanisterResponse},
    CanisterIdRecord, CanisterStatusResultV2,
};
use ic_sns_swap::pb::v1::{
    self as swap_pb, set_dapp_controllers_call_result, SetDappControllersCallResult,
    SetDappControllersResponse,
};
use ic_sns_test_utils::itest_helpers::{populate_canister_ids, SnsTestsInitPayloadBuilder};
use ic_state_machine_tests::StateMachine;
use ic_types::{
    crypto::{AlgorithmId, UserPublicKey},
    ingress::WasmResult,
};
use lazy_static::lazy_static;
use ledger_canister::{
    AccountIdentifier, BinaryAccountBalanceArgs as AccountBalanceArgs, Memo, TransferArgs,
    DEFAULT_TRANSFER_FEE,
};
use num_traits::ToPrimitive;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use std::{
    collections::HashMap,
    time::{Duration, SystemTime},
};

const SECONDS_PER_DAY: u64 = 24 * 60 * 60;

/// 10^8
const E8: u64 = 1_0000_0000;

const COMMUNITY_FUND_INVESTMENT_E8S: u64 = 30 * E8;

lazy_static! {
    static ref TEST_USER2_ORIGINAL_BALANCE_ICP: Tokens = Tokens::from_tokens(100).unwrap();
    static ref SWAP_DUE_TIMESTAMP_SECONDS: u64 = StateMachine::new()
        .time()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 13 * SECONDS_PER_DAY;
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct SwapPerformanceResults {
    instructions_consumed_base: f64,
    instructions_consumed_swapping: f64,
    instructions_consumed_finalization: f64,
    time_to_finalize_swap: Duration,
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
    ///   1. The swap canister is funded (with the provided number of SNS tokens).
    ///   2. The canister_id fields are populated.
    ///
    /// The dapp canister is owned by TEST_USER1.
    pub fn new(state_machine: &mut StateMachine, sns_tokens: Tokens) -> Self {
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
        let account_identifier = Account {
            owner: swap_canister_id.into(),
            subaccount: None,
        };
        let mut configuration = SnsTestsInitPayloadBuilder::new()
            .with_ledger_account(account_identifier, sns_tokens)
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

fn make_account(seed: u64) -> ic_base_types::PrincipalId {
    /// This is copied from ic_canister_client::agent::ed25519_public_key_to_der to
    /// avoid having to import that crate.
    fn ed25519_public_key_to_der(mut key: Vec<u8>) -> Vec<u8> {
        let mut encoded: Vec<u8> = vec![
            0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        encoded.append(&mut key);
        encoded
    }

    let keypair = {
        let mut rng = ChaChaRng::seed_from_u64(seed);
        ic_canister_client_sender::Ed25519KeyPair::generate(&mut rng)
    };
    let pubkey: UserPublicKey = UserPublicKey {
        key: keypair.public_key.to_vec(),
        algorithm_id: AlgorithmId::Ed25519,
    };
    let principal_id: PrincipalId =
        PrincipalId::new_self_authenticating(&ed25519_public_key_to_der(pubkey.key));
    principal_id
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
/// TEST_USER2 has 100 ICP that they can use to buy into the swap, as well as any accounts listed in `accounts`.
fn begin_swap(
    state_machine: &mut StateMachine,
    accounts: &[ic_base_types::PrincipalId],
    planned_contribution_per_account: u64,
    planned_cf_contribution: u64,
) -> (
    Scenario,
    /* community_fund_nns_neurons */ Vec<nns_governance_pb::Neuron>,
) {
    let num_accounts = accounts.len().max(1) as u64;
    // Give TEST_USER2 and everyone in `accounts` some ICP so that they can buy into the swap.
    let test_user2_principal_id: PrincipalId = *TEST_USER2_PRINCIPAL;
    let mut nns_init_payloads = NnsInitPayloadsBuilder::new()
        .with_ledger_account(
            test_user2_principal_id.into(),
            *TEST_USER2_ORIGINAL_BALANCE_ICP,
        )
        .with_ledger_accounts(
            accounts
                .iter()
                .map(|principal_id| ((*principal_id).into(), *TEST_USER2_ORIGINAL_BALANCE_ICP))
                .collect(),
        )
        .with_test_neurons()
        .build();
    // Give neurons maturity and make the first two join the community fund.
    let mut community_fund_neurons = vec![];
    {
        for (i, neuron) in nns_init_payloads
            .governance
            .neurons
            .values_mut()
            .enumerate()
        {
            let n = (i + 1) as u64;
            neuron.maturity_e8s_equivalent = n * 25 * E8;

            if i < 2 {
                neuron.joined_community_fund_timestamp_seconds = Some(1);
                community_fund_neurons.push(neuron.clone());
            }
        }
    }
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
    let mut scenario = Scenario::new(
        state_machine,
        Tokens::from_tokens(100 * num_accounts).unwrap(),
    );
    // Fill in more swap parameters.
    {
        let swap = &mut scenario.configuration.swap;

        // In case of failure, restore TEST_USER1 as the controller of the dapp.
        swap.fallback_controller_principal_ids = vec![TEST_USER1_PRINCIPAL.to_string()];

        swap.validate()
            .unwrap_or_else(|err| panic!("Swap init arg: {:#?} invalid because {:?}", swap, err));
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

    // Propose that a swap be scheduled to start 3 days from now, and last for
    // 10 days.
    let neuron_id = nns_common_pb::NeuronId {
        id: TEST_NEURON_1_ID,
    };
    let goal_tokens_raised = Tokens::from_tokens(
        planned_contribution_per_account * num_accounts + planned_cf_contribution,
    )
    .unwrap()
    .get_e8s();
    let response = nns_governance_make_proposal(
        state_machine,
        *TEST_NEURON_1_OWNER_PRINCIPAL, // sender
        neuron_id,
        &Proposal {
            title: Some("Schedule SNS Token Sale".to_string()),
            summary: "".to_string(),
            url: "".to_string(),
            action: Some(proposal::Action::OpenSnsTokenSwap(OpenSnsTokenSwap {
                target_swap_canister_id: Some(scenario.swap_canister_id.into()),
                params: Some(swap_pb::Params {
                    // Succeed as soon as we raise `goal_tokens_raised`. In this case,
                    // SNS tokens and ICP trade at parity.
                    max_icp_e8s: goal_tokens_raised,
                    // We want to make sure our test is exactly right, so we set the
                    // minimum to be just one e8 less than the maximum.
                    min_icp_e8s: goal_tokens_raised - 1,

                    // We need at least one participant, but they can contribute whatever
                    // amount they want (subject to max_icp_e8s for the whole swap).
                    min_participants: 1,
                    min_participant_icp_e8s: 1,
                    max_participant_icp_e8s: TEST_USER2_ORIGINAL_BALANCE_ICP.get_e8s(),

                    swap_due_timestamp_seconds: *SWAP_DUE_TIMESTAMP_SECONDS,
                    sns_token_e8s: goal_tokens_raised,
                }),
                // This is not sufficient to make the swap an automatic success.
                community_fund_investment_e8s: Some(COMMUNITY_FUND_INVESTMENT_E8S),
            })),
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

    // Make sure that the swap is now open.
    {
        let result = swap_get_state(
            state_machine,
            scenario.swap_canister_id,
            &swap_pb::GetStateRequest {},
        )
        .swap
        .unwrap();

        assert_eq!(
            result.lifecycle(),
            swap_pb::Lifecycle::Open,
            "{:#?}",
            result
        );
    }

    (scenario, community_fund_neurons)
}

#[test]
fn swap_lifecycle_happy_one_neuron() {
    swap_n_accounts(1);
}

#[test]
fn swap_lifecycle_happy_two_neurons() {
    swap_n_accounts(2);
}

#[test]
fn swap_lifecycle_happy_more_neurons() {
    swap_n_accounts(101);
}

fn swap_n_accounts(num_accounts: u64) -> SwapPerformanceResults {
    assert!(
        num_accounts > 0,
        "Testing the swap lifecycle requires num_accounts > 0"
    );
    // Step 0: Constants
    let planned_contribution_per_account = 70;
    let planned_cf_contribution = 30;

    // Step 1: Prepare the world.
    let mut state_machine = StateMachine::new();
    let accounts = (0..num_accounts).map(make_account).collect::<Vec<_>>();
    let (scenario, community_fund_neurons) = begin_swap(
        &mut state_machine,
        &accounts,
        planned_contribution_per_account,
        planned_cf_contribution,
    );

    // Step 1.5: initialize variables for the benchmark
    let instructions_consumed_base = state_machine.instructions_consumed();
    let mut instructions_consumed_swapping = None;
    let mut time_finalization_started = None;

    let assert_cf_neuron_maturities =
        |state_machine: &mut StateMachine, withdrawl_amounts_e8s: &[u64]| {
            assert_eq!(community_fund_neurons.len(), withdrawl_amounts_e8s.len());

            for (original_neuron, withdrawl_amount_e8s) in community_fund_neurons
                .iter()
                .zip(withdrawl_amounts_e8s.iter())
            {
                let new_neuron = nns_governance_get_full_neuron(
                    state_machine,
                    original_neuron.controller.unwrap(),
                    original_neuron.id.as_ref().unwrap().id,
                )
                .unwrap();
                assert_eq!(
                    new_neuron.maturity_e8s_equivalent,
                    original_neuron.maturity_e8s_equivalent - withdrawl_amount_e8s,
                );
            }
        };

    // We'll do this again after finalizing the swap.
    assert_cf_neuron_maturities(&mut state_machine, &[10 * E8, 20 * E8]);

    // Step 2: Run code under test.

    // Have all the accounts we created participate in the swap
    for (index, principal_id) in accounts.iter().enumerate() {
        println!("Swapping user {index}/{num_accounts}");
        if index == num_accounts as usize - 1 {
            time_finalization_started = Some(SystemTime::now());
            instructions_consumed_swapping =
                Some(state_machine.instructions_consumed() - instructions_consumed_base);
        }
        participate_in_swap(
            &mut state_machine,
            scenario.swap_canister_id,
            *principal_id,
            Tokens::from_tokens(planned_contribution_per_account).unwrap(),
        );
    }

    // Make sure the swap reached the Committed state.
    {
        let result = swap_get_state(
            &mut state_machine,
            scenario.swap_canister_id,
            &swap_pb::GetStateRequest {},
        )
        .swap
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

    let instructions_consumed_finalization =
        state_machine.instructions_consumed() - instructions_consumed_swapping.unwrap();
    let time_to_finalize_swap = time_finalization_started.unwrap().elapsed().unwrap();

    // Step 3: Inspect results.

    // Step 3.1: Inspect finalize_swap_response.
    {
        use swap_pb::settle_community_fund_participation_result::{Possibility, Response};
        assert_eq!(
            finalize_swap_response,
            swap_pb::FinalizeSwapResponse {
                sweep_icp: Some(swap_pb::SweepResult {
                    // While, the other fields in the response count 3 successes,
                    // this only counts 1, because 2 of the participants are from
                    // the (maturity of) Community Fund (NNS neurons).
                    success: num_accounts as u32,
                    failure: 0,
                    skipped: 0,
                }),
                sweep_sns: Some(swap_pb::SweepResult {
                    success: num_accounts as u32 + 2,
                    failure: 0,
                    skipped: 0,
                }),
                create_neuron: Some(swap_pb::SweepResult {
                    success: num_accounts as u32 + 2,
                    failure: 0,
                    skipped: 0,
                }),
                sns_governance_normal_mode_enabled: Some(swap_pb::SetModeCallResult {
                    possibility: None
                }),
                set_dapp_controllers_result: None,
                settle_community_fund_participation_result: Some(
                    swap_pb::SettleCommunityFundParticipationResult {
                        possibility: Some(Possibility::Ok(Response {
                            governance_error: None,
                        })),
                    }
                )
            }
        );
    }

    // Step 3.2.1: Inspect ICP balances.

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
        let total_transferred = Tokens::from_tokens(
            planned_contribution_per_account * num_accounts + planned_cf_contribution,
        )
        .unwrap();
        let total_paid_in_transfer_fee =
            Tokens::from_e8s(DEFAULT_TRANSFER_FEE.get_e8s() * num_accounts);
        let expected_balance = (total_transferred - total_paid_in_transfer_fee).unwrap();
        assert_eq!(observed_balance, expected_balance);
    }
    // All the users still has the change left over from their participation in the swap/sale.
    for principal_id in accounts.iter() {
        let observed_balance = ledger_account_balance(
            &mut state_machine,
            ICP_LEDGER_CANISTER_ID,
            &AccountBalanceArgs {
                account: AccountIdentifier::new(*principal_id, None).to_address(),
            },
        );
        let expected_balance =
            (Tokens::from_tokens(planned_cf_contribution).unwrap() - DEFAULT_TRANSFER_FEE).unwrap();
        assert_eq!(observed_balance, expected_balance);
    }

    // Step 3.2.2: Inspect SNS token balances.
    let community_fund_total_maturity: u64 = community_fund_neurons
        .iter()
        .map(|neuron| neuron.maturity_e8s_equivalent)
        .sum();
    let expected_sns_neuron_subaccount_to_gross_participation_amount_e8s = community_fund_neurons
        .iter()
        .map(|nns_neuron| {
            let sns_neuron_subaccount = compute_neuron_staking_subaccount_bytes(
                NNS_GOVERNANCE_CANISTER_ID.into(),
                nns_neuron.id.clone().unwrap().id,
            );
            let participation_amount_e8s = COMMUNITY_FUND_INVESTMENT_E8S
                * nns_neuron.maturity_e8s_equivalent
                / community_fund_total_maturity;

            (sns_neuron_subaccount, participation_amount_e8s)
        })
        .chain(accounts.iter().map(|principal_id| {
            (
                compute_neuron_staking_subaccount_bytes(*principal_id, 0),
                planned_contribution_per_account * E8,
            )
        }))
        .collect::<Vec<(
            /* subaccount: */ [u8; 32],
            /* gross_participation_amount_e8s: */ u64,
        )>>();
    for (sns_neuron_subaccount, expected_gross_participation_amount_e8s) in
        &expected_sns_neuron_subaccount_to_gross_participation_amount_e8s
    {
        let observed_balance = icrc1_balance_of(
            &mut state_machine,
            scenario.ledger_canister_id,
            &ic_icrc1::Account {
                owner: scenario.governance_canister_id.into(),
                subaccount: Some(*sns_neuron_subaccount),
            },
        )
        .0
        .to_u64()
        .unwrap();
        let expected_balance =
            expected_gross_participation_amount_e8s - DEFAULT_TRANSFER_FEE.get_e8s();

        assert_eq!(observed_balance, expected_balance);
    }
    let expected_sns_neuron_id_to_net_participation_amount_e8s =
        expected_sns_neuron_subaccount_to_gross_participation_amount_e8s
            .iter()
            .map(|(sns_neuron_subaccount, participation_amount_e8s)| {
                let sns_neuron_id = sns_governance_pb::NeuronId::from(*sns_neuron_subaccount);
                (
                    sns_neuron_id,
                    participation_amount_e8s - DEFAULT_TRANSFER_FEE.get_e8s(),
                )
            })
            .collect::<HashMap<_, _>>();

    // Step 3.3: Inspect SNS neurons.
    // `sns_governance_list_neurons` returns at most 100 neurons.
    // So we need to page through the results to get them all.
    let observed_sns_neurons = {
        let mut observed_sns_neurons = Vec::new();
        let mut start_page_at: Option<ic_sns_governance::pb::v1::NeuronId> = None;
        loop {
            let current_batch = sns_governance_list_neurons(
                &mut state_machine,
                scenario.governance_canister_id,
                &ListNeurons {
                    start_page_at,
                    ..ListNeurons::default()
                },
            )
            .neurons;
            if current_batch.is_empty() {
                break;
            } else {
                start_page_at = Some(current_batch[current_batch.len() - 1].id.clone().unwrap());
                observed_sns_neurons.extend(current_batch);
            }
        }
        observed_sns_neurons
    };
    assert_eq!(observed_sns_neurons.len() as u64, num_accounts + 2);
    for observed_sns_neuron in &observed_sns_neurons {
        assert_eq!(
            observed_sns_neuron.maturity_e8s_equivalent, 0,
            "{:#?}",
            observed_sns_neuron,
        );
        assert_eq!(
            observed_sns_neuron.neuron_fees_e8s, 0,
            "{:#?}",
            observed_sns_neuron
        );

        let neuron_id = observed_sns_neuron.id.clone().unwrap();
        let expected_e8s = *expected_sns_neuron_id_to_net_participation_amount_e8s
            .get(&neuron_id)
            .unwrap_or_else(|| {
                panic!(
                    "Unexpected SNS NeuronId: {}. Expected NeuronIds: {:#?}",
                    neuron_id,
                    expected_sns_neuron_id_to_net_participation_amount_e8s
                        .keys()
                        .map(|neuron_id| neuron_id.to_string())
                        .collect::<Vec<_>>(),
                )
            });
        assert_eq!(
            observed_sns_neuron.cached_neuron_stake_e8s, expected_e8s,
            "{:#?}",
            observed_sns_neuron
        );
    }

    // STEP 3.4: NNS governance is responsible for "settling" CF
    // contributions. In this case, that means that a total of 30 ICP was minted
    // and sent to the the default account of the SNS governance canister, 10
    // ICP coming from NNS neuron 1 and 20 ICP from neuron 2 (more accurately,
    // from their maturity).
    //
    // We already noticed the 30 ICP being added to the SNS governance
    // canister's (default) account in step 3.2.1. Therefore, all that remains
    // for us to verify is that the maturity of the two CF neurons have been
    // decreased by the right amounts.
    assert_cf_neuron_maturities(&mut state_machine, &[10 * E8, 20 * E8]);

    SwapPerformanceResults {
        instructions_consumed_base,
        instructions_consumed_swapping: instructions_consumed_swapping.unwrap(),
        instructions_consumed_finalization,
        time_to_finalize_swap,
    }
}

#[test]
fn swap_lifecycle_sad() {
    // Step 0: Constants
    let planned_contribution_per_account = 70;
    let planned_cf_contribution = 30;

    // Step 1: Prepare the world.
    let mut state_machine = StateMachine::new();
    let (scenario, community_fund_neurons) = begin_swap(
        &mut state_machine,
        &[],
        planned_contribution_per_account,
        planned_cf_contribution,
    );

    let assert_cf_neuron_maturities =
        |state_machine: &mut StateMachine, withdrawl_amounts_e8s: &[u64]| {
            assert_eq!(community_fund_neurons.len(), withdrawl_amounts_e8s.len());

            for (original_neuron, withdrawl_amount_e8s) in community_fund_neurons
                .iter()
                .zip(withdrawl_amounts_e8s.iter())
            {
                let new_neuron = nns_governance_get_full_neuron(
                    state_machine,
                    original_neuron.controller.unwrap(),
                    original_neuron.id.as_ref().unwrap().id,
                )
                .unwrap();
                let expected_e8s = original_neuron.maturity_e8s_equivalent - withdrawl_amount_e8s;
                assert!(new_neuron.maturity_e8s_equivalent >= expected_e8s);
                // This can occur if neurons are given their voting rewards.
                let extra =
                    (new_neuron.maturity_e8s_equivalent as f64) / (expected_e8s as f64) - 1.0;
                assert!(
                    extra < 0.015,
                    "observed = {} expected = {} extra = {}",
                    new_neuron.maturity_e8s_equivalent,
                    expected_e8s,
                    extra,
                );
            }
        };

    // We'll do something like this again after finalizing the swap, except
    // we'll pass all zero withdrawl amounts instead, because finalization ins
    // supposed to include restoring maturities after a failed swap.
    assert_cf_neuron_maturities(&mut state_machine, &[10 * E8, 20 * E8]);

    // Step 2: Run code under test.

    // TEST_USER2 participates, but not enough for the swap to succeed, even
    // after the open time window has passed.
    participate_in_swap(
        &mut state_machine,
        scenario.swap_canister_id,
        *TEST_USER2_PRINCIPAL,
        Tokens::from_e8s(E8 - 1),
    );

    // Make sure the swap is still in the Open state.
    {
        let result = swap_get_state(
            &mut state_machine,
            scenario.swap_canister_id,
            &swap_pb::GetStateRequest {},
        )
        .swap
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
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(*SWAP_DUE_TIMESTAMP_SECONDS + 1),
    );

    // Make sure the swap reached the Aborted state.
    {
        let result = swap_get_state(
            &mut state_machine,
            scenario.swap_canister_id,
            &swap_pb::GetStateRequest {},
        )
        .swap
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

    // Step 3.1: Inspect finalize_swap_response.
    {
        use swap_pb::settle_community_fund_participation_result::{Possibility, Response};
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
                settle_community_fund_participation_result: Some(
                    swap_pb::SettleCommunityFundParticipationResult {
                        possibility: Some(Possibility::Ok(Response {
                            governance_error: None,
                        })),
                    }
                )
            }
        );
    }

    // Step 3.2.1: Inspect ICP balance(s).
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

    // Step 3.2.2: Inspect SNS token balance(s).
    {
        // Assert that the swap/sale canister's SNS token balance is unchanged.
        // Since this is the entire supply, we can be sure that nobody else has
        // any SNS tokens.
        let observed_balance = icrc1_balance_of(
            &mut state_machine,
            scenario.ledger_canister_id,
            &ic_icrc1::Account {
                owner: scenario.swap_canister_id.into(),
                subaccount: None,
            },
        )
        .0
        .to_u64()
        .unwrap();
        assert_eq!(observed_balance, 100 * E8);
    }

    // Step 3.3: There should be no SNS neurons.
    {
        let observed_neurons = sns_governance_list_neurons(
            &mut state_machine,
            scenario.governance_canister_id,
            &ListNeurons::default(),
        )
        .neurons;
        assert_eq!(observed_neurons, vec![]);
    }

    // Dapp should once again return to the (exclusive) control of TEST_USER1.
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

    // Maturity of CF neurons should be restored.
    assert_cf_neuron_maturities(&mut state_machine, &[0, 0]);
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
    let result = state_test_helpers::nns_governance_make_proposal(
        state_machine,
        sender,
        neuron_id,
        proposal,
    );

    match result.command {
        Some(manage_neuron_response::Command::MakeProposal(response)) => response,
        _ => panic!("Response was not of type MakeProposal: {:#?}", result),
    }
}

fn nns_governance_get_full_neuron(
    state_machine: &mut StateMachine,
    sender: PrincipalId,
    neuron_id: u64,
) -> Result<nns_governance_pb::Neuron, nns_governance_pb::GovernanceError> {
    let result = state_machine
        .execute_ingress_as(
            sender,
            NNS_GOVERNANCE_CANISTER_ID,
            "get_full_neuron",
            Encode!(&neuron_id).unwrap(),
        )
        .unwrap();

    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!(
                "get_full_neuron was rejected by the NNS governance canister: {:#?}",
                reject
            )
        }
    };
    Decode!(&result, Result<nns_governance_pb::Neuron, nns_governance_pb::GovernanceError>).unwrap()
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

fn icrc1_balance_of(
    state_machine: &mut StateMachine,
    target_canister_id: CanisterId,
    request: &ic_icrc1::Account,
) -> Nat {
    let result = state_machine
        .execute_ingress(
            target_canister_id,
            "icrc1_balance_of",
            Encode!(&request).unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!("get_state was rejected by the swap canister: {:#?}", reject)
        }
    };
    Decode!(&result, Nat).unwrap()
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

#[cfg(feature = "long_bench")]
#[test]
fn swap_load_test() {
    use std::fs::OpenOptions;
    use std::io::prelude::*;
    let filename = "swap_load_test_results.csv";

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true) // Fail if the file already exists
        .open(filename)
        .unwrap();

    if let Err(e) = writeln!(file, "num_accounts,instructions_consumed_base,instructions_consumed_swapping,instructions_consumed_finalization,time_ms") {
        eprintln!("Couldn't write to file: {}", e);
    }

    let max_accounts = 100_000;
    let mut num_accounts = 10;
    loop {
        if num_accounts > max_accounts {
            break;
        }
        let SwapPerformanceResults {
            instructions_consumed_base,
            instructions_consumed_swapping,
            instructions_consumed_finalization,
            time_to_finalize_swap,
        } = swap_n_accounts(num_accounts);

        let mut file = OpenOptions::new()
            .write(true)
            .append(true)
            .open(filename)
            .unwrap();

        if let Err(e) = writeln!(
            file,
            "{},{},{},{},{}",
            num_accounts,
            instructions_consumed_base,
            instructions_consumed_swapping,
            instructions_consumed_finalization,
            time_to_finalize_swap.as_millis()
        ) {
            eprintln!("Couldn't write to file: {}", e);
        }
        num_accounts = ((num_accounts as f64) * 2.0) as u64;
    }
}
