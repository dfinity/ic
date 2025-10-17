//! Unit tests that were previously written in rs/sns/governance/src/governance.rs are now
//! here, so that Bazel does not recompile the whole production crate each time the tests are run.
//! The name of this file is indeed too generic; feel free to factor specific tests out into
//! more appropriate locations, or create new file modules for them, whatever makes more sense.
use crate::{
    extensions::{ExtensionSpec, ExtensionType, ExtensionVersion},
    governance::{
        test_helpers::{
            A_MOTION_PROPOSAL, A_NEURON, A_NEURON_ID, A_NEURON_PRINCIPAL_ID, DoNothingLedger,
            TEST_ARCHIVES_CANISTER_IDS, TEST_DAPP_CANISTER_IDS, TEST_GOVERNANCE_CANISTER_ID,
            TEST_INDEX_CANISTER_ID, TEST_LEDGER_CANISTER_ID, TEST_ROOT_CANISTER_ID,
            TEST_SWAP_CANISTER_ID, basic_governance_proto, canister_status_for_test,
            canister_status_from_management_canister_for_test,
        },
        *,
    },
    pb::v1::{
        Account as AccountProto, Motion, NervousSystemFunction, NeuronPermissionType, ProposalData,
        ProposalId, Tally, UpgradeJournalEntry, UpgradeSnsControlledCanister,
        UpgradeSnsToNextVersion, VotingRewardsParameters, WaitForQuietState,
        governance::{CachedUpgradeSteps as CachedUpgradeStepsPb, Versions},
        manage_neuron_response,
        nervous_system_function::{FunctionType, GenericNervousSystemFunction},
        neuron,
    },
    reward,
    sns_upgrade::{
        CanisterSummary, GetNextSnsVersionRequest, GetNextSnsVersionResponse,
        GetSnsCanistersSummaryRequest, GetSnsCanistersSummaryResponse, GetWasmRequest,
        GetWasmResponse, ListUpgradeStep, ListUpgradeStepsRequest, ListUpgradeStepsResponse,
        SnsCanisterType, SnsVersion, SnsWasm,
    },
    storage::cache_registered_extension,
    topics::{
        ListTopicsResponse, NervousSystemFunctions, RegisteredExtensionOperationSpec, TopicInfo,
    },
    types::test_helpers::NativeEnvironment,
};
use assert_matches::assert_matches;
use async_trait::async_trait;
use candid::{Nat, Principal};
use futures::{FutureExt, join};
use ic_canister_client_sender::Sender;
use ic_nervous_system_canisters::cmc::FakeCmc;
use ic_nervous_system_clients::{
    canister_id_record::CanisterIdRecord, canister_status::CanisterStatusType,
};
use ic_nervous_system_common::{
    E8, ONE_DAY_SECONDS, START_OF_2022_TIMESTAMP_SECONDS, assert_is_err, assert_is_ok,
    ledger::compute_neuron_staking_subaccount_bytes,
};
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_OWNER_PRINCIPAL, TEST_NEURON_2_OWNER_PRINCIPAL, TEST_USER1_KEYPAIR,
};
use ic_nns_constants::SNS_WASM_CANISTER_ID;
use ic_sns_governance_api::pb::v1::topics::Topic;
use ic_sns_governance_token_valuation::{Token, ValuationFactors};
use ic_sns_test_utils::itest_helpers::UserInfo;
use ic_test_utilities_types::ids::canister_test_id;
use icrc_ledger_types::icrc3::blocks::{GetBlocksRequest, GetBlocksResult};
use maplit::btreemap;
use pretty_assertions::assert_eq;
use proptest::prelude::{prop_assert, proptest};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

struct AlwaysSucceedingLedger {}

#[async_trait]
impl ICRC1Ledger for AlwaysSucceedingLedger {
    async fn transfer_funds(
        &self,
        _amount_e8s: u64,
        _fee_e8s: u64,
        _from_subaccount: Option<Subaccount>,
        _to: Account,
        _memo: u64,
    ) -> Result<u64, NervousSystemError> {
        Ok(0)
    }

    async fn total_supply(&self) -> Result<Tokens, NervousSystemError> {
        Ok(Tokens::default())
    }

    async fn account_balance(&self, _account: Account) -> Result<Tokens, NervousSystemError> {
        Ok(Tokens::default())
    }

    fn canister_id(&self) -> CanisterId {
        CanisterId::from_u64(42)
    }

    async fn icrc2_approve(
        &self,
        _spender: Account,
        _amount: u64,
        _expires_at: Option<u64>,
        _fee: u64,
        _from_subaccount: Option<Subaccount>,
        _expected_allowance: Option<u64>,
    ) -> Result<Nat, NervousSystemError> {
        Err(NervousSystemError {
            error_message: "Not Implemented".to_string(),
        })
    }

    async fn icrc3_get_blocks(
        &self,
        _args: Vec<GetBlocksRequest>,
    ) -> Result<GetBlocksResult, NervousSystemError> {
        Err(NervousSystemError {
            error_message: "Not Implemented".to_string(),
        })
    }
}

const TRANSITION_ROUND_COUNT: u64 = 42;
const BASE_VOTING_REWARDS_PARAMETERS: VotingRewardsParameters = VotingRewardsParameters {
    round_duration_seconds: Some(7 * 24 * 60 * 60), // 1 week
    reward_rate_transition_duration_seconds: Some(TRANSITION_ROUND_COUNT * 7 * 24 * 60 * 60), // 42 weeks
    initial_reward_rate_basis_points: Some(200),                                              // 2%
    final_reward_rate_basis_points: Some(100),                                                // 1%
};

#[test]
fn fixtures_are_valid() {
    assert_is_ok!(ValidGovernanceProto::try_from(basic_governance_proto()));
    assert_is_ok!(BASE_VOTING_REWARDS_PARAMETERS.validate());
}

#[test]
fn unspecified_mode_is_invalid() {
    let g = GovernanceProto {
        mode: governance::Mode::Unspecified as i32,
        ..basic_governance_proto()
    };
    assert!(ValidGovernanceProto::try_from(g.clone()).is_err(), "{g:#?}");
}

#[test]
fn garbage_mode_is_invalid() {
    let g = GovernanceProto {
        mode: 0xDEADBEF,
        ..basic_governance_proto()
    };
    assert!(ValidGovernanceProto::try_from(g.clone()).is_err(), "{g:#?}");
}

#[tokio::test]
async fn test_perform_transfer_sns_treasury_funds_execution_fails_when_another_call_is_in_progress()
{
    // Step 0: Define helpers.

    // This expects a transfer_funds call. That call takes 10 ms to complete. This allows us to
    // make concurrent calls to code under test.
    struct StubLedger {}

    #[async_trait]
    impl ICRC1Ledger for StubLedger {
        async fn transfer_funds(
            &self,
            _amount_e8s: u64,
            _fee_e8s: u64,
            _from_subaccount: Option<Subaccount>,
            _to: Account,
            _memo: u64,
        ) -> Result<u64, NervousSystemError> {
            tokio::time::sleep(Duration::from_millis(200)).await;
            Ok(1)
        }

        // The rest are unimplemented.

        async fn total_supply(&self) -> Result<Tokens, NervousSystemError> {
            unimplemented!()
        }

        async fn account_balance(&self, _account: Account) -> Result<Tokens, NervousSystemError> {
            unimplemented!()
        }

        fn canister_id(&self) -> CanisterId {
            unimplemented!()
        }

        async fn icrc2_approve(
            &self,
            _spender: Account,
            _amount: u64,
            _expires_at: Option<u64>,
            _fee: u64,
            _from_subaccount: Option<Subaccount>,
            _expected_allowance: Option<u64>,
        ) -> Result<Nat, NervousSystemError> {
            Err(NervousSystemError {
                error_message: "Not Implemented".to_string(),
            })
        }

        async fn icrc3_get_blocks(
            &self,
            _args: Vec<GetBlocksRequest>,
        ) -> Result<GetBlocksResult, NervousSystemError> {
            unimplemented!()
        }
    }

    let governance_proto = basic_governance_proto();
    let mut governance = Governance::new(
        ValidGovernanceProto::try_from(governance_proto).unwrap(),
        Box::new(NativeEnvironment::new(None)),
        Box::new(DoNothingLedger {}), // SNS token ledger.
        Box::new(StubLedger {}),      // ICP ledger.
        Box::new(FakeCmc::new()),
    );

    // Step 2: Run code under test.

    // No need to be aware of the particular values in here; they should not affect the outcome
    // of this test.
    let transfer_sns_treasury_funds = TransferSnsTreasuryFunds {
        amount_e8s: 272,
        from_treasury: TransferFrom::IcpTreasury as i32,
        to_principal: Some(PrincipalId::new_user_test_id(181_931_560)),
        to_subaccount: None,
        memo: None,
    };
    let valuation = Valuation {
        token: Token::Icp,
        account: Account {
            owner: Principal::from(PrincipalId::new_user_test_id(104_622_969)),
            subaccount: None,
        },
        timestamp: SystemTime::now(),
        valuation_factors: ValuationFactors {
            tokens: Decimal::from(314),
            icps_per_token: Decimal::from(2),
            xdrs_per_icp: Decimal::from(5),
        },
    };

    // This lets us (later) make a second manage_neuron method call
    // while one is in flight, which is essential for this test.
    let raw_governance = &mut governance as *mut Governance;

    let (result_1, result_2) = join! {
        // Call the code under test with 0 delay.
        governance.perform_transfer_sns_treasury_funds(
            7, // proposal_id,
            Ok(valuation),
            &transfer_sns_treasury_funds,
        ),

        // Make the same call, except this one is delayed by 5 ms. Later, we assert that this
        // fails with the right Err.
        async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            unsafe {
                raw_governance.as_mut().unwrap().perform_transfer_sns_treasury_funds(
                    7, // proposal_id,
                    Ok(valuation),
                    &transfer_sns_treasury_funds,
                )
                .await
            }
        }
    };

    // Step 3: Inspect results.

    // First call works.
    assert_eq!(result_1, Ok(()));

    // Second call fails.
    let err = result_2.unwrap_err();
    let GovernanceError {
        error_type,
        error_message,
    } = &err;

    assert_eq!(
        ErrorType::try_from(*error_type),
        Ok(ErrorType::PreconditionFailed),
        "{:#?}",
        err
    );

    let error_message = error_message.to_lowercase();
    for term in [
        "another",
        "transfersnstreasuryfunds",
        "7",
        "already",
        "in progress",
    ] {
        assert!(error_message.contains(term), "{err:#?}");
    }
}

#[tokio::test]
async fn test_neuron_operations_exclude_one_another() {
    // Step 0: Define helpers.
    struct TestLedger {
        transfer_funds_arrived: Arc<tokio::sync::Notify>,
        transfer_funds_continue: Arc<tokio::sync::Notify>,
    }

    #[async_trait]
    impl ICRC1Ledger for TestLedger {
        async fn transfer_funds(
            &self,
            _amount_e8s: u64,
            _fee_e8s: u64,
            _from_subaccount: Option<Subaccount>,
            _to: Account,
            _memo: u64,
        ) -> Result<u64, NervousSystemError> {
            self.transfer_funds_arrived.notify_one();
            self.transfer_funds_continue.notified().await;
            Ok(1)
        }

        async fn total_supply(&self) -> Result<Tokens, NervousSystemError> {
            unimplemented!()
        }

        async fn account_balance(&self, _account: Account) -> Result<Tokens, NervousSystemError> {
            Ok(Tokens::new(1, 0).unwrap())
        }

        fn canister_id(&self) -> CanisterId {
            unimplemented!()
        }

        async fn icrc2_approve(
            &self,
            _spender: Account,
            _amount: u64,
            _expires_at: Option<u64>,
            _fee: u64,
            _from_subaccount: Option<Subaccount>,
            _expected_allowance: Option<u64>,
        ) -> Result<Nat, NervousSystemError> {
            Err(NervousSystemError {
                error_message: "Not Implemented".to_string(),
            })
        }

        async fn icrc3_get_blocks(
            &self,
            _args: Vec<GetBlocksRequest>,
        ) -> Result<GetBlocksResult, NervousSystemError> {
            unimplemented!()
        }
    }

    let local_set = tokio::task::LocalSet::new(); // Because we are working with !Send data.
    local_set
        .run_until(async move {
            // Step 1: Prepare the world.
            let user = UserInfo::new(Sender::from_keypair(&TEST_USER1_KEYPAIR));
            let principal_id = user.sender.get_principal_id();
            // work around the fact that the type inside UserInfo is not the same as the type in this crate
            let neuron_id = crate::pb::v1::NeuronId {
                id: user.subaccount.to_vec(),
            };

            let mut governance_proto = basic_governance_proto();

            // Step 1.1: Add a neuron (so that we can operate on it).
            governance_proto.neurons.insert(
                neuron_id.to_string(),
                Neuron {
                    id: Some(neuron_id.clone()),
                    cached_neuron_stake_e8s: 10_000,
                    permissions: vec![NeuronPermission {
                        principal: Some(principal_id),
                        permission_type: NeuronPermissionType::all(),
                    }],
                    ..Default::default()
                },
            );

            // Lets us know that a transfer is in progress.
            let transfer_funds_arrived = Arc::new(tokio::sync::Notify::new());

            // Lets us tell ledger that it can proceed with the transfer.
            let transfer_funds_continue = Arc::new(tokio::sync::Notify::new());

            // Step 1.3: Create Governance that we will be sending manage_neuron calls to.
            let mut governance = Governance::new(
                ValidGovernanceProto::try_from(governance_proto).unwrap(),
                Box::<NativeEnvironment>::default(),
                Box::new(TestLedger {
                    transfer_funds_arrived: transfer_funds_arrived.clone(),
                    transfer_funds_continue: transfer_funds_continue.clone(),
                }),
                Box::new(DoNothingLedger {}),
                Box::new(FakeCmc::new()),
            );

            // Step 2: Execute code under test.

            // This lets us (later) make a second manage_neuron method call
            // while one is in flight, which is essential for this test.
            let raw_governance = &mut governance as *mut Governance;

            // Step 2.1: Begin an async that is supposed to interfere with a
            // later manage_neuron call.
            let disburse = ManageNeuron {
                subaccount: user.subaccount.to_vec(),
                command: Some(manage_neuron::Command::Disburse(manage_neuron::Disburse {
                    amount: None,
                    to_account: Some(AccountProto {
                        owner: Some(user.sender.get_principal_id()),
                        subaccount: None,
                    }),
                })),
            };
            let disburse_future = {
                let raw_disburse = &disburse as *const ManageNeuron;
                let raw_principal_id = &principal_id as *const PrincipalId;
                tokio::task::spawn_local(unsafe {
                    raw_governance.as_mut().unwrap().manage_neuron(
                        raw_disburse.as_ref().unwrap(),
                        raw_principal_id.as_ref().unwrap(),
                    )
                })
            };

            transfer_funds_arrived.notified().await;
            // It is now guaranteed that disburse is now in mid flight.

            // Step 2.2: Begin another manage_neuron call.
            let configure = ManageNeuron {
                subaccount: user.subaccount.to_vec(),
                command: Some(manage_neuron::Command::Configure(
                    manage_neuron::Configure {
                        operation: Some(
                            manage_neuron::configure::Operation::IncreaseDissolveDelay(
                                manage_neuron::IncreaseDissolveDelay {
                                    additional_dissolve_delay_seconds: 42,
                                },
                            ),
                        ),
                    },
                )),
            };
            let configure_result = unsafe {
                raw_governance
                    .as_mut()
                    .unwrap()
                    .manage_neuron(&configure, &principal_id)
                    .await
            };

            // Step 3: Inspect results.

            // Assert that configure_result is NeuronLocked.
            match &configure_result.command.as_ref().unwrap() {
                manage_neuron_response::Command::Error(err) => {
                    assert_eq!(
                        err.error_type,
                        ErrorType::NeuronLocked as i32,
                        "err: {:#?}",
                        err,
                    );
                }
                _ => panic!("configure_result: {configure_result:#?}"),
            }

            // Allow disburse to complete.
            transfer_funds_continue.notify_one();
            let disburse_result = disburse_future.await;
            assert!(disburse_result.is_ok(), "{disburse_result:#?}");
        })
        .await;
}

#[test]
fn test_governance_proto_must_have_root_canister_ids() {
    let mut proto = basic_governance_proto();
    proto.root_canister_id = None;
    assert!(ValidGovernanceProto::try_from(proto).is_err());
}

#[test]
fn test_governance_proto_must_have_ledger_canister_ids() {
    let mut proto = basic_governance_proto();
    proto.ledger_canister_id = None;
    assert!(ValidGovernanceProto::try_from(proto).is_err());
}

#[test]
fn test_governance_proto_must_have_swap_canister_ids() {
    let mut proto = basic_governance_proto();
    proto.swap_canister_id = None;
    assert!(ValidGovernanceProto::try_from(proto).is_err());
}

#[test]
fn test_governance_proto_must_have_parameters() {
    let mut proto = basic_governance_proto();
    proto.parameters = None;
    assert!(ValidGovernanceProto::try_from(proto).is_err());
}

#[test]
fn test_governance_proto_ids_in_nervous_system_functions_match() {
    let mut proto = basic_governance_proto();
    proto.id_to_nervous_system_functions.insert(
        1001,
        NervousSystemFunction {
            id: 1000,
            name: "THIS_IS_DEFECTIVE".to_string(),
            description: None,
            function_type: Some(FunctionType::GenericNervousSystemFunction(
                GenericNervousSystemFunction {
                    topic: None,
                    target_canister_id: Some(CanisterId::from_u64(1).get()),
                    target_method_name: Some("test_method".to_string()),
                    validator_canister_id: Some(CanisterId::from_u64(1).get()),
                    validator_method_name: Some("test_validator_method".to_string()),
                },
            )),
        },
    );
    assert!(ValidGovernanceProto::try_from(proto).is_err());
}

#[test]
fn swap_canister_id_is_required_when_mode_is_pre_initialization_swap() {
    let proto = GovernanceProto {
        mode: governance::Mode::PreInitializationSwap as i32,
        swap_canister_id: None,
        ..basic_governance_proto()
    };

    let r = ValidGovernanceProto::try_from(proto.clone());
    match r {
        Ok(_ok) => panic!("Invalid Governance proto, but wasn't rejected: {proto:#?}"),
        Err(err) => {
            for key_word in ["swap_canister_id", "populate"] {
                assert!(
                    err.contains(key_word),
                    "{key_word:#?} not present in the error: {err:#?}"
                );
            }
        }
    }
}

#[test]
fn test_governance_proto_neurons_voting_power_multiplier_in_expected_range() {
    let mut proto = basic_governance_proto();
    proto.neurons = btreemap! {
        "A".to_string() => Neuron {
            voting_power_percentage_multiplier: 0,
            ..Default::default()
        },
        "B".to_string() => Neuron {
            voting_power_percentage_multiplier: 50,
            ..Default::default()
        },
        "C".to_string() => Neuron {
            voting_power_percentage_multiplier: 100,
            ..Default::default()
        },
    };
    assert!(ValidGovernanceProto::try_from(proto.clone()).is_ok());
    proto.neurons.insert(
        "D".to_string(),
        Neuron {
            voting_power_percentage_multiplier: 101,
            ..Default::default()
        },
    );
    assert!(ValidGovernanceProto::try_from(proto).is_err());
}

#[test]
fn test_time_warp() {
    let w = TimeWarp { delta_s: 0_i64 };
    assert_eq!(w.apply(100_u64), 100);

    let w = TimeWarp { delta_s: 42_i64 };
    assert_eq!(w.apply(100_u64), 142);

    let w = TimeWarp { delta_s: -42_i64 };
    assert_eq!(w.apply(100_u64), 58);
}

proptest! {
    /// This test ensures that none of the asserts in
    /// `evaluate_wait_for_quiet` fire, and that the wait-for-quiet
    /// deadline is only ever increased, if at all.
    #[test]
    fn test_evaluate_wait_for_quiet_doesnt_shorten_deadline(
        initial_voting_period_seconds in 3600u64..604_800,
        wait_for_quiet_deadline_increase_seconds in 0u64..604_800,
        now_seconds in 0u64..1_000_000,
        old_yes in 0u64..1_000_000,
        old_no in 0u64..1_000_000,
        old_total in 10_000_000u64..100_000_000,
        yes_votes in 0u64..1_000_000,
        no_votes in 0u64..1_000_000,
    ) {
        let proposal_creation_timestamp_seconds = 0; // initial timestamp is always 0
        let mut proposal = ProposalData {
            id: Some(ProposalId { id: 0 }),
            proposal_creation_timestamp_seconds,
            wait_for_quiet_state: Some(WaitForQuietState {
                current_deadline_timestamp_seconds: initial_voting_period_seconds,
            }),
            initial_voting_period_seconds,
            wait_for_quiet_deadline_increase_seconds,
            ..Default::default()
        };
        let old_tally = Tally {
            timestamp_seconds: now_seconds,
            yes: old_yes,
            no: old_no,
            total: old_total,
        };
        let new_tally = Tally {
            timestamp_seconds: now_seconds,
            yes: old_yes + yes_votes,
            no: old_no + no_votes,
            total: old_total,
        };
        proposal.evaluate_wait_for_quiet(
            now_seconds,
            &old_tally,
            &new_tally,
        );
        let new_deadline = proposal
            .wait_for_quiet_state
            .unwrap()
            .current_deadline_timestamp_seconds;
        prop_assert!(new_deadline >= initial_voting_period_seconds);
    }
}

proptest! {
    /// This test ensures that the wait-for-quiet
    /// deadline is increased the correct amount when there is a flip
    /// at the end of a proposal's lifetime.
    #[test]
    fn test_evaluate_wait_for_quiet_flip_at_end(
        initial_voting_period_seconds in 3600u64..604_800,
        wait_for_quiet_deadline_increase_seconds in 0u64..604_800,
        no_votes in 0u64..1_000_000,
        yes_votes_margin in 1u64..1_000_000,
        total in 10_000_000u64..100_000_000,
) {
        let now_seconds = initial_voting_period_seconds;
        let mut proposal = ProposalData {
            id: Some(ProposalId { id: 0 }),
            wait_for_quiet_state: Some(WaitForQuietState {
                current_deadline_timestamp_seconds: initial_voting_period_seconds,
            }),
            initial_voting_period_seconds,
            wait_for_quiet_deadline_increase_seconds,
            ..Default::default()
        };
        let old_tally = Tally {
            timestamp_seconds: now_seconds,
            yes: 0,
            no: no_votes,
            total,
        };
        let new_tally = Tally {
            timestamp_seconds: now_seconds,
            yes: no_votes + yes_votes_margin,
            no: no_votes,
            total,
        };
        proposal.evaluate_wait_for_quiet(
            now_seconds,
            &old_tally,
            &new_tally,
        );
        let new_deadline = proposal
            .wait_for_quiet_state
            .unwrap()
            .current_deadline_timestamp_seconds;
        prop_assert!(new_deadline == initial_voting_period_seconds + wait_for_quiet_deadline_increase_seconds);
    }
}

proptest! {
    /// This test ensures that the wait-for-quiet
    /// deadline is increased the correct amount when there is a flip
    /// at any point during of a proposal's lifetime.
    #[test]
    fn test_evaluate_wait_for_quiet_flip(
        initial_voting_period_seconds in 3600u64..604_800,
        wait_for_quiet_deadline_increase_seconds in 0u64..604_800,
        no_votes in 0u64..1_000_000,
        yes_votes_margin in 1u64..1_000_000,
        total in 10_000_000u64..100_000_000,
        time in 0f32..=1f32,
) {
        // To make the math easy, we'll do the same trick we did in the previous test, where increase the `adjusted_wait_for_quiet_deadline_increase_seconds`
        // by the smallest time where any flip in the vote will cause a deadline increase.
        let adjusted_wait_for_quiet_deadline_increase_seconds = wait_for_quiet_deadline_increase_seconds + initial_voting_period_seconds.div_ceil(2);
        // We'll also use the `time` parameter to tell us what fraction of the `initial_voting_period_seconds` to test at.
        let now_seconds = (time * initial_voting_period_seconds as f32) as u64;
        let mut proposal = ProposalData {
            id: Some(ProposalId { id: 0 }),
            wait_for_quiet_state: Some(WaitForQuietState {
                current_deadline_timestamp_seconds: initial_voting_period_seconds,
            }),
            initial_voting_period_seconds,
            wait_for_quiet_deadline_increase_seconds: adjusted_wait_for_quiet_deadline_increase_seconds,
            ..Default::default()
        };
        let old_tally = Tally {
            timestamp_seconds: now_seconds,
            yes: 0,
            no: no_votes,
            total,
        };
        let new_tally = Tally {
            timestamp_seconds: now_seconds,
            yes: no_votes + yes_votes_margin,
            no: no_votes,
            total,
        };
        proposal.evaluate_wait_for_quiet(
            now_seconds,
            &old_tally,
            &new_tally,
        );
        let new_deadline = proposal
            .wait_for_quiet_state
            .unwrap()
            .current_deadline_timestamp_seconds;
        dbg!(new_deadline , initial_voting_period_seconds + wait_for_quiet_deadline_increase_seconds + now_seconds.div_ceil(2));
        prop_assert!(new_deadline == initial_voting_period_seconds + wait_for_quiet_deadline_increase_seconds + now_seconds.div_ceil(2));
    }
}

// A helper function to execute each proposal.
fn execute_proposal(governance: &mut Governance, proposal_id: u64) -> ProposalData {
    governance.process_proposal(proposal_id);

    let now = std::time::Instant::now;

    let start = now();
    // In practice, the exit condition of the following loop occurs in much
    // less than 1 s (on my Macbook Pro 2019 Intel). The reason for this
    // generous limit is twofold: 1. avoid flakes in CI, while at the same
    // time 2. do not run forever if something goes wrong.
    let give_up = || now() < start + std::time::Duration::from_secs(30);

    loop {
        let result = governance
            .get_proposal(&GetProposal {
                proposal_id: Some(ProposalId { id: proposal_id }),
            })
            .result
            .unwrap();
        let proposal_data = match result {
            get_proposal_response::Result::Proposal(p) => p,
            _ => panic!("get_proposal result: {result:#?}"),
        };

        let upgrade_sns_action_id = 7;

        // If the proposal is an SNS upgrade action, it won't move to the "executed" state in
        // this env (non-canister env), hence return.
        if proposal_data.status().is_final() || proposal_data.action == upgrade_sns_action_id {
            break proposal_data;
        }

        if give_up() {
            panic!("Proposal took too long to terminate (in the failed state).")
        }

        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[should_panic]
#[test]
fn test_disallow_set_mode_not_normal() {
    // Step 1: Prepare the world, i.e. Governance.
    let mut governance = Governance::new(
        GovernanceProto {
            mode: governance::Mode::Normal as i32,
            ..basic_governance_proto()
        }
        .try_into()
        .unwrap(),
        Box::<NativeEnvironment>::default(),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );
    let swap_canister_id = governance.proto.swap_canister_id_or_panic();

    // Step 2: Run code under test.
    governance.set_mode(
        governance::Mode::PreInitializationSwap as i32,
        swap_canister_id.into(),
    );

    // Step 3: Inspect result(s). This is taken care of by #[should_panic]
}

#[tokio::test]
async fn test_disallow_enabling_voting_rewards_while_in_pre_initialization_swap() {
    // Step 1: Prepare the world, i.e. Governance.

    let governance_canister_id = canister_test_id(501);

    let mut env = NativeEnvironment::default();
    env.local_canister_id = Some(governance_canister_id);
    let mut governance = Governance::new(
        GovernanceProto {
            neurons: btreemap! {
                A_NEURON_ID.to_string() => A_NEURON.clone(),
            },
            mode: governance::Mode::PreInitializationSwap as i32,

            ..basic_governance_proto()
        }
        .try_into()
        .unwrap(),
        Box::new(NativeEnvironment::new(Some(CanisterId::from_u64(350519)))),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    // Step 2: Run code under test.
    let result = governance
        .make_proposal(
            &A_NEURON_ID,
            &A_NEURON_PRINCIPAL_ID,
            &Proposal {
                action: Some(Action::ManageNervousSystemParameters(
                    NervousSystemParameters {
                        // The operative data is here. Foils make_proposal.
                        voting_rewards_parameters: Some(BASE_VOTING_REWARDS_PARAMETERS),
                        ..Default::default()
                    },
                )),
                ..Default::default()
            },
        )
        .await;

    // Step 3: Inspect result(s).
    let err = match result {
        Ok(ok) => panic!("Proposal should have been rejected: {ok:#?}"),
        Err(err) => err,
    };

    let err = err.error_message.to_lowercase();
    assert!(err.contains("manage nervous system parameters"), "{err:#?}");
    assert!(err.contains("not allowed"), "{err:#?}");
    assert!(
        err.contains("in preinitializationswap (2) mode"),
        "{err:#?}"
    );
}

#[tokio::test]
async fn no_new_reward_event_when_there_are_no_new_proposals() {
    // Step 0: Define helper type(s).

    // The main feature this implements is control of perceived time.
    struct DummyEnvironment {
        now: Arc<Mutex<u64>>,
    }

    impl DummyEnvironment {
        fn new(now: Arc<Mutex<u64>>) -> Self {
            Self { now }
        }
    }

    #[async_trait]
    impl Environment for DummyEnvironment {
        fn now(&self) -> u64 {
            *self.now.lock().unwrap()
        }

        fn set_time_warp(&mut self, _new_time_warp: TimeWarp) {
            unimplemented!();
        }

        fn insecure_random_u64(&mut self) -> u64 {
            unimplemented!();
        }

        async fn call_canister(
            &self,
            _canister_id: CanisterId,
            _method_name: &str,
            _arg: Vec<u8>,
        ) -> Result<
            /* reply: */ Vec<u8>,
            (
                /* error_code: */ Option<i32>,
                /* message: */ String,
            ),
        > {
            unimplemented!();
        }

        fn heap_growth_potential(&self) -> HeapGrowthPotential {
            HeapGrowthPotential::NoIssue
        }

        fn canister_id(&self) -> CanisterId {
            CanisterId::from_u64(318680)
        }

        fn canister_version(&self) -> Option<u64> {
            None
        }
    }

    // Step 1: Prepare the world.

    // Step 1.1: Helper.
    let now = Arc::new(Mutex::new(START_OF_2022_TIMESTAMP_SECONDS));

    // Step 1.2: Craft the test subject.
    let mut governance_proto = GovernanceProto {
        neurons: btreemap! {
            A_NEURON_ID.to_string() => A_NEURON.clone(),
        },
        ..basic_governance_proto()
    };
    let voting_rewards_parameters = governance_proto
        .parameters
        .as_mut()
        .unwrap()
        .voting_rewards_parameters
        .as_mut()
        .unwrap();
    *voting_rewards_parameters = VotingRewardsParameters {
        round_duration_seconds: Some(ONE_DAY_SECONDS),
        reward_rate_transition_duration_seconds: Some(1),
        initial_reward_rate_basis_points: Some(101),
        final_reward_rate_basis_points: Some(100),
    };
    let min_reward_rate = i2d(1) / i2d(100);
    let mut governance = Governance::new(
        governance_proto.try_into().unwrap(),
        Box::new(DummyEnvironment::new(now.clone())),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    // Step 1.3: Record original last_reward_event. That way, we can detect
    // changes (there aren't supposed to be any).
    let original_latest_reward_event = governance.proto.latest_reward_event.clone();
    assert!(
        original_latest_reward_event.is_some(),
        "{original_latest_reward_event:#?}"
    );

    // Step 1.4: Make a proposal.
    let proposal_id = governance
        .make_proposal(&A_NEURON_ID, &A_NEURON_PRINCIPAL_ID, &A_MOTION_PROPOSAL)
        .await
        .unwrap();

    // Step 1.5: Assert pre-condition.
    assert_eq!(
        governance
            .ready_to_be_settled_proposal_ids()
            .collect::<Vec<_>>(),
        vec![]
    );

    // Step 2: Run code under test (to wit, distribute_rewards), which
    // usually updates latest_reward_event, but not this time, because there
    // are no proposals that are ready to settle yet.
    let supply = Tokens::from_e8s(100 * E8);
    governance.distribute_rewards(supply);

    // Step 3: Inspect result(s): No change to latest_reward_event.
    assert_eq!(
        governance.proto.latest_reward_event,
        original_latest_reward_event
    );
    assert_eq!(
        original_latest_reward_event
            .as_ref()
            .unwrap()
            .rounds_since_last_distribution,
        Some(0)
    );

    // Step 4: Repeat, but with a twist: this time, there is indeed a
    // proposal that's ready to settle. Because of this, calling
    // distribute_rewards causes latest_reward_event to update, unlike
    // before.

    // Step 4.1: Advance time so that the proposal we made earlier becomes
    // ready to settle.
    let wait_days = 9;
    *now.lock().unwrap() += ONE_DAY_SECONDS * wait_days;
    assert_eq!(
        governance
            .ready_to_be_settled_proposal_ids()
            .collect::<Vec<_>>(),
        vec![proposal_id]
    );

    // Step 4.2: Call code under test (to wit, distribute_rewards) a second time.
    let supply = Tokens::from_e8s(100 * E8);
    governance.distribute_rewards(supply);

    // Step 4.3: Inspect result(s). This time, latest_reward_event has
    // changed, unlike in step 3.
    assert_ne!(
        governance.proto.latest_reward_event,
        original_latest_reward_event
    );

    // Now that we've seen that latest_reward_event has changed, let's take
    // a closer look at it.
    let final_latest_reward_event = governance.proto.latest_reward_event.as_ref().unwrap();
    assert_eq!(
        final_latest_reward_event.settled_proposals,
        vec![proposal_id]
    );
    assert_eq!(
        final_latest_reward_event.rounds_since_last_distribution,
        Some(wait_days)
    );

    // Inspect the amount distributed in final_latest_reward_event. In
    // principle, we could calculate this exactly, but it's someone
    // complicated, because the reward rate varies. To make this assertion a
    // simpler, we instead calculate a range that the reward amount must
    // fall within. That window is pretty small, and should be sufficient to
    // detect an incorrect implementation of roll over, which is the main
    // thing we are trying to do here.
    let min_distributed_e8s =
        (i2d(supply.get_e8s()) * i2d(wait_days) / *reward::NOMINAL_DAYS_PER_YEAR * min_reward_rate)
            .floor();
    // Scale up by 1%, because the max/initial reward rate is exactly this
    // much bigger than the min/final reward rate.
    let max_distributed_e8s = min_distributed_e8s * i2d(101) / i2d(100);
    let distributed_e8s_range = min_distributed_e8s..max_distributed_e8s;
    assert!(
        distributed_e8s_range.contains(&i2d(final_latest_reward_event.distributed_e8s_equivalent)),
        "distributed_e8s_range = {distributed_e8s_range:?}\n\
            final_latest_reward_event = {final_latest_reward_event:#?}",
    );

    assert_eq!(
        governance
            .ready_to_be_settled_proposal_ids()
            .collect::<Vec<_>>(),
        vec![]
    );

    let neuron = governance
        .proto
        .neurons
        .get(&A_NEURON_ID.to_string())
        .unwrap();
    assert_eq!(
        neuron.maturity_e8s_equivalent, final_latest_reward_event.distributed_e8s_equivalent,
        "neuron = {:#?}",
        neuron,
    );
}

#[test]
fn two_sns_version_upgrades_cannot_be_concurrent() {
    let action = Action::UpgradeSnsToNextVersion(UpgradeSnsToNextVersion::default());
    test_disallow_concurrent_upgrade_execution((&action).into(), action);
}

#[test]
fn two_canister_upgrades_cannot_be_concurrent() {
    let action = Action::UpgradeSnsControlledCanister(UpgradeSnsControlledCanister::default());
    test_disallow_concurrent_upgrade_execution((&action).into(), action);
}

#[test]
fn sns_upgrades_block_concurrent_canister_upgrades() {
    let executing_action_id =
        (&Action::UpgradeSnsToNextVersion(UpgradeSnsToNextVersion::default())).into();
    let action = Action::UpgradeSnsControlledCanister(UpgradeSnsControlledCanister::default());
    test_disallow_concurrent_upgrade_execution(executing_action_id, action);
}

#[test]
fn canister_upgrades_block_concurrent_sns_upgrades() {
    let executing_action_id =
        (&Action::UpgradeSnsControlledCanister(UpgradeSnsControlledCanister::default())).into();
    let action = Action::UpgradeSnsToNextVersion(UpgradeSnsToNextVersion::default());
    test_disallow_concurrent_upgrade_execution(executing_action_id, action);
}

#[test]
fn two_manage_ledger_parameters_proposals_cannot_be_concurrent() {
    let executing_action_id =
        (&Action::ManageLedgerParameters(ManageLedgerParameters::default())).into();
    let action = Action::ManageLedgerParameters(ManageLedgerParameters::default());
    test_disallow_concurrent_upgrade_execution(executing_action_id, action);
}

#[test]
fn manage_ledger_parameters_block_concurrent_sns_upgrades() {
    let executing_action_id =
        (&Action::ManageLedgerParameters(ManageLedgerParameters::default())).into();
    let action = Action::UpgradeSnsToNextVersion(UpgradeSnsToNextVersion::default());
    test_disallow_concurrent_upgrade_execution(executing_action_id, action);
}

#[test]
fn manage_ledger_parameters_block_concurrent_canister_upgrades() {
    let executing_action_id =
        (&Action::ManageLedgerParameters(ManageLedgerParameters::default())).into();
    let action = Action::UpgradeSnsControlledCanister(UpgradeSnsControlledCanister::default());
    test_disallow_concurrent_upgrade_execution(executing_action_id, action);
}

/// A test method to allow testing concurrent upgrades for multiple scenarios
fn test_disallow_concurrent_upgrade_execution(
    proposal_in_progress_action_id: u64,
    action_to_be_executed: Action,
) {
    // Step 1: Prepare the world.
    use ProposalDecisionStatus as Status;

    // Step 1.1: First proposal, which will block the next one.
    let execution_in_progress_proposal = ProposalData {
        action: proposal_in_progress_action_id,
        id: Some(1_u64.into()),
        decided_timestamp_seconds: NativeEnvironment::DEFAULT_TEST_START_TIMESTAMP_SECONDS - 10,
        latest_tally: Some(Tally {
            yes: 1,
            no: 0,
            total: 1,
            timestamp_seconds: 1,
        }),
        ..Default::default()
    };
    assert_eq!(execution_in_progress_proposal.status(), Status::Adopted);

    // Step 1.2: Second proposal. This one will be thwarted by the first.
    let to_be_processed_proposal = ProposalData {
        action: (&action_to_be_executed).into(),
        id: Some(2_u64.into()),
        ballots: btreemap! {
            "neuron 1".to_string() => Ballot {
                vote: Vote::Yes as i32,
                voting_power: 9001,
                cast_timestamp_seconds: 1,
            },
        },
        wait_for_quiet_state: Some(WaitForQuietState::default()),
        proposal: Some(Proposal {
            title: "Doomed".to_string(),
            action: Some(action_to_be_executed),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert_eq!(to_be_processed_proposal.status(), Status::Open);

    // Step 1.3: Init Governance.
    let mut governance = Governance::new(
        GovernanceProto {
            proposals: btreemap! {
                1 => execution_in_progress_proposal,
                2 => to_be_processed_proposal,
            },
            ..basic_governance_proto()
        }
        .try_into()
        .unwrap(),
        Box::<NativeEnvironment>::default(),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    let upgrade_proposals_in_progress = governance.upgrade_proposals_in_progress();
    assert_eq!(upgrade_proposals_in_progress, BTreeSet::from([1]));

    // Step 2: Execute code under test.
    governance.process_proposal(2);

    // Step 2.1: Wait for result.
    let now = std::time::Instant::now;

    let start = now();
    // In practice, the exit condition of the following loop occurs in much
    // less than 1 s (on my Macbook Pro 2019 Intel). The reason for this
    // generous limit is twofold: 1. avoid flakes in CI, while at the same
    // time 2. do not run forever if something goes wrong.
    let give_up = || now() < start + std::time::Duration::from_secs(30);
    let final_proposal_data = loop {
        let result = governance
            .get_proposal(&GetProposal {
                proposal_id: Some(ProposalId { id: 2 }),
            })
            .result
            .unwrap();
        let proposal_data = match result {
            get_proposal_response::Result::Proposal(p) => p,
            _ => panic!("get_proposal result: {result:#?}"),
        };

        if proposal_data.status().is_final() {
            break proposal_data;
        }

        if give_up() {
            panic!("Proposal took too long to terminate (in the failed state).")
        }

        std::thread::sleep(std::time::Duration::from_millis(100));
    };

    // Step 3: Inspect results.
    assert_eq!(
        final_proposal_data.status(),
        Status::Failed,
        "The second upgrade proposal did not fail. final_proposal_data: {:#?}",
        final_proposal_data,
    );
    let final_failure_reason = ErrorType::try_from(
        final_proposal_data
            .failure_reason
            .as_ref()
            .unwrap()
            .error_type,
    )
    .unwrap();
    assert_eq!(
        final_failure_reason,
        ErrorType::ResourceExhausted,
        "The second upgrade proposal failed, but failure_reason ({:?}) was not as expected. \
            final_proposal_data: {:#?}",
        final_failure_reason,
        final_proposal_data,
    );
}

#[test]
fn test_upgrade_sns_to_next_version_for_root() {
    let expected_canister_to_upgrade = SnsCanisterType::Root;
    let next_version = SnsVersion {
        root_wasm_hash: vec![1, 2, 3, 4],
        governance_wasm_hash: vec![2, 3, 4],
        ledger_wasm_hash: vec![3, 4, 5],
        swap_wasm_hash: vec![4, 5, 6],
        archive_wasm_hash: vec![5, 6, 7],
        index_wasm_hash: vec![6, 7, 8],
    };
    test_upgrade_sns_to_next_version_upgrades_correct_canister(
        next_version,
        vec![1, 2, 3, 4],
        expected_canister_to_upgrade,
    );
}
#[test]
fn test_upgrade_sns_to_next_version_for_governance() {
    let expected_canister_to_upgrade = SnsCanisterType::Governance;
    let next_version = SnsVersion {
        root_wasm_hash: vec![1, 2, 3],
        governance_wasm_hash: vec![2, 3, 4, 5],
        ledger_wasm_hash: vec![3, 4, 5],
        swap_wasm_hash: vec![4, 5, 6],
        archive_wasm_hash: vec![5, 6, 7],
        index_wasm_hash: vec![6, 7, 8],
    };
    test_upgrade_sns_to_next_version_upgrades_correct_canister(
        next_version,
        vec![2, 3, 4, 5],
        expected_canister_to_upgrade,
    );
}
#[test]
fn test_upgrade_sns_to_next_version_for_ledger() {
    let expected_canister_to_upgrade = SnsCanisterType::Ledger;
    let next_version = SnsVersion {
        root_wasm_hash: vec![1, 2, 3],
        governance_wasm_hash: vec![2, 3, 4],
        ledger_wasm_hash: vec![3, 4, 5, 6],
        swap_wasm_hash: vec![4, 5, 6],
        archive_wasm_hash: vec![5, 6, 7],
        index_wasm_hash: vec![6, 7, 8],
    };
    test_upgrade_sns_to_next_version_upgrades_correct_canister(
        next_version,
        vec![3, 4, 5, 6],
        expected_canister_to_upgrade,
    );
}

#[test]
fn test_upgrade_sns_to_next_version_for_archive() {
    let expected_canister_to_upgrade = SnsCanisterType::Archive;
    let next_version = SnsVersion {
        root_wasm_hash: vec![1, 2, 3],
        governance_wasm_hash: vec![2, 3, 4],
        ledger_wasm_hash: vec![3, 4, 5],
        swap_wasm_hash: vec![4, 5, 6],
        archive_wasm_hash: vec![5, 6, 7, 8],
        index_wasm_hash: vec![6, 7, 8],
    };
    test_upgrade_sns_to_next_version_upgrades_correct_canister(
        next_version,
        vec![5, 6, 7, 8],
        expected_canister_to_upgrade,
    );
}

#[test]
fn test_upgrade_sns_to_next_version_for_index() {
    let expected_canister_to_upgrade = SnsCanisterType::Index;
    let next_version = SnsVersion {
        root_wasm_hash: vec![1, 2, 3],
        governance_wasm_hash: vec![2, 3, 4],
        ledger_wasm_hash: vec![3, 4, 5],
        swap_wasm_hash: vec![4, 5, 6],
        archive_wasm_hash: vec![5, 6, 7],
        index_wasm_hash: vec![6, 7, 8, 9],
    };
    test_upgrade_sns_to_next_version_upgrades_correct_canister(
        next_version,
        vec![6, 7, 8, 9],
        expected_canister_to_upgrade,
    );
}

/// This assumes that the current_version is:
/// SnsVersion {
///     root_wasm_hash: vec![1, 2, 3],
///     governance_wasm_hash: vec![2, 3, 4],
///     ledger_wasm_hash: vec![3, 4, 5],
///     swap_wasm_hash: vec![4, 5, 6],
///     archive_wasm_hash: vec![5, 6, 7],
/// }
/// Any test inputs should only change one canister to a new version
///
/// This also sets a slightly different expectation for upgrading root versus other canisters
fn test_upgrade_sns_to_next_version_upgrades_correct_canister(
    next_version: SnsVersion,
    expected_wasm_hash_requested: Vec<u8>,
    expected_canister_to_be_upgraded: SnsCanisterType,
) {
    let root_canister_id = *TEST_ROOT_CANISTER_ID;
    let ledger_canister_id = *TEST_LEDGER_CANISTER_ID;

    let action = Action::UpgradeSnsToNextVersion(UpgradeSnsToNextVersion {});

    // Upgrade Proposal
    let proposal_id = 1;
    let proposal = ProposalData {
        action: (&action).into(),
        id: Some(proposal_id.into()),
        ballots: btreemap! {
            "neuron 1".to_string() => Ballot {
                vote: Vote::Yes as i32,
                voting_power: 9001,
                cast_timestamp_seconds: 1,
            },
        },
        wait_for_quiet_state: Some(WaitForQuietState::default()),
        proposal: Some(Proposal {
            title: "Upgrade Proposal".to_string(),
            action: Some(action),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert_eq!(proposal.status(), Status::Open);

    use ProposalDecisionStatus as Status;

    let current_version = SnsVersion {
        root_wasm_hash: vec![1, 2, 3],
        governance_wasm_hash: vec![2, 3, 4],
        ledger_wasm_hash: vec![3, 4, 5],
        swap_wasm_hash: vec![4, 5, 6],
        archive_wasm_hash: vec![5, 6, 7],
        index_wasm_hash: vec![6, 7, 8],
    };
    let sns_canister_summary_response = std_sns_canisters_summary_response();
    let env = setup_env_for_sns_upgrade_to_next_version_test(
        &current_version,
        &next_version,
        expected_wasm_hash_requested,
        expected_canister_to_be_upgraded,
        sns_canister_summary_response,
    );

    let assert_required_calls = env.get_assert_required_calls_fn();

    let now = env.now();
    // Init Governance.
    let mut governance = Governance::new(
        GovernanceProto {
            proposals: btreemap! {
                proposal_id => proposal
            },
            root_canister_id: Some(root_canister_id.get()),
            ledger_canister_id: Some(ledger_canister_id.get()),
            deployed_version: Some(current_version.into()),
            ..basic_governance_proto()
        }
        .try_into()
        .unwrap(),
        Box::new(env),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    // When we execute the proposal
    execute_proposal(&mut governance, 1);
    // Then we check things happened as expected
    assert_required_calls();
    assert_eq!(
        governance.proto.pending_version.clone().unwrap(),
        PendingVersion {
            target_version: Some(next_version.into()),
            mark_failed_at_seconds: now + 5 * 60,
            checking_upgrade_lock: 0,
            proposal_id: Some(proposal_id),
        }
    );
    // We do not check the upgrade completion in this test because of limitations
    // with the test infrastructure for Environment
}

// Sets up an env that assumes using TEST_*_CANISTER_ID for sns canisters, which can handle requests for SnsUpgradeToNextVersion requests.
fn setup_env_for_sns_upgrade_to_next_version_test(
    current_version: &SnsVersion,
    next_version: &SnsVersion,
    expected_wasm_hash_requested: Vec<u8>,
    expected_canister_to_be_upgraded: SnsCanisterType,
    sns_canister_summary_response: GetSnsCanistersSummaryResponse,
) -> NativeEnvironment {
    let root_canister_id = *TEST_ROOT_CANISTER_ID;
    let governance_canister_id = *TEST_GOVERNANCE_CANISTER_ID;
    let ledger_canister_id = *TEST_LEDGER_CANISTER_ID;
    let ledger_archive_ids = TEST_ARCHIVES_CANISTER_IDS.clone();
    let index_canister_id = *TEST_INDEX_CANISTER_ID;

    let mut env = NativeEnvironment::new(Some(governance_canister_id));
    env.default_canister_call_response =
        Err((Some(1), "Oh no something was not covered!".to_string()));
    env.set_call_canister_response(
        root_canister_id,
        "get_sns_canisters_summary",
        Encode!(&GetSnsCanistersSummaryRequest {
            update_canister_list: Some(true)
        })
        .unwrap(),
        Ok(Encode!(&sns_canister_summary_response).unwrap()),
    );

    env.set_call_canister_response(
        SNS_WASM_CANISTER_ID,
        "get_next_sns_version",
        Encode!(&GetNextSnsVersionRequest {
            current_version: Some(current_version.clone())
        })
        .unwrap(),
        Ok(Encode!(&GetNextSnsVersionResponse {
            next_version: Some(next_version.clone())
        })
        .unwrap()),
    );
    env.set_call_canister_response(
        SNS_WASM_CANISTER_ID,
        "get_wasm",
        Encode!(&GetWasmRequest {
            hash: expected_wasm_hash_requested
        })
        .unwrap(),
        Ok(Encode!(&GetWasmResponse {
            wasm: Some(SnsWasm {
                wasm: vec![9, 8, 7, 6, 5, 4, 3, 2],
                canister_type: expected_canister_to_be_upgraded.into(), // Governance
                proposal_id: None,
            })
        })
        .unwrap()),
    );

    let canisters_to_be_upgraded = match expected_canister_to_be_upgraded {
        SnsCanisterType::Unspecified => {
            panic!("Cannot be unspecified")
        }
        SnsCanisterType::Root => vec![root_canister_id],
        SnsCanisterType::Governance => vec![governance_canister_id],
        SnsCanisterType::Ledger => vec![ledger_canister_id],
        SnsCanisterType::Archive => ledger_archive_ids,
        SnsCanisterType::Swap => {
            panic!("Swap upgrade not supported via SNS (ownership)")
        }
        SnsCanisterType::Index => vec![index_canister_id],
    };

    assert!(!canisters_to_be_upgraded.is_empty());

    if expected_canister_to_be_upgraded != SnsCanisterType::Root {
        // This is the essential call we need to happen in order to know that the correct canister
        // was upgraded.
        for canister_id in canisters_to_be_upgraded {
            env.require_call_canister_invocation(
                root_canister_id,
                "change_canister",
                Encode!(
                    &ChangeCanisterRequest::new(true, CanisterInstallMode::Upgrade, canister_id)
                        .with_wasm(vec![9, 8, 7, 6, 5, 4, 3, 2])
                        .with_arg(Encode!().unwrap())
                )
                .unwrap(),
                // We don't actually look at the response from this call anywhere
                Some(Ok(Encode!().unwrap())),
            );
        }
    } else {
        // These three are needed for the request to function, but we aren't interested in re-testing
        // canister_control methods here.
        for canister_id in canisters_to_be_upgraded {
            env.set_call_canister_response(
                CanisterId::ic_00(),
                "stop_canister",
                Encode!(&CanisterIdRecord::from(canister_id)).unwrap(),
                Ok(vec![]),
            );
            env.set_call_canister_response(
                CanisterId::ic_00(),
                "canister_status",
                Encode!(&CanisterIdRecord::from(canister_id)).unwrap(),
                Ok(Encode!(&canister_status_from_management_canister_for_test(
                    vec![],
                    CanisterStatusType::Stopped,
                ))
                .unwrap()),
            );
            env.set_call_canister_response(
                CanisterId::ic_00(),
                "start_canister",
                Encode!(&CanisterIdRecord::from(canister_id)).unwrap(),
                Ok(vec![]),
            );
            // For root canister, this is the required call that ensures our wiring was correct.
            env.require_call_canister_invocation(
                CanisterId::ic_00(),
                "install_code",
                Encode!(&ic_management_canister_types_private::InstallCodeArgs {
                    mode: ic_management_canister_types_private::CanisterInstallMode::Upgrade,
                    canister_id: canister_id.get(),
                    wasm_module: vec![9, 8, 7, 6, 5, 4, 3, 2],
                    arg: Encode!().unwrap(),
                    sender_canister_version: None,
                })
                .unwrap(),
                Some(Ok(vec![])),
            );
        }
    }
    env
}

fn std_sns_canisters_summary_response() -> GetSnsCanistersSummaryResponse {
    let root_canister_id = *TEST_ROOT_CANISTER_ID;
    let governance_canister_id = *TEST_GOVERNANCE_CANISTER_ID;
    let ledger_canister_id = *TEST_LEDGER_CANISTER_ID;
    let swap_canister_id = *TEST_SWAP_CANISTER_ID;
    let ledger_archive_ids = TEST_ARCHIVES_CANISTER_IDS.clone();
    let index_canister_id = *TEST_INDEX_CANISTER_ID;
    let dapp_canisters = TEST_DAPP_CANISTER_IDS.clone();

    GetSnsCanistersSummaryResponse {
        root: Some(CanisterSummary {
            status: Some(canister_status_for_test(
                vec![1, 2, 3],
                CanisterStatusType::Running,
            )),
            canister_id: Some(root_canister_id.get()),
        }),
        governance: Some(CanisterSummary {
            status: Some(canister_status_for_test(
                vec![2, 3, 4],
                CanisterStatusType::Running,
            )),
            canister_id: Some(governance_canister_id.get()),
        }),
        ledger: Some(CanisterSummary {
            status: Some(canister_status_for_test(
                vec![3, 4, 5],
                CanisterStatusType::Running,
            )),
            canister_id: Some(ledger_canister_id.get()),
        }),
        swap: Some(CanisterSummary {
            status: Some(canister_status_for_test(
                vec![4, 5, 6],
                CanisterStatusType::Running,
            )),
            canister_id: Some(swap_canister_id.get()),
        }),
        dapps: dapp_canisters
            .iter()
            .map(|id| CanisterSummary {
                status: Some(canister_status_for_test(
                    vec![0, 0, 0],
                    CanisterStatusType::Running,
                )),
                canister_id: Some(id.get()),
            })
            .collect(),
        archives: ledger_archive_ids
            .iter()
            .map(|id| CanisterSummary {
                status: Some(canister_status_for_test(
                    vec![5, 6, 7],
                    CanisterStatusType::Running,
                )),
                canister_id: Some(id.get()),
            })
            .collect(),
        index: Some(CanisterSummary {
            status: Some(canister_status_for_test(
                vec![6, 7, 8],
                CanisterStatusType::Running,
            )),
            canister_id: Some(index_canister_id.get()),
        }),
    }
}

#[test]
fn test_distribute_rewards_does_not_block_upgrades() {
    // Setup the canister ids for the test
    let root_canister_id = *TEST_ROOT_CANISTER_ID;
    let governance_canister_id = *TEST_GOVERNANCE_CANISTER_ID;

    // Create the environment and add mocked responses from root
    let mut env = NativeEnvironment::new(Some(governance_canister_id));

    let mut canisters_summary_response = std_sns_canisters_summary_response();
    if let Some(ref mut canister_summary) = canisters_summary_response.governance {
        canister_summary.status = Some(canister_status_for_test(
            vec![2, 3, 4],
            CanisterStatusType::Running,
        ));
    }
    env.set_call_canister_response(
        root_canister_id,
        "get_sns_canisters_summary",
        Encode!(&GetSnsCanistersSummaryRequest {
            update_canister_list: Some(true)
        })
        .unwrap(),
        Ok(Encode!(&canisters_summary_response).unwrap()),
    );

    // Create the versions that will be used to exercise the test
    let next_version = SnsVersion {
        root_wasm_hash: vec![1, 2, 3],
        governance_wasm_hash: vec![2, 3, 4],
        ledger_wasm_hash: vec![3, 4, 5],
        swap_wasm_hash: vec![4, 5, 6],
        archive_wasm_hash: vec![5, 6, 7],
        index_wasm_hash: vec![6, 7, 8],
    };

    let current_version = {
        let mut version = next_version.clone();
        version.governance_wasm_hash = vec![1, 1, 1];
        version
    };

    // Create the governance struct with voting reward parameters that require rewards
    // to be distributed once a day. There is no pending version at initialization
    let mut governance = Governance::new(
        GovernanceProto {
            root_canister_id: Some(root_canister_id.get()),
            deployed_version: Some(current_version.clone().into()),
            cached_upgrade_steps: Some(CachedUpgradeStepsPb {
                upgrade_steps: Some(Versions {
                    versions: vec![current_version.clone().into(), next_version.clone().into()],
                }),
                requested_timestamp_seconds: Some(111),
                response_timestamp_seconds: Some(222),
            }),
            parameters: Some(NervousSystemParameters {
                voting_rewards_parameters: Some(VotingRewardsParameters {
                    round_duration_seconds: Some(ONE_DAY_SECONDS),
                    reward_rate_transition_duration_seconds: Some(0),
                    initial_reward_rate_basis_points: Some(250),
                    final_reward_rate_basis_points: Some(250),
                }),
                ..NervousSystemParameters::with_default_values()
            }),
            neurons: btreemap! {
                A_NEURON_ID.to_string() => A_NEURON.clone(),
            },
            ..basic_governance_proto()
        }
        .try_into()
        .unwrap(),
        Box::new(env),
        Box::new(AlwaysSucceedingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    // Get the initial reward event for comparison later
    let initial_reward_event = governance.latest_reward_event();

    // Make a proposal that should settle
    governance
        .make_proposal(&A_NEURON_ID, &A_NEURON_PRINCIPAL_ID, &A_MOTION_PROPOSAL)
        .now_or_never()
        .unwrap()
        .expect("Expected proposal to be submitted");

    // Assert that the rewards should not be distributed, and trigger the periodic tasks to
    // try to distribute them.
    assert!(!governance.should_distribute_rewards());
    governance.run_periodic_tasks().now_or_never();

    // Get the latest reward event and assert that its equal to the initial reward event. This
    // puts governance in the state that the OC-SNS was in for NNS1-2105.
    let latest_reward_event = governance.latest_reward_event();
    assert_eq!(initial_reward_event, latest_reward_event);

    // Advance time such that a reward event should be distributed
    governance.env.set_time_warp(TimeWarp {
        delta_s: (ONE_DAY_SECONDS * 5) as i64,
    });

    // Now set the pending_version in Governance such that the period_task to check upgrade
    // status is triggered.
    let mark_failed_at_seconds = governance.env.now() + ONE_DAY_SECONDS;
    governance.proto.pending_version = Some(PendingVersion {
        target_version: Some(next_version.clone().into()),
        mark_failed_at_seconds,
        checking_upgrade_lock: 0,
        proposal_id: Some(0),
    });

    // Make sure Governance state is correctly set
    assert_eq!(
        governance.proto.pending_version.clone().unwrap(),
        PendingVersion {
            target_version: Some(next_version.clone().into()),
            mark_failed_at_seconds,
            checking_upgrade_lock: 0,
            proposal_id: Some(0),
        }
    );
    assert_eq!(
        governance.proto.deployed_version.clone().unwrap(),
        current_version.into()
    );

    // Check that both conditions in `run_periodic_tasks` will be triggered on this instance.
    // and run the tasks.
    assert!(governance.should_distribute_rewards());
    assert!(governance.should_check_upgrade_status());
    governance.run_periodic_tasks().now_or_never();

    // These asserts would fail before the change in NNS1-2105. Now, even though
    // there was an attempt to distribute rewards, the status of the upgrade was still checked.
    let latest_reward_event = governance.latest_reward_event();
    assert_ne!(initial_reward_event, latest_reward_event);
    assert!(governance.proto.pending_version.is_none());
    assert_eq!(
        governance.proto.deployed_version.unwrap(),
        next_version.into()
    );

    // Check that the upgrade journal reflects the succeeded upgrade
    assert_matches!(
        &governance.proto.upgrade_journal.clone().unwrap().entries[..],
        [UpgradeJournalEntry {
            timestamp_seconds: Some(_),
            event: Some(upgrade_journal_entry::Event::UpgradeOutcome(
                upgrade_journal_entry::UpgradeOutcome {
                    human_readable: Some(_),
                    status: Some(upgrade_journal_entry::upgrade_outcome::Status::Success(
                        Empty {}
                    )),
                }
            )),
        }]
    )
}

#[test]
fn test_check_upgrade_status_fails_if_upgrade_not_finished_in_time() {
    let root_canister_id = *TEST_ROOT_CANISTER_ID;
    let governance_canister_id = *TEST_GOVERNANCE_CANISTER_ID;
    let next_version = SnsVersion {
        root_wasm_hash: vec![1, 2, 3],
        governance_wasm_hash: vec![2, 3, 4],
        ledger_wasm_hash: vec![3, 4, 5],
        swap_wasm_hash: vec![4, 5, 6],
        archive_wasm_hash: vec![5, 6, 7],
        index_wasm_hash: vec![6, 7, 8],
    };

    let mut env = NativeEnvironment::new(Some(governance_canister_id));
    // We set a status that matches our pending version
    let mut canisters_summary_response = std_sns_canisters_summary_response();
    for summary in canisters_summary_response.archives.iter_mut() {
        summary.status = Some(canister_status_for_test(
            vec![1, 1, 1],
            CanisterStatusType::Running,
        ));
    }
    env.set_call_canister_response(
        root_canister_id,
        "get_sns_canisters_summary",
        Encode!(&GetSnsCanistersSummaryRequest {
            update_canister_list: Some(true)
        })
        .unwrap(),
        Ok(Encode!(&canisters_summary_response).unwrap()),
    );

    let current_version = {
        let mut version = next_version.clone();
        version.archive_wasm_hash = vec![1, 1, 1];
        version
    };

    let now = env.now();
    let mut governance = Governance::new(
        GovernanceProto {
            root_canister_id: Some(root_canister_id.get()),
            deployed_version: Some(current_version.clone().into()),
            pending_version: Some(PendingVersion {
                target_version: Some(next_version.clone().into()),
                mark_failed_at_seconds: now - 1,
                checking_upgrade_lock: 0,
                proposal_id: Some(0),
            }),
            ..basic_governance_proto()
        }
        .try_into()
        .unwrap(),
        Box::new(env),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    assert_eq!(
        governance.proto.pending_version.clone().unwrap(),
        PendingVersion {
            target_version: Some(next_version.into()),
            mark_failed_at_seconds: now - 1,
            checking_upgrade_lock: 0,
            proposal_id: Some(0),
        }
    );
    assert_eq!(
        governance.proto.deployed_version.clone().unwrap(),
        current_version.clone().into()
    );
    // After we run our periodic tasks, the version should be marked as failed because of time
    // constraint.
    governance.run_periodic_tasks().now_or_never();

    // A failed deployment is when pending is erased but deployed_version is not updated.
    assert!(governance.proto.pending_version.is_none());
    assert_eq!(
        governance.proto.deployed_version.unwrap(),
        current_version.clone().into()
    );

    // Check that the upgrade journal reflects the timed-out upgrade attempt
    let upgrade_journal = governance.proto.upgrade_journal.clone().unwrap();
    let observed_upgrade_steps = assert_matches!(
        &upgrade_journal.entries[..],
        [
            UpgradeJournalEntry {
                timestamp_seconds: _,
                event: Some(upgrade_journal_entry::Event::UpgradeOutcome(
                    upgrade_journal_entry::UpgradeOutcome {
                        human_readable: Some(_),
                        status: Some(upgrade_journal_entry::upgrade_outcome::Status::Timeout(
                            Empty {}
                        )),
                    }
                )),
            },
            UpgradeJournalEntry {
                timestamp_seconds: _,
                event: Some(upgrade_journal_entry::Event::UpgradeStepsReset(
                    upgrade_journal_entry::UpgradeStepsReset {
                        human_readable: Some(_),
                        upgrade_steps: Some(observed_upgrade_steps),
                    }
                )),
            },
        ] => observed_upgrade_steps
    );

    assert_eq!(
        observed_upgrade_steps,
        &Versions {
            versions: vec![current_version.into()]
        }
    );
}

#[test]
fn test_check_upgrade_status_succeeds() {
    let root_canister_id = *TEST_ROOT_CANISTER_ID;
    let governance_canister_id = *TEST_GOVERNANCE_CANISTER_ID;
    let next_version = SnsVersion {
        root_wasm_hash: vec![1, 2, 3],
        governance_wasm_hash: vec![2, 3, 4],
        ledger_wasm_hash: vec![3, 4, 5],
        swap_wasm_hash: vec![4, 5, 6],
        archive_wasm_hash: vec![5, 6, 7],
        index_wasm_hash: vec![6, 7, 8],
    };

    let mut env = NativeEnvironment::new(Some(governance_canister_id));
    // We set a status that matches our pending version
    env.set_call_canister_response(
        root_canister_id,
        "get_sns_canisters_summary",
        Encode!(&GetSnsCanistersSummaryRequest {
            update_canister_list: Some(true)
        })
        .unwrap(),
        Ok(Encode!(&std_sns_canisters_summary_response()).unwrap()),
    );

    let current_version = {
        let mut version = next_version.clone();
        version.archive_wasm_hash = vec![1, 1, 1];
        version
    };

    let now = env.now();
    let proposal_id = 12;
    let action = Action::UpgradeSnsToNextVersion(UpgradeSnsToNextVersion {});
    let mut governance = Governance::new(
        GovernanceProto {
            root_canister_id: Some(root_canister_id.get()),
            deployed_version: Some(current_version.clone().into()),
            pending_version: Some(PendingVersion {
                target_version: Some(next_version.clone().into()),
                mark_failed_at_seconds: now + 5 * 60,
                checking_upgrade_lock: 0,
                proposal_id: Some(proposal_id),
            }),
            // we make a proposal that is already decided so that it won't execute again because
            // proposals to upgrade SNS's cannot execute if there's no deployed_version set on Governance state
            proposals: btreemap! {
                proposal_id => ProposalData {
                    action: (&action).into(),
                    id: Some(proposal_id.into()),
                    ballots: btreemap! {
                    "neuron 1".to_string() => Ballot {
                        vote: Vote::Yes as i32,
                        voting_power: 9001,
                        cast_timestamp_seconds: 1,
                    },
                },
                wait_for_quiet_state: Some(WaitForQuietState::default()),
                decided_timestamp_seconds: now,
                proposal: Some(Proposal {
                    title: "Upgrade Proposal".to_string(),
                    action: Some(action),
                    ..Default::default()
                }),
                latest_tally: Some(Tally {
                    timestamp_seconds: now,
                    yes: 100000000,
                    no: 0,
                    total: 100000000
                }),
                ..Default::default()
            }},
            ..basic_governance_proto()
        }
        .try_into()
        .unwrap(),
        Box::new(env),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    assert_eq!(
        governance.proto.pending_version.clone().unwrap(),
        PendingVersion {
            target_version: Some(next_version.clone().into()),
            mark_failed_at_seconds: now + 5 * 60,
            checking_upgrade_lock: 0,
            proposal_id: Some(proposal_id),
        }
    );
    assert_eq!(
        governance.proto.deployed_version.clone().unwrap(),
        current_version.into()
    );
    // After we run our periodic tasks, the version should be marked as successful
    governance.run_periodic_tasks().now_or_never();

    assert!(governance.proto.pending_version.is_none());
    assert_eq!(
        governance.proto.deployed_version.clone().unwrap(),
        next_version.clone().into()
    );
    // Assert proposal executed
    let proposal = governance.get_proposal(&GetProposal {
        proposal_id: Some(ProposalId { id: proposal_id }),
    });
    let proposal_data = match proposal.result.unwrap() {
        get_proposal_response::Result::Error(e) => {
            panic!("Error: {e:?}")
        }
        get_proposal_response::Result::Proposal(proposal) => proposal,
    };
    assert_ne!(proposal_data.executed_timestamp_seconds, 0);

    assert!(proposal_data.failure_reason.is_none());

    // Check that the upgrade journal reflects the succeeded upgrade
    assert_eq!(
        governance.proto.upgrade_journal.clone().unwrap().entries,
        vec![
            UpgradeJournalEntry {
                timestamp_seconds: Some(now),
                event: Some(upgrade_journal_entry::Event::UpgradeOutcome(
                    upgrade_journal_entry::UpgradeOutcome {
                        human_readable: Some(format!(
                            "Upgrade marked successful at {}.",
                            format_timestamp_for_humans(governance.env.now()),
                        )),
                        status: Some(upgrade_journal_entry::upgrade_outcome::Status::Success(
                            Empty {}
                        )),
                    }
                )),
            },
            UpgradeJournalEntry {
                timestamp_seconds: Some(now),
                event: Some(upgrade_journal_entry::Event::UpgradeStepsReset(
                    upgrade_journal_entry::UpgradeStepsReset {
                        human_readable: Some("Initializing the cache".to_string()),
                        upgrade_steps: Some(Versions {
                            versions: vec![Version::from(next_version)],
                        }),
                    }
                )),
            },
        ]
    )
}

#[test]
fn test_check_upgrade_not_yet_failed_if_canister_summary_errs_and_before_mark_failed_at_time() {
    let root_canister_id = *TEST_ROOT_CANISTER_ID;
    let governance_canister_id = *TEST_GOVERNANCE_CANISTER_ID;
    let next_version = SnsVersion {
        root_wasm_hash: vec![1, 2, 3],
        governance_wasm_hash: vec![2, 3, 4],
        ledger_wasm_hash: vec![3, 4, 5],
        swap_wasm_hash: vec![4, 5, 6],
        archive_wasm_hash: vec![5, 6, 7],
        index_wasm_hash: vec![6, 7, 8],
    };

    let bad_summary = GetSnsCanistersSummaryResponse {
        root: Some(CanisterSummary {
            canister_id: None,
            status: None,
        }),
        ..std_sns_canisters_summary_response()
    };
    let mut env = NativeEnvironment::new(Some(governance_canister_id));
    // We set a status that matches our pending version
    env.set_call_canister_response(
        root_canister_id,
        "get_sns_canisters_summary",
        Encode!(&GetSnsCanistersSummaryRequest {
            update_canister_list: Some(true)
        })
        .unwrap(),
        Ok(Encode!(&bad_summary).unwrap()),
    );

    let current_version = {
        let mut version = next_version.clone();
        version.archive_wasm_hash = vec![1, 1, 1];
        version
    };

    let now = env.now();
    let proposal_id = 12;
    let action = Action::UpgradeSnsToNextVersion(UpgradeSnsToNextVersion {});
    let mut governance = Governance::new(
        GovernanceProto {
            root_canister_id: Some(root_canister_id.get()),
            deployed_version: Some(current_version.clone().into()),
            pending_version: Some(PendingVersion {
                target_version: Some(next_version.clone().into()),
                mark_failed_at_seconds: now + 1,
                checking_upgrade_lock: 0,
                proposal_id: Some(proposal_id),
            }),
            // we make a proposal that is already decided so that it won't execute again because
            // proposals to upgrade SNS's cannot execute if there's no deployed_version set on Governance state
            proposals: btreemap! {
                proposal_id => ProposalData {
                    action: (&action).into(),
                    id: Some(proposal_id.into()),
                    ballots: btreemap! {
                    "neuron 1".to_string() => Ballot {
                        vote: Vote::Yes as i32,
                        voting_power: 9001,
                        cast_timestamp_seconds: 1,
                    },
                },
                wait_for_quiet_state: Some(WaitForQuietState::default()),
                decided_timestamp_seconds: now,
                proposal: Some(Proposal {
                    title: "Upgrade Proposal".to_string(),
                    action: Some(action),
                    ..Default::default()
                }),
                latest_tally: Some(Tally {
                    timestamp_seconds: now,
                    yes: 100000000,
                    no: 0,
                    total: 100000000
                }),
                ..Default::default()
            }},
            ..basic_governance_proto()
        }
        .try_into()
        .unwrap(),
        Box::new(env),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    assert_eq!(
        governance.proto.pending_version.clone().unwrap(),
        PendingVersion {
            target_version: Some(next_version.clone().into()),
            mark_failed_at_seconds: now + 1,
            checking_upgrade_lock: 0,
            proposal_id: Some(proposal_id),
        }
    );
    assert_eq!(
        governance.proto.deployed_version.clone().unwrap(),
        current_version.clone().into()
    );
    // After we run our periodic tasks, the version should be marked as successful
    governance.run_periodic_tasks().now_or_never();

    // We still have pending version
    assert_eq!(
        governance.proto.pending_version.clone().unwrap(),
        PendingVersion {
            target_version: Some(next_version.into()),
            mark_failed_at_seconds: now + 1,
            checking_upgrade_lock: 0,
            proposal_id: Some(proposal_id),
        }
    );

    // Assert proposal not failed or executed
    let proposal = governance.get_proposal(&GetProposal {
        proposal_id: Some(ProposalId { id: proposal_id }),
    });

    let proposal_data = match proposal.result.unwrap() {
        get_proposal_response::Result::Error(e) => {
            panic!("Error: {e:?}")
        }
        get_proposal_response::Result::Proposal(proposal) => proposal,
    };
    assert_eq!(proposal_data.failed_timestamp_seconds, 0);
    assert_eq!(proposal_data.executed_timestamp_seconds, 0);

    assert!(proposal_data.failure_reason.is_none());

    let journal = governance.proto.upgrade_journal.unwrap();
    assert_eq!(
        &journal.entries[..],
        [UpgradeJournalEntry {
            timestamp_seconds: Some(governance.env.now(),),
            event: Some(upgrade_journal_entry::Event::UpgradeStepsReset(
                upgrade_journal_entry::UpgradeStepsReset {
                    human_readable: Some("Initializing the cache".to_string(),),
                    upgrade_steps: Some(Versions {
                        versions: vec![current_version.into()],
                    }),
                },
            ),),
        }],
    );
}

#[test]
fn test_check_upgrade_fails_if_canister_summary_errs_and_past_mark_failed_at_time() {
    let root_canister_id = *TEST_ROOT_CANISTER_ID;
    let governance_canister_id = *TEST_GOVERNANCE_CANISTER_ID;
    let next_version = SnsVersion {
        root_wasm_hash: vec![1, 2, 3],
        governance_wasm_hash: vec![2, 3, 4],
        ledger_wasm_hash: vec![3, 4, 5],
        swap_wasm_hash: vec![4, 5, 6],
        archive_wasm_hash: vec![5, 6, 7],
        index_wasm_hash: vec![6, 7, 8],
    };

    let bad_summary = GetSnsCanistersSummaryResponse {
        root: Some(CanisterSummary {
            canister_id: None,
            status: None,
        }),
        ..std_sns_canisters_summary_response()
    };
    let mut env = NativeEnvironment::new(Some(governance_canister_id));
    // We set a status that matches our pending version
    env.set_call_canister_response(
        root_canister_id,
        "get_sns_canisters_summary",
        Encode!(&GetSnsCanistersSummaryRequest {
            update_canister_list: Some(true)
        })
        .unwrap(),
        Ok(Encode!(&bad_summary).unwrap()),
    );

    let current_version = {
        let mut version = next_version.clone();
        version.archive_wasm_hash = vec![1, 1, 1];
        version
    };

    let now = env.now();
    let proposal_id = 12;
    let action = Action::UpgradeSnsToNextVersion(UpgradeSnsToNextVersion {});
    let mut governance = Governance::new(
        GovernanceProto {
            root_canister_id: Some(root_canister_id.get()),
            deployed_version: Some(current_version.clone().into()),
            pending_version: Some(PendingVersion {
                target_version: Some(next_version.clone().into()),
                mark_failed_at_seconds: now - 1,
                checking_upgrade_lock: 0,
                proposal_id: Some(proposal_id),
            }),
            // we make a proposal that is already decided so that it won't execute again because
            // proposals to upgrade SNS's cannot execute if there's no deployed_version set on Governance state
            proposals: btreemap! {
                proposal_id => ProposalData {
                    action: (&action).into(),
                    id: Some(proposal_id.into()),
                    ballots: btreemap! {
                    "neuron 1".to_string() => Ballot {
                        vote: Vote::Yes as i32,
                        voting_power: 9001,
                        cast_timestamp_seconds: 1,
                    },
                },
                wait_for_quiet_state: Some(WaitForQuietState::default()),
                decided_timestamp_seconds: now,
                proposal: Some(Proposal {
                    title: "Upgrade Proposal".to_string(),
                    action: Some(action),
                    ..Default::default()
                }),
                latest_tally: Some(Tally {
                    timestamp_seconds: now,
                    yes: 100000000,
                    no: 0,
                    total: 100000000
                }),
                ..Default::default()
            }},
            ..basic_governance_proto()
        }
        .try_into()
        .unwrap(),
        Box::new(env),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    assert_eq!(
        governance.proto.pending_version.clone().unwrap(),
        PendingVersion {
            target_version: Some(next_version.clone().into()),
            mark_failed_at_seconds: now - 1,
            checking_upgrade_lock: 0,
            proposal_id: Some(proposal_id),
        }
    );
    assert_eq!(
        governance.proto.deployed_version.clone().unwrap(),
        current_version.into()
    );
    // After we run our periodic tasks, the version should be marked as successful
    governance.run_periodic_tasks().now_or_never();

    assert!(governance.proto.pending_version.is_none());
    assert_ne!(
        governance.proto.deployed_version.clone().unwrap(),
        next_version.into()
    );

    // Assert proposal failed
    let proposal = governance.get_proposal(&GetProposal {
        proposal_id: Some(ProposalId { id: proposal_id }),
    });
    let proposal_data = match proposal.result.unwrap() {
        get_proposal_response::Result::Error(e) => {
            panic!("Error: {e:?}")
        }
        get_proposal_response::Result::Proposal(proposal) => proposal,
    };
    assert_ne!(proposal_data.failed_timestamp_seconds, 0);

    assert_eq!(
        proposal_data.failure_reason.unwrap(),
        GovernanceError::new_with_message(
            ErrorType::External,
            format!(
                "Upgrade marked as failed at {}. \
                 Governance could not determine running version from root: Root had no status. \
                 Setting upgrade to failed to unblock retry.",
                format_timestamp_for_humans(now),
            )
        )
    );

    // Check that the upgrade journal reflects the timed-out upgrade attempt
    assert_matches!(
        &governance.proto.upgrade_journal.clone().unwrap().entries[..],
        [
            UpgradeJournalEntry {
                timestamp_seconds: _,
                event: Some(upgrade_journal_entry::Event::UpgradeOutcome(
                    upgrade_journal_entry::UpgradeOutcome {
                        human_readable: Some(_),
                        status: Some(upgrade_journal_entry::upgrade_outcome::Status::Timeout(
                            Empty {}
                        )),
                    }
                )),
            },
            UpgradeJournalEntry {
                timestamp_seconds: _,
                event: Some(upgrade_journal_entry::Event::UpgradeStepsReset(
                    upgrade_journal_entry::UpgradeStepsReset {
                        human_readable: Some(_),
                        upgrade_steps: Some(_),
                    },
                )),
            },
        ]
    )
}

#[test]
fn test_no_target_version_fails_check_upgrade_status() {
    let root_canister_id = *TEST_ROOT_CANISTER_ID;
    let governance_canister_id = *TEST_GOVERNANCE_CANISTER_ID;
    let next_version = SnsVersion {
        root_wasm_hash: vec![1, 2, 3],
        governance_wasm_hash: vec![2, 3, 4],
        ledger_wasm_hash: vec![3, 4, 5],
        swap_wasm_hash: vec![4, 5, 6],
        archive_wasm_hash: vec![5, 6, 7],
        index_wasm_hash: vec![6, 7, 8],
    };

    let summary = std_sns_canisters_summary_response();
    let mut env = NativeEnvironment::new(Some(governance_canister_id));
    // We set a status that matches our pending version
    env.set_call_canister_response(
        root_canister_id,
        "get_sns_canisters_summary",
        Encode!(&GetSnsCanistersSummaryRequest {
            update_canister_list: Some(true)
        })
        .unwrap(),
        Ok(Encode!(&summary).unwrap()),
    );

    let current_version = {
        let mut version = next_version.clone();
        version.archive_wasm_hash = vec![1, 1, 1];
        version
    };

    let now = env.now();
    let proposal_id = 12;
    let action = Action::UpgradeSnsToNextVersion(UpgradeSnsToNextVersion {});
    let mut governance = Governance::new(
        GovernanceProto {
            root_canister_id: Some(root_canister_id.get()),
            deployed_version: Some(current_version.into()),
            pending_version: Some(PendingVersion {
                // This should be impossible due to how it's set, but is the condition of this test
                target_version: None,
                mark_failed_at_seconds: now - 1,
                checking_upgrade_lock: 0,
                proposal_id: Some(proposal_id),
            }),
            // we make a proposal that is already decided so that it won't execute again because
            // proposals to upgrade SNS's cannot execute if there's no target_version set on Governance state
            proposals: btreemap! {
                proposal_id => ProposalData {
                    action: (&action).into(),
                    id: Some(proposal_id.into()),
                    ballots: btreemap! {
                    "neuron 1".to_string() => Ballot {
                        vote: Vote::Yes as i32,
                        voting_power: 9001,
                        cast_timestamp_seconds: 1,
                    },
                },
                wait_for_quiet_state: Some(WaitForQuietState::default()),
                decided_timestamp_seconds: now,
                proposal: Some(Proposal {
                    title: "Upgrade Proposal".to_string(),
                    action: Some(action),
                    ..Default::default()
                }),
                latest_tally: Some(Tally {
                    timestamp_seconds: now,
                    yes: 100000000,
                    no: 0,
                    total: 100000000
                }),
                ..Default::default()
            }},
            ..basic_governance_proto()
        }
        .try_into()
        .unwrap(),
        Box::new(env),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    governance.run_periodic_tasks().now_or_never();

    assert!(governance.proto.pending_version.is_none());
    assert_ne!(
        governance.proto.deployed_version.clone().unwrap(),
        next_version.into()
    );

    // Assert proposal failed
    let proposal = governance.get_proposal(&GetProposal {
        proposal_id: Some(ProposalId { id: proposal_id }),
    });
    let proposal_data = match proposal.result.unwrap() {
        get_proposal_response::Result::Error(e) => {
            panic!("Error: {e:?}")
        }
        get_proposal_response::Result::Proposal(proposal) => proposal,
    };
    assert_ne!(proposal_data.failed_timestamp_seconds, 0);

    assert_eq!(
        proposal_data.failure_reason.unwrap(),
        GovernanceError::new_with_message(
            ErrorType::InconsistentInternalData,
            "No target_version set for upgrade_in_progress. This should be impossible. Clearing \
             upgrade_in_progress state and marking proposal failed to unblock further upgrades."
        )
    );

    // Check that the upgrade journal reflects the failed upgrade attempt
    assert_matches!(
        &governance.proto.upgrade_journal.clone().unwrap().entries[..],
        [
            UpgradeJournalEntry {
                timestamp_seconds: _,
                event: Some(upgrade_journal_entry::Event::UpgradeOutcome(
                    upgrade_journal_entry::UpgradeOutcome {
                        human_readable: Some(_),
                        status: Some(
                            upgrade_journal_entry::upgrade_outcome::Status::InvalidState(
                                upgrade_journal_entry::upgrade_outcome::InvalidState {
                                    version: None
                                }
                            )
                        ),
                    }
                )),
            },
            UpgradeJournalEntry {
                timestamp_seconds: Some(_),
                event: Some(upgrade_journal_entry::Event::UpgradeStepsReset(
                    upgrade_journal_entry::UpgradeStepsReset {
                        human_readable: Some(_),
                        upgrade_steps: Some(Versions { versions: _ }),
                    }
                )),
            },
        ]
    );
}

#[test]
fn test_check_upgrade_fails_and_sets_deployed_version_if_deployed_version_missing_auto() {
    let automatically_advance_target_version = true;
    test_check_upgrade_fails_and_sets_deployed_version_if_deployed_version_missing(
        automatically_advance_target_version,
    );
}

#[test]
fn test_check_upgrade_fails_and_sets_deployed_version_if_deployed_version_missing_no_auto() {
    let automatically_advance_target_version = false;
    test_check_upgrade_fails_and_sets_deployed_version_if_deployed_version_missing(
        automatically_advance_target_version,
    );
}

fn test_check_upgrade_fails_and_sets_deployed_version_if_deployed_version_missing(
    automatically_advance_target_version: bool,
) {
    let root_canister_id = *TEST_ROOT_CANISTER_ID;
    let governance_canister_id = *TEST_GOVERNANCE_CANISTER_ID;
    let next_version = SnsVersion {
        root_wasm_hash: vec![1, 2, 3],
        governance_wasm_hash: vec![2, 3, 4],
        ledger_wasm_hash: vec![3, 4, 5],
        swap_wasm_hash: vec![4, 5, 6],
        archive_wasm_hash: vec![5, 6, 7],
        index_wasm_hash: vec![9, 9, 9],
    };

    // This is set to the version returned by std_sns_canisters_summary_response()
    // But is different from next_version so we can assert the right result below
    let running_version = {
        let mut version = next_version.clone();
        version.index_wasm_hash = vec![6, 7, 8];
        version
    };

    let mut env = NativeEnvironment::new(Some(governance_canister_id));

    let first_get_sns_canisters_summary_response = std_sns_canisters_summary_response();

    let second_get_sns_canisters_summary_response = {
        let mut response = first_get_sns_canisters_summary_response.clone();
        let index = {
            let mut index = response.index.clone().unwrap();
            let status = {
                let mut status = index.status.clone().unwrap();
                status.module_hash = Some(vec![9, 9, 9]);
                status
            };
            index.status = Some(status);
            index
        };
        response.index = Some(index);
        response
    };

    env.set_call_canister_response(
        root_canister_id,
        "get_sns_canisters_summary",
        Encode!(&GetSnsCanistersSummaryRequest {
            update_canister_list: Some(true)
        })
        .unwrap(),
        Ok(Encode!(&first_get_sns_canisters_summary_response).unwrap()),
    );
    env.set_call_canister_response(
        SNS_WASM_CANISTER_ID,
        "list_upgrade_steps",
        Encode!(&ListUpgradeStepsRequest {
            starting_at: Some(running_version.clone()),
            sns_governance_canister_id: Some(governance_canister_id.into()),
            limit: 0,
        })
        .unwrap(),
        Ok(Encode!(&ListUpgradeStepsResponse {
            steps: vec![
                ListUpgradeStep {
                    version: Some(running_version.clone())
                },
                ListUpgradeStep {
                    version: Some(next_version.clone())
                },
            ]
        })
        .unwrap()),
    );

    let now = env.now();
    let proposal_id = 12;
    let action = Action::UpgradeSnsToNextVersion(UpgradeSnsToNextVersion {});
    let mut governance = Governance::new(
        GovernanceProto {
            root_canister_id: Some(root_canister_id.get()),
            deployed_version: None,
            pending_version: Some(PendingVersion {
                target_version: Some(next_version.clone().into()),
                mark_failed_at_seconds: now + 5 * 60,
                checking_upgrade_lock: 0,
                proposal_id: Some(proposal_id),
            }),
            // we make a proposal that is already decided so that it won't execute again because
            // proposals to upgrade SNS's cannot execute if there's no deployed_version set on Governance state
            proposals: btreemap! {
                proposal_id => ProposalData {
                    action: (&action).into(),
                    id: Some(proposal_id.into()),
                    ballots: btreemap! {
                    "neuron 1".to_string() => Ballot {
                        vote: Vote::Yes as i32,
                        voting_power: 9001,
                        cast_timestamp_seconds: 1,
                    },
                },
                wait_for_quiet_state: Some(WaitForQuietState::default()),
                decided_timestamp_seconds: now,
                proposal: Some(Proposal {
                    title: "Upgrade Proposal".to_string(),
                    action: Some(action),
                    ..Default::default()
                }),
                latest_tally: Some(Tally {
                    timestamp_seconds: now,
                    yes: 100000000,
                    no: 0,
                    total: 100000000
                }),
                ..Default::default()
            }},
            ..basic_governance_proto()
        }
        .try_into()
        .unwrap(),
        Box::new(env),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );
    if let Some(parameters) = governance.proto.parameters.as_mut() {
        parameters.automatically_advance_target_version = Some(automatically_advance_target_version)
    };

    let expected_running_version_before_upgrade = Some(running_version.clone().into());
    let expected_running_version_after_upgrade = Some(next_version.clone().into());
    let expected_pending_version = Some(PendingVersion {
        target_version: expected_running_version_after_upgrade.clone(),
        mark_failed_at_seconds: now + 5 * 60,
        checking_upgrade_lock: 0,
        proposal_id: Some(proposal_id),
    });

    // Preconditions
    assert_eq!(governance.proto.deployed_version, None);
    assert_eq!(governance.proto.pending_version, expected_pending_version);

    // After the 1st run of periodic tasks, deployed_version should be recovered, but the upgrade
    // does not succeed yet (as the target version wasn't reached).
    {
        governance.run_periodic_tasks().now_or_never();
        assert_eq!(
            governance.proto.deployed_version,
            expected_running_version_before_upgrade
        );
        assert_eq!(governance.proto.pending_version, expected_pending_version);
    }

    // Modify the environment to enable calling `get_sns_canisters_summary` again.
    // Due to the limitations of this testing framework, we can't add this call spec upfront,
    // as it needs to be hashed by the same key as the first call.
    {
        let mut env = NativeEnvironment::new(Some(governance_canister_id));
        env.set_call_canister_response(
            root_canister_id,
            "get_sns_canisters_summary",
            Encode!(&GetSnsCanistersSummaryRequest {
                update_canister_list: Some(true)
            })
            .unwrap(),
            Ok(Encode!(&second_get_sns_canisters_summary_response).unwrap()),
        );
        governance.env = Box::new(env);
    }

    // After the 2nd run of periodic tasks, the upgrade is expected to succeed,
    // consuming `pending_version`.
    {
        governance.run_periodic_tasks().now_or_never();
        assert_eq!(governance.proto.pending_version, None);
        assert_eq!(
            governance.proto.deployed_version,
            expected_running_version_after_upgrade
        );
    }

    // Assert proposal succeeded.
    let proposal = governance.get_proposal(&GetProposal {
        proposal_id: Some(ProposalId { id: proposal_id }),
    });
    let proposal_data = match proposal.result.unwrap() {
        get_proposal_response::Result::Error(e) => {
            panic!("Error: {e:?}")
        }
        get_proposal_response::Result::Proposal(proposal) => proposal,
    };

    assert_eq!(proposal_data.failed_timestamp_seconds, 0);
    assert_eq!(proposal_data.failure_reason, None);

    // Check that the upgrade journal reflects the succeeded upgrade.
    let upgrade_journal = governance.proto.upgrade_journal.clone().unwrap();

    let (reset_upgrade_steps, refreshed_versions) = if automatically_advance_target_version {
        assert_matches!(
            &upgrade_journal.entries[..],
            [
                UpgradeJournalEntry {
                    timestamp_seconds: _,
                    event: Some(upgrade_journal_entry::Event::UpgradeStepsReset(
                        upgrade_journal_entry::UpgradeStepsReset {
                            human_readable: Some(_),
                            upgrade_steps: Some(reset_upgrade_steps),
                        },
                    )),
                },
                UpgradeJournalEntry {
                    timestamp_seconds: Some(_),
                    event: Some(upgrade_journal_entry::Event::TargetVersionSet(
                        upgrade_journal_entry::TargetVersionSet {
                            old_target_version: None,
                            new_target_version: Some(_),
                            is_advanced_automatically: Some(true),
                        },
                    )),
                },
                UpgradeJournalEntry {
                    timestamp_seconds: Some(_),
                    event: Some(upgrade_journal_entry::Event::UpgradeStepsRefreshed(
                        upgrade_journal_entry::UpgradeStepsRefreshed {
                            upgrade_steps: Some(
                                Versions {
                                    versions: refreshed_versions,
                                },
                            ),
                        },
                    )),
                },
                UpgradeJournalEntry {
                    timestamp_seconds: _,
                    event: Some(upgrade_journal_entry::Event::UpgradeOutcome(
                        upgrade_journal_entry::UpgradeOutcome {
                            human_readable: Some(_),
                            status: Some(
                                upgrade_journal_entry::upgrade_outcome::Status::Success(Empty {})
                            ),
                        }
                    )),
                }
            ] => (reset_upgrade_steps, refreshed_versions)
        )
    } else {
        assert_matches!(
            &upgrade_journal.entries[..],
            [
                UpgradeJournalEntry {
                    timestamp_seconds: _,
                    event: Some(upgrade_journal_entry::Event::UpgradeStepsReset(
                        upgrade_journal_entry::UpgradeStepsReset {
                            human_readable: Some(_),
                            upgrade_steps: Some(reset_upgrade_steps),
                        },
                    )),
                },
                UpgradeJournalEntry {
                    timestamp_seconds: Some(_),
                    event: Some(upgrade_journal_entry::Event::UpgradeStepsRefreshed(
                        upgrade_journal_entry::UpgradeStepsRefreshed {
                            upgrade_steps: Some(
                                Versions {
                                    versions: refreshed_versions,
                                },
                            ),
                        },
                    )),
                },
                UpgradeJournalEntry {
                    timestamp_seconds: _,
                    event: Some(upgrade_journal_entry::Event::UpgradeOutcome(
                        upgrade_journal_entry::UpgradeOutcome {
                            human_readable: Some(_),
                            status: Some(
                                upgrade_journal_entry::upgrade_outcome::Status::Success(Empty {})
                            ),
                        }
                    )),
                }
            ] => (reset_upgrade_steps, refreshed_versions)
        )
    };

    assert_eq!(
        reset_upgrade_steps.versions,
        vec![Version::from(running_version.clone())]
    );
    assert_eq!(
        &refreshed_versions[..],
        [Version::from(running_version), Version::from(next_version)]
    );
}

#[test]
fn test_upgrade_periodic_task_lock() {
    let env = NativeEnvironment::new(Some(*TEST_GOVERNANCE_CANISTER_ID));
    let mut gov = Governance::new(
        basic_governance_proto().try_into().unwrap(),
        Box::new(env),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    // The lock is initially None
    assert!(gov.upgrade_periodic_task_lock.is_none());

    // Test acquiring it
    assert!(gov.acquire_upgrade_periodic_task_lock());
    assert!(gov.upgrade_periodic_task_lock.is_some()); // the lock is now engaged
    assert!(!gov.acquire_upgrade_periodic_task_lock()); // acquiring it twice fails
    assert!(!gov.acquire_upgrade_periodic_task_lock()); // acquiring it a third time fails
    assert!(gov.upgrade_periodic_task_lock.is_some()); // the lock is still engaged

    // Test releasing it
    gov.release_upgrade_periodic_task_lock();
    assert!(gov.upgrade_periodic_task_lock.is_none());

    // Releasing twice is fine
    gov.release_upgrade_periodic_task_lock();
    assert!(gov.upgrade_periodic_task_lock.is_none());
}

#[test]
fn test_check_upgrade_can_succeed_if_archives_out_of_sync() {
    let root_canister_id = *TEST_ROOT_CANISTER_ID;
    let governance_canister_id = *TEST_GOVERNANCE_CANISTER_ID;

    // Beginning situation is SNS next_version is out of sync with
    // running version in regards to archive
    let next_version = SnsVersion {
        root_wasm_hash: vec![1, 2, 3],
        governance_wasm_hash: vec![2, 3, 4],
        ledger_wasm_hash: vec![3, 4, 5],
        swap_wasm_hash: vec![4, 5, 6],
        archive_wasm_hash: vec![9, 9, 9],
        index_wasm_hash: vec![6, 7, 8],
    };

    let mut env = NativeEnvironment::new(Some(governance_canister_id));
    let canisters_summary_response = std_sns_canisters_summary_response();
    // We set a status that matches our pending version
    env.set_call_canister_response(
        root_canister_id,
        "get_sns_canisters_summary",
        Encode!(&GetSnsCanistersSummaryRequest {
            update_canister_list: Some(true)
        })
        .unwrap(),
        Ok(Encode!(&canisters_summary_response).unwrap()),
    );

    // Our current version is different than next version by a single field
    // But archive won't match the running version
    let current_version = {
        let mut version = next_version.clone();
        version.governance_wasm_hash = vec![1, 1, 1];
        version
    };

    let now = env.now();
    let proposal_id = 45;
    let mut governance = Governance::new(
        GovernanceProto {
            root_canister_id: Some(root_canister_id.get()),
            deployed_version: Some(current_version.clone().into()),
            pending_version: Some(PendingVersion {
                target_version: Some(next_version.clone().into()),
                mark_failed_at_seconds: now + 5 * 60,
                checking_upgrade_lock: 0,
                proposal_id: Some(proposal_id),
            }),
            ..basic_governance_proto()
        }
        .try_into()
        .unwrap(),
        Box::new(env),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    assert_eq!(
        governance.proto.pending_version.clone().unwrap(),
        PendingVersion {
            target_version: Some(next_version.clone().into()),
            mark_failed_at_seconds: now + 5 * 60,
            checking_upgrade_lock: 0,
            proposal_id: Some(proposal_id),
        }
    );
    assert_eq!(
        governance.proto.deployed_version.clone().unwrap(),
        current_version.into()
    );
    // After we run our periodic tasks, the version should succeed
    governance.run_periodic_tasks().now_or_never();

    assert!(governance.proto.pending_version.is_none());
    assert_eq!(
        governance.proto.deployed_version.clone().unwrap(),
        next_version.into()
    );
}

#[test]
fn test_check_upgrade_status_succeeds_if_no_archives_present() {
    let root_canister_id = *TEST_ROOT_CANISTER_ID;
    let governance_canister_id = *TEST_GOVERNANCE_CANISTER_ID;
    let next_version = SnsVersion {
        root_wasm_hash: vec![1, 2, 3],
        governance_wasm_hash: vec![2, 3, 4],
        ledger_wasm_hash: vec![3, 4, 5],
        swap_wasm_hash: vec![4, 5, 6],
        archive_wasm_hash: vec![5, 6, 7],
        index_wasm_hash: vec![6, 7, 8],
    };

    let mut env = NativeEnvironment::new(Some(governance_canister_id));
    let mut canisters_summary_response = std_sns_canisters_summary_response();
    canisters_summary_response.archives = vec![];
    // We set a status that matches our pending version
    env.set_call_canister_response(
        root_canister_id,
        "get_sns_canisters_summary",
        Encode!(&GetSnsCanistersSummaryRequest {
            update_canister_list: Some(true)
        })
        .unwrap(),
        Ok(Encode!(&canisters_summary_response).unwrap()),
    );

    let current_version = {
        let mut version = next_version.clone();
        version.archive_wasm_hash = vec![1, 1, 1];
        version
    };

    let now = env.now();
    let proposal_id = 45;
    let mut governance = Governance::new(
        GovernanceProto {
            root_canister_id: Some(root_canister_id.get()),
            deployed_version: Some(current_version.clone().into()),
            pending_version: Some(PendingVersion {
                target_version: Some(next_version.clone().into()),
                mark_failed_at_seconds: now + 5 * 60,
                checking_upgrade_lock: 0,
                proposal_id: Some(proposal_id),
            }),
            ..basic_governance_proto()
        }
        .try_into()
        .unwrap(),
        Box::new(env),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    assert_eq!(
        governance.proto.pending_version.clone().unwrap(),
        PendingVersion {
            target_version: Some(next_version.clone().into()),
            mark_failed_at_seconds: now + 5 * 60,
            checking_upgrade_lock: 0,
            proposal_id: Some(proposal_id),
        }
    );
    assert_eq!(
        governance.proto.deployed_version.clone().unwrap(),
        current_version.into()
    );
    // After we run our periodic tasks, the version should be marked as successful
    governance.run_periodic_tasks().now_or_never();

    assert!(governance.proto.pending_version.is_none());
    assert_eq!(
        governance.proto.deployed_version.unwrap(),
        next_version.into()
    );
}

#[test]
fn test_sns_controlled_canister_upgrade_only_upgrades_dapp_canisters() {
    // Helper to let us create a lot of proposals to test.
    let create_upgrade_proposal = |id: u64, canister_id: CanisterId| {
        let action = Action::UpgradeSnsControlledCanister(UpgradeSnsControlledCanister {
            canister_id: Some(canister_id.get()),
            // small valid wasm
            new_canister_wasm: vec![0, 0x61, 0x73, 0x6D, 2, 0, 0, 0],
            canister_upgrade_arg: None,
            mode: Some(CanisterInstallModeProto::Upgrade.into()),
            chunked_canister_wasm: None,
        });

        // Upgrade Proposal
        let proposal = ProposalData {
            action: (&action).into(),
            id: Some(id.into()),
            ballots: btreemap! {
                "neuron 1".to_string() => Ballot {
                    vote: Vote::Yes as i32,
                    voting_power: 9001,
                    cast_timestamp_seconds: 1,
                },
            },
            wait_for_quiet_state: Some(WaitForQuietState::default()),
            proposal: Some(Proposal {
                title: "Upgrade Proposal".to_string(),
                action: Some(action),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(proposal.status(), Status::Open);

        proposal
    };

    use ProposalDecisionStatus as Status;

    let root_canister_id = *TEST_ROOT_CANISTER_ID;
    let governance_canister_id = *TEST_GOVERNANCE_CANISTER_ID;
    let ledger_canister_id = *TEST_LEDGER_CANISTER_ID;
    let swap_canister_id = *TEST_SWAP_CANISTER_ID;
    let ledger_archive_ids = TEST_ARCHIVES_CANISTER_IDS.clone();
    let dapp_canisters = TEST_DAPP_CANISTER_IDS.clone();

    // Setup Env to return a response to our canister_call query.
    let mut env = NativeEnvironment::new(Some(governance_canister_id));
    env.set_call_canister_response(
        root_canister_id,
        "get_sns_canisters_summary",
        Encode!(&GetSnsCanistersSummaryRequest {
            update_canister_list: Some(true)
        })
        .unwrap(),
        Ok(Encode!(&std_sns_canisters_summary_response()).unwrap()),
    );
    // Make all of our proposals and initialize them in Governance
    let dapp_proposal = create_upgrade_proposal(1, dapp_canisters[0]);
    let root_proposal = create_upgrade_proposal(2, root_canister_id);
    let governance_proposal = create_upgrade_proposal(3, governance_canister_id);
    let ledger_proposal = create_upgrade_proposal(4, ledger_canister_id);
    let swap_proposal = create_upgrade_proposal(5, swap_canister_id);
    let ledger_archive_proposal = create_upgrade_proposal(6, ledger_archive_ids[0]);
    let unknown_canister_upgrade_proposal = create_upgrade_proposal(7, canister_test_id(2000));

    // Init Governance.
    let mut governance = Governance::new(
        GovernanceProto {
            proposals: btreemap! {
                1 => dapp_proposal,
                2 => root_proposal,
                3 => governance_proposal,
                4 => ledger_proposal,
                5 => swap_proposal,
                6 => ledger_archive_proposal,
                7 => unknown_canister_upgrade_proposal
            },
            root_canister_id: Some(root_canister_id.get()),
            ledger_canister_id: Some(ledger_canister_id.get()),
            ..basic_governance_proto()
        }
        .try_into()
        .unwrap(),
        Box::new(env),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    // Helper function to assert failures.
    let assert_proposal_failed = |data: ProposalData, proposal_name: &str| {
        assert_eq!(
            data.status(),
            Status::Failed,
            "{} proposal did not fail. final_proposal_data: {:#?}",
            proposal_name,
            data,
        );
        assert_eq!(
            data.failure_reason.as_ref().unwrap().error_type,
            ErrorType::InvalidCommand as i32,
            "{} proposal failed, but failure_reason was not as expected. \
            final_proposal_data: {:#?}",
            proposal_name,
            data,
        );
    };

    // This is the only proposal that should succeed.
    let dapp_upgrade_result = execute_proposal(&mut governance, 1);
    assert_eq!(dapp_upgrade_result.status(), Status::Executed);

    // We assert the rest of the proposals fail.
    assert_proposal_failed(execute_proposal(&mut governance, 2), "Root upgrade");
    assert_proposal_failed(execute_proposal(&mut governance, 3), "Governance upgrade");
    assert_proposal_failed(execute_proposal(&mut governance, 4), "Ledger upgrade");
    assert_proposal_failed(execute_proposal(&mut governance, 5), "Swap upgrade");
    assert_proposal_failed(execute_proposal(&mut governance, 6), "Archive upgrade");
    assert_proposal_failed(
        execute_proposal(&mut governance, 7),
        "Unknown canister upgrade",
    );
}

#[test]
fn test_allow_canister_upgrades_while_motion_proposal_execution_is_in_progress() {
    // Step 1: Prepare the world.
    use ProposalDecisionStatus as Status;

    let motion_action_id: u64 = (&Action::Motion(Motion::default())).into();
    let upgrade_action_id: u64 =
        (&Action::UpgradeSnsControlledCanister(UpgradeSnsControlledCanister::default())).into();

    let motion_proposal_id = 1_u64;
    let motion_proposal = ProposalData {
        action: motion_action_id,
        id: Some(motion_proposal_id.into()),
        decided_timestamp_seconds: NativeEnvironment::DEFAULT_TEST_START_TIMESTAMP_SECONDS - 10,
        latest_tally: Some(Tally {
            yes: 1,
            no: 0,
            total: 1,
            timestamp_seconds: 1,
        }),
        ..Default::default()
    };
    assert_eq!(motion_proposal.status(), Status::Adopted);

    let upgrade_proposal_id = 2_u64;
    let upgrade_proposal = ProposalData {
        action: upgrade_action_id,
        id: Some(upgrade_proposal_id.into()),
        decided_timestamp_seconds: NativeEnvironment::DEFAULT_TEST_START_TIMESTAMP_SECONDS - 10,
        latest_tally: Some(Tally {
            yes: 1,
            no: 0,
            total: 1,
            timestamp_seconds: 1,
        }),
        ..Default::default()
    };

    let governance = Governance::new(
        GovernanceProto {
            proposals: btreemap! {
                motion_proposal_id => motion_proposal,
                upgrade_proposal_id => upgrade_proposal,
            },
            ..basic_governance_proto()
        }
        .try_into()
        .unwrap(),
        Box::<NativeEnvironment>::default(),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    // Step 2: Run code under test.
    let result = governance.check_no_upgrades_in_progress(Some(upgrade_proposal_id));

    // Step 3: Inspect result.
    assert!(result.is_ok(), "{result:#?}");
}

#[test]
fn test_allow_canister_upgrades_while_another_upgrade_proposal_is_open() {
    // Step 1: Prepare the world.
    use ProposalDecisionStatus as Status;

    let upgrade_action_id: u64 =
        (&Action::UpgradeSnsControlledCanister(UpgradeSnsControlledCanister::default())).into();

    let open_upgrade_proposal_id = 1_u64;
    let open_upgrade_proposal = ProposalData {
        action: upgrade_action_id,
        id: Some(open_upgrade_proposal_id.into()),
        latest_tally: Some(Tally {
            yes: 0,
            no: 0,
            total: 1,
            timestamp_seconds: 1,
        }),
        ..Default::default()
    };
    assert_eq!(open_upgrade_proposal.status(), Status::Open);

    let executing_upgrade_proposal_id = 2_u64;
    let executing_upgrade_proposal = ProposalData {
        action: upgrade_action_id,
        id: Some(executing_upgrade_proposal_id.into()),
        decided_timestamp_seconds: NativeEnvironment::DEFAULT_TEST_START_TIMESTAMP_SECONDS - 10,
        latest_tally: Some(Tally {
            yes: 1,
            no: 0,
            total: 1,
            timestamp_seconds: 1,
        }),
        ..Default::default()
    };
    assert_eq!(executing_upgrade_proposal.status(), Status::Adopted);

    let governance = Governance::new(
        GovernanceProto {
            proposals: btreemap! {
                open_upgrade_proposal_id => open_upgrade_proposal,
                executing_upgrade_proposal_id => executing_upgrade_proposal,
            },
            ..basic_governance_proto()
        }
        .try_into()
        .unwrap(),
        Box::<NativeEnvironment>::default(),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    // Step 2: Run code under test.
    let result = governance.check_no_upgrades_in_progress(Some(executing_upgrade_proposal_id));

    // Step 3: Inspect result.
    assert!(result.is_ok(), "{result:#?}");
}

#[test]
fn test_allow_canister_upgrades_after_another_upgrade_proposal_has_executed() {
    // Step 1: Prepare the world.
    use ProposalDecisionStatus as Status;

    let upgrade_action_id: u64 =
        (&Action::UpgradeSnsControlledCanister(UpgradeSnsControlledCanister::default())).into();

    let previous_upgrade_proposal_id = 1_u64;
    let previous_upgrade_proposal = ProposalData {
        action: upgrade_action_id,
        id: Some(previous_upgrade_proposal_id.into()),
        decided_timestamp_seconds: NativeEnvironment::DEFAULT_TEST_START_TIMESTAMP_SECONDS - 10,
        executed_timestamp_seconds: NativeEnvironment::DEFAULT_TEST_START_TIMESTAMP_SECONDS - 5,
        latest_tally: Some(Tally {
            yes: 1,
            no: 0,
            total: 1,
            timestamp_seconds: 1,
        }),
        ..Default::default()
    };
    assert_eq!(previous_upgrade_proposal.status(), Status::Executed);

    let upgrade_proposal_id = 2_u64;
    let upgrade_proposal = ProposalData {
        action: upgrade_action_id,
        id: Some(upgrade_proposal_id.into()),
        decided_timestamp_seconds: NativeEnvironment::DEFAULT_TEST_START_TIMESTAMP_SECONDS - 10,
        latest_tally: Some(Tally {
            yes: 1,
            no: 0,
            total: 1,
            timestamp_seconds: 1,
        }),
        ..Default::default()
    };

    let governance = Governance::new(
        GovernanceProto {
            proposals: btreemap! {
                previous_upgrade_proposal_id => previous_upgrade_proposal,
                upgrade_proposal_id => upgrade_proposal,
            },
            ..basic_governance_proto()
        }
        .try_into()
        .unwrap(),
        Box::<NativeEnvironment>::default(),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    // Step 2: Run code under test.
    let result = governance.check_no_upgrades_in_progress(Some(upgrade_proposal_id));

    // Step 3: Inspect result.
    assert!(result.is_ok(), "{result:#?}");
}

#[test]
fn test_allow_canister_upgrades_proposal_does_not_block_itself_but_does_block_others() {
    // Step 1: Prepare the world.
    use ProposalDecisionStatus as Status;

    let upgrade_action_id: u64 =
        (&Action::UpgradeSnsControlledCanister(UpgradeSnsControlledCanister::default())).into();

    let proposal_id = 1_u64;
    let proposal = ProposalData {
        action: upgrade_action_id,
        id: Some(proposal_id.into()),
        decided_timestamp_seconds: NativeEnvironment::DEFAULT_TEST_START_TIMESTAMP_SECONDS - 10,
        latest_tally: Some(Tally {
            yes: 1,
            no: 0,
            total: 1,
            timestamp_seconds: 1,
        }),
        ..Default::default()
    };
    assert_eq!(proposal.status(), Status::Adopted);

    let governance = Governance::new(
        GovernanceProto {
            proposals: btreemap! {
                proposal_id => proposal,
            },
            ..basic_governance_proto()
        }
        .try_into()
        .unwrap(),
        Box::<NativeEnvironment>::default(),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    // Step 2 & 3: Run code under test, and inspect results.
    let result = governance.check_no_upgrades_in_progress(Some(proposal_id));
    assert!(result.is_ok(), "{result:#?}");

    // Other upgrades should be blocked by proposal 1 though.
    let some_other_proposal_id = 99_u64;
    match governance.check_no_upgrades_in_progress(Some(some_other_proposal_id)) {
        Ok(_) => panic!("Some other upgrade proposal was not blocked."),
        Err(err) => assert_eq!(
            err.error_type,
            ErrorType::ResourceExhausted as i32,
            "{:#?}",
            err,
        ),
    }
}

#[test]
fn test_upgrade_proposals_blocked_by_pending_upgrade() {
    // Step 1: Prepare the world.
    use ProposalDecisionStatus as Status;

    let upgrade_action_id: u64 =
        (&Action::UpgradeSnsControlledCanister(UpgradeSnsControlledCanister::default())).into();

    let proposal_id = 1_u64;
    let proposal = ProposalData {
        action: upgrade_action_id,
        id: Some(proposal_id.into()),
        decided_timestamp_seconds: NativeEnvironment::DEFAULT_TEST_START_TIMESTAMP_SECONDS - 10,
        latest_tally: Some(Tally {
            yes: 1,
            no: 0,
            total: 1,
            timestamp_seconds: 1,
        }),
        ..Default::default()
    };
    assert_eq!(proposal.status(), Status::Adopted);

    let governance = Governance::new(
        GovernanceProto {
            proposals: btreemap! {
                proposal_id => proposal,
            },
            // There's already an upgrade pending
            pending_version: Some(PendingVersion {
                ..Default::default()
            }),
            ..basic_governance_proto()
        }
        .try_into()
        .unwrap(),
        Box::<NativeEnvironment>::default(),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    // Step 2 & 3: Run code under test, and inspect results.
    match governance.check_no_upgrades_in_progress(Some(proposal_id)) {
        Ok(_) => panic!("Some other upgrade proposal was not blocked."),
        Err(err) => assert_eq!(
            err.error_type,
            ErrorType::ResourceExhausted as i32,
            "{:#?}",
            err,
        ),
    }

    let some_other_proposal_id = 99_u64;
    match governance.check_no_upgrades_in_progress(Some(some_other_proposal_id)) {
        Ok(_) => panic!("Some other upgrade proposal was not blocked."),
        Err(err) => assert_eq!(
            err.error_type,
            ErrorType::ResourceExhausted as i32,
            "{:#?}",
            err,
        ),
    }
}

/// Ugrade proposals (e.g. UpgradeSnsToNextVersion) block all other upgrade actions while they're adopted until they're done executing, unless they're too old. This test checks the "unless they're too old" part
#[test]
fn test_upgrade_proposals_not_blocked_by_old_upgrade_proposals() {
    // Step 1: Prepare the world.
    use ProposalDecisionStatus as Status;

    let upgrade_action_id: u64 =
        (&Action::UpgradeSnsControlledCanister(UpgradeSnsControlledCanister::default())).into();

    let proposal_id = 1_u64;
    let some_other_proposal_id = 99_u64;
    let proposal = ProposalData {
        action: upgrade_action_id,
        id: Some(proposal_id.into()),
        decided_timestamp_seconds: NativeEnvironment::DEFAULT_TEST_START_TIMESTAMP_SECONDS
            - crate::governance::UPGRADE_PROPOSAL_BLOCK_EXPIRY_SECONDS
            - 1,
        latest_tally: Some(Tally {
            yes: 1,
            no: 0,
            total: 1,
            timestamp_seconds: 1,
        }),
        ..Default::default()
    };
    assert_eq!(proposal.status(), Status::Adopted);

    let mut governance = Governance::new(
        GovernanceProto {
            proposals: btreemap! {
                proposal_id => proposal,
            },
            ..basic_governance_proto()
        }
        .try_into()
        .unwrap(),
        Box::<NativeEnvironment>::default(),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    // Step 2: Check that the proposal is not blocked by an old proposal.
    match governance.check_no_upgrades_in_progress(Some(some_other_proposal_id)) {
        Ok(_) => {}
        Err(err) => panic!(
            "The proposal should not have gotten blocked by an old proposal. Instead, it was blocked due to: {err:#?}"
        ),
    }

    // Step 3: Make the proposal newer
    governance
        .proto
        .proposals
        .get_mut(&proposal_id)
        .unwrap()
        .decided_timestamp_seconds = NativeEnvironment::DEFAULT_TEST_START_TIMESTAMP_SECONDS
        - crate::governance::UPGRADE_PROPOSAL_BLOCK_EXPIRY_SECONDS
        + 1;

    // Step 4: Check that the proposal is now blocked by an old proposal.
    match governance.check_no_upgrades_in_progress(Some(some_other_proposal_id)) {
        Ok(_) => panic!("The proposal should have gotten blocked by an old proposal"),
        Err(err) => assert_eq!(
            err.error_type,
            ErrorType::ResourceExhausted as i32,
            "{:#?}",
            err,
        ),
    }
}

#[test]
fn test_add_generic_nervous_system_function_succeeds() {
    let root_canister_id = *TEST_ROOT_CANISTER_ID;
    let governance_canister_id = *TEST_GOVERNANCE_CANISTER_ID;
    let ledger_canister_id = *TEST_LEDGER_CANISTER_ID;
    let swap_canister_id = *TEST_SWAP_CANISTER_ID;

    let env = NativeEnvironment::new(Some(governance_canister_id));
    let mut governance = Governance::new(
        GovernanceProto {
            proposals: btreemap! {},
            root_canister_id: Some(root_canister_id.get()),
            ledger_canister_id: Some(ledger_canister_id.get()),
            swap_canister_id: Some(swap_canister_id.get()),
            ..basic_governance_proto()
        }
        .try_into()
        .unwrap(),
        Box::new(env),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    let id = 1000;
    let valid = NervousSystemFunction {
        id,
        name: "a".to_string(),
        description: None,
        function_type: Some(FunctionType::GenericNervousSystemFunction(
            GenericNervousSystemFunction {
                topic: Some(Topic::ApplicationBusinessLogic as i32),
                target_canister_id: Some(CanisterId::from(200).get()),
                target_method_name: Some("test_method".to_string()),
                validator_canister_id: Some(CanisterId::from(100).get()),
                validator_method_name: Some("test_validator_method".to_string()),
            },
        )),
    };
    assert_is_ok!(governance.perform_add_generic_nervous_system_function(valid.clone()));

    assert_eq!(governance.proto.id_to_nervous_system_functions.len(), 1);
    assert_eq!(governance.proto.id_to_nervous_system_functions[&id], valid);
}

#[test]
fn test_cant_add_generic_nervous_system_function_without_topic() {
    let id = 1000;
    let valid = NervousSystemFunction {
        id,
        name: "a".to_string(),
        description: None,
        function_type: Some(FunctionType::GenericNervousSystemFunction(
            GenericNervousSystemFunction {
                topic: None, // No topic specified
                target_canister_id: Some(CanisterId::from(200).get()),
                target_method_name: Some("test_method".to_string()),
                validator_canister_id: Some(CanisterId::from(100).get()),
                validator_method_name: Some("test_validator_method".to_string()),
            },
        )),
    };

    match crate::proposal::validate_and_render_add_generic_nervous_system_function(
        &Default::default(),
        &valid,
        &Default::default(),
    ) {
        Ok(_) => panic!(
            "Should not be able to add generic nervous system functions without a topic, but was able to add it."
        ),
        Err(err) => assert_eq!(err, "NervousSystemFunction must have a topic",),
    }
}

fn default_governance_with_proto(governance_proto: GovernanceProto) -> Governance {
    Governance::new(
        governance_proto
            .try_into()
            .expect("Failed validating governance proto"),
        Box::<NativeEnvironment>::default(),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    )
    .enable_test_features()
}

fn test_neuron_id(controller: PrincipalId) -> NeuronId {
    NeuronId::from(compute_neuron_staking_subaccount_bytes(controller, 0))
}

#[test]
fn test_stake_maturity_succeeds() {
    // Step 1: Prepare the world and parameters.
    let controller = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let neuron_id = test_neuron_id(controller);
    let permission = NeuronPermission {
        principal: Some(controller),
        permission_type: vec![NeuronPermissionType::StakeMaturity as i32],
    };
    let initial_staked_maturity: u64 = 100000;
    let earned_maturity: u64 = 12345;
    let neuron = Neuron {
        id: Some(neuron_id.clone()),
        permissions: vec![permission],
        staked_maturity_e8s_equivalent: Some(initial_staked_maturity),
        maturity_e8s_equivalent: earned_maturity,
        ..Default::default()
    };
    let mut governance_proto = basic_governance_proto();
    governance_proto
        .neurons
        .insert(neuron_id.to_string(), neuron);
    let mut governance = default_governance_with_proto(governance_proto);
    let stake_maturity = manage_neuron::StakeMaturity {
        ..Default::default()
    };

    // Step 2: Run code under test.
    let result = governance.stake_maturity_of_neuron(&neuron_id, &controller, &stake_maturity);

    // Step 3: Inspect result(s).
    assert_is_ok!(result);
    let neuron = governance
        .proto
        .neurons
        .get(&neuron_id.to_string())
        .expect("Missing neuron!");
    assert_eq!(neuron.maturity_e8s_equivalent, 0);
    assert_eq!(
        neuron
            .staked_maturity_e8s_equivalent
            .expect("staked_maturity must be set"),
        initial_staked_maturity + earned_maturity
    );
}

#[test]
fn test_stake_maturity_succeeds_without_initial_stake() {
    // Step 1: Prepare the world and parameters.
    let controller = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let neuron_id = test_neuron_id(controller);
    let permission = NeuronPermission {
        principal: Some(controller),
        permission_type: vec![NeuronPermissionType::StakeMaturity as i32],
    };
    let earned_maturity: u64 = 12345;
    let neuron = Neuron {
        id: Some(neuron_id.clone()),
        permissions: vec![permission],
        staked_maturity_e8s_equivalent: None,
        maturity_e8s_equivalent: earned_maturity,
        ..Default::default()
    };
    let mut governance_proto = basic_governance_proto();
    governance_proto
        .neurons
        .insert(neuron_id.to_string(), neuron);
    let mut governance = default_governance_with_proto(governance_proto);
    let stake_maturity = manage_neuron::StakeMaturity {
        ..Default::default()
    };

    // Step 2: Run code under test.
    let result = governance.stake_maturity_of_neuron(&neuron_id, &controller, &stake_maturity);

    // Step 3: Inspect result(s).
    assert_is_ok!(result);
    let neuron = governance
        .proto
        .neurons
        .get(&neuron_id.to_string())
        .expect("Missing neuron!");
    assert_eq!(neuron.maturity_e8s_equivalent, 0);
    assert_eq!(
        neuron
            .staked_maturity_e8s_equivalent
            .expect("staked_maturity must be set"),
        earned_maturity
    );
}

#[test]
fn test_stake_maturity_succeeds_with_partial_percentage() {
    // Step 1: Prepare the world and parameters.
    let controller = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let neuron_id = test_neuron_id(controller);
    let permission = NeuronPermission {
        principal: Some(controller),
        permission_type: vec![NeuronPermissionType::StakeMaturity as i32],
    };
    let initial_staked_maturity: u64 = 100000;
    let earned_maturity: u64 = 12345;
    let neuron = Neuron {
        id: Some(neuron_id.clone()),
        permissions: vec![permission],
        staked_maturity_e8s_equivalent: Some(initial_staked_maturity),
        maturity_e8s_equivalent: earned_maturity,
        ..Default::default()
    };
    let mut governance_proto = basic_governance_proto();
    governance_proto
        .neurons
        .insert(neuron_id.to_string(), neuron);
    let mut governance = default_governance_with_proto(governance_proto);
    let partial_percentage = 42;
    let stake_maturity = manage_neuron::StakeMaturity {
        percentage_to_stake: Some(partial_percentage),
    };

    // Step 2: Run code under test.
    let result = governance.stake_maturity_of_neuron(&neuron_id, &controller, &stake_maturity);

    // Step 3: Inspect result(s).
    assert_is_ok!(result);
    let neuron = governance
        .proto
        .neurons
        .get(&neuron_id.to_string())
        .expect("Missing neuron!");
    let expected_newly_staked_maturity =
        earned_maturity.saturating_mul(partial_percentage as u64) / 100;
    assert_eq!(
        neuron.maturity_e8s_equivalent,
        earned_maturity - expected_newly_staked_maturity
    );
    assert_eq!(
        neuron
            .staked_maturity_e8s_equivalent
            .expect("staked_maturity must be set"),
        initial_staked_maturity + expected_newly_staked_maturity
    );
}

#[test]
fn test_stake_maturity_fails_on_non_existing_neuron() {
    // Step 1: Prepare the world and parameters.
    let controller = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let neuron_id = test_neuron_id(controller);
    let mut governance = default_governance_with_proto(basic_governance_proto());
    let stake_maturity = manage_neuron::StakeMaturity {
        ..Default::default()
    };

    // Step 2: Run code under test.
    let result = governance.stake_maturity_of_neuron(&neuron_id, &controller, &stake_maturity);

    // Step 3: Inspect result(s).
    assert_matches!(
    result,
    Err(GovernanceError{error_type: code, error_message: msg})
        if code == ErrorType::NotFound as i32 && msg.to_lowercase().contains("neuron not found")
    );
}

#[test]
fn test_stake_maturity_fails_if_not_authorized() {
    // Step 1: Prepare the world and parameters.
    let controller = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let neuron_id = test_neuron_id(controller);
    let neuron = Neuron {
        id: Some(neuron_id.clone()),
        ..Default::default()
    };
    let mut governance_proto = basic_governance_proto();
    governance_proto
        .neurons
        .insert(neuron_id.to_string(), neuron);
    let mut governance = default_governance_with_proto(governance_proto);
    let stake_maturity = manage_neuron::StakeMaturity {
        ..Default::default()
    };

    // Step 2: Run code under test.
    let result = governance.stake_maturity_of_neuron(&neuron_id, &controller, &stake_maturity);

    // Step 3: Inspect result(s).
    assert_matches!(
    result,
    Err(GovernanceError{error_type: code, error_message: _msg})
        if code == ErrorType::NotAuthorized as i32);
}

#[test]
fn test_stake_maturity_fails_if_invalid_percentage_to_stake() {
    // Step 1: Prepare the world and parameters.
    let controller = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let neuron_id = test_neuron_id(controller);
    let permission = NeuronPermission {
        principal: Some(controller),
        permission_type: vec![NeuronPermissionType::StakeMaturity as i32],
    };
    let neuron = Neuron {
        id: Some(neuron_id.clone()),
        permissions: vec![permission],
        ..Default::default()
    };
    let mut governance_proto = basic_governance_proto();
    governance_proto
        .neurons
        .insert(neuron_id.to_string(), neuron);
    let mut governance = default_governance_with_proto(governance_proto);

    for percentage in &[0, 101, 120] {
        let stake_maturity = manage_neuron::StakeMaturity {
            percentage_to_stake: Some(*percentage),
        };

        // Step 2: Run code under test.
        let result = governance.stake_maturity_of_neuron(&neuron_id, &controller, &stake_maturity);

        // Step 3: Inspect result(s).
        assert_matches!(
        result,
        Err(GovernanceError{error_type: code, error_message: msg})
            if code == ErrorType::PreconditionFailed as i32 && msg.to_lowercase().contains("percentage of maturity"),
        "Didn't reject invalid percentage_to_stake value {}", percentage
        );
    }
}

#[test]
fn test_move_staked_maturity_on_dissolved_neurons_works() {
    // Step 1: Prepare the world and parameters.
    let controller_1 = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let controller_2 = *TEST_NEURON_2_OWNER_PRINCIPAL;
    let neuron_id_1 = test_neuron_id(controller_1);
    let neuron_id_2 = test_neuron_id(controller_2);
    let regular_maturity: u64 = 1000000;
    let staked_maturity: u64 = 424242;
    let now = NativeEnvironment::DEFAULT_TEST_START_TIMESTAMP_SECONDS;
    // Dissolved neuron.
    let neuron_1 = Neuron {
        id: Some(neuron_id_1.clone()),
        maturity_e8s_equivalent: regular_maturity,
        staked_maturity_e8s_equivalent: Some(staked_maturity),
        dissolve_state: Some(neuron::DissolveState::WhenDissolvedTimestampSeconds(
            now - 100,
        )),
        ..Default::default()
    };
    // Non-dissolved neuron.
    let neuron_2 = Neuron {
        id: Some(neuron_id_2.clone()),
        maturity_e8s_equivalent: regular_maturity,
        staked_maturity_e8s_equivalent: Some(staked_maturity),
        dissolve_state: Some(neuron::DissolveState::WhenDissolvedTimestampSeconds(
            now + 100,
        )),
        ..Default::default()
    };

    let mut governance_proto = basic_governance_proto();
    governance_proto
        .neurons
        .insert(neuron_id_1.to_string(), neuron_1);
    governance_proto
        .neurons
        .insert(neuron_id_2.to_string(), neuron_2);
    let mut governance = default_governance_with_proto(governance_proto);

    // Step 2: Run code under test.
    governance.maybe_move_staked_maturity();

    // Step 3: Inspect result(s).
    let neuron_1 = governance
        .proto
        .neurons
        .get(&neuron_id_1.to_string())
        .expect("Missing neuron!");
    assert_eq!(
        neuron_1.maturity_e8s_equivalent,
        regular_maturity + staked_maturity
    );
    assert_eq!(neuron_1.staked_maturity_e8s_equivalent.unwrap_or(0), 0);
    let neuron_2 = governance
        .proto
        .neurons
        .get(&neuron_id_2.to_string())
        .expect("Missing neuron!");
    assert_eq!(neuron_2.maturity_e8s_equivalent, regular_maturity);
    assert_eq!(
        neuron_2.staked_maturity_e8s_equivalent,
        Some(staked_maturity)
    );
}

struct DisburseMaturityTestSetup {
    pub governance: Governance,
    pub neuron_id: NeuronId,
    pub controller: PrincipalId,
}

// Sets up an environment for a disburse-maturity test. The returned
// setup consists of:
// - an initialized governance, whose API can be called
// - an id of a neuron (with the specified maturity) contained in the initialized governance
// - an id of a principal that controls the neuron
fn prepare_setup_for_disburse_maturity_tests(
    earned_maturity_e8s: u64,
) -> DisburseMaturityTestSetup {
    let controller = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let neuron_id = test_neuron_id(controller);
    let permission = NeuronPermission {
        principal: Some(controller),
        permission_type: vec![NeuronPermissionType::DisburseMaturity as i32],
    };
    let neuron = Neuron {
        id: Some(neuron_id.clone()),
        permissions: vec![permission],
        maturity_e8s_equivalent: earned_maturity_e8s,
        ..Default::default()
    };
    let mut governance_proto = GovernanceProto {
        maturity_modulation: Some(MaturityModulation {
            current_basis_points: Some(0), // Neither positive nor negative.
            updated_at_timestamp_seconds: Some(1),
        }),
        ..basic_governance_proto()
    };
    governance_proto
        .neurons
        .insert(neuron_id.to_string(), neuron);
    let governance = default_governance_with_proto(governance_proto);
    DisburseMaturityTestSetup {
        controller,
        neuron_id,
        governance,
    }
}

#[test]
fn test_disburse_maturity_succeeds_to_self() {
    // Step 1: Prepare the world and parameters.
    let earned_maturity_e8s = 1_234_567;
    let mut setup = prepare_setup_for_disburse_maturity_tests(earned_maturity_e8s);

    // Step 2: Run code under test.
    let disburse_maturity = DisburseMaturity {
        percentage_to_disburse: 100,
        to_account: None,
    };
    let result =
        setup
            .governance
            .disburse_maturity(&setup.neuron_id, &setup.controller, &disburse_maturity);

    // Step 3: Inspect result(s).
    let response = result.expect("Operation failed unexpectedly.");
    assert_eq!(response.amount_disbursed_e8s, earned_maturity_e8s);
    let neuron = setup
        .governance
        .proto
        .neurons
        .get(&setup.neuron_id.to_string())
        .expect("Missing neuron!");
    assert_eq!(neuron.maturity_e8s_equivalent, 0);
    assert_eq!(neuron.disburse_maturity_in_progress.len(), 1);
    let in_progress = &neuron.disburse_maturity_in_progress[0];
    assert_eq!(in_progress.amount_e8s, earned_maturity_e8s);
    assert!(
        in_progress.account_to_disburse_to.is_some(),
        "Missing target account for disbursement."
    );
    let target_account_pb = in_progress.account_to_disburse_to.as_ref().unwrap().clone();
    assert_eq!(
        Account::try_from(target_account_pb),
        Ok(Account {
            owner: setup.controller.0,
            subaccount: None
        })
    );
    let d_age = (setup.governance.env.now() as i64)
        - (in_progress.timestamp_of_disbursement_seconds as i64);
    assert!(d_age >= 0, "Disbursement timestamp is in the future");
    assert!(d_age < 10, "Disbursement timestamp is too old");
}

#[test]
fn test_disburse_maturity_succeeds_to_other_account() {
    // Step 1: Prepare the world and parameters.
    let earned_maturity_e8s = 3_456_789;
    let mut setup = prepare_setup_for_disburse_maturity_tests(earned_maturity_e8s);
    let target_principal = *TEST_NEURON_2_OWNER_PRINCIPAL;
    assert_ne!(target_principal, setup.controller);

    // Step 2: Run code under test.
    let disburse_maturity = DisburseMaturity {
        percentage_to_disburse: 100,
        to_account: Some(AccountProto {
            owner: Some(target_principal),
            subaccount: None,
        }),
    };
    let result =
        setup
            .governance
            .disburse_maturity(&setup.neuron_id, &setup.controller, &disburse_maturity);

    // Step 3: Inspect result(s).
    let response = result.expect("Operation failed unexpectedly.");
    assert_eq!(response.amount_disbursed_e8s, earned_maturity_e8s);
    let neuron = setup
        .governance
        .proto
        .neurons
        .get(&setup.neuron_id.to_string())
        .expect("Missing neuron!");
    assert_eq!(neuron.maturity_e8s_equivalent, 0);
    assert_eq!(neuron.disburse_maturity_in_progress.len(), 1);
    let in_progress = &neuron.disburse_maturity_in_progress[0];
    assert_eq!(in_progress.amount_e8s, earned_maturity_e8s);
    assert!(
        in_progress.account_to_disburse_to.is_some(),
        "Missing target account for disbursement."
    );
    let target_account_pb = in_progress.account_to_disburse_to.as_ref().unwrap().clone();
    assert_eq!(
        Account::try_from(target_account_pb),
        Ok(Account {
            owner: target_principal.0,
            subaccount: None
        })
    );
    let d_age = (setup.governance.env.now() as i64)
        - (in_progress.timestamp_of_disbursement_seconds as i64);
    assert!(d_age >= 0, "Disbursement timestamp is in the future");
    assert!(d_age < 10, "Disbursement timestamp is too old");
}

#[test]
fn test_disburse_maturity_succeeds_with_partial_percentage() {
    // Step 1: Prepare the world and parameters.
    let earned_maturity_e8s = 71_112_345;
    let mut setup = prepare_setup_for_disburse_maturity_tests(earned_maturity_e8s);

    // Step 2: Run code under test.
    let partial_percentage = 72;
    let disburse_maturity = DisburseMaturity {
        percentage_to_disburse: partial_percentage,
        to_account: None,
    };
    let result =
        setup
            .governance
            .disburse_maturity(&setup.neuron_id, &setup.controller, &disburse_maturity);

    // Step 3: Inspect result(s).
    let response = result.expect("Operation failed unexpectedly.");
    let expected_disbursing_maturity =
        earned_maturity_e8s.saturating_mul(partial_percentage as u64) / 100;
    assert_eq!(response.amount_disbursed_e8s, expected_disbursing_maturity);
    let neuron = setup
        .governance
        .proto
        .neurons
        .get(&setup.neuron_id.to_string())
        .expect("Missing neuron!");

    assert_eq!(
        neuron.maturity_e8s_equivalent,
        earned_maturity_e8s - expected_disbursing_maturity
    );
    assert_eq!(neuron.disburse_maturity_in_progress.len(), 1);
    let in_progress = &neuron.disburse_maturity_in_progress[0];
    assert_eq!(in_progress.amount_e8s, expected_disbursing_maturity);
    assert!(
        in_progress.account_to_disburse_to.is_some(),
        "Missing target account for disbursement."
    );
    let target_account_pb = in_progress.account_to_disburse_to.as_ref().unwrap().clone();
    assert_eq!(
        Account::try_from(target_account_pb),
        Ok(Account {
            owner: setup.controller.0,
            subaccount: None
        })
    );
    let d_age = (setup.governance.env.now() as i64)
        - (in_progress.timestamp_of_disbursement_seconds as i64);
    assert!(d_age >= 0, "Disbursement timestamp is in the future");
    assert!(d_age < 10, "Disbursement timestamp is too old");
}

#[test]
fn test_disburse_maturity_succeeds_with_multiple_disbursals() {
    // Step 1: Prepare the world and parameters.
    let earned_maturity_e8s = 12345678;
    let mut setup = prepare_setup_for_disburse_maturity_tests(earned_maturity_e8s);

    // Step 2: Run code under test.
    let percentages: Vec<u32> = vec![50, 20, 10];
    for percentage_to_disburse in &percentages {
        let disburse_maturity = DisburseMaturity {
            percentage_to_disburse: *percentage_to_disburse,
            to_account: None,
        };
        let result = setup.governance.disburse_maturity(
            &setup.neuron_id,
            &setup.controller,
            &disburse_maturity,
        );
        assert_is_ok!(result);
    }

    // Step 3: Inspect result(s).
    let neuron = setup
        .governance
        .proto
        .neurons
        .get(&setup.neuron_id.to_string())
        .expect("Missing neuron!");
    assert_eq!(
        neuron.disburse_maturity_in_progress.len(),
        percentages.len()
    );
    let mut remaining_maturity = earned_maturity_e8s;
    for (i, percentage_to_disburse) in percentages.iter().enumerate() {
        let expected_disbursing_maturity =
            remaining_maturity.saturating_mul(*percentage_to_disburse as u64) / 100;
        let in_progress = &neuron.disburse_maturity_in_progress[i];
        assert_eq!(
            in_progress.amount_e8s, expected_disbursing_maturity,
            "unexpected disbursing maturity for percentage {}",
            percentage_to_disburse
        );
        remaining_maturity -= expected_disbursing_maturity;
        if i > 0 {
            let prev_in_progress = &neuron.disburse_maturity_in_progress[i - 1];
            assert!(
                in_progress.timestamp_of_disbursement_seconds
                    >= prev_in_progress.timestamp_of_disbursement_seconds,
                "disburse_maturity_in_progress is not sorted by the timestamp"
            )
        }
    }
    assert_eq!(neuron.maturity_e8s_equivalent, remaining_maturity);
}

#[test]
fn test_disburse_maturity_fails_on_non_existing_neuron() {
    // Step 1: Prepare the world and parameters.
    let mut setup = prepare_setup_for_disburse_maturity_tests(1000);
    let non_existing_neuron_id = test_neuron_id(*TEST_NEURON_2_OWNER_PRINCIPAL);

    // Step 2: Run code under test.
    let disburse_maturity = DisburseMaturity {
        percentage_to_disburse: 100,
        to_account: None,
    };
    let result = setup.governance.disburse_maturity(
        &non_existing_neuron_id,
        &setup.controller,
        &disburse_maturity,
    );

    // Step 3: Inspect result(s).
    assert_matches!(
    result,
    Err(GovernanceError{error_type: code, error_message: msg})
        if code == ErrorType::NotFound as i32 && msg.to_lowercase().contains("neuron not found")
    );
}

#[test]
fn test_disburse_maturity_fails_if_maturity_too_low() {
    // Step 1: Prepare the world and parameters.
    let mut setup = prepare_setup_for_disburse_maturity_tests(1000);

    // Step 2: Run code under test.
    let disburse_maturity = DisburseMaturity {
        percentage_to_disburse: 100,
        to_account: None,
    };
    let result =
        setup
            .governance
            .disburse_maturity(&setup.neuron_id, &setup.controller, &disburse_maturity);

    // Step 3: Inspect result(s).
    assert_matches!(
    result,
    Err(GovernanceError{error_type: code, error_message: msg})
        if code == ErrorType::PreconditionFailed as i32 && msg.to_lowercase().contains("can't disburse an amount less than"));
}

#[test]
fn test_disburse_maturity_fails_if_not_authorized() {
    // Step 1: Prepare the world and parameters.
    let mut setup = prepare_setup_for_disburse_maturity_tests(1000000);
    let not_authorized_controller = *TEST_NEURON_2_OWNER_PRINCIPAL;

    // Step 2: Run code under test.
    let disburse_maturity = DisburseMaturity {
        percentage_to_disburse: 100,
        to_account: None,
    };
    let result = setup.governance.disburse_maturity(
        &setup.neuron_id,
        &not_authorized_controller,
        &disburse_maturity,
    );

    // Step 3: Inspect result(s).
    assert_matches!(
    result,
    Err(GovernanceError{error_type: code, error_message: _msg})
        if code == ErrorType::NotAuthorized as i32);
}

#[test]
fn test_disburse_maturity_fails_if_invalid_percentage_to_disburse() {
    // Step 1: Prepare the world and parameters.
    let mut setup = prepare_setup_for_disburse_maturity_tests(1000);

    for percentage in &[0, 101, 120] {
        // Step 2: Run code under test.
        let disburse_maturity = DisburseMaturity {
            percentage_to_disburse: *percentage,
            to_account: None,
        };
        let result = setup.governance.disburse_maturity(
            &setup.neuron_id,
            &setup.controller,
            &disburse_maturity,
        );

        // Step 3: Inspect result(s).
        assert_matches!(
        result,
        Err(GovernanceError{error_type: code, error_message: msg})
            if code == ErrorType::PreconditionFailed as i32 && msg.to_lowercase().contains("percentage of maturity"),
        "Didn't reject invalid percentage_to_disburse value {}", percentage
        );
    }
}

struct SplitNeuronTestSetup {
    pub governance: Governance,
    pub neuron_id: NeuronId,
    pub controller: PrincipalId,
}

// Sets up an environment for a split-neuron test. The returned
// setup consists of:
// - an initialized governance, whose API can be called
// - an id of a neuron (with the specified stake and maturity) contained in the initialized governance
// - an id of a principal that controls the neuron
fn prepare_setup_for_split_neuron_tests(stake_e8s: u64, maturity_e8s: u64) -> SplitNeuronTestSetup {
    let controller = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let neuron_id = test_neuron_id(controller);
    let permission = NeuronPermission {
        principal: Some(controller),
        permission_type: vec![NeuronPermissionType::Split as i32],
    };
    let neuron = Neuron {
        id: Some(neuron_id.clone()),
        permissions: vec![permission],
        cached_neuron_stake_e8s: stake_e8s,
        maturity_e8s_equivalent: maturity_e8s,
        ..Default::default()
    };
    let mut governance_proto = basic_governance_proto();
    governance_proto
        .neurons
        .insert(neuron_id.to_string(), neuron);
    let canister_id = CanisterId::from_u64(123456);
    let governance = Governance::new(
        governance_proto
            .try_into()
            .expect("Failed validating governance proto"),
        Box::new(NativeEnvironment::new(Some(canister_id))),
        Box::new(AlwaysSucceedingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    SplitNeuronTestSetup {
        controller,
        neuron_id,
        governance,
    }
}

#[tokio::test]
async fn test_split_neuron_succeeds() {
    // Step 1: Prepare the world and parameters.
    let stake_e8s = 1_000_000_000_000;
    let split_amount_e8s = stake_e8s / 3;
    let maturity_e8s = 123_456_789;
    let mut setup = prepare_setup_for_split_neuron_tests(stake_e8s, maturity_e8s);
    let orig_neuron = setup
        .governance
        .proto
        .neurons
        .get(&setup.neuron_id.to_string())
        .expect("Missing orig neuron!")
        .clone();
    let split = manage_neuron::Split {
        amount_e8s: split_amount_e8s,
        memo: 42,
    };

    // Step 2: Run code under test.
    let result = setup
        .governance
        .split_neuron(&setup.neuron_id, &setup.controller, &split)
        .await;

    // Step 3: Inspect result(s).
    let child_neuron_id = result.expect("Operation failed unexpectedly.");
    let parent_neuron = setup
        .governance
        .proto
        .neurons
        .get(&setup.neuron_id.to_string())
        .expect("Missing old neuron!");
    assert_eq!(
        parent_neuron.cached_neuron_stake_e8s,
        stake_e8s - split_amount_e8s
    );
    assert_eq!(parent_neuron.maturity_e8s_equivalent, maturity_e8s);
    assert_eq!(parent_neuron.neuron_fees_e8s, orig_neuron.neuron_fees_e8s);
    let child_neuron = setup
        .governance
        .proto
        .neurons
        .get(&child_neuron_id.to_string())
        .expect("Missing new neuron!");
    assert_eq!(
        child_neuron.cached_neuron_stake_e8s,
        split_amount_e8s - setup.governance.transaction_fee_e8s_or_panic()
    );
    assert_eq!(child_neuron.maturity_e8s_equivalent, 0);
    assert!(child_neuron.disburse_maturity_in_progress.is_empty());
    assert_eq!(child_neuron.neuron_fees_e8s, 0);

    let p = parent_neuron;
    let c = child_neuron;
    assert_eq!(p.permissions, c.permissions);
    assert_eq!(p.followees, c.followees);
    assert_eq!(p.dissolve_state, c.dissolve_state);
    assert_eq!(p.source_nns_neuron_id, c.source_nns_neuron_id);
    assert_eq!(p.auto_stake_maturity, c.auto_stake_maturity);
    assert_eq!(
        p.aging_since_timestamp_seconds,
        c.aging_since_timestamp_seconds
    );
    assert_eq!(
        p.voting_power_percentage_multiplier,
        c.voting_power_percentage_multiplier
    );
}

#[tokio::test]
async fn test_split_neuron_fails_if_not_authorized() {
    // Step 1: Prepare the world and parameters.
    let mut setup = prepare_setup_for_split_neuron_tests(1_000_000_000, 100);
    let not_authorized_controller = *TEST_NEURON_2_OWNER_PRINCIPAL;
    let split = manage_neuron::Split {
        amount_e8s: 10_000_000,
        memo: 42,
    };

    // Step 2: Run code under test.
    let result = setup
        .governance
        .split_neuron(&setup.neuron_id, &not_authorized_controller, &split)
        .await;

    // Step 3: Inspect result(s).
    assert_matches!(
    result,
    Err(GovernanceError{error_type: code, error_message: _msg})
        if code == ErrorType::NotAuthorized as i32);
}

#[tokio::test]
async fn test_split_neuron_fails_on_non_existing_neuron() {
    // Step 1: Prepare the world and parameters.
    let mut setup = prepare_setup_for_split_neuron_tests(1_000_000_000, 100);
    let wrong_neuron_id = test_neuron_id(*TEST_NEURON_2_OWNER_PRINCIPAL);
    let split = manage_neuron::Split {
        amount_e8s: 10_000_000,
        memo: 42,
    };

    // Step 2: Run code under test.
    let result = setup
        .governance
        .split_neuron(&wrong_neuron_id, &setup.controller, &split)
        .await;

    // Step 3: Inspect result(s).
    assert_matches!(
    result,
    Err(GovernanceError{error_type: code, error_message: msg})
        if code == ErrorType::NotFound as i32 && msg.to_lowercase().contains("neuron not found")
    );
}

#[tokio::test]
async fn test_split_neuron_fails_if_split_amount_too_low() {
    // Step 1: Prepare the world and parameters.
    let mut setup = prepare_setup_for_split_neuron_tests(1_000_000_000, 100);
    let params = setup.governance.nervous_system_parameters_or_panic();
    // The requested amount does not account for transaction fee, so the split should fail.
    let split = manage_neuron::Split {
        amount_e8s: params
            .neuron_minimum_stake_e8s
            .expect("Missing min stake param."),
        memo: 42,
    };
    // Step 2: Run code under test.
    let result = setup
        .governance
        .split_neuron(&setup.neuron_id, &setup.controller, &split)
        .await;

    // Step 3: Inspect result(s).
    assert_matches!(
    result,
    Err(GovernanceError{error_type: code, error_message: msg})
        if code == ErrorType::InsufficientFunds as i32&& msg.to_lowercase().contains("minimum split amount"));
}

#[tokio::test]
async fn test_split_neuron_fails_if_remaining_stake_too_low() {
    // Step 1: Prepare the world and parameters.
    let stake_e8s = 10_000_000_000;
    let mut setup = prepare_setup_for_split_neuron_tests(stake_e8s, 100);
    let params = setup.governance.nervous_system_parameters_or_panic();
    // The remaining amount would be below min stake, so the split should fail.
    let split = manage_neuron::Split {
        amount_e8s: stake_e8s + 1
            - params
                .neuron_minimum_stake_e8s
                .expect("Missing min stake param."),
        memo: 42,
    };
    // Step 2: Run code under test.
    let result = setup
        .governance
        .split_neuron(&setup.neuron_id, &setup.controller, &split)
        .await;

    // Step 3: Inspect result(s).
    assert_matches!(
    result,
    Err(GovernanceError{error_type: code, error_message: msg})
        if code == ErrorType::InsufficientFunds as i32&& msg.to_lowercase().contains("minimum allowed stake"));
}

#[tokio::test]
async fn test_split_neuron_fails_with_repeated_memo() {
    // Step 1: Prepare the world and parameters.
    let mut setup = prepare_setup_for_split_neuron_tests(10_000_000_000, 100);
    let split = manage_neuron::Split {
        amount_e8s: 1_000_000_000,
        memo: 42,
    };

    // Step 2: Run code under test.
    // The first split should succeed.
    let result = setup
        .governance
        .split_neuron(&setup.neuron_id, &setup.controller, &split)
        .await;
    assert!(result.is_ok(), "Error: {}", result.err().unwrap());
    // The second, repeated split should fail.
    let result = setup
        .governance
        .split_neuron(&setup.neuron_id, &setup.controller, &split)
        .await;

    // Step 3: Inspect result(s).
    assert_matches!(
    result,
    Err(GovernanceError{error_type: code, error_message: msg})
        if code == ErrorType::PreconditionFailed as i32 && msg.to_lowercase().contains("neuron already exists")
    );
}

#[test]
fn test_add_generic_nervous_system_function_fails_when_restricted() {
    let root_canister_id = *TEST_ROOT_CANISTER_ID;
    let governance_canister_id = *TEST_GOVERNANCE_CANISTER_ID;
    let ledger_canister_id = *TEST_LEDGER_CANISTER_ID;
    let swap_canister_id = *TEST_SWAP_CANISTER_ID;

    let env = NativeEnvironment::new(Some(governance_canister_id));
    let mut governance = Governance::new(
        GovernanceProto {
            proposals: btreemap! {},
            root_canister_id: Some(root_canister_id.get()),
            ledger_canister_id: Some(ledger_canister_id.get()),
            swap_canister_id: Some(swap_canister_id.get()),
            ..basic_governance_proto()
        }
        .try_into()
        .unwrap(),
        Box::new(env),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    let list_that_should_fail = vec![
        root_canister_id,
        governance_canister_id,
        ledger_canister_id,
        swap_canister_id,
        CanisterId::ic_00(),
        NNS_LEDGER_CANISTER_ID,
    ];

    for canister_id in list_that_should_fail {
        assert_adding_generic_nervous_system_function_fails_for_target_and_validator(
            &mut governance,
            canister_id,
        );
    }
}

fn assert_adding_generic_nervous_system_function_fails_for_target_and_validator(
    governance: &mut Governance,
    invalid_canister_target: CanisterId,
) {
    let nns_function_invalid_validator = NervousSystemFunction {
        id: 1000,
        name: "a".to_string(),
        description: None,
        function_type: Some(FunctionType::GenericNervousSystemFunction(
            GenericNervousSystemFunction {
                topic: None,
                target_canister_id: Some(invalid_canister_target.get()),
                target_method_name: Some("test_method".to_string()),
                validator_canister_id: Some(CanisterId::from(1).get()),
                validator_method_name: Some("test_validator_method".to_string()),
            },
        )),
    };
    let result = governance
        .perform_add_generic_nervous_system_function(nns_function_invalid_validator.clone());
    assert!(
        result.is_err(),
        "function: {nns_function_invalid_validator:?}\nresult: {result:?}"
    );

    let nns_function_invalid_target = NervousSystemFunction {
        id: 1000,
        name: "a".to_string(),
        description: None,
        function_type: Some(FunctionType::GenericNervousSystemFunction(
            GenericNervousSystemFunction {
                topic: None,
                target_canister_id: Some(CanisterId::from(1).get()),
                target_method_name: Some("test_method".to_string()),
                validator_canister_id: Some(invalid_canister_target.get()),
                validator_method_name: Some("test_validator_method".to_string()),
            },
        )),
    };
    let result =
        governance.perform_add_generic_nervous_system_function(nns_function_invalid_target.clone());
    assert!(
        result.is_err(),
        "function: {nns_function_invalid_target:?}\nresult: {result:?}"
    );
}

#[test]
fn test_effective_maturity_modulation_basis_points() {
    let mut governance_proto = GovernanceProto {
        maturity_modulation: Some(MaturityModulation {
            current_basis_points: Some(42),
            updated_at_timestamp_seconds: Some(1),
        }),
        parameters: Some(NervousSystemParameters {
            maturity_modulation_disabled: None, // Maturity modulation is enabled.
            ..Default::default()
        }),
        ..Default::default()
    };

    assert_eq!(
        governance_proto.effective_maturity_modulation_basis_points(),
        Ok(42),
        "{:#?}",
        governance_proto,
    );

    governance_proto.parameters = Some(NervousSystemParameters {
        maturity_modulation_disabled: Some(false), // Behaves the same as None.
        ..Default::default()
    });

    assert_eq!(
        governance_proto.effective_maturity_modulation_basis_points(),
        Ok(42),
        "{:#?}",
        governance_proto,
    );

    governance_proto.parameters = Some(NervousSystemParameters {
        maturity_modulation_disabled: Some(true), // Causes maturity_modulation to be ignored.
        ..Default::default()
    });

    assert_eq!(
        governance_proto.effective_maturity_modulation_basis_points(),
        Ok(0),
        "{:#?}",
        governance_proto,
    );

    let governance_proto = GovernanceProto {
        maturity_modulation: Some(MaturityModulation {
            current_basis_points: None, // No value yet.
            updated_at_timestamp_seconds: Some(1),
        }),
        parameters: Some(NervousSystemParameters {
            maturity_modulation_disabled: Some(false), // Maturity modulation is enabled.
            ..Default::default()
        }),
        ..Default::default()
    };

    let result = governance_proto.effective_maturity_modulation_basis_points();
    assert_is_err!(result.clone());
    let err = result.unwrap_err();
    assert_eq!(err.error_type, ErrorType::Unavailable as i32);
    assert!(err.error_message.contains("retriev"));
}

#[test]
fn test_list_topics() {
    use crate::pb::v1::NervousSystemFunction;

    // Set up the environment
    let function_1 = NervousSystemFunction {
        id: 1000,
        name: "Test1".to_string(),
        description: None,
        function_type: Some(FunctionType::GenericNervousSystemFunction(
            GenericNervousSystemFunction {
                topic: Some(Topic::DaoCommunitySettings as i32),
                target_canister_id: Some(CanisterId::from_u64(1).get()),
                target_method_name: Some("test_method".to_string()),
                validator_canister_id: Some(CanisterId::from_u64(1).get()),
                validator_method_name: Some("test_validator_method".to_string()),
            },
        )),
    };
    let function_2 = NervousSystemFunction {
        id: 1001,
        name: "Test2".to_string(),
        description: None,
        function_type: Some(FunctionType::GenericNervousSystemFunction(
            GenericNervousSystemFunction {
                topic: Some(Topic::SnsFrameworkManagement as i32),
                target_canister_id: Some(CanisterId::from_u64(1).get()),
                target_method_name: Some("test_method".to_string()),
                validator_canister_id: Some(CanisterId::from_u64(1).get()),
                validator_method_name: Some("test_validator_method".to_string()),
            },
        )),
    };
    let function_3 = NervousSystemFunction {
        id: 1003,
        name: "Test3".to_string(),
        description: None,
        function_type: Some(FunctionType::GenericNervousSystemFunction(
            GenericNervousSystemFunction {
                topic: None,
                target_canister_id: Some(CanisterId::from_u64(1).get()),
                target_method_name: Some("test_method".to_string()),
                validator_canister_id: Some(CanisterId::from_u64(1).get()),
                validator_method_name: Some("test_validator_method".to_string()),
            },
        )),
    };
    let governance_proto = basic_governance_proto();
    let governance_proto = GovernanceProto {
        id_to_nervous_system_functions: {
            let mut id_to_nervous_system_functions = BTreeMap::new();
            id_to_nervous_system_functions.insert(1000, function_1.clone());
            id_to_nervous_system_functions.insert(1001, function_2.clone());
            id_to_nervous_system_functions.insert(1003, function_3.clone());
            id_to_nervous_system_functions
        },
        ..governance_proto
    };

    let governance = Governance::new(
        ValidGovernanceProto::try_from(governance_proto).unwrap(),
        Box::new(NativeEnvironment::new(None)),
        Box::new(DoNothingLedger {}),
        Box::new(DoNothingLedger {}),
        Box::new(FakeCmc::new()),
    );

    let registered_spec = ExtensionSpec {
        name: "KongSwap".to_string(),
        version: ExtensionVersion(1),
        topic: Topic::TreasuryAssetManagement.into(),
        extension_type: ExtensionType::TreasuryManager,
    };

    let deposit_operation_spec = registered_spec.get_operation("deposit").unwrap();
    let withdraw_operation_spec = registered_spec.get_operation("withdraw").unwrap();

    cache_registered_extension(CanisterId::from_u64(100_001), registered_spec.clone());
    cache_registered_extension(CanisterId::from_u64(100_002), registered_spec);

    // Call the API under test
    let ListTopicsResponse {
        topics: topic_infos,
        uncategorized_functions,
    } = governance.list_topics();

    // Assert the results are as expected
    assert_eq!(uncategorized_functions, vec![function_3]);
    let expected_topic_infos = vec![
        TopicInfo {
            topic: Topic::DaoCommunitySettings,
            name: "DAO community settings".to_string(),
            description: "Proposals to set the direction of the DAO by tokenomics & branding, such as the name and description, token name etc".to_string(),
            functions: NervousSystemFunctions {
                native_functions: vec![
                    NervousSystemFunction {
                        id: 2,
                        name: "Manage nervous system parameters".to_string(),
                        description: Some(
                            "Proposal to change the core parameters of SNS governance.".to_string(),
                        ),
                        function_type: Some(
                            FunctionType::NativeNervousSystemFunction(
                                Empty {},
                            ),
                        ),
                    },
                    NervousSystemFunction {
                        id: 13,
                        name: "Manage ledger parameters".to_string(),
                        description: Some(
                            "Proposal to change some parameters in the ledger canister.".to_string(),
                        ),
                        function_type: Some(
                            FunctionType::NativeNervousSystemFunction(
                                Empty {},
                            ),
                        ),
                    },
                    NervousSystemFunction {
                        id: 8,
                        name: "Manage SNS metadata".to_string(),
                        description: Some(
                            "Proposal to change the metadata associated with an SNS.".to_string(),
                        ),
                        function_type: Some(
                            FunctionType::NativeNervousSystemFunction(
                                Empty {},
                            ),
                        ),
                    },
                ],
                custom_functions: vec![
                    function_1,
                ],
            },
            extension_operations: vec![],
            is_critical: true,
        },
        TopicInfo {
            topic: Topic::SnsFrameworkManagement,
            name: "SNS framework management".to_string(),
            description: "Proposals to upgrade and manage the SNS DAO framework.".to_string(),
            functions: NervousSystemFunctions {
                native_functions: vec![
                    NervousSystemFunction {
                        id: 7,
                        name: "Upgrade SNS to next version".to_string(),
                        description: Some(
                            "Proposal to upgrade the WASM of a core SNS canister.".to_string(),
                        ),
                        function_type: Some(
                            FunctionType::NativeNervousSystemFunction(
                                Empty {},
                            ),
                        ),
                    },
                    NervousSystemFunction {
                        id: 15,
                        name: "Advance SNS target version".to_string(),
                        description: Some(
                            "Proposal to advance the target version of this SNS.".to_string(),
                        ),
                        function_type: Some(
                            FunctionType::NativeNervousSystemFunction(
                                Empty {},
                            ),
                        ),
                    },
                ],
                custom_functions: vec![
                    function_2
                ],
            },
            extension_operations: vec![],
            is_critical: false,
        },
        TopicInfo {
            topic: Topic::DappCanisterManagement,
            name: "Dapp canister management".to_string(),
            description: "Proposals to upgrade the registered dapp canisters and dapp upgrades via built-in or custom logic and updates to frontend assets.".to_string(),
            functions: NervousSystemFunctions {
                native_functions: vec![
                    NervousSystemFunction {
                        id: 3,
                        name: "Upgrade SNS controlled canister".to_string(),
                        description: Some(
                            "Proposal to upgrade the wasm of an SNS controlled canister.".to_string(),
                        ),
                        function_type: Some(
                            FunctionType::NativeNervousSystemFunction(
                                Empty {},
                            ),
                        ),
                    },
                    NervousSystemFunction {
                        id: 10,
                        name: "Register dapp canisters".to_string(),
                        description: Some(
                            "Proposal to register a dapp canister with the SNS.".to_string(),
                        ),
                        function_type: Some(
                            FunctionType::NativeNervousSystemFunction(
                                Empty {},
                            ),
                        ),
                    },
                    NervousSystemFunction {
                        id: 14,
                        name: "Manage dapp canister settings".to_string(),
                        description: Some(
                            "Proposal to change canister settings for some dapp canisters.".to_string(),
                        ),
                        function_type: Some(
                            FunctionType::NativeNervousSystemFunction(
                                Empty {},
                            ),
                        ),
                    },
                ],
                custom_functions: vec![],
            },
            extension_operations: vec![],
            is_critical: false,
        },
        TopicInfo {
            topic: Topic::ApplicationBusinessLogic,
            name: "Application Business Logic".to_string(),
            description: "Proposals that are custom to what the governed dapp requires.".to_string(),
            functions: NervousSystemFunctions {
                native_functions: vec![],
                custom_functions: vec![],
            },
            extension_operations: vec![],
            is_critical: false,
        },
        TopicInfo {
            topic: Topic::Governance,
            name: "Governance".to_string(),
            description: "Proposals that represent community polls or other forms of community opinion but don't have any immediate effect in terms of code changes.".to_string(),
            functions: NervousSystemFunctions {
                native_functions: vec![
                    NervousSystemFunction {
                        id: 1,
                        name: "Motion".to_string(),
                        description: Some(
                            "Side-effect-less proposals to set general governance direction.".to_string(),
                        ),
                        function_type: Some(
                            FunctionType::NativeNervousSystemFunction(
                                Empty {},
                            ),
                        ),
                    },
                ],
                custom_functions: vec![],
            },
            extension_operations: vec![],
            is_critical: false,
        },
        TopicInfo {
            topic: Topic::TreasuryAssetManagement,
            name: "Treasury & asset management".to_string(),
            description: "Proposals to move and manage assets that are DAO-owned, including tokens in the treasury, tokens in liquidity pools, or DAO-owned neurons.".to_string(),
            functions: NervousSystemFunctions {
                native_functions: vec![
                    NervousSystemFunction {
                        id: 9,
                        name: "Transfer SNS treasury funds".to_string(),
                        description: Some(
                            "Proposal to transfer funds from an SNS Governance controlled treasury account".to_string(),
                        ),
                        function_type: Some(
                            FunctionType::NativeNervousSystemFunction(
                                Empty {},
                            ),
                        ),
                    },
                    NervousSystemFunction {
                        id: 12,
                        name: "Mint SNS tokens".to_string(),
                        description: Some(
                            "Proposal to mint SNS tokens to a specified recipient.".to_string(),
                        ),
                        function_type: Some(
                            FunctionType::NativeNervousSystemFunction(
                                Empty {},
                            ),
                        ),
                    },
                ],
                custom_functions: vec![],
            },
            extension_operations: vec![
                RegisteredExtensionOperationSpec { canister_id: CanisterId::from_u64(100_001), spec:  deposit_operation_spec.clone() },
                RegisteredExtensionOperationSpec { canister_id: CanisterId::from_u64(100_001), spec:  withdraw_operation_spec.clone() },
                RegisteredExtensionOperationSpec { canister_id: CanisterId::from_u64(100_002), spec:  deposit_operation_spec },
                RegisteredExtensionOperationSpec { canister_id: CanisterId::from_u64(100_002), spec:  withdraw_operation_spec },
            ],
            is_critical: true,
        },
        TopicInfo {
            topic: Topic::CriticalDappOperations,
            name: "Critical Dapp Operations".to_string(),
            description: "Proposals to execute critical operations on dapps, such as adding or removing dapps from the SNS, or executing custom logic on dapps.".to_string(),
            functions: NervousSystemFunctions {
                native_functions: vec![
                    NervousSystemFunction {
                        id: 11,
                        name: "Deregister Dapp Canisters".to_string(),
                        description: Some(
                            "Proposal to deregister a previously-registered dapp canister from the SNS.".to_string(),
                        ),
                        function_type: Some(
                            FunctionType::NativeNervousSystemFunction(
                                Empty {},
                            ),
                        ),
                    },
                    NervousSystemFunction {
                        id: 4,
                        name: "Add nervous system function".to_string(),
                        description: Some(
                            "Proposal to add a new, user-defined, nervous system function: a canister call which can then be executed by proposal.".to_string(),
                        ),
                        function_type: Some(
                            FunctionType::NativeNervousSystemFunction(
                                Empty {},
                            ),
                        ),
                    },
                    NervousSystemFunction {
                        id: 5,
                        name: "Remove nervous system function".to_string(),
                        description: Some(
                            "Proposal to remove a user-defined nervous system function, which will be no longer executable by proposal.".to_string(),
                        ),
                        function_type: Some(
                            FunctionType::NativeNervousSystemFunction(
                                Empty {},
                            ),
                        ),
                    },
                    NervousSystemFunction {
                        id: 16,
                        name: "Set topics for custom proposals".to_string(),
                        description: Some(
                            "Proposal to set the topics for custom SNS proposals.".to_string(),
                        ),
                        function_type: Some(
                            FunctionType::NativeNervousSystemFunction(
                                Empty {},
                            ),
                        ),
                    },
                    NervousSystemFunction {
                        id: 17,
                        name: "Register SNS extension".to_string(),
                        description: Some(
                            "Proposal to register a new SNS extension.".to_string(),
                        ),
                        function_type: Some(
                            FunctionType::NativeNervousSystemFunction(
                                Empty {},
                            ),
                        ),
                    },
                    NervousSystemFunction {
                        id: 19,
                        name: "Upgrade SNS extension".to_string(),
                        description: Some(
                            "Proposal to upgrade the WASM of a registered SNS extension.".to_string(),
                        ),
                        function_type: Some(
                            FunctionType::NativeNervousSystemFunction(
                                Empty {},
                            ),
                        ),
                    },
                ],
                custom_functions: vec![],
            },
            extension_operations: vec![],
            is_critical: true,
        },
    ];
    assert_eq!(topic_infos, expected_topic_infos);
}
