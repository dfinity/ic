use crate::sns::root::get_sns_canisters_summary;
use assert_matches::assert_matches;
use candid::{Nat, Principal};
use canister_test::Wasm;
use futures::{stream, StreamExt};
use ic_base_types::{CanisterId, PrincipalId};
use ic_ledger_core::Tokens;
use ic_nervous_system_common::{
    assert_is_ok, i2d, ledger::compute_distribution_subaccount_bytes, E8, ONE_DAY_SECONDS,
};
use ic_nervous_system_common_test_keys::TEST_NEURON_1_OWNER_PRINCIPAL;
use ic_nervous_system_integration_tests::{
    create_service_nervous_system_builder::CreateServiceNervousSystemBuilder,
    pocket_ic_helpers::{
        add_wasms_to_sns_wasm, install_canister_with_controllers, install_nns_canisters, nns,
        sns::{self, swap::SwapFinalizationStatus},
    },
};
use ic_nervous_system_proto::pb::v1::{Duration as DurationPb, Tokens as TokensPb};
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, ROOT_CANISTER_ID};
use ic_nns_governance::neurons_fund::neurons_fund_neuron::pick_most_important_hotkeys;
use ic_nns_governance_api::pb::v1::{
    create_service_nervous_system::initial_token_distribution::developer_distribution::NeuronDistribution,
    get_neurons_fund_audit_info_response, neurons_fund_snapshot::NeuronsFundNeuronPortion,
    CreateServiceNervousSystem, Neuron,
};
use ic_sns_governance::{
    governance::TREASURY_SUBACCOUNT_NONCE,
    pb::v1::{self as sns_pb, NeuronPermissionType},
};
use ic_sns_init::distributions::MAX_DEVELOPER_DISTRIBUTION_COUNT;
use ic_sns_root::CanisterSummary;
use ic_sns_swap::{
    pb::v1::{
        new_sale_ticket_response, set_dapp_controllers_call_result, set_mode_call_result,
        settle_neurons_fund_participation_result, BuyerState, FinalizeSwapResponse,
        GetDerivedStateResponse, Lifecycle, RefreshBuyerTokensResponse,
        SetDappControllersCallResult, SetDappControllersResponse, SetModeCallResult,
        SettleNeuronsFundParticipationResult, SweepResult,
    },
    swap::principal_to_subaccount,
};
use ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM;
use icp_ledger::{AccountIdentifier, DEFAULT_TRANSFER_FEE};
use icrc_ledger_types::icrc1::{account::Account, transfer::TransferArg};
use maplit::btreemap;
use pocket_ic::PocketIcBuilder;
use rust_decimal::{
    prelude::{FromPrimitive, ToPrimitive},
    Decimal,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Copy, Clone, Debug)]
struct DirectParticipantConfig {
    pub use_ticketing_system: bool,
}

#[derive(Clone, Debug, Default)]
struct NeuronsFundConfig {
    pub hotkeys: Vec<PrincipalId>,
}

impl NeuronsFundConfig {
    fn new_with_20_hotkeys() -> Self {
        let hotkeys = (0..20)
            .map(|i: u64| {
                if i % 2 == 0 {
                    // Model some self-authenticating hotkeys.
                    PrincipalId::new_self_authenticating(&i.to_be_bytes())
                } else {
                    // Model some non-self-authenticating hotkeys.
                    PrincipalId::new_user_test_id(i)
                }
            })
            .collect();
        Self { hotkeys }
    }
}

/// This is a parametric test function for the testing the SNS lifecycle. A test instance should
/// end by calling this function, instantiating it with a set of parameter values that define
/// a particular testing scenario. If this function panics, the test fails. Otherwise, it succeeds.
///
/// The direct participants represented by `direct_participants` participate with
/// `maximum_direct_participation_icp / N` each, where `N==direct_participants.len()`.
///
/// At a high level, the following aspects of an SNS are covered in this function:
/// 1. Basic properties on an SNS instance:
///     1. An SNS instance can be deployed successfully by submitting an NNS proposal.
///     2. A new SNS instance automatically transitions into `Lifecycle::Open`.
///     3. Direct participation works as expected.
///
/// 2. Auto-finalization works as expected.
///
/// 3. The SNS instance obeys the following Hoare triples:
///
///    Abbreviations. (See diagram in rs/sns/swap/proto/ic_sns_swap/pb/v1/swap.proto for more details.)
///    - `FinalizeUnSuccessfully` is an operation that brings the SNS instance from an initial state
///      `Lifecycle::Open` to the terminal state `Lifecycle::Aborted`, i.e., the following assertion
///      holds by-definition: `{ Lifecycle::Open } FinalizeUnSuccessfully { Lifecycle::Aborted }`.
///    - `FinalizeSuccessfully` is an operation that brings the SNS instance from an initial state
///      `Lifecycle::Open` to the terminal state `Lifecycle::Committed`, i.e., the following assertion
///      holds by-definition: `{ Lifecycle::Open } FinalizeUnSuccessfully { Lifecycle::Committed }`.
///    - `Finalize` is the same as
///      ```
///      if ensure_swap_timeout_is_reached {
///          FinalizeUnSuccessfully
///      } else {
///          FinalizeSuccessfully
///      }
///      ```
///    - `Canister.function()` refers to calling `Canister`s public API `function`.
///
///    Notation.
///    - Hoare triples are in pseudo code, e.g., `{ Precondition } Operation { Postcondition }`.
///    - `old(P)` in `{ Postcondition }` refers to condition `P` evaluated in `{ Precondition }`.
///    - `snake_case` is used to refer to values and structures.
///    - `CamelCase` is used to refer to operations.
///    - `Operation.is_enabled()` refers to the possibility of calling `Operation` in this state.
///
///     1. State machine:
///         1. `{ governance::Mode::PreInitializationSwap } FinalizeUnSuccessfully { governance::Mode::PreInitializationSwap }`
///         2. `{ governance::Mode::PreInitializationSwap } FinalizeSuccessfully   { governance::Mode::Normal }`
///
///     2. Availability of SNS operations in different states:
///         1. `{ !ManageNervousSystemParameters.is_enabled() } FinalizeUnSuccessfully { !ManageNervousSystemParameters.is_enabled() }`
///         2. `{ !ManageNervousSystemParameters.is_enabled() } FinalizeSuccessfully   {  ManageNervousSystemParameters.is_enabled() }`
///         3. `{ !DissolveSnsNeuron.is_enabled() } FinalizeUnSuccessfully { !DissolveSnsNeuron.is_enabled() }`
///         4. `{ !DissolveSnsNeuron.is_enabled() } FinalizeSuccessfully   {  DissolveSnsNeuron.is_enabled() }`
///         5. `{ RefreshBuyerTokens.is_enabled() } Finalize { !RefreshBuyerTokens.is_enabled() }`
///
///     3. ICP refunding mechanism and ICP balances:
///         1. `{ true } FinalizeUnSuccessfully; Swap.error_refund_icp() { All directly participated ICP (minus the fees) are refunded. }`
///         2. `{ true } FinalizeSuccessfully;   Swap.error_refund_icp() { Excess directly participated ICP (minus the fees) are refunded. }`
///
/// 4. The Neurons' Fund works as expected:
///     1. `{  neurons_fund_participation && direct_participation_icp_e8s==0 && neurons_fund_participation_icp_e8s==0 } FinalizeUnSuccessfully { direct_participation_icp_e8s==0            && neurons_fund_participation_icp_e8s==0 }`
///     2. `{  neurons_fund_participation && direct_participation_icp_e8s==0 && neurons_fund_participation_icp_e8s==0 } FinalizeSuccessfully   { direct_participation_icp_e8s==650_000 * E8 && neurons_fund_participation_icp_e8s==150_000 * E8 }`
///     3. `{ !neurons_fund_participation && direct_participation_icp_e8s==0 && neurons_fund_participation_icp_e8s==0 } FinalizeUnSuccessfully { direct_participation_icp_e8s==0            && neurons_fund_participation_icp_e8s==0 }`
///     4. `{ !neurons_fund_participation && direct_participation_icp_e8s==0 && neurons_fund_participation_icp_e8s==0 } FinalizeSuccessfully   { direct_participation_icp_e8s==650_000 * E8 && neurons_fund_participation_icp_e8s==0 }`
///
///     Unused portions of Neurons' Fund maturity reserved at SNS creation time are refunded.
///
/// 5. Control over the dapp:
///     1. `{ dapp_canister_status.controllers() == vec![developer, nns_root] } FinalizeUnSuccessfully { dapp_canister_status.controllers() == vec![fallback_controllers] }`
///     2. `{ dapp_canister_status.controllers() == vec![developer, nns_root] } FinalizeSuccessfully   { dapp_canister_status.controllers() == vec![sns_root] }`
///
/// 6. SNS neuron creation:
///     1. `{ true } FinalizeUnSuccessfully { No additional SNS neurons are created. }`
///     2. `{ true } FinalizeSuccessfully   { New SNS neurons are created as expected. }`
///
/// 7. SNS token balances:
///     1. `{ true } FinalizeUnSuccessfully { sns_token_balances == old(sns_token_balances) }`
///     2. `{ true } FinalizeSuccessfully   { SNS token balances are as expected. }`
async fn test_sns_lifecycle(
    ensure_swap_timeout_is_reached: bool,
    create_service_nervous_system: CreateServiceNervousSystem,
    direct_participants: BTreeMap<PrincipalId, DirectParticipantConfig>,
    neurons_fund_config: NeuronsFundConfig,
) {
    // 0. Deconstruct and clone some immutable objects for convenience.
    let initial_token_distribution = create_service_nervous_system
        .initial_token_distribution
        .clone()
        .unwrap();
    let developer_neurons = initial_token_distribution
        .developer_distribution
        .as_ref()
        .unwrap()
        .developer_neurons
        .clone();
    let developer_neuron_controller_principal_ids: BTreeSet<_> = developer_neurons
        .iter()
        .map(|x| x.controller.unwrap())
        .collect();
    let fallback_controllers = create_service_nervous_system
        .fallback_controller_principal_ids
        .clone();
    let swap_parameters = create_service_nervous_system
        .swap_parameters
        .clone()
        .unwrap();
    let max_direct_participation_icp_e8s = swap_parameters
        .maximum_direct_participation_icp
        .unwrap()
        .e8s
        .unwrap();
    let min_participant_icp_e8s = swap_parameters
        .minimum_participant_icp
        .unwrap()
        .e8s
        .unwrap();
    let max_participant_icp_e8s = swap_parameters
        .maximum_participant_icp
        .unwrap()
        .e8s
        .unwrap();
    let expect_swap_overcommitted = {
        let minimum_participants = swap_parameters.minimum_participants.unwrap();
        max_participant_icp_e8s as u128 * minimum_participants as u128
            > max_direct_participation_icp_e8s as u128
    };
    let expect_neurons_fund_participation = swap_parameters
        .neurons_fund_participation
        .unwrap_or_default();
    let (developer_neuron_stake_sns_e8s, treasury_distribution_sns_e8s, swap_distribution_sns_e8s) = {
        let treasury_distribution_sns_e8s = initial_token_distribution
            .treasury_distribution
            .unwrap()
            .total
            .unwrap()
            .e8s
            .unwrap();
        let swap_distribution_sns_e8s = initial_token_distribution
            .swap_distribution
            .unwrap()
            .total
            .unwrap()
            .e8s
            .unwrap();
        (
            developer_neurons
                .iter()
                .fold(0_u64, |acc, x| acc + x.stake.unwrap().e8s.unwrap()),
            treasury_distribution_sns_e8s,
            swap_distribution_sns_e8s,
        )
    };
    let transaction_fee_sns_e8s = create_service_nervous_system
        .ledger_parameters
        .as_ref()
        .unwrap()
        .transaction_fee
        .unwrap()
        .e8s
        .unwrap();

    // 1. Prepare the world
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .build_async()
        .await;

    let participation_amount_per_direct_participant_icp = Tokens::from_e8s(
        (max_direct_participation_icp_e8s / (direct_participants.len() as u64))
            + DEFAULT_TRANSFER_FEE.get_e8s(),
    );
    // Sanity check
    assert!(participation_amount_per_direct_participant_icp.get_e8s() >= min_participant_icp_e8s);

    let direct_participants: BTreeMap<PrincipalId, _> = direct_participants
        .iter()
        .map(|(direct_participant, direct_participant_config)| {
            (
                *direct_participant,
                (
                    AccountIdentifier::new(*direct_participant, None),
                    participation_amount_per_direct_participant_icp,
                    direct_participant_config,
                ),
            )
        })
        .collect();

    // Install the pre-configured NNS canisters, obtaining information about the original neuron(s).
    let original_nns_controller_to_neurons: BTreeMap<PrincipalId, Vec<Neuron>> = {
        let direct_participant_initial_icp_balances = direct_participants
            .values()
            .map(|(account_identifier, balance_icp, _)| (*account_identifier, *balance_icp))
            .collect();

        let with_mainnet_nns_canister_versions = true;
        let neurons_fund_hotkeys = neurons_fund_config.hotkeys;
        let nns_neuron_controller_principal_ids = install_nns_canisters(
            &pocket_ic,
            direct_participant_initial_icp_balances,
            with_mainnet_nns_canister_versions,
            None,
            neurons_fund_hotkeys,
        )
        .await;

        let with_mainnet_sns_wasms = true;
        add_wasms_to_sns_wasm(&pocket_ic, with_mainnet_sns_wasms)
            .await
            .unwrap();

        stream::iter(nns_neuron_controller_principal_ids.into_iter())
            .then(|controller_principal_id| {
                let pocket_ic = &pocket_ic;
                async move {
                    let response =
                        nns::governance::list_neurons(pocket_ic, controller_principal_id).await;
                    (controller_principal_id, response.full_neurons)
                }
            })
            .collect::<BTreeMap<_, _>>()
            .await
    };
    let original_nns_controller_to_maturities_e8s: BTreeMap<PrincipalId, Vec<u64>> =
        original_nns_controller_to_neurons
            .iter()
            .map(|(controller_principal_id, nns_neurons)| {
                (
                    *controller_principal_id,
                    nns_neurons
                        .iter()
                        .map(|nns_neuron| nns_neuron.maturity_e8s_equivalent)
                        .collect(),
                )
            })
            .collect();
    let nns_controller_to_neurons_fund_neurons: BTreeMap<PrincipalId, Vec<Neuron>> =
        original_nns_controller_to_neurons
            .iter()
            .filter_map(|(controller_principal_id, nns_neurons)| {
                let neurons_fund_nns_neurons: Vec<_> = nns_neurons
                    .iter()
                    .filter_map(|nns_neuron| {
                        if nns_neuron.joined_community_fund_timestamp_seconds.is_some() {
                            Some(nns_neuron.clone())
                        } else {
                            None
                        }
                    })
                    .collect();
                if neurons_fund_nns_neurons.is_empty() {
                    None
                } else {
                    Some((*controller_principal_id, neurons_fund_nns_neurons))
                }
            })
            .collect();
    let neurons_fund_nns_neurons: BTreeSet<_> = nns_controller_to_neurons_fund_neurons
        .values()
        .flat_map(|nns_neurons| {
            nns_neurons
                .iter()
                .map(|nns_neuron| (nns_neuron.id, nns_neuron.maturity_e8s_equivalent))
        })
        .collect();

    // Install the test dapp.
    let dapp_canister_ids: Vec<_> = create_service_nervous_system
        .dapp_canisters
        .iter()
        .map(|canister| CanisterId::unchecked_from_principal(canister.id.unwrap()))
        .collect();
    // Controlled by the original developers, and by NNS Root
    let original_controllers = developer_neuron_controller_principal_ids
        .clone()
        .into_iter()
        .chain(std::iter::once(ROOT_CANISTER_ID.get()))
        .collect::<Vec<_>>();
    for dapp_canister_id in dapp_canister_ids.clone() {
        install_canister_with_controllers(
            &pocket_ic,
            "My Test Dapp",
            dapp_canister_id,
            vec![],
            Wasm::from_bytes(UNIVERSAL_CANISTER_WASM.to_vec()),
            original_controllers.clone(),
        )
        .await;
    }

    // Check who has control over the dapp before the swap.
    // This is very likely to succeed, because we just created the canisters a moment ago.
    {
        for dapp_canister_id in dapp_canister_ids.clone() {
            let controllers: BTreeSet<_> = pocket_ic
                .canister_status(
                    Principal::from(dapp_canister_id),
                    Some(Principal::from(ROOT_CANISTER_ID.get())),
                )
                .await
                .unwrap()
                .settings
                .controllers
                .into_iter()
                .map(PrincipalId::from)
                .collect();
            assert_eq!(
                controllers,
                original_controllers.clone().into_iter().collect()
            );
        }
    }

    // 2. Create an SNS instance
    let sns_instance_label = "1";
    let (sns, nns_proposal_id) = nns::governance::propose_to_deploy_sns_and_wait(
        &pocket_ic,
        create_service_nervous_system,
        sns_instance_label,
    )
    .await;

    // Check that total SNS Ledger supply adds up.
    let original_total_supply_sns_e8s =
        sns::ledger::icrc1_total_supply(&pocket_ic, sns.ledger.canister_id)
            .await
            .0
            .to_u64()
            .unwrap();
    assert_eq!(
        original_total_supply_sns_e8s,
        developer_neuron_stake_sns_e8s + treasury_distribution_sns_e8s + swap_distribution_sns_e8s,
        "original_total_supply_sns_e8s ({}) should = developer_neuron_stake_sns_e8s ({}) + \
        treasury_distribution_sns_e8s ({}) + swap_distribution_sns_e8s ({})",
        original_total_supply_sns_e8s,
        developer_neuron_stake_sns_e8s,
        treasury_distribution_sns_e8s,
        swap_distribution_sns_e8s,
    );

    let nervous_system_parameters = sns
        .governance
        .get_nervous_system_parameters(&pocket_ic)
        .await
        .unwrap();
    let swap_init = sns::swap::get_init(&pocket_ic, sns.swap.canister_id)
        .await
        .init
        .unwrap();
    let sns_neurons_per_backet = swap_init
        .neuron_basket_construction_parameters
        .unwrap()
        .count;

    // This set is used to determine SNS neurons created as a result of the swap (by excluding those
    // which are in this collection).
    let original_sns_neuron_ids: BTreeSet<_> =
        sns::governance::list_neurons(&pocket_ic, sns.governance.canister_id)
            .await
            .neurons
            .into_iter()
            .map(|sns_neuron| sns_neuron.id.unwrap())
            .collect();

    // Assert that the mode of SNS Governance is `PreInitializationSwap`.
    assert_eq!(
        sns.governance
            .get_mode(&pocket_ic)
            .await
            .unwrap()
            .mode
            .unwrap(),
        sns_pb::governance::Mode::PreInitializationSwap as i32
    );

    // Get an ID of an SNS neuron that can submit proposals. We rely on the fact that this neuron
    // either holds the majority of the voting power or the follow graph is set up s.t. when this
    // neuron submits a proposal, that proposal gets through without the need for any voting.
    let (sns_neuron_id, sns_neuron_principal_id) =
        sns::governance::find_neuron_with_majority_voting_power(
            &pocket_ic,
            sns.governance.canister_id,
        )
        .await
        .expect("cannot find SNS neuron with dissolve delay over 6 months.");

    // Currently, we are not allowed to make `ManageNervousSystemParameter` proposals.
    {
        let err = sns::governance::propose_and_wait(
            &pocket_ic,
            sns.governance.canister_id,
            sns_neuron_principal_id,
            sns_neuron_id.clone(),
            sns_pb::Proposal {
                title: "Try to smuggle in a ManageNervousSystemParameters proposal while \
                        in PreInitializationSwap mode."
                    .to_string(),
                summary: "".to_string(),
                url: "".to_string(),
                action: Some(sns_pb::proposal::Action::ManageNervousSystemParameters(
                    sns_pb::NervousSystemParameters {
                        reject_cost_e8s: Some(20_000), // More strongly discourage spam
                        ..Default::default()
                    },
                )),
            },
        )
        .await
        .unwrap_err();
        let sns_pb::GovernanceError {
            error_type,
            error_message,
        } = &err;
        use sns_pb::governance_error::ErrorType;
        assert_eq!(
            ErrorType::try_from(*error_type).unwrap(),
            ErrorType::PreconditionFailed,
            "{:#?}",
            err
        );
        assert!(
            error_message.contains("PreInitializationSwap"),
            "{:#?}",
            err
        );
    }

    // Check that the dapp canisters are now controlled by SNS Root and NNS Root.
    {
        let expected_new_controllers =
            BTreeSet::from([sns.root.canister_id, ROOT_CANISTER_ID.get()]);
        for dapp_canister_id in dapp_canister_ids.clone() {
            let sender = expected_new_controllers // the sender must be a controller
                .first()
                .cloned()
                .map(Principal::from);
            let controllers: BTreeSet<_> = pocket_ic
                .canister_status(Principal::from(dapp_canister_id), sender)
                .await
                .unwrap()
                .settings
                .controllers
                .into_iter()
                .map(PrincipalId::from)
                .collect();

            assert_eq!(controllers, expected_new_controllers);
        }
    }

    // Currently, the neuron cannot start dissolving (an error is expected).
    {
        let start_dissolving_response = sns::governance::start_dissolving_neuron(
            &pocket_ic,
            sns.governance.canister_id,
            sns_neuron_principal_id,
            sns_neuron_id.clone(),
        )
        .await;
        match start_dissolving_response.command {
            Some(sns_pb::manage_neuron_response::Command::Error(error)) => {
                let sns_pb::GovernanceError {
                    error_type,
                    error_message,
                } = &error;
                use sns_pb::governance_error::ErrorType;
                assert_eq!(
                    ErrorType::try_from(*error_type).unwrap(),
                    ErrorType::PreconditionFailed,
                    "{:#?}",
                    error
                );
                assert!(
                    error_message.contains("PreInitializationSwap"),
                    "{:#?}",
                    error
                );
            }
            response => {
                panic!("{:#?}", response);
            }
        };
    }

    sns::swap::await_swap_lifecycle(&pocket_ic, sns.swap.canister_id, Lifecycle::Open)
        .await
        .unwrap();

    // Check that the swap cannot be finalized yet.
    {
        let response = sns::swap::finalize_swap(&pocket_ic, sns.swap.canister_id).await;
        let error_message = assert_matches!(response, FinalizeSwapResponse {
            error_message: Some(error_message),
            sweep_icp_result: None,
            sweep_sns_result: None,
            claim_neuron_result: None,
            set_mode_call_result: None,
            set_dapp_controllers_call_result: None,
            settle_community_fund_participation_result: None,
            create_sns_neuron_recipes_result: None,
            settle_neurons_fund_participation_result: None
        } => error_message);
        assert_eq!(
            error_message,
            "The Swap can only be finalized in the COMMITTED or ABORTED states. \
            Current state is Open",
        );
    }

    // Check that the derived state correctly reflects the pre-state of the swap.
    {
        let derived_state = sns::swap::get_derived_state(&pocket_ic, sns.swap.canister_id).await;
        assert_eq!(
            derived_state,
            GetDerivedStateResponse {
                buyer_total_icp_e8s: Some(0),
                direct_participant_count: Some(0),
                cf_participant_count: Some(0),
                cf_neuron_count: Some(0),
                sns_tokens_per_icp: Some(0.0),
                direct_participation_icp_e8s: Some(0),
                neurons_fund_participation_icp_e8s: Some(0),
            }
        );
    }

    // 3. Transfer ICP to our direct participants' SNSes subaccounts.
    for (
        direct_participant,
        (
            direct_participant_icp_account,
            direct_participant_icp_account_initial_balance_icp,
            direct_participant_config,
        ),
    ) in direct_participants.clone()
    {
        let direct_participant_swap_subaccount = Some(principal_to_subaccount(&direct_participant));
        let direct_participant_swap_account = Account {
            owner: sns.swap.canister_id.0,
            subaccount: direct_participant_swap_subaccount,
        };
        // Participate with as much as we have minus the transfer fee
        assert_eq!(
            nns::ledger::account_balance(&pocket_ic, &direct_participant_icp_account).await,
            direct_participant_icp_account_initial_balance_icp,
        );
        let attempted_participation_amount_e8s = direct_participant_icp_account_initial_balance_icp
            .get_e8s()
            - DEFAULT_TRANSFER_FEE.get_e8s();

        // The ticketing system is optional in the current implementation, so the participants are
        // free to choose if they use it or not.
        if direct_participant_config.use_ticketing_system {
            let expected_accepted_participation_amount_e8s =
                if attempted_participation_amount_e8s < min_participant_icp_e8s {
                    0
                } else {
                    attempted_participation_amount_e8s.min(max_participant_icp_e8s)
                };
            // Creating a ticket for this participation should succeed even before the ICP transfer.
            let response = sns::swap::new_sale_ticket(
                &pocket_ic,
                sns.swap.canister_id,
                direct_participant,
                expected_accepted_participation_amount_e8s,
            )
            .await
            .expect("Swap.new_sale_ticket response should be Ok.");
            assert_matches!(
            response.result,
            Some(new_sale_ticket_response::Result::Ok(new_sale_ticket_response::Ok {
                ticket
            })) => {
                ticket.expect("field ticket must be specified in new_sale_ticket_response::Ok")
            });
        }
        // Make the actual ICP transfer
        nns::ledger::icrc1_transfer(
            &pocket_ic,
            direct_participant,
            TransferArg {
                from_subaccount: None,
                to: direct_participant_swap_account,
                fee: None,
                created_at_time: None,
                memo: None,
                amount: Nat::from(attempted_participation_amount_e8s),
            },
        )
        .await
        .unwrap();
        // Ensure there are no tokens left on this user's account (this slightly simplifies the checks).
        assert_eq!(
            nns::ledger::account_balance(&pocket_ic, &direct_participant_icp_account).await,
            Tokens::from_e8s(0)
        );
    }

    // 4. Force the swap to reach either Aborted, or Committed. Collect the de facto participants.
    let direct_sns_neuron_recipients = if ensure_swap_timeout_is_reached {
        // Await the end of the swap period.
        pocket_ic
            .advance_time(Duration::from_secs(30 * ONE_DAY_SECONDS))
            .await; // 30 days
        sns::swap::await_swap_lifecycle(&pocket_ic, sns.swap.canister_id, Lifecycle::Aborted)
            .await
            .unwrap();
        vec![]
    } else {
        let mut direct_sns_neuron_recipients = vec![];
        for (direct_participant, (_, direct_participant_icp_account_initial_balance_icp, _)) in
            direct_participants.clone()
        {
            let attempted_participation_amount_e8s =
                direct_participant_icp_account_initial_balance_icp.get_e8s()
                    - DEFAULT_TRANSFER_FEE.get_e8s();
            let expected_accepted_participation_amount_e8s =
                if attempted_participation_amount_e8s < min_participant_icp_e8s {
                    0
                } else {
                    attempted_participation_amount_e8s.min(max_participant_icp_e8s)
                };

            // Precondition: The buyer does not have a buyer state.
            {
                let response = sns::swap::get_buyer_state(
                    &pocket_ic,
                    sns.swap.canister_id,
                    direct_participant,
                )
                .await
                .expect("Swap.get_buyer_state response should be Ok.");
                assert_eq!(response.buyer_state, None);
            }

            // Execute the operation under test.
            let response = sns::swap::refresh_buyer_tokens(
                &pocket_ic,
                sns.swap.canister_id,
                direct_participant,
                None,
            )
            .await;

            // Postcondition A: accepted amount matches our expectations.
            assert_eq!(
                response,
                Ok(RefreshBuyerTokensResponse {
                    icp_ledger_account_balance_e8s: attempted_participation_amount_e8s,
                    icp_accepted_participation_e8s: expected_accepted_participation_amount_e8s,
                })
            );

            // Postcondition B: The buyer has an expected buyer state.
            {
                let response = sns::swap::get_buyer_state(
                    &pocket_ic,
                    sns.swap.canister_id,
                    direct_participant,
                )
                .await
                .expect("Swap.get_buyer_state response should be Ok.");
                let (icp, has_created_neuron_recipes) = assert_matches!(
                    response.buyer_state,
                    Some(BuyerState {
                        icp,
                        has_created_neuron_recipes,
                    }) => (
                        icp.expect("buyer_state.icp must be specified."),
                        has_created_neuron_recipes
                            .expect("buyer_state.has_created_neuron_recipes must be specified.")
                    )
                );
                assert!(
                    !has_created_neuron_recipes,
                    "Neuron recipes are expected to be created only after the swap is adopted"
                );
                assert_eq!(icp.amount_e8s, expected_accepted_participation_amount_e8s);
            }

            // Postcondition C: the ticket has been deleted.
            {
                let response = sns::swap::get_open_ticket(
                    &pocket_ic,
                    sns.swap.canister_id,
                    direct_participant,
                )
                .await
                .expect("Swap.get_open_ticket response should be Ok.");
                assert_eq!(response.ticket(), Ok(None));
            }

            direct_sns_neuron_recipients.push(direct_participant);
        }

        // In this runbook, all participants participate s.t. `max_participant_icp_e8s` is reached.
        let expected_lifecycle = if expect_swap_overcommitted {
            Lifecycle::Aborted
        } else {
            Lifecycle::Committed
        };
        sns::swap::await_swap_lifecycle(&pocket_ic, sns.swap.canister_id, expected_lifecycle)
            .await
            .unwrap();
        direct_sns_neuron_recipients
    };

    // 5. Double check that auto-finalization worked as expected, i.e.,
    // `Swap.get_auto_finalization_status` returns a structure with the top-level fields being set,
    // no errors, and matching the expected pattern (different for `Aborted` and `Committed`).
    // It may take some time for the process to complete, so we should await (implemented via a busy
    // loop) rather than try just once.
    let swap_finalization_status = {
        let expected_swap_finalization_status =
            if ensure_swap_timeout_is_reached || expect_swap_overcommitted {
                SwapFinalizationStatus::Aborted
            } else {
                SwapFinalizationStatus::Committed
            };
        if let Err(err) = sns::swap::await_swap_finalization_status(
            &pocket_ic,
            sns.swap.canister_id,
            expected_swap_finalization_status,
        )
        .await
        {
            println!("{}", err);
            panic!(
                "Awaiting Swap finalization status {:?} failed.",
                expected_swap_finalization_status
            );
        }
        expected_swap_finalization_status
    };

    // Participation is no longer possible due to Swap being in a terminal state.
    for direct_participant in direct_participants.keys() {
        let err = assert_matches!(
            sns::swap::refresh_buyer_tokens(&pocket_ic, sns.swap.canister_id, *direct_participant, None).await,
            Err(err) => err
        );
        assert!(err.contains("Participation is possible only when the Swap is in the OPEN state."));
    }

    // 6. Check that refunding works as expected.
    for (
        direct_participant,
        (direct_participant_icp_account, direct_participant_icp_account_initial_balance_icp, _),
    ) in direct_participants.clone()
    {
        let attempted_participation_amount_e8s = direct_participant_icp_account_initial_balance_icp
            .get_e8s()
            - DEFAULT_TRANSFER_FEE.get_e8s();
        let accepted_participation_amount_e8s =
            if attempted_participation_amount_e8s < min_participant_icp_e8s {
                0
            } else {
                attempted_participation_amount_e8s.min(max_participant_icp_e8s)
            };

        let error_refund_icp_result =
            sns::swap::error_refund_icp(&pocket_ic, sns.swap.canister_id, direct_participant)
                .await
                .result
                .expect("Error while calling Swap.error_refund_icp");

        use ic_sns_swap::pb::v1::error_refund_icp_response;

        // Notes to help understand this spec:
        // 1. Currently, Swap.error_refund_icp returns an error from ICP Ledger if the amount
        //    to reimburse is zero (or less than the transfer fee).
        // 2. Currently, when `ensure_swap_timeout_is_reached` is true, none of the direct
        //    participants call Swap.refresh_buyer_tokens before the timeout, so their ICP is still
        //    to be refunded by calling Swap.error_refund_icp (case A).
        // 3. Conversely, when `ensure_swap_timeout_is_reached` is false and
        //    `expect_swap_overcommitted` is true, Swap.sweep_icp takes care of all the refunds,
        //    so there's no more refunds that can happen in Swap.error_refund_icp, which thus
        //    returns an error (case B).
        let expected_refund_e8s = if ensure_swap_timeout_is_reached {
            // Case A: Expecting to get refunded with Transferred - (ICP Ledger transfer fee).
            assert_matches!(
                error_refund_icp_result,
                error_refund_icp_response::Result::Ok(_)
            );

            attempted_participation_amount_e8s - DEFAULT_TRANSFER_FEE.get_e8s()
        } else if accepted_participation_amount_e8s == 0
            || accepted_participation_amount_e8s == attempted_participation_amount_e8s
        {
            // Case B: (No tokens accepted) || (All tokens accepted)  ==>  nothing to refund.

            let error_text = assert_matches!(
                error_refund_icp_result,
                error_refund_icp_response::Result::Err(err) => {
                    err.description.expect("ICP Ledger errors should have a description.")
                }
            );
            assert!(error_text.contains(
                "the debit account doesn't have enough funds to complete the transaction"
            ));

            if expect_swap_overcommitted {
                attempted_participation_amount_e8s - DEFAULT_TRANSFER_FEE.get_e8s()
            } else {
                0
            }
        } else {
            // Case C: Expecting to get refunded with Transferred - Accepted - (ICP Ledger transfer fee).
            assert_matches!(
                error_refund_icp_result,
                error_refund_icp_response::Result::Ok(_)
            );

            attempted_participation_amount_e8s
                - accepted_participation_amount_e8s
                - DEFAULT_TRANSFER_FEE.get_e8s()
        };

        // This assertion works because we have consumed all of the tokens from this user's
        // account up to the last e8.
        assert_eq!(
            nns::ledger::account_balance(&pocket_ic, &direct_participant_icp_account).await,
            Tokens::from_e8s(expected_refund_e8s)
        );
    }

    // Inspect the finalize swap response after swap finalization. Note that `Swap.finalize_swap` is
    // idempotent only from the second call, e.g., success counters in sweep results are counted
    // towards skipped in the responses of the second (and all consecutive) calls.
    {
        let expected_neuron_count = if swap_finalization_status == SwapFinalizationStatus::Aborted {
            0
        } else {
            let swap_participating_nns_neuron_count = if expect_neurons_fund_participation {
                direct_participants.len() as u128 + neurons_fund_nns_neurons.len() as u128
            } else {
                direct_participants.len() as u128
            };
            (swap_participating_nns_neuron_count * sns_neurons_per_backet as u128) as u32
        };

        let expected_sweep_icp_result = Some(SweepResult {
            success: 0,
            failure: 0,
            skipped: if ensure_swap_timeout_is_reached {
                0
            } else {
                direct_participants.len() as u32
            },
            invalid: 0,
            global_failures: 0,
        });

        let expected_create_sns_neuron_recipes_result =
            if swap_finalization_status == SwapFinalizationStatus::Aborted {
                None
            } else {
                Some(SweepResult {
                    success: 0,
                    failure: 0,
                    skipped: expected_neuron_count,
                    invalid: 0,
                    global_failures: 0,
                })
            };

        let expected_sweep_sns_result =
            if swap_finalization_status == SwapFinalizationStatus::Aborted {
                None
            } else {
                Some(SweepResult {
                    success: 0,
                    failure: 0,
                    skipped: expected_neuron_count,
                    invalid: 0,
                    global_failures: 0,
                })
            };

        let expected_claim_neuron_result =
            if swap_finalization_status == SwapFinalizationStatus::Aborted {
                None
            } else {
                Some(SweepResult {
                    success: 0,
                    failure: 0,
                    skipped: expected_neuron_count,
                    invalid: 0,
                    global_failures: 0,
                })
            };

        let expected_set_mode_call_result =
            if swap_finalization_status == SwapFinalizationStatus::Aborted {
                None
            } else {
                Some(SetModeCallResult {
                    possibility: Some(set_mode_call_result::Possibility::Ok(
                        set_mode_call_result::SetModeResult {},
                    )),
                })
            };

        let expected_settle_neurons_fund_participation_result = {
            let (neurons_fund_participation_icp_e8s, neurons_fund_neurons_count) =
                if swap_finalization_status == SwapFinalizationStatus::Committed
                    && expect_neurons_fund_participation
                {
                    (
                        Some(150_000 * E8),
                        Some(neurons_fund_nns_neurons.len() as u64),
                    )
                } else {
                    (Some(0), Some(0))
                };
            use settle_neurons_fund_participation_result::{Ok, Possibility};
            Some(SettleNeuronsFundParticipationResult {
                possibility: Some(Possibility::Ok(Ok {
                    neurons_fund_participation_icp_e8s,
                    neurons_fund_neurons_count,
                })),
            })
        };

        let expected_set_dapp_controllers_call_result = Some(SetDappControllersCallResult {
            possibility: Some(set_dapp_controllers_call_result::Possibility::Ok(
                SetDappControllersResponse {
                    failed_updates: vec![],
                },
            )),
        });

        assert_eq!(
            sns::swap::finalize_swap(&pocket_ic, sns.swap.canister_id).await,
            FinalizeSwapResponse {
                sweep_icp_result: expected_sweep_icp_result,
                create_sns_neuron_recipes_result: expected_create_sns_neuron_recipes_result,
                sweep_sns_result: expected_sweep_sns_result,
                claim_neuron_result: expected_claim_neuron_result,
                set_mode_call_result: expected_set_mode_call_result,
                settle_neurons_fund_participation_result:
                    expected_settle_neurons_fund_participation_result,

                settle_community_fund_participation_result: None, // deprecated field
                set_dapp_controllers_call_result: expected_set_dapp_controllers_call_result,
                error_message: None,
            }
        );
    }

    // Inspect the final derived state
    {
        // Declare the expectations for all relevant fields.
        let dpc = || direct_participants.len() as u64;
        // For cf_participant_count.
        let nfpc = || nns_controller_to_neurons_fund_neurons.keys().len() as u64;
        // For cf_neuron_count.
        let nfnc = || nns_controller_to_neurons_fund_neurons.values().len() as u64;
        let (
            direct_participant_count,
            direct_participation_icp_e8s,
            cf_participant_count,
            cf_neuron_count,
            neurons_fund_participation_icp_e8s,
            buyer_total_icp_e8s,
        ) = match (
            ensure_swap_timeout_is_reached,
            expect_swap_overcommitted,
            expect_neurons_fund_participation,
        ) {
            (true, true, _) => {
                // Only !(ensure_swap_timeout_is_reached ^ expect_swap_overcommitted) scenarios
                // are currently supported.
                unimplemented!();
            }
            (true, false, _) => (Some(0), Some(0), Some(0), Some(0), Some(0), Some(0)),
            (false, true, true) => {
                // The Neurons' Fund is orthogonal to the overpayment scenario.
                unimplemented!();
            }
            (false, true, false) => (
                Some(dpc()),
                Some(650_000 * E8),
                Some(0),
                Some(0),
                Some(0),
                Some(650_000 * E8),
            ),
            (false, false, true) => (
                Some(dpc()),
                Some(650_000 * E8),
                Some(nfpc()),
                Some(nfnc()),
                Some(150_000 * E8),
                Some(800_000 * E8),
            ),
            (false, false, false) => (
                Some(dpc()),
                Some(650_000 * E8),
                Some(0),
                Some(0),
                Some(0),
                Some(650_000 * E8),
            ),
        };
        let sns_tokens_per_icp = Some(
            buyer_total_icp_e8s
                .map(|buyer_total_icp_e8s| {
                    let sns_token_e8s = swap_init.sns_token_e8s.unwrap();
                    i2d(sns_token_e8s)
                        .checked_div(i2d(buyer_total_icp_e8s))
                        .and_then(|d| d.to_f32())
                        .unwrap_or(0.0)
                })
                .unwrap_or(0.0) as f64,
        );

        let observed_derived_state =
            sns::swap::get_derived_state(&pocket_ic, sns.swap.canister_id).await;
        assert_eq!(
            observed_derived_state,
            GetDerivedStateResponse {
                direct_participant_count,
                direct_participation_icp_e8s,
                cf_participant_count,
                cf_neuron_count,
                neurons_fund_participation_icp_e8s,
                buyer_total_icp_e8s,
                sns_tokens_per_icp,
            }
        );
    };

    // Assert that the mode of SNS Governance is correct
    if swap_finalization_status == SwapFinalizationStatus::Aborted {
        assert_eq!(
            sns.governance
                .get_mode(&pocket_ic)
                .await
                .unwrap()
                .mode
                .unwrap(),
            sns_pb::governance::Mode::PreInitializationSwap as i32,
        );
    } else {
        assert_eq!(
            sns.governance
                .get_mode(&pocket_ic)
                .await
                .unwrap()
                .mode
                .unwrap(),
            sns_pb::governance::Mode::Normal as i32
        );
    }

    // Validate `get_sns_canisters_summary`.
    {
        let response = sns::root::get_sns_canisters_summary(&pocket_ic, sns.root.canister_id).await;
        let observed_dapp_canister_ids = response
            .dapps
            .into_iter()
            .map(|canister_summary| {
                CanisterId::unchecked_from_principal(canister_summary.canister_id.unwrap())
            })
            .collect::<Vec<_>>();
        if swap_finalization_status == SwapFinalizationStatus::Aborted {
            assert_eq!(observed_dapp_canister_ids, vec![]);
        } else {
            assert_eq!(observed_dapp_canister_ids, dapp_canister_ids);
        }
    }

    // Ensure that the proposal submission is possible if and only if the SNS governance has
    // launched, and that `PreInitializationSwap` mode limitations are still in place if and only
    // if the swap aborted.
    {
        let proposal_result = sns::governance::propose_and_wait(
            &pocket_ic,
            sns.governance.canister_id,
            sns_neuron_principal_id,
            sns_neuron_id.clone(),
            sns_pb::Proposal {
                title: "Try to smuggle in a ManageNervousSystemParameters proposal while \
                        in PreInitializationSwap mode."
                    .to_string(),
                summary: "".to_string(),
                url: "".to_string(),
                action: Some(sns_pb::proposal::Action::ManageNervousSystemParameters(
                    sns_pb::NervousSystemParameters {
                        reject_cost_e8s: Some(20_000), // More strongly discourage spam
                        ..Default::default()
                    },
                )),
            },
        )
        .await;
        if swap_finalization_status == SwapFinalizationStatus::Aborted {
            let err = proposal_result.unwrap_err();
            let sns_pb::GovernanceError {
                error_type,
                error_message,
            } = &err;
            use sns_pb::governance_error::ErrorType;
            assert_eq!(
                ErrorType::try_from(*error_type).unwrap(),
                ErrorType::PreconditionFailed,
                "{:#?}",
                err
            );
            assert!(
                error_message.contains("PreInitializationSwap"),
                "{:#?}",
                err
            );
        } else {
            assert_is_ok!(proposal_result);
        }
    }

    // Ensure that the neuron can start dissolving now if and only if the SNS governance has
    // launched.
    {
        let start_dissolving_response = sns::governance::start_dissolving_neuron(
            &pocket_ic,
            sns.governance.canister_id,
            sns_neuron_principal_id,
            sns_neuron_id,
        )
        .await;
        if swap_finalization_status == SwapFinalizationStatus::Aborted {
            match start_dissolving_response.command {
                Some(sns_pb::manage_neuron_response::Command::Error(error)) => {
                    let sns_pb::GovernanceError {
                        error_type,
                        error_message,
                    } = &error;
                    use sns_pb::governance_error::ErrorType;
                    assert_eq!(
                        ErrorType::try_from(*error_type).unwrap(),
                        ErrorType::PreconditionFailed,
                        "{:#?}",
                        error
                    );
                    assert!(
                        error_message.contains("PreInitializationSwap"),
                        "{:#?}",
                        error
                    );
                }
                response => {
                    panic!("{:#?}", response);
                }
            };
        } else {
            match start_dissolving_response.command {
                Some(sns_pb::manage_neuron_response::Command::Configure(_)) => (),
                _ => panic!("{:#?}", start_dissolving_response),
            };
        }
    }

    // Inspect SNS token balances.
    // A. Inspect the SNS Governance (treasury) balance.
    {
        let sns_governance_canister_balance_sns_e8s = {
            let treasury_subaccount = compute_distribution_subaccount_bytes(
                sns.governance.canister_id,
                TREASURY_SUBACCOUNT_NONCE,
            );
            let sns_treasury_account = Account {
                owner: sns.governance.canister_id.0,
                subaccount: Some(treasury_subaccount),
            };
            sns::ledger::icrc1_balance_of(&pocket_ic, sns.ledger.canister_id, sns_treasury_account)
                .await
                .0
                .to_u64()
                .unwrap()
        };
        assert_eq!(
            sns_governance_canister_balance_sns_e8s,
            treasury_distribution_sns_e8s
        );
    }

    // B. Inspect Swap's balance.
    {
        let swap_canister_balance_sns_e8s = sns::ledger::icrc1_balance_of(
            &pocket_ic,
            sns.ledger.canister_id,
            Account {
                owner: sns.swap.canister_id.0,
                subaccount: None,
            },
        )
        .await
        .0
        .to_u64()
        .unwrap();
        if swap_finalization_status == SwapFinalizationStatus::Aborted {
            // If the swap fails, the SNS swap does not distribute any tokens.
            assert_eq!(swap_canister_balance_sns_e8s, swap_distribution_sns_e8s);
        } else {
            // In a happy scenario, the SNS swap distributes all the tokens.
            assert_eq!(swap_canister_balance_sns_e8s, 0);
        }
    }

    // C. The total supply has decreased by `N * transaction_fee_sns_e8s`, where `N` is
    //    the number of transactions from the creation of this SNS.
    {
        let total_supply_sns_e8s =
            sns::ledger::icrc1_total_supply(&pocket_ic, sns.ledger.canister_id)
                .await
                .0
                .to_u64()
                .unwrap();
        assert_eq!(
            (original_total_supply_sns_e8s - total_supply_sns_e8s) % transaction_fee_sns_e8s,
            0,
            "original_total_supply_sns_e8s ({}) - total_supply_sns_e8s ({}) should be a multiple \
            of transaction_fee_sns_e8s ({})",
            original_total_supply_sns_e8s,
            total_supply_sns_e8s,
            transaction_fee_sns_e8s,
        );
    }

    // Keys are principals of controllers of the Neurons' Fund-participating NNS neuron.
    let neurons_fund_neuron_controllers_to_neuron_portions: BTreeMap<
        PrincipalId,
        NeuronsFundNeuronPortion,
    > = if expect_neurons_fund_participation {
        let Some(get_neurons_fund_audit_info_response::Result::Ok(
            get_neurons_fund_audit_info_response::Ok {
                neurons_fund_audit_info: Some(neurons_fund_audit_info),
            },
        )) = nns::governance::get_neurons_fund_audit_info(&pocket_ic, nns_proposal_id)
            .await
            .result
        else {
            panic!(
                "Proposal {:?} did not result in a successfully deployed SNS",
                nns_proposal_id
            );
        };
        neurons_fund_audit_info
            .final_neurons_fund_participation
            .unwrap()
            .neurons_fund_reserves
            .unwrap()
            .neurons_fund_neuron_portions
            .into_iter()
            .map(|neurons_fund_neuron_portion| {
                (
                    neurons_fund_neuron_portion.controller.unwrap(),
                    neurons_fund_neuron_portion,
                )
            })
            .collect()
    } else {
        btreemap! {}
    };

    // Inspect SNS neurons.
    {
        // Note that in the check of neuron permissions, we ignore the `NeuronId`, which means that
        // it does not effectively check that each principal has permissions on the expected number of neurons,
        // or even that it has permissions on the correct neuron, or that there is at least one neuron
        // for which it has a set of permissions that this principal was expected to have
        let expected_neuron_permissions =
            {
                let neuron_claimer_permissions = nervous_system_parameters
                    .neuron_claimer_permissions
                    .clone()
                    .unwrap()
                    .permissions
                    .into_iter()
                    .map(|permission| NeuronPermissionType::try_from(permission).unwrap())
                    .collect::<BTreeSet<_>>();

                let neurons_fund_participant_neuron_permissions =
                    neurons_fund_neuron_controllers_to_neuron_portions
                        .values()
                        .flat_map(|neurons_fund_neuron_portion| {
                            // The controller of Neurons' Fund neurons is NNS Governance.
                            let controller = PrincipalId::from(GOVERNANCE_CANISTER_ID);
                            vec![
                                // Add governance as the controller
                                (controller, neuron_claimer_permissions.clone()),
                                // Add the controller of the NNS neuron as a hotkey that also has ManageVotingPermissions
                                (
                                    neurons_fund_neuron_portion.controller.unwrap(),
                                    BTreeSet::from([
                                        NeuronPermissionType::Vote,
                                        NeuronPermissionType::SubmitProposal,
                                        NeuronPermissionType::ManageVotingPermission,
                                    ]),
                                ),
                            ]
                            .into_iter()
                            .chain(
                                neurons_fund_neuron_portion.hotkeys.clone().into_iter().map(
                                    |hotkey| {
                                        (
                                            hotkey,
                                            BTreeSet::from([
                                                NeuronPermissionType::Vote,
                                                NeuronPermissionType::SubmitProposal,
                                            ]),
                                        )
                                    },
                                ),
                            )
                        });

                let direct_participant_neuron_permissions = direct_participants
                    .keys()
                    .map(|principal_id| (*principal_id, neuron_claimer_permissions.clone()));

                let developer_neuron_permissions = developer_neuron_controller_principal_ids
                    .iter()
                    .map(|principal_id| (*principal_id, neuron_claimer_permissions.clone()));

                if swap_finalization_status == SwapFinalizationStatus::Committed {
                    neurons_fund_participant_neuron_permissions
                        .chain(direct_participant_neuron_permissions)
                        .chain(developer_neuron_permissions)
                        .collect::<BTreeSet<_>>()
                } else {
                    // Developer neurons are always expected to be present
                    developer_neuron_permissions.collect()
                }
            };
        let sns_neurons = sns::governance::list_neurons(&pocket_ic, sns.governance.canister_id)
            .await
            .neurons;
        // Validate that the set of SNS neuron hotkeys and controllers is expected.
        {
            let observed_neuron_permissions = sns_neurons
                .iter()
                .flat_map(|neuron| {
                    neuron.permissions.iter().map(|neuron_permission| {
                        let permissions = neuron_permission
                            .permission_type
                            .iter()
                            .map(|permission_type| {
                                NeuronPermissionType::try_from(*permission_type).unwrap()
                            })
                            .collect::<BTreeSet<_>>();
                        (neuron_permission.principal.unwrap(), permissions)
                    })
                })
                .collect::<BTreeSet<_>>();

            assert_eq!(observed_neuron_permissions, expected_neuron_permissions);
        }
        // Collect all SNS neurons except the initial ones that were not created as a result of
        // the SNS swap.
        let swap_sns_neurons: Vec<_> = sns_neurons
            .into_iter()
            .filter(|sns_neuron| !original_sns_neuron_ids.contains(sns_neuron.id.as_ref().unwrap()))
            .collect();
        // Check SNS neuron balances for direct swap participants.
        let total_participation_icp_e8s = {
            // We assume that all direct participations were fully accepted.
            let total_direct_participation_icp_e8s: u64 = direct_participants
                .values()
                .map(|(_, amount_icp, _)| amount_icp.get_e8s())
                .sum();
            let total_neurons_fund_participation_icp_e8s: u64 =
                neurons_fund_neuron_controllers_to_neuron_portions
                    .values()
                    .map(|neuron_portion| neuron_portion.amount_icp_e8s.unwrap())
                    .sum();
            total_direct_participation_icp_e8s + total_neurons_fund_participation_icp_e8s
        };
        let swap_participants = direct_sns_neuron_recipients
            .iter()
            .chain(neurons_fund_neuron_controllers_to_neuron_portions.keys());
        for principal_id in swap_participants {
            // Contains `(source_nns_neuron_id, neuron_basket)` for this controller. For direct
            // participants, `source_nns_neuron_id` is `None`. Some Neurons' Fund neurons,
            // `source_nns_neuron_id` is `Some`.
            let swap_neuron_baskets_of_this_principal: BTreeMap<Option<u64>, Vec<_>> =
                swap_sns_neurons
                    .iter()
                    .filter(|sns_neuron| {
                        sns_neuron.permissions.iter().any(|neuron_permission| {
                            neuron_permission.principal.unwrap() == *principal_id
                        })
                    })
                    .fold(BTreeMap::new(), |mut baskets, sns_neuron| {
                        let sns_neuron = sns_neuron.clone();
                        if let Some(basket) = baskets.get_mut(&sns_neuron.source_nns_neuron_id) {
                            basket.push(sns_neuron);
                        } else {
                            baskets.insert(sns_neuron.source_nns_neuron_id, vec![sns_neuron]);
                        }
                        baskets
                    });

            // Validate that the number of swap SNS neurons obtained by this participant falls into
            // some number of equally-sized neuron baskets.
            {
                let swap_neurons_of_this_principal: Vec<_> = swap_neuron_baskets_of_this_principal
                    .values()
                    .flatten()
                    .collect();
                assert_eq!(
                    swap_neurons_of_this_principal.len() as u64,
                    sns_neurons_per_backet * (swap_neuron_baskets_of_this_principal.len() as u64),
                    "sns_neurons_per_backet = {}, swap_neuron_baskets_of_this_principal.len() = {}",
                    sns_neurons_per_backet,
                    swap_neuron_baskets_of_this_principal.len(),
                );
            }

            // Validate each SNS neuron basket in isolation and sum up the swapped SNS token
            // amounts for direct and Neurons' Fund participants, resp.
            let mut actually_swapped_direct_sns_tokens_e8s = 0;
            let mut actually_swapped_neurons_fund_sns_tokens_e8s = 0;
            for (_, swap_neuron_basket) in swap_neuron_baskets_of_this_principal {
                let longest_dissolve_delay_sns_neuron_id = {
                    let now_seconds = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let longest_dissolve_delay_sns_neuron = swap_neuron_basket
                        .iter()
                        .max_by_key(|neuron| neuron.dissolve_delay_seconds(now_seconds))
                        .expect(
                            "Expected to have at least one swap SNS neuron for each participant.",
                        );
                    longest_dissolve_delay_sns_neuron.id.clone().unwrap()
                };

                // The purpose of this loop is to check individual neurons' fields.
                for sns_neuron in swap_neuron_basket {
                    let is_neuron_from_direct_participation =
                        sns_neuron.source_nns_neuron_id.is_none();

                    // Validate `auto_stake_maturity`:
                    {
                        let expected_auto_stake_maturity = if is_neuron_from_direct_participation {
                            None
                        } else {
                            Some(true)
                        };
                        assert_eq!(
                            sns_neuron.auto_stake_maturity, expected_auto_stake_maturity,
                            "{:#?}",
                            sns_neuron
                        );
                    }
                    // Validate `permissions`:
                    {
                        // TODO: derive `Ord` for `sns_pb::NeuronPermission` and use `BTreeSet`s.
                        fn sorted_permissions(
                            permissions: &[sns_pb::NeuronPermission],
                        ) -> Vec<sns_pb::NeuronPermission> {
                            let mut permissions = permissions.to_vec();
                            permissions
                                .sort_by(|x, y| y.principal.unwrap().cmp(&x.principal.unwrap()));
                            permissions
                        }
                        let claimer_permissions = nervous_system_parameters
                            .neuron_claimer_permissions
                            .as_ref()
                            .expect("Expected neuron_claimer_permissions to be set");
                        let expected_permissions = if is_neuron_from_direct_participation {
                            vec![sns_pb::NeuronPermission {
                                principal: Some(*principal_id),
                                permission_type: claimer_permissions.permissions.clone(),
                            }]
                        } else {
                            let prototype_nns_neuron_of_this_sns_neuron =
                                nns_controller_to_neurons_fund_neurons
                                    .get(principal_id)
                                    .unwrap_or_else(|| {
                                        panic!(
                                        "There should be an NNS neuron controlled by the Neurons' \
                                        Fund user {}", principal_id,
                                    )
                                    })
                                    .iter()
                                    .filter(|nns_neurons| {
                                        sns_neuron.source_nns_neuron_id.unwrap()
                                            == nns_neurons.id.unwrap().id
                                    })
                                    .collect::<Vec<_>>()
                                    .pop()
                                    .expect(
                                        "There should be exactly 1 NNS neuron for an SNS neuron",
                                    );

                            let relevant_hotkeys = pick_most_important_hotkeys(
                                &prototype_nns_neuron_of_this_sns_neuron.hot_keys,
                            );

                            let mut expected_permissions = relevant_hotkeys
                                .into_iter()
                                .map(|hotkey_principal_id| sns_pb::NeuronPermission {
                                    principal: Some(hotkey_principal_id),
                                    permission_type: vec![
                                        sns_pb::NeuronPermissionType::SubmitProposal as i32,
                                        sns_pb::NeuronPermissionType::Vote as i32,
                                    ],
                                })
                                .collect::<Vec<_>>();

                            expected_permissions.extend([
                                sns_pb::NeuronPermission {
                                    principal: Some(GOVERNANCE_CANISTER_ID.get()),
                                    permission_type: claimer_permissions.permissions.clone(),
                                },
                                sns_pb::NeuronPermission {
                                    principal: Some(*principal_id),
                                    permission_type: vec![
                                        sns_pb::NeuronPermissionType::ManageVotingPermission as i32,
                                        sns_pb::NeuronPermissionType::SubmitProposal as i32,
                                        sns_pb::NeuronPermissionType::Vote as i32,
                                    ],
                                },
                            ]);

                            sorted_permissions(&expected_permissions)
                        };
                        assert_eq!(
                            sorted_permissions(&sns_neuron.permissions),
                            expected_permissions,
                            "{:#?}",
                            sns_neuron
                        );
                    }
                    // Validate the SNS neuron baskets' follow graph.
                    {
                        if sns_neuron.id.as_ref().unwrap() == &longest_dissolve_delay_sns_neuron_id
                        {
                            for followees in sns_neuron.followees.values() {
                                assert_eq!(followees.followees, vec![], "{:#?}", sns_neuron);
                            }
                        } else {
                            for followees in sns_neuron.followees.values() {
                                assert_eq!(
                                    followees.followees,
                                    vec![longest_dissolve_delay_sns_neuron_id.clone()],
                                    "{:#?}",
                                    sns_neuron,
                                );
                            }
                        }
                    }
                    // Miscellaneous checks:
                    assert_eq!(sns_neuron.maturity_e8s_equivalent, 0, "{:#?}", sns_neuron);
                    assert_eq!(sns_neuron.neuron_fees_e8s, 0, "{:#?}", sns_neuron);

                    // Finally, check that the SNS Ledger balances add up.
                    {
                        let subaccount = sns_neuron.id.as_ref().unwrap().subaccount().unwrap();
                        let observed_balance_e8s = sns::ledger::icrc1_balance_of(
                            &pocket_ic,
                            sns.ledger.canister_id,
                            Account {
                                owner: sns.governance.canister_id.0,
                                subaccount: Some(subaccount),
                            },
                        )
                        .await
                        .0
                        .to_u64()
                        .unwrap();

                        // Check that the cached balance of the sns_neuron is equal to the sns_neuron's
                        // account in the ledger.
                        assert_eq!(sns_neuron.cached_neuron_stake_e8s, observed_balance_e8s);

                        // Add to the actual total including the default transfer fee which was deducted
                        // during swap committal.
                        if is_neuron_from_direct_participation {
                            actually_swapped_direct_sns_tokens_e8s +=
                                observed_balance_e8s + transaction_fee_sns_e8s;
                        } else {
                            actually_swapped_neurons_fund_sns_tokens_e8s +=
                                observed_balance_e8s + transaction_fee_sns_e8s;
                        }
                    }
                }
            }

            if !direct_participants.contains_key(principal_id)
                || swap_finalization_status == SwapFinalizationStatus::Aborted
            {
                assert_eq!(actually_swapped_direct_sns_tokens_e8s, 0);
            } else {
                let expected_sns_token_e8s = (participation_amount_per_direct_participant_icp
                    .get_e8s() as u128)
                    * (swap_distribution_sns_e8s as u128)
                    / (total_participation_icp_e8s as u128);
                assert_eq!(
                    actually_swapped_direct_sns_tokens_e8s,
                    expected_sns_token_e8s as u64
                );
            }

            if swap_finalization_status == SwapFinalizationStatus::Aborted
                || neurons_fund_neuron_controllers_to_neuron_portions.is_empty()
                || !nns_controller_to_neurons_fund_neurons.contains_key(principal_id)
            {
                // ((The swap has aborted)
                //  || (The Neuron's Fund has not participated in this swap)
                //  || (The are no Neurons' Fund neurons))
                //     ==>  There should not be any Neurons' Fund-related SNS neurons.
                assert_eq!(actually_swapped_neurons_fund_sns_tokens_e8s, 0);
            } else {
                // This is the amount of ICP participated by all Neurons' Fund neurons that this
                // controller has.
                let participation_amount_for_this_nf_neuron_icp_e8s =
                    neurons_fund_neuron_controllers_to_neuron_portions
                        .get(principal_id)
                        .unwrap()
                        .amount_icp_e8s
                        .unwrap();
                // Use fixed point to keep the precision as much as possible. In particular, we
                // round to the nearest integer, rather than always rounding down. This is typically
                // enough to keep up with the precision of the computation done by the actual
                // Swap canister. However, the ideal solution would be to replicate the exact
                // calculation done by Swap. This would result in an e8-precise spec, rather than
                // an approximate spec that we have here right now.
                let expected_sns_token_e8s =
                    Decimal::from_u64(participation_amount_for_this_nf_neuron_icp_e8s).unwrap()
                        * Decimal::from_u64(swap_distribution_sns_e8s).unwrap()
                        / Decimal::from_u64(total_participation_icp_e8s).unwrap();
                let expected_sns_token_e8s =
                    Decimal::to_u64(&Decimal::round(&expected_sns_token_e8s)).unwrap();
                assert_eq!(
                    actually_swapped_neurons_fund_sns_tokens_e8s,
                    expected_sns_token_e8s
                );
            }
        }
    }

    // Inspect SNS neuron recipes. TODO: Eventually, this check could be replaced with a single call
    // to a function in the `rs/sns/audit` crate.
    {
        let sns_neuron_recipes =
            sns::swap::list_sns_neuron_recipes(&pocket_ic, sns.swap.canister_id)
                .await
                .sns_neuron_recipes;
        use ic_sns_swap::pb::v1::sns_neuron_recipe::Investor;
        {
            let direct_participant_sns_neuron_recipes: Vec<_> = sns_neuron_recipes
                .iter()
                .filter_map(|recipe| {
                    if let Some(Investor::Direct(ref investment)) = recipe.investor {
                        let buyer_principal = investment.buyer_principal.clone();
                        let amount_sns_e8s = recipe.sns.unwrap().amount_e8s;
                        Some((buyer_principal, amount_sns_e8s))
                    } else {
                        None
                    }
                })
                .collect();

            if swap_finalization_status == SwapFinalizationStatus::Aborted {
                assert_eq!(direct_participant_sns_neuron_recipes, vec![]);
            } else {
                assert_eq!(
                    direct_participant_sns_neuron_recipes.len() as u128,
                    (sns_neurons_per_backet as u128) * (direct_participants.len() as u128)
                );
            }
        }
        {
            let neurons_fund_sns_neuron_recipes: Vec<_> = sns_neuron_recipes
                .iter()
                .filter_map(|recipe| {
                    if let Some(Investor::CommunityFund(ref investment)) = recipe.investor {
                        let controller = investment.try_get_controller().unwrap();
                        let amount_sns_e8s = recipe.sns.unwrap().amount_e8s;
                        Some((controller, amount_sns_e8s))
                    } else {
                        None
                    }
                })
                .collect();

            if swap_finalization_status == SwapFinalizationStatus::Aborted {
                assert_eq!(neurons_fund_sns_neuron_recipes, vec![]);
            } else {
                assert_eq!(
                    neurons_fund_sns_neuron_recipes.len() as u128,
                    (sns_neurons_per_backet as u128)
                        * (neurons_fund_neuron_controllers_to_neuron_portions.len() as u128)
                );
            }
        }
    }

    // Check that the maturity of the Neurons' Fund neurons adds up.
    if expect_neurons_fund_participation {
        let Some(get_neurons_fund_audit_info_response::Result::Ok(
            get_neurons_fund_audit_info_response::Ok {
                neurons_fund_audit_info: Some(neurons_fund_audit_info),
            },
        )) = nns::governance::get_neurons_fund_audit_info(&pocket_ic, nns_proposal_id)
            .await
            .result
        else {
            panic!(
                "Proposal {:?} did not result in a successfully deployed SNS",
                nns_proposal_id
            );
        };
        // Maps neuron IDs to maturity equivalent ICP e8s.
        let mut final_neurons_fund_participation: BTreeMap<PrincipalId, Vec<u64>> =
            neurons_fund_audit_info
                .final_neurons_fund_participation
                .unwrap()
                .neurons_fund_reserves
                .unwrap()
                .neurons_fund_neuron_portions
                .iter()
                .fold(
                    BTreeMap::new(),
                    |mut neuron_portions_per_controller, neuron_portion| {
                        let controller_principal_id = neuron_portion.controller.unwrap();
                        let amount_icp_e8s = neuron_portion.amount_icp_e8s.unwrap();
                        neuron_portions_per_controller
                            .entry(controller_principal_id)
                            .and_modify(|neuron_portions| neuron_portions.push(amount_icp_e8s))
                            .or_insert(vec![amount_icp_e8s]);
                        neuron_portions_per_controller
                    },
                );
        for (controller_principal_id, mut original_nns_neuron_maturities_e8s) in
            original_nns_controller_to_maturities_e8s
        {
            let mut nns_neuron_maturities_e8s: Vec<u64> = {
                let response =
                    nns::governance::list_neurons(&pocket_ic, controller_principal_id).await;
                response
                    .full_neurons
                    .iter()
                    .map(|neuron| neuron.maturity_e8s_equivalent)
                    .collect()
            };
            assert_eq!(
                original_nns_neuron_maturities_e8s.len(),
                nns_neuron_maturities_e8s.len(),
                "Controller {} is expected to have {} neurons, but it actually has {}. \
                original_nns_neuron_maturities_e8s = {:#?}, nns_neuron_maturities_e8s = {:#?}",
                controller_principal_id,
                original_nns_neuron_maturities_e8s.len(),
                nns_neuron_maturities_e8s.len(),
                original_nns_neuron_maturities_e8s,
                nns_neuron_maturities_e8s,
            );

            let mut participated_neurons = final_neurons_fund_participation
                .remove(&controller_principal_id)
                .unwrap_or_default();

            // Reverse the order to process the largest neurons first.
            {
                original_nns_neuron_maturities_e8s.sort_by(|a, b| b.cmp(a));
                nns_neuron_maturities_e8s.sort_by(|a, b| b.cmp(a));
                // This collection will be popped, so the order does not need to be reversed.
                participated_neurons.sort();
            }

            for (original_maturity_icp_e8s, current_maturity_icp_e8s) in
                original_nns_neuron_maturities_e8s
                    .into_iter()
                    .zip(nns_neuron_maturities_e8s.iter())
            {
                // If the neuron is not in `final_neurons_fund_participation`, it didn't participate.
                let participated_amount_icp_e8s = participated_neurons.pop().unwrap_or(0);
                assert_eq!(
                    current_maturity_icp_e8s + participated_amount_icp_e8s,
                    original_maturity_icp_e8s,
                    "current_maturity_icp_e8s ({}) + participated_amount_icp_e8s ({}) should equal original_maturity_icp_e8s ({})",
                    current_maturity_icp_e8s,
                    participated_amount_icp_e8s,
                    original_maturity_icp_e8s,
                );
            }
        }
        assert!(
            final_neurons_fund_participation.is_empty(),
            "Neurons' Fund participants must be a subset of initial NNS neurons"
        );
    } else {
        // Neuron's Fund maturity should be completely unchanged.
        for (controller_principal_id, original_nns_neuron_maturities_e8s) in
            original_nns_controller_to_maturities_e8s
        {
            let nns_neuron_maturities_e8s: Vec<u64> = {
                let response =
                    nns::governance::list_neurons(&pocket_ic, controller_principal_id).await;
                response
                    .full_neurons
                    .iter()
                    .map(|neuron| neuron.maturity_e8s_equivalent)
                    .collect()
            };
            assert_eq!(
                nns_neuron_maturities_e8s,
                original_nns_neuron_maturities_e8s,
                "Unexpected mismatch in maturity ICP equivalent for controller {}. \
                nns_neuron_maturities_e8s={:?} e8s, original_nns_neuron_maturities_e8s({:?}) e8s.",
                controller_principal_id,
                nns_neuron_maturities_e8s,
                original_nns_neuron_maturities_e8s,
            );
        }
    }

    // Check who has control over the dapp after the swap.
    {
        let expected_new_controllers =
            if swap_finalization_status == SwapFinalizationStatus::Aborted {
                // The SNS swap has failed  ==>  control should be returned to the fallback controllers.
                fallback_controllers.into_iter().collect::<BTreeSet<_>>()
            } else {
                // The SNS swap has succeeded  ==>  root should have sole control.
                BTreeSet::from([sns.root.canister_id])
            };
        for dapp_canister_id in dapp_canister_ids {
            let sender = expected_new_controllers // the sender must be a controller
                .first()
                .cloned()
                .map(Principal::from);
            let controllers: BTreeSet<_> = pocket_ic
                .canister_status(Principal::from(dapp_canister_id), sender)
                .await
                .unwrap()
                .settings
                .controllers
                .into_iter()
                .map(PrincipalId::from)
                .collect();

            assert_eq!(controllers, expected_new_controllers);
        }
    }

    // Ensure that the archive canister is spawned and can be found through SNS Root.
    sns::ensure_archive_canister_is_spawned_or_panic(
        &pocket_ic,
        sns.governance.canister_id,
        sns.ledger.canister_id,
    )
    .await;
    // SNS Root polls archives every 24 hours, so we need to advance time to trigger the polling.
    pocket_ic
        .advance_time(Duration::from_secs(24 * 60 * 60))
        .await;
    pocket_ic.tick().await;
    let response = sns::root::get_sns_canisters_summary(&pocket_ic, sns.root.canister_id).await;
    assert!(
        !response.archives_canister_summaries().is_empty(),
        "No archives found from get_sns_canisters_summary response: {:#?}",
        response
    );

    // Check that the SNS framework canister settings are as expected
    {
        // get SNS canisters summary
        let sns_canisters_summary =
            get_sns_canisters_summary(&pocket_ic, sns.root.canister_id).await;
        fn get_wasm_memory_limit(summary: Option<CanisterSummary>) -> u64 {
            u64::try_from(
                summary
                    .unwrap()
                    .status
                    .unwrap()
                    .settings
                    .wasm_memory_limit
                    .unwrap()
                    .0,
            )
            .unwrap()
        }
        // Governance should have a higher memory limit
        assert_eq!(
            get_wasm_memory_limit(sns_canisters_summary.governance),
            4 * 1024 * 1024 * 1024,
        );
        // Other canisters should have a lower memory limit
        assert_eq!(
            get_wasm_memory_limit(sns_canisters_summary.root),
            3 * 1024 * 1024 * 1024,
        );
        assert_eq!(
            get_wasm_memory_limit(sns_canisters_summary.swap),
            3 * 1024 * 1024 * 1024,
        );
        assert_eq!(
            get_wasm_memory_limit(sns_canisters_summary.ledger),
            3 * 1024 * 1024 * 1024,
        );
        assert_eq!(
            get_wasm_memory_limit(sns_canisters_summary.index),
            3 * 1024 * 1024 * 1024,
        );
    }
}

#[tokio::test]
async fn test_sns_lifecycle_happy_scenario_with_neurons_fund_participation() {
    test_sns_lifecycle(
        false,
        CreateServiceNervousSystemBuilder::default()
            .neurons_fund_participation(true)
            .build(),
        btreemap! { PrincipalId::new_user_test_id(1) => DirectParticipantConfig { use_ticketing_system: true } },
        NeuronsFundConfig::new_with_20_hotkeys(),
    ).await;
}

#[tokio::test]
async fn test_sns_lifecycle_happy_scenario_direct_participation_with_and_without_ticketing_with_neurons_fund_participation(
) {
    test_sns_lifecycle(
        false,
        CreateServiceNervousSystemBuilder::default()
            .neurons_fund_participation(true)
            .build(),
        btreemap! {
            PrincipalId::new_user_test_id(1) => DirectParticipantConfig { use_ticketing_system: true },
            PrincipalId::new_user_test_id(2) => DirectParticipantConfig { use_ticketing_system: false },
        },
        NeuronsFundConfig::new_with_20_hotkeys(),
    ).await;
}

#[tokio::test]
async fn test_sns_lifecycle_happy_scenario_without_neurons_fund_participation() {
    test_sns_lifecycle(
        false,
        CreateServiceNervousSystemBuilder::default()
            .neurons_fund_participation(false)
            .build(),
        btreemap! { PrincipalId::new_user_test_id(1) => DirectParticipantConfig { use_ticketing_system: true } },
        // No Neurons' Fund ==> no need to configure NNS neurons.
        NeuronsFundConfig::default(),
    ).await;
}

#[tokio::test]
async fn test_sns_lifecycle_overpayment_scenario() {
    test_sns_lifecycle(
        false,
        CreateServiceNervousSystemBuilder::default()
            .neurons_fund_participation(false)
            .with_minimum_participants(2)
            .with_dapp_canisters(vec![CanisterId::from_u64(100)])
            .build(),
        btreemap! { PrincipalId::new_user_test_id(1) => DirectParticipantConfig { use_ticketing_system: true } },
        // Overpayment is a scenario driven only by direct participants, so we don't need NF.
        NeuronsFundConfig::default(),
    ).await;
}

#[tokio::test]
async fn test_sns_lifecycle_happy_scenario_with_dapp_canisters() {
    test_sns_lifecycle(
        false,
        CreateServiceNervousSystemBuilder::default()
            .neurons_fund_participation(false)
            // If we add dapp canisters, test_sns_lifecycle will automatically create
            // dapp canisters and set up their controllership appropriately, then
            // verify that they are controlled only by SNS root after the swap is
            // finalized.
            .with_dapp_canisters(vec![CanisterId::from_u64(100)])
            .build(),
        btreemap! { PrincipalId::new_user_test_id(1) => DirectParticipantConfig { use_ticketing_system: true } },
        // No Neurons' Fund ==> no need to configure NNS neurons.
        NeuronsFundConfig::default(),
    ).await;
}

#[tokio::test]
async fn test_sns_lifecycle_happy_scenario_with_neurons_fund_participation_same_principal() {
    test_sns_lifecycle(
        false,
        CreateServiceNervousSystemBuilder::default()
            .neurons_fund_participation(true)
            .build(),
        // Direct participant has the same principal as the one controlling the Neurons' Fund neuron.
        btreemap! { *TEST_NEURON_1_OWNER_PRINCIPAL => DirectParticipantConfig { use_ticketing_system: true } },
        NeuronsFundConfig::new_with_20_hotkeys(),
    ).await;
}

#[tokio::test]
async fn test_sns_lifecycle_swap_timeout_with_neurons_fund_participation() {
    test_sns_lifecycle(
        true,
        CreateServiceNervousSystemBuilder::default()
            .neurons_fund_participation(true)
            .build(),
        btreemap! { PrincipalId::new_user_test_id(1) => DirectParticipantConfig { use_ticketing_system: true } },
        // There won't be any SNS neurons created, so no need to configure the Neurons' Fund.
        NeuronsFundConfig::default(),
    ).await;
}

#[tokio::test]
async fn test_sns_lifecycle_swap_timeout_without_neurons_fund_participation() {
    test_sns_lifecycle(
        true,
        CreateServiceNervousSystemBuilder::default()
            .neurons_fund_participation(false)
            .build(),
        btreemap! { PrincipalId::new_user_test_id(1) => DirectParticipantConfig { use_ticketing_system: true } },
        // No Neurons' Fund ==> no need to configure NNS neurons.
        NeuronsFundConfig::default(),
    ).await;
}

#[tokio::test]
async fn test_sns_lifecycle_happy_scenario_with_lots_of_dev_neurons() {
    let num_neurons = MAX_DEVELOPER_DISTRIBUTION_COUNT as u64;
    let mut developer_neurons: Vec<_> = (0..num_neurons - 1)
        .map(|i| NeuronDistribution {
            controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
            memo: Some(i),
            // Set the dissolve delay to ~10 days, which is somewhat arbitrary. It needs to be less
            // than or equal to the maximum dissolve delay (as defined
            // in `CreateServiceNervousSystemBuilder::default()`), but high enough that it still has
            // some voting power.
            dissolve_delay: Some(DurationPb::from_secs(927391)),
            stake: Some(TokensPb::from_e8s(E8)),
            vesting_period: Some(DurationPb::from_secs(0)),
        })
        .collect();
    // One developer neuron needs to have the voting power majority for the underlying tests to
    // be able to get SNS proposals through without arranging any following or voting. The dissolve
    // delay of this neuron needs to be sufficient for voting (we set it to 7 months).
    developer_neurons.push(NeuronDistribution {
        controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
        memo: Some(num_neurons - 1),
        dissolve_delay: Some(DurationPb::from_secs(ONE_DAY_SECONDS * 30 * 7)),
        // All other neurons together have `num_neurons - 1` e8s, so this one has the majority.
        stake: Some(TokensPb::from_e8s(num_neurons * E8)),
        vesting_period: Some(DurationPb::from_secs(0)),
    });

    let create_service_nervous_system = CreateServiceNervousSystemBuilder::default()
        .neurons_fund_participation(true)
        .initial_token_distribution_developer_neurons(developer_neurons)
        .initial_token_distribution_total(TokensPb::from_e8s((num_neurons * 2 - 1) * E8))
        .build();

    test_sns_lifecycle(
        false,
        create_service_nervous_system,
        btreemap! { PrincipalId::new_user_test_id(1) => DirectParticipantConfig { use_ticketing_system: true } },
        NeuronsFundConfig::new_with_20_hotkeys(),
    ).await;
}

#[tokio::test]
async fn test_sns_lifecycle_swap_timeout_with_lots_of_dev_neurons() {
    let num_neurons = MAX_DEVELOPER_DISTRIBUTION_COUNT as u64;
    let mut developer_neurons: Vec<_> = (0..num_neurons - 1)
        .map(|i| NeuronDistribution {
            controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
            memo: Some(i),
            // Set the dissolve delay to ~10 days, which is somewhat arbitrary. It needs to be less
            // than or equal to the maximum dissolve delay (as defined
            // in `CreateServiceNervousSystemBuilder::default()`), but high enough that it still has
            // some voting power.
            dissolve_delay: Some(DurationPb::from_secs(927391)),
            stake: Some(TokensPb::from_e8s(E8)),
            vesting_period: Some(DurationPb::from_secs(0)),
        })
        .collect();
    // One developer neuron needs to have the voting power majority for the underlying tests to
    // be able to get SNS proposals through without arranging any following or voting. The dissolve
    // delay of this neuron needs to be sufficient for voting (we set it to 7 months).
    developer_neurons.push(NeuronDistribution {
        controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
        memo: Some(num_neurons - 1),
        dissolve_delay: Some(DurationPb::from_secs(ONE_DAY_SECONDS * 30 * 7)),
        // All other neurons together have `num_neurons - 1` e8s, so this one has the majority.
        stake: Some(TokensPb::from_e8s(num_neurons * E8)),
        vesting_period: Some(DurationPb::from_secs(0)),
    });

    let mut create_service_nervous_system = CreateServiceNervousSystemBuilder::default()
        .neurons_fund_participation(false)
        .initial_token_distribution_developer_neurons(developer_neurons)
        .initial_token_distribution_total(TokensPb::from_e8s((num_neurons * 2 - 1) * E8))
        .build();

    let logo = "data:image/png;base64,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"
        .to_string();

    let logo = ic_nervous_system_proto::pb::v1::Image {
        base64_encoding: Some(logo),
    };

    create_service_nervous_system.logo.replace(logo.clone());
    create_service_nervous_system
        .name
        .replace("ICTO".to_string());
    create_service_nervous_system.description.replace("ICTO is an innovative new platform allowing any project on Internet Computer to automate token vesting, payroll, locking, and fundraising.".to_string());
    create_service_nervous_system.ledger_parameters = Some(
        ic_nns_governance_api::pb::v1::create_service_nervous_system::LedgerParameters {
            token_logo: Some(logo),
            ..create_service_nervous_system
                .ledger_parameters
                .clone()
                .unwrap()
        },
    );

    test_sns_lifecycle(
        true,
        create_service_nervous_system,
        btreemap! { PrincipalId::new_user_test_id(1) => DirectParticipantConfig { use_ticketing_system: true } },
        NeuronsFundConfig::new_with_20_hotkeys(),
    ).await;

    panic!("The end!");
}
