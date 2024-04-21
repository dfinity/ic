//! TODO(NNS1-2994): Delete.

use candid::Principal;
use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_common::{E8, SECONDS_PER_DAY};
use ic_nervous_system_integration_tests::{
    pocket_ic_helpers,
    pocket_ic_helpers::{
        add_wasm_via_nns_proposal, install_sns_directly_with_snsw_versions, sns, SnsTestCanisterIds,
    },
};
use ic_nns_governance::governance::ONE_MONTH_SECONDS;
use ic_nns_test_utils::sns_wasm::{build_governance_sns_wasm, ensure_sns_wasm_gzipped};
use ic_sns_governance::pb::v1::{
    get_proposal_response, neuron::DissolveState, proposal::Action, Motion,
    NervousSystemParameters, Neuron, NeuronPermission, NeuronPermissionType, Proposal,
    ProposalData, ProposalId, ProposalRewardStatus, VotingRewardsParameters,
};
use ic_sns_test_utils::itest_helpers::SnsTestsInitPayloadBuilder;
use std::{
    str::FromStr,
    string::ToString,
    time::{Duration, SystemTime},
};

/// What happens in this test:
///
///     0. Create an SNS using (latest) published WASMs. The most salient
///        setting is positive initial voting reward rate. As usual, the SNS has
///        a whale neuron that will make and instantly pass proposals.
///
///     1. Make three motion proposals (in the SNS, not NNS). Shortly after
///        making (and instantly passing) them, they should be in the
///        AcceptVotes reward status. Give plenty of time for rewards after each
///        one before making another proposal.
///
///         a. Shortly after making the second motion proposal, make (and pass)
///            a proposal that sets rewards to 0. Even after plenty of time has
///            passed, the motion proposal stays (stuck) in the ReadyToSettle
///            reward status.
///
///         b. Except for the second proposal, the motion proposals should end
///            up in the Settled reward status.
///
///     2. Propose to upgrade (SNS) governance to a build from the current
///        working copy.
///
///     3. Observe that the upgrade succeeded. This verifies that we fixed the
///        bug where there was a panic in post_upgrade.
///
///     4. Inspect the three motion proposals. They should all be in the Settled
///        reward status. In particular, the second motion proposal has gotten
///        unstuck, the thing that we originally intended to implement. These
///        assertions are less interesting, because this behavior is already
///        covered in a unit test, but since we are here, we might as well
///        (re-)verify this behavior.
#[test]
fn test_settle_proposals_if_reward_rates_are_zero() {
    // Step 1: Prepare the world

    let pocket_ic = pocket_ic_helpers::pocket_ic_for_sns_tests_with_mainnet_versions();

    // Step 1.1: Create an SNS.

    let whale_principal_id = PrincipalId::new_user_test_id(942_950_245);
    let whale_neuron_id = sns::governance::new_sns_neuron_id(
        whale_principal_id,
        0, // memo
    );
    let whale_neuron = Neuron {
        id: Some(whale_neuron_id.clone()),
        // Has all permissions.
        permissions: vec![NeuronPermission {
            principal: Some(whale_principal_id),
            permission_type: NeuronPermissionType::all(),
        }],
        cached_neuron_stake_e8s: 1_000_000 * E8,
        dissolve_state: Some(DissolveState::DissolveDelaySeconds(ONE_MONTH_SECONDS * 7)),
        voting_power_percentage_multiplier: 100,
        ..Default::default()
    };
    let mut sns_init_payload = SnsTestsInitPayloadBuilder::new()
        .with_initial_neurons(vec![whale_neuron])
        .build();

    // Make initial reward rate positive.
    let initial_reward_rate_basis_points = sns_init_payload
        .governance
        .parameters
        .as_mut()
        .unwrap()
        .voting_rewards_parameters
        .as_mut()
        .unwrap()
        .initial_reward_rate_basis_points
        .as_mut()
        .unwrap();
    *initial_reward_rate_basis_points = 1000; // 10%

    let SnsTestCanisterIds {
        root_canister_id,
        governance_canister_id,
        ledger_canister_id: _,
        swap_canister_id: _,
        index_canister_id: _,
    } = install_sns_directly_with_snsw_versions(
        &pocket_ic,
        sns_init_payload,
        Some(SnsTestCanisterIds {
            root_canister_id: CanisterId::unchecked_from_principal(
                PrincipalId::from_str("zxeu2-7aaaa-aaaaq-aaafa-cai").unwrap(),
            ),
            governance_canister_id: CanisterId::unchecked_from_principal(
                PrincipalId::from_str("zqfso-syaaa-aaaaq-aaafq-cai").unwrap(),
            ),
            ledger_canister_id: CanisterId::unchecked_from_principal(
                PrincipalId::from_str("zfcdd-tqaaa-aaaaq-aaaga-cai").unwrap(),
            ),
            swap_canister_id: CanisterId::unchecked_from_principal(
                PrincipalId::from_str("zcdfx-6iaaa-aaaaq-aaagq-cai").unwrap(),
            ),
            index_canister_id: CanisterId::unchecked_from_principal(
                PrincipalId::from_str("zlaol-iaaaa-aaaaq-aaaha-cai").unwrap(),
            ),
        }),
    );

    // Step 1.2: Make various proposals described in the docstring.

    let get_reward_status = |proposal: &ProposalData| {
        let now_timestamp_seconds = pocket_ic
            .get_time()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        proposal.reward_status(now_timestamp_seconds)
    };

    let mut i = 0;
    let mut make_motion_proposal = || -> ProposalId {
        i += 1;

        let title = format!("Motion proposal number {}", i);
        let motion_text = title.clone();
        let proposal = Proposal {
            title,
            summary: "".to_string(),
            url: "".to_string(),
            action: Some(Action::Motion(Motion { motion_text })),
        };

        let target_canister_id = PrincipalId::from(governance_canister_id);

        let proposal = sns::governance::propose_and_wait(
            &pocket_ic,
            target_canister_id,
            whale_principal_id, // sender
            whale_neuron_id.clone(),
            proposal,
        )
        .unwrap();

        assert_eq!(
            get_reward_status(&proposal),
            ProposalRewardStatus::AcceptVotes,
            "{:#?}",
            proposal
        );

        proposal.id.unwrap()
    };

    let get_current_proposal_data = |proposal_id| {
        let target_canister_id = PrincipalId::from(governance_canister_id);

        let result = sns::governance::get_proposal(
            &pocket_ic,
            target_canister_id,
            proposal_id,
            whale_principal_id, // sender
        )
        .unwrap()
        .result
        .unwrap();

        match result {
            get_proposal_response::Result::Proposal(ok) => ok,
            _ => panic!("{:?}", result),
        }
    };

    let motion_proposal_1_id = make_motion_proposal();
    // Assert that the first motion proposal reaches Settled.
    {
        // Give first motion proposal time to settle.
        pocket_ic.advance_time(Duration::from_secs(7 * SECONDS_PER_DAY));
        for _ in 0..10 {
            pocket_ic.tick();
        }

        let proposal_1 = get_current_proposal_data(motion_proposal_1_id);
        assert_eq!(
            get_reward_status(&proposal_1),
            ProposalRewardStatus::Settled,
        );
    }

    let motion_proposal_2_id = make_motion_proposal();

    // Let 10 minutes pass
    for _ in 0..10 {
        pocket_ic.tick();
        pocket_ic.advance_time(Duration::from_secs(60));
    }

    // Set reward rate to 0.
    sns::governance::propose_and_wait(
        &pocket_ic,
        PrincipalId::from(governance_canister_id),
        whale_principal_id, // sender
        whale_neuron_id.clone(),
        Proposal {
            title: "Set rewards to 0".to_string(),
            summary: "".to_string(),
            url: "".to_string(),
            action: Some(Action::ManageNervousSystemParameters(
                NervousSystemParameters {
                    voting_rewards_parameters: Some(VotingRewardsParameters::with_default_values()),
                    ..Default::default()
                },
            )),
        },
    )
    .unwrap();

    // Assert that the second motion proposal is stuck in ReadyToSettle.
    {
        // Give second motion proposal time to settle.
        pocket_ic.advance_time(Duration::from_secs(7 * SECONDS_PER_DAY));
        for _ in 0..10 {
            pocket_ic.tick();
        }

        let proposal_2 = get_current_proposal_data(motion_proposal_2_id);
        assert_eq!(
            get_reward_status(&proposal_2),
            ProposalRewardStatus::ReadyToSettle,
        );
    }

    let motion_proposal_3_id = make_motion_proposal();
    // Assert that the last motion proposal reaches Settled.
    {
        // Give third/last motion proposal time to settle.
        pocket_ic.advance_time(Duration::from_secs(7 * SECONDS_PER_DAY));
        for _ in 0..10 {
            pocket_ic.tick();
        }

        let proposal_3 = get_current_proposal_data(motion_proposal_3_id);
        assert_eq!(
            get_reward_status(&proposal_3),
            ProposalRewardStatus::Settled,
        );
    }

    // Step 2: Run code under test. Namely, upgrade SNS governance to the
    // current working copy.

    let get_current_sns_governance_module_hash = || {
        pocket_ic
            .canister_status(
                Principal::from(governance_canister_id),
                Some(Principal::from(PrincipalId::from(root_canister_id))), // sender
            )
            .unwrap()
            .module_hash
            .unwrap()
    };

    let wasm = build_governance_sns_wasm();
    let wasm = ensure_sns_wasm_gzipped(wasm);
    let goal_wasm_hash = wasm.sha256_hash().to_vec();

    assert_ne!(get_current_sns_governance_module_hash(), goal_wasm_hash);

    let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).unwrap();
    assert_eq!(proposal_info.failure_reason, None);
    sns::governance::propose_to_upgrade_sns_to_next_version_and_wait(
        &pocket_ic,
        governance_canister_id.get(),
    );

    // Step 3: Verify results.

    // Step 3.1: Assert that SNS governance is running the WASM built from the
    // current working tree/copy.
    assert_eq!(get_current_sns_governance_module_hash(), goal_wasm_hash);

    // Step 3.2: Assert that post_upgrade performed the modifications that we
    // wanted to see in the three motion proposals.
    let motion_proposals = [
        motion_proposal_1_id,
        motion_proposal_2_id,
        motion_proposal_3_id,
    ]
    .into_iter()
    .map(get_current_proposal_data)
    .collect::<Vec<_>>();

    for proposal in &motion_proposals {
        assert_eq!(
            get_reward_status(proposal),
            ProposalRewardStatus::Settled,
            "{:?}",
            proposal,
        );
    }
}
