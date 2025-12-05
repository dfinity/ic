use ic_base_types::PrincipalId;
use ic_nervous_system_common::{E8, ONE_DAY_SECONDS};
use ic_nervous_system_timers::test::run_pending_timers_every_interval_for_count;
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_nns_governance::canister_state::{governance_mut, set_governance_for_tests};
use ic_nns_governance::timer_tasks::schedule_tasks;
use ic_nns_governance::{
    governance::{Governance, REWARD_DISTRIBUTION_PERIOD_SECONDS},
    pb::v1::{
        Ballot, Proposal, ProposalData, ProposalRewardStatus, Topic, Vote, WaitForQuietState,
        proposal::Action,
    },
    proposals::sum_weighted_voting_power,
};
use ic_nns_governance_api as api;
use icp_ledger::Tokens;
use lazy_static::lazy_static;
use maplit::{btreemap, hashmap};
use std::collections::BTreeMap;
use std::time::Duration;

pub mod fake;

// Jan 1, 2025 (midnight UTC). There is nothing really special about this value; it's just realistic.
const NOW_SECONDS: u64 = 1735689600;

lazy_static! {
    static ref NEURONS: BTreeMap<u64, api::Neuron> = {
        let base = api::Neuron {
            controller: Some(PrincipalId::new_user_test_id(783_068_996)),
            dissolve_state: Some(api::neuron::DissolveState::WhenDissolvedTimestampSeconds(NOW_SECONDS)),
            aging_since_timestamp_seconds: u64::MAX,
            ..Default::default()
        };

        let result = btreemap! {
            1042 => api::Neuron {
                id: Some(NeuronId { id: 1042 }),
                account: vec![42; 32],
                ..base.clone()
            },
            1043 => api::Neuron {
                id: Some(NeuronId { id: 1043 }),
                account: vec![43; 32],
                ..base.clone()
            },
            1044 => api::Neuron {
                id: Some(NeuronId { id: 1044 }),
                account: vec![44; 32],
                ..base.clone()
            },
        };

        result
    };

    // There are three proposals here:
    //
    //   * Has no total_potential_voting_power. Thus, 100 + 2_000 + 30_000
    //     is used in lieu of total_potential_voting_power.
    //   * Actually has total_potential_voting_power.
    //   * Also has total_potential_voting_power, but its reward weight is
    //     20x, not the usual 1x.
    //
    // And three neurons that vote the same way on all of the above
    // proposals:
    //
    //   * 1042 - never votes, and has 100 voting_power
    //   * 1043 - Always votes Yes, and has 2_000 voting_power
    //   * 1044 - Always votes No, and has 30_000 voting_power
    static ref PROPOSALS: BTreeMap<u64, ProposalData> = {
        let ballots = hashmap! {
            1042 => Ballot {
                vote: Vote::Unspecified as i32,
                voting_power: 100 * E8,
            },
            1043 => Ballot {
                vote: Vote::Yes as i32,
                voting_power: 2_000 * E8,
            },
            1044 => Ballot {
                vote: Vote::No as i32,
                voting_power: 30_000 * E8,
            },
        };

        let proposal = Some(Proposal {
            action: Some(Action::AddOrRemoveNodeProvider(Default::default())),
            ..Default::default()
        });

        // This is used as a base. All proposals are ReadyToSettle, because,
        // they have no associated reward event, and the voting period is over.
        let proposal_data = ProposalData {
            proposal,
            ballots,
            total_potential_voting_power: Some(80_000 * E8),
            wait_for_quiet_state: Some(WaitForQuietState {
                current_deadline_timestamp_seconds: NOW_SECONDS - 5 * ONE_DAY_SECONDS,
            }),
            topic: Some(Topic::ParticipantManagement as i32),
            ..Default::default()
        };

        let proposals = btreemap! {
            // A "legacy" proposal. I.e. has no total_potential_voting_power. Has 1x reward weight.
            77 => ProposalData {
                id: Some(ProposalId { id: 77 }),
                total_potential_voting_power: None,
                ..proposal_data.clone()
            },

            // A new proposal (i.e. with total_potential_voting_power, and 1x
            // reward weight.). Has 1x reward weight.
            78 => ProposalData {
                id: Some(ProposalId { id: 78 }),
                ballots: hashmap! {
                    1042 => Ballot {
                        vote: Vote::Unspecified as i32,
                        voting_power: 700 * E8,
                    },
                    1043 => Ballot {
                        vote: Vote::Yes as i32,
                        voting_power: 1_000 * E8,
                    },
                    1044 => Ballot {
                        vote: Vote::No as i32,
                        voting_power: 20_000 * E8,
                    },
                },
                ..proposal_data.clone()
            },

            // A new proposal, but with 20x reward weight.
            79 => {
                let mut proposal_data = proposal_data;
                proposal_data.id = Some(ProposalId { id: 79 });
                proposal_data.topic = Some(Topic::Governance as i32);

                let proposal = proposal_data.proposal.as_mut().unwrap();
                proposal.action = Some(Action::Motion(Default::default()));
                proposal_data
            },
        };

        // Verify all ReadyToSettle.
        assert_eq!(
            proposals
                .values()
                .map(|proposal| proposal.reward_status(NOW_SECONDS, 4 * ONE_DAY_SECONDS))
                .collect::<Vec<_>>(),
            // Using all is more concise, but if the assert fails, assert! gives
            // less diagnostic information than assert_eq!.
            vec![
                ProposalRewardStatus::ReadyToSettle,
                ProposalRewardStatus::ReadyToSettle,
                ProposalRewardStatus::ReadyToSettle,
            ],
        );

        // Verify reward weights.
        assert_eq!(
            proposals
                .values()
                .map(|proposal| proposal.topic().reward_weight())
                .collect::<Vec<f64>>(),
            [1.0, 1.0, 20.0]
        );

        proposals
    };
}

#[test]
fn test_sum_weighted_voting_power() {
    // Step 1: Prepare the world.

    // Step 2: Call code under test.
    let result = sum_weighted_voting_power(PROPOSALS.values());

    // Step 3: Inspect result(s).
    #[rustfmt::skip]
    assert_eq!(
        result,
        (
            hashmap! {
                // Neuron 1042 never voted, and because of this, the return
                // value has no entry for this neuron.

                // Voted (Yes) twice on 1x weight proposals and once on a 20x weight proposal.
                NeuronId { id: 1043 } => ((2_000 + 1_000 + 20 * 2_000) * E8) as f64,

                // Similar to previous, but voted No, and has different (more) voting power.
                // In voting rewards, Yes and No are treated the same.
                NeuronId { id: 1044 } => ((30_000 + 20_000 + 20 * 30_000) * E8) as f64,
            },
            ((
                (100 + 2_000 + 30_000) // First proposal.
                + 80_000               // Second proposal
                + 20 * 80_000          // Third proposal
            ) * E8) as f64
        ),
    );
}

#[tokio::test]
async fn test_distribute_rewards_with_total_potential_voting_power() {
    // Step 1: Prepare the world.

    let fake_driver = fake::FakeDriver::default()
        .at(NOW_SECONDS)
        .with_supply(Tokens::from_tokens(100).unwrap());

    let governance_init = api::Governance {
        neurons: NEURONS.clone(),
        genesis_timestamp_seconds: NOW_SECONDS - REWARD_DISTRIBUTION_PERIOD_SECONDS,
        economics: Some(api::NetworkEconomics::with_default_values()),
        ..Default::default()
    };
    let mut governance = Governance::new(
        governance_init,
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
        fake_driver.get_fake_cmc(),
        fake_driver.get_fake_randomness_generator(),
    );
    governance.heap_data.proposals = PROPOSALS.clone();

    set_governance_for_tests(governance);
    let governance = governance_mut();
    schedule_tasks();

    // Step 2: Call code under test.
    run_pending_timers_every_interval_for_count(
        Duration::from_secs(REWARD_DISTRIBUTION_PERIOD_SECONDS),
        1,
    )
    .await;

    // Step 3: Inspect result(s).
    let get_neuron_rewards = |neuron_id| {
        governance
            .with_neuron(&NeuronId { id: neuron_id }, |neuron| {
                neuron.maturity_e8s_equivalent
            })
            .unwrap()
    };

    assert_eq!(get_neuron_rewards(1042), 0); // Didn't vote -> no rewards.

    let rewards = (get_neuron_rewards(1043), get_neuron_rewards(1044));

    let weighted_voting_powers = (
        2_000 + 1_000 + 20 * 2_000,    // 2nd neuron (id = 1043)
        30_000 + 20_000 + 20 * 30_000, // 3rd neuron (id = 1044)
    );

    // Remember, this can return NEGATIVE. Most of the time, you want to do
    // assert!(e.abs() < EPSILON, ...). Do NOT forget the .abs() !
    fn assert_ratio_relative_error_close(
        observed: (u64, u64),
        expected: (u64, u64),
        epsilon: f64,
        msg: &str,
    ) {
        let ob = observed.0 as f64 / observed.1 as f64;
        let ex = expected.0 as f64 / expected.1 as f64;

        let relative_error = (ob - ex) / ex;

        assert!(
            relative_error.abs() < epsilon,
            "{msg}: {observed:?} vs. {expected:?} (relative error = {relative_error})",
        );
    }

    assert_ratio_relative_error_close(
        rewards,
        weighted_voting_powers,
        2e-6,
        "rewards vs. weighted_voting_powers",
    );

    let reward_event = governance.latest_reward_event();
    assert_ratio_relative_error_close(
        (rewards.0, reward_event.total_available_e8s_equivalent),
        (weighted_voting_powers.0, (32_100 + 80_000 + 20 * 80_000)),
        2e-6,
        "2nd neuron (ID = 1043)",
    );
    assert_ratio_relative_error_close(
        (rewards.1, reward_event.total_available_e8s_equivalent),
        (weighted_voting_powers.1, (32_100 + 80_000 + 20 * 80_000)),
        2e-6,
        "2nd neuron (ID = 1043)",
    );
}
