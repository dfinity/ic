use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_nns_governance::{
    pb::v1::{proposal::Action, Ballot, Proposal, ProposalData, Vote},
    proposals::sum_weighted_voting_power,
};
use maplit::hashmap;

#[test]
fn test_sum_weighted_voting_power() {
    let proposal = Some(Proposal {
        action: Some(Action::AddOrRemoveNodeProvider(Default::default())),
        ..Default::default()
    });

    let ballots = hashmap! {
        1042 => Ballot {
            vote: Vote::Unspecified as i32,
            voting_power: 100,
        },
        1043 => Ballot {
            vote: Vote::Yes as i32,
            voting_power: 2_000,
        },
        1044 => Ballot {
            vote: Vote::No as i32,
            voting_power: 30_000,
        },
    };

    let proposal_data = ProposalData {
        proposal,
        ballots,
        total_potential_voting_power: Some(40_000),
        ..Default::default()
    };

    // Scenario: Three proposals, three neurons. They always vote the same:
    //
    //   * 1042 - never votes, and has 100 voting_power
    //   * 1043 - Always votes Yes, and has 2_000 voting_power
    //   * 1044 - Always votes No, and has 30_000 voting_power
    //
    // The proposals:
    //
    //   * 57 - Has no total_potential_voting_power. Thus, 100 + 2_000 + 30_000
    //     is used in lieu of total_potential_voting_power.
    //   * 58 - Actually has total_potential_voting_power.
    //   * 59 - Also has total_potential_voting_power, but its reward weight is
    //          20x, not 1x.
    let proposals = vec![
        (
            ProposalId { id: 57 },
            ProposalData {
                total_potential_voting_power: None,
                ..proposal_data.clone()
            },
        ),
        (ProposalId { id: 58 }, proposal_data.clone()),
        (ProposalId { id: 59 }, {
            let mut proposal_data = proposal_data;
            let proposal = proposal_data.proposal.as_mut().unwrap();
            proposal.action = Some(Action::Motion(Default::default()));
            proposal_data
        }),
    ];

    // Make sure our input has the reward weights as described in the scenario.
    assert_eq!(
        proposals
            .iter()
            .map(|(_, proposal): &(_, ProposalData)| proposal.topic().reward_weight())
            .collect::<Vec<f64>>(),
        [1.0, 1.0, 20.0]
    );

    // Step 2: Call code under test.
    let proposals = proposals
        .iter()
        .map(|(id, proposal_data)| (*id, Some(proposal_data)));
    let result = sum_weighted_voting_power(proposals);

    // Step 3: Inspect result(s).
    #[rustfmt::skip]
    assert_eq!(
        result,
        (
            hashmap! {
                // Neuron 1042 never voted, and as a result, has no entry in the result.

                // Voted (Yes) twice on 1x weight proposals and once on a 20x weight proposal.
                NeuronId { id: 1043 } => (2 * 2_000 + 20 * 2_000) as f64,

                // Similar to previous, but voted No, and has different (more) voting power.
                NeuronId { id: 1044 } => (2 * 30_000 + 20 * 30_000) as f64,
            },
            (
                (100 + 2_000 + 30_000) // First proposal.
                + 40_000               // Second proposal
                + 20 * 40_000          // Third proposal
            ) as f64
        ),
    );
}
