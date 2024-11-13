use ic_nns_common::pb::v1::NeuronId;
use ic_nns_governance::{
    pb::v1::{proposal::Action, Ballot, Proposal, ProposalData, Vote},
    proposals::sum_weighted_voting_power,
};
use maplit::hashmap;

#[test]
fn test_sum_weighted_voting_power() {
    // Step 1: Prepare the world. Basically, we come up with some proposal that
    // have ballots in them. More precisely, there are three proposals here:
    //
    //   * Has no total_potential_voting_power. Thus, 100 + 2_000 + 30_000
    //     is used in lieu of total_potential_voting_power.
    //   * Actually has total_potential_voting_power.
    //   * Also has total_potential_voting_power, but its reward weight is
    //     20x, not the usual 1x.
    //
    // And three neurons that vote the same way on all of the above proposals:
    //
    //   * 1042 - never votes, and has 100 voting_power
    //   * 1043 - Always votes Yes, and has 2_000 voting_power
    //   * 1044 - Always votes No, and has 30_000 voting_power

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

    let proposals = vec![
        ProposalData {
            total_potential_voting_power: None,
            ..proposal_data.clone()
        },
        proposal_data.clone(),
        {
            let mut proposal_data = proposal_data;
            let proposal = proposal_data.proposal.as_mut().unwrap();
            proposal.action = Some(Action::Motion(Default::default()));
            proposal_data
        },
    ];

    // Make sure our input has the reward weights as described in the scenario.
    assert_eq!(
        proposals
            .iter()
            .map(|proposal: &ProposalData| proposal.topic().reward_weight())
            .collect::<Vec<f64>>(),
        [1.0, 1.0, 20.0]
    );

    // Step 2: Call code under test.
    let result = sum_weighted_voting_power(proposals.iter());

    // Step 3: Inspect result(s).
    #[rustfmt::skip]
    assert_eq!(
        result,
        (
            hashmap! {
                // Neuron 1042 never voted, and because of this, the return
                // value has no entry for this neuron.

                // Voted (Yes) twice on 1x weight proposals and once on a 20x weight proposal.
                NeuronId { id: 1043 } => (2 * 2_000 + 20 * 2_000) as f64,

                // Similar to previous, but voted No, and has different (more) voting power.
                // In voting rewards, Yes and No are treated the same.
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
