use crate::{
    governance::Governance,
    neuron_store::NeuronStore,
    pb::v1::{Ballot, Topic, Vote},
};
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Register `voting_neuron_id` voting according to
/// `vote_of_neuron` (which must be `yes` or `no`) in 'ballots' and
/// cascade voting according to the following relationships
/// specified in 'followee_index' (mapping followees to followers for
/// the topic) and 'neurons' (which contains a mapping of followers
/// to followees).
/// Cascading only occurs for proposal topics that support following (i.e.,
/// all topics except Topic::NeuronManagement).
pub(crate) fn cast_vote_and_cascade_follow(
    proposal_id: &ProposalId,
    ballots: &mut HashMap<u64, Ballot>,
    voting_neuron_id: &NeuronId,
    vote_of_neuron: Vote,
    topic: Topic,
    neuron_store: &mut NeuronStore,
) {
    assert!(topic != Topic::Unspecified);

    // This is the induction variable of the loop: a map from
    // neuron ID to the neuron's vote - 'yes' or 'no' (other
    // values not allowed).
    let mut induction_votes = BTreeMap::new();
    induction_votes.insert(*voting_neuron_id, vote_of_neuron);

    // Retain only neurons that have a ballot that can still be cast.  This excludes
    // neurons with no ballots or ballots that have already been cast.
    fn retain_neurons_with_castable_ballots(
        followers: &mut BTreeSet<NeuronId>,
        ballots: &HashMap<u64, Ballot>,
    ) {
        followers.retain(|f| {
            ballots
                .get(&f.id)
                // Only retain neurons with unspecified ballots
                .map(|b| b.vote == Vote::Unspecified as i32)
                // Neurons without ballots are also dropped
                .unwrap_or_default()
        });
    }

    loop {
        // First, we cast the specified votes (in the first round,
        // this will be a single vote) and collect all neurons
        // that follow some of the neurons that are voting.
        let mut all_followers = BTreeSet::new();
        for (k, v) in induction_votes.iter() {
            // The new/induction votes cannot be unspecified.
            assert!(*v != Vote::Unspecified);
            if let Some(k_ballot) = ballots.get_mut(&k.id) {
                // Neuron with ID k is eligible to vote.
                if k_ballot.vote == (Vote::Unspecified as i32) {
                    let register_ballot_result =
                        neuron_store.with_neuron_mut(&NeuronId { id: k.id }, |k_neuron| {
                            // Register the neuron's ballot in the
                            // neuron itself.
                            k_neuron.register_recent_ballot(topic, proposal_id, *v);
                        });
                    match register_ballot_result {
                        Ok(_) => {
                            // Only update a vote if it was previously unspecified. Following
                            // can trigger votes for neurons that have already voted (manually)
                            // and we don't change these votes.
                            k_ballot.vote = *v as i32;
                            // Here k is the followee, i.e., the neuron that has just cast a
                            // vote that may be followed by other neurons.
                            //
                            // Insert followers from 'topic'
                            all_followers.extend(
                                neuron_store.get_followers_by_followee_and_topic(*k, topic),
                            );
                            // Default following doesn't apply to governance or SNS
                            // decentralization swap proposals.
                            if ![Topic::Governance, Topic::SnsAndCommunityFund].contains(&topic) {
                                // Insert followers from 'Unspecified' (default followers)
                                all_followers.extend(
                                    neuron_store.get_followers_by_followee_and_topic(
                                        *k,
                                        Topic::Unspecified,
                                    ),
                                );
                            }
                        }
                        Err(e) => {
                            // The voting neuron not found in the neurons table. This is a bad
                            // inconsistency, but there is nothing that can be done about it at
                            // this place.
                            eprintln!("error in cast_vote_and_cascade_follow when attempting to cast ballot: {:?}", e);
                        }
                    }
                }
            } else {
                // A non-eligible voter was specified in
                // new/induction votes. We don't compute the
                // followers of this neuron as it didn't actually
                // vote.
            }
        }
        // Clear the induction_votes, as we are going to compute a
        // new set now.
        induction_votes.clear();

        // Following is not enabled for neuron management proposals
        if topic == Topic::NeuronManagement {
            return;
        }

        // Calling "would_follow_ballots" for neurons that cannot vote is wasteful.
        retain_neurons_with_castable_ballots(&mut all_followers, ballots);

        for f in all_followers.iter() {
            let f_vote = match neuron_store.with_neuron(&NeuronId { id: f.id }, |n| {
                n.would_follow_ballots(topic, ballots)
            }) {
                Ok(vote) => vote,
                Err(e) => {
                    // This is a bad inconsistency, but there is
                    // nothing that can be done about it at this
                    // place.  We somehow have followers recorded that don't exist.
                    eprintln!("error in cast_vote_and_cascade_follow when gathering induction votes: {:?}", e);
                    Vote::Unspecified
                }
            };
            if f_vote != Vote::Unspecified {
                // f_vote is yes or no, i.e., f_neuron's
                // followee relations indicates that it should
                // vote now.
                induction_votes.insert(*f, f_vote);
            }
        }
        // If induction_votes is empty, the loop will terminate
        // here.
        if induction_votes.is_empty() {
            return;
        }
        // We now continue to the next iteration of the loop.
        // Because induction_votes is not empty, either at least
        // one entry in 'ballots' will change from unspecified to
        // yes or no, or all_followers will be empty, whence
        // induction_votes will become empty.
        //
        // Thus, for each iteration of the loop, the number of
        // entries in 'ballots' that have an unspecified value
        // decreases, or else the loop terminates. As nothing is
        // added to 'ballots' (or removed for that matter), the
        // loop terminates in at most 'ballots.len()+1' steps.
        //
        // The worst case is attained if there is a linear
        // following graph, like this:
        //
        // X follows A follows B follows C,
        //
        // where X is not eligible to vote and nobody has
        // voted, i.e.,
        //
        // ballots = {
        //   A -> unspecified, B -> unspecified, C -> unspecified
        // }
        //
        // In this case, the subsequent values of
        // 'induction_votes' will be {C}, {B}, {A}, {X}.
        //
        // Note that it does not matter if X has followers. As X
        // doesn't vote, its followers are not considered.
        //
        // The above argument also shows how the algorithm deals
        // with cycles in the following graph: votes are
        // propagated through the graph in a manner similar to the
        // breadth-first search (BFS) algorithm. A node is
        // explored when it has voted yes or no.
    }
}
