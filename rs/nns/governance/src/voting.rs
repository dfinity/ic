use crate::{
    governance::Governance,
    neuron_store::NeuronStore,
    pb::v1::{Ballot, Topic, Topic::NeuronManagement, Vote},
};
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet, HashMap},
};

thread_local! {
    static VOTING_STATE_MACHINES: RefCell<VotingStateMachines> = RefCell::new(VotingStateMachines::new());
}
impl Governance {
    pub async fn cast_vote_and_cascade_follow(
        &mut self,
        proposal_id: ProposalId,
        voting_neuron_id: NeuronId,
        vote_of_neuron: Vote,
        topic: Topic,
    ) {
        let neuron_store = &mut self.neuron_store;
        let ballots = &mut self
            .heap_data
            .proposals
            .get_mut(&proposal_id.id)
            .unwrap()
            .ballots;
        // Use of thread local storage to store the state machines prevents
        // more than one state machine per proposal, which limits the overall
        // memory usage for voting, which will be relevant when this can be used
        // across multiple messages, which would cause the memory usage to accumulate.
        VOTING_STATE_MACHINES.with(|vsm| {
            let mut voting_state_machines = vsm.borrow_mut();
            let proposal_voting_machine =
                voting_state_machines.get_or_create_machine(proposal_id, topic);

            proposal_voting_machine.cast_vote(ballots, voting_neuron_id, vote_of_neuron);

            while !proposal_voting_machine.is_done() {
                proposal_voting_machine.continue_processing(neuron_store, ballots);
            }

            voting_state_machines.remove_if_done(&proposal_id);
        });
    }
}

struct VotingStateMachines {
    // Up to one machine per proposal, to avoid having to do unnecessary checks for followers that
    // might follow.  This allows the state machines to be used across multiple messages
    // without duplicating state and memory usage.
    machines: BTreeMap<ProposalId, ProposalVotingStateMachine>,
}

impl VotingStateMachines {
    fn new() -> Self {
        Self {
            machines: BTreeMap::new(),
        }
    }

    fn get_or_create_machine(
        &mut self,
        proposal_id: ProposalId,
        topic: Topic,
    ) -> &mut ProposalVotingStateMachine {
        self.machines
            .entry(proposal_id)
            .or_insert_with(|| ProposalVotingStateMachine::try_new(proposal_id, topic).unwrap())
    }

    fn remove_if_done(&mut self, proposal_id: &ProposalId) {
        if let Some(machine) = self.machines.get(proposal_id) {
            if machine.is_done() {
                self.machines.remove(proposal_id);
            }
        }
    }
}

#[derive(Debug, PartialEq, Default)]
struct ProposalVotingStateMachine {
    // The proposal ID that is being voted on.
    proposal_id: ProposalId,
    // The topic of the proposal.
    topic: Topic,
    // Votes that have been cast before checking followees
    neurons_to_check_followers: BTreeSet<NeuronId>,
    // followers to process
    followers_to_check: BTreeSet<NeuronId>,
    // votes that need to be recorded in each neuron's recent_ballots
    recent_neuron_ballots_to_record: BTreeMap<NeuronId, Vote>,
}

impl ProposalVotingStateMachine {
    fn try_new(proposal_id: ProposalId, topic: Topic) -> Result<Self, String> {
        if topic == Topic::Unspecified {
            return Err("Topic must be specified".to_string());
        }

        Ok(Self {
            proposal_id,
            topic,
            ..Default::default()
        })
    }

    fn is_done(&self) -> bool {
        self.neurons_to_check_followers.is_empty()
            && self.followers_to_check.is_empty()
            && self.recent_neuron_ballots_to_record.is_empty()
    }

    fn add_followers_to_check(
        &mut self,
        neuron_store: &NeuronStore,
        voting_neuron: NeuronId,
        topic: Topic,
    ) {
        self.followers_to_check
            .extend(neuron_store.get_followers_by_followee_and_topic(voting_neuron, topic));
        if ![Topic::Governance, Topic::SnsAndCommunityFund].contains(&topic) {
            // Insert followers from 'Unspecified' (default followers)
            self.followers_to_check.extend(
                neuron_store.get_followers_by_followee_and_topic(voting_neuron, Topic::Unspecified),
            );
        }
    }

    fn cast_vote(&mut self, ballots: &mut HashMap<u64, Ballot>, neuron_id: NeuronId, vote: Vote) {
        // There is no action to take with unspecfiied votes, so we early return.  It is
        // a legitimate argument in the context of continue_processing, but it simply means
        // that no vote is cast, and therefore there is no followup work to do.
        // This condition is also important to ensure that the state machine always terminates
        // even if an Unspecified vote is somehow cast manually.
        if vote == Vote::Unspecified {
            return;
        }

        if let Some(ballot) = ballots.get_mut(&neuron_id.id) {
            // The following conditional is CRITICAL, as it prevents a neuron's vote from
            // being overwritten by a later vote. This is important because otherwse
            // a cyclic voting graph is possible, which could result in never finishing voting.
            if ballot.vote == Vote::Unspecified as i32 {
                // Cast vote in ballot
                ballot.vote = vote as i32;
                // record the votes that have been cast, to log
                self.recent_neuron_ballots_to_record.insert(neuron_id, vote);

                // Do not check followers for NeuronManagement topic
                if self.topic != NeuronManagement {
                    self.neurons_to_check_followers.insert(neuron_id);
                }
            }
        }
    }

    fn continue_processing(
        &mut self,
        neuron_store: &mut NeuronStore,
        ballots: &mut HashMap<u64, Ballot>,
    ) {
        while let Some(neuron_id) = self.neurons_to_check_followers.pop_first() {
            self.add_followers_to_check(neuron_store, neuron_id, self.topic);
        }

        // Memory optimization, will not cause tests to fail if removed
        retain_neurons_with_castable_ballots(&mut self.followers_to_check, ballots);

        while let Some(follower) = self.followers_to_check.pop_first() {
            let vote = match neuron_store.neuron_would_follow_ballots(follower, self.topic, ballots)
            {
                Ok(vote) => vote,
                Err(e) => {
                    // This is a bad inconsistency, but there is
                    // nothing that can be done about it at this
                    // place.  We somehow have followers recorded that don't exist.
                    eprintln!("error in cast_vote_and_cascade_follow when gathering induction votes: {:?}", e);
                    Vote::Unspecified
                }
            };
            // Casting vote immediately might affect other follower votes, which makes
            // voting resolution take fewer iterations.
            // Vote::Unspecified is ignored by cast_vote.
            self.cast_vote(ballots, follower, vote);
        }

        while let Some((neuron_id, vote)) = self.recent_neuron_ballots_to_record.pop_first() {
            match neuron_store.register_recent_neuron_ballot(
                neuron_id,
                self.topic,
                self.proposal_id,
                vote,
            ) {
                Ok(_) => {}
                Err(e) => {
                    // This is a bad inconsistency, but there is
                    // nothing that can be done about it at this
                    // place.  We somehow have followers recorded that don't exist.
                    eprintln!("error in cast_vote_and_cascade_follow when gathering induction votes: {:?}", e);
                }
            };
        }
    }
}

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

#[cfg(test)]
mod test {

    use crate::{
        governance::{Governance, MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS},
        neuron::{DissolveStateAndAge, Neuron, NeuronBuilder},
        neuron_store::NeuronStore,
        pb::v1::{neuron::Followees, Ballot, ProposalData, Topic, Vote},
        test_utils::{MockEnvironment, StubCMC, StubIcpLedger},
        voting::ProposalVotingStateMachine,
    };
    use futures::FutureExt;
    use ic_base_types::PrincipalId;
    use ic_nns_common::pb::v1::{NeuronId, ProposalId};
    use icp_ledger::Subaccount;
    use maplit::{btreemap, hashmap};
    use std::collections::{BTreeMap, BTreeSet, HashMap};

    fn make_ballot(voting_power: u64, vote: Vote) -> Ballot {
        Ballot {
            voting_power,
            vote: vote as i32,
        }
    }

    fn make_neuron(
        id: u64,
        cached_neuron_stake_e8s: u64,
        followees: HashMap<i32, Followees>,
    ) -> Neuron {
        let mut account = vec![0; 32];
        for (destination, data) in account.iter_mut().zip(id.to_le_bytes().iter().cycle()) {
            *destination = *data;
        }
        let subaccount = Subaccount::try_from(account.as_slice()).unwrap();

        let now = 123_456_789;
        let dissolve_state_and_age = DissolveStateAndAge::NotDissolving {
            dissolve_delay_seconds: MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS,
            aging_since_timestamp_seconds: now - MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS,
        };

        NeuronBuilder::new(
            NeuronId { id },
            subaccount,
            PrincipalId::new_user_test_id(id),
            dissolve_state_and_age,
            now,
        )
        .with_followees(followees)
        .with_cached_neuron_stake_e8s(cached_neuron_stake_e8s)
        .build()
    }

    #[test]
    fn test_cast_vote_and_cascade_doesnt_cascade_neuron_management() {
        let now = 1000;
        let topic = Topic::NeuronManagement;

        let make_neuron = |id: u64, followees: Vec<u64>| {
            make_neuron(
                id,
                100,
                hashmap! {topic.into() => Followees {
                    followees: followees.into_iter().map(|id| NeuronId { id }).collect(),
                }},
            )
        };

        let add_neuron_with_ballot = |neuron_map: &mut BTreeMap<u64, Neuron>,
                                      ballots: &mut HashMap<u64, Ballot>,
                                      id: u64,
                                      followees: Vec<u64>,
                                      vote: Vote| {
            let neuron = make_neuron(id, followees);
            let deciding_voting_power = neuron.deciding_voting_power(now);
            neuron_map.insert(id, neuron);
            ballots.insert(id, make_ballot(deciding_voting_power, vote));
        };

        let add_neuron_without_ballot =
            |neuron_map: &mut BTreeMap<u64, Neuron>, id: u64, followees: Vec<u64>| {
                let neuron = make_neuron(id, followees);
                neuron_map.insert(id, neuron);
            };

        let mut heap_neurons = BTreeMap::new();
        let mut ballots = HashMap::new();
        for id in 1..=5 {
            // Each neuron follows all neurons with a lower id
            let followees = (1..id).collect();

            add_neuron_with_ballot(
                &mut heap_neurons,
                &mut ballots,
                id,
                followees,
                Vote::Unspecified,
            );
        }
        // Add another neuron that follows both a neuron with a ballot and without a ballot
        add_neuron_with_ballot(
            &mut heap_neurons,
            &mut ballots,
            6,
            vec![1, 7],
            Vote::Unspecified,
        );

        // Add a neuron without a ballot for neuron 6 to follow.
        add_neuron_without_ballot(&mut heap_neurons, 7, vec![1]);

        let governance_proto = crate::pb::v1::Governance {
            neurons: heap_neurons
                .into_iter()
                .map(|(id, neuron)| (id, neuron.into_proto(now)))
                .collect(),
            proposals: btreemap! {
                1 => ProposalData {
                    id: Some(ProposalId {id: 1}),
                    ballots,
                    ..Default::default()
                }
            },
            ..Default::default()
        };
        let mut governance = Governance::new(
            governance_proto,
            Box::new(MockEnvironment::new(Default::default(), 0)),
            Box::new(StubIcpLedger {}),
            Box::new(StubCMC {}),
        );

        governance
            .cast_vote_and_cascade_follow(
                ProposalId { id: 1 },
                NeuronId { id: 1 },
                Vote::Yes,
                topic,
            )
            .now_or_never()
            .unwrap();

        let deciding_voting_power = |neuron_id| {
            governance
                .neuron_store
                .with_neuron(&neuron_id, |n| n.deciding_voting_power(now))
                .unwrap()
        };
        assert_eq!(
            governance.heap_data.proposals.get(&1).unwrap().ballots,
            hashmap! {
                1 => make_ballot(deciding_voting_power(NeuronId { id: 1}), Vote::Yes),
                2 => make_ballot(deciding_voting_power(NeuronId { id: 2}), Vote::Unspecified),
                3 => make_ballot(deciding_voting_power(NeuronId { id: 3}), Vote::Unspecified),
                4 => make_ballot(deciding_voting_power(NeuronId { id: 4}), Vote::Unspecified),
                5 => make_ballot(deciding_voting_power(NeuronId { id: 5}), Vote::Unspecified),
                6 => make_ballot(deciding_voting_power(NeuronId { id: 6}), Vote::Unspecified),
            }
        );
    }

    #[test]
    fn test_cast_vote_and_cascade_works() {
        let now = 1000;
        let topic = Topic::NetworkCanisterManagement;

        let make_neuron = |id: u64, followees: Vec<u64>| {
            make_neuron(
                id,
                100,
                hashmap! {topic.into() => Followees {
                    followees: followees.into_iter().map(|id| NeuronId { id }).collect(),
                }},
            )
        };

        let add_neuron_with_ballot = |neuron_map: &mut BTreeMap<u64, Neuron>,
                                      ballots: &mut HashMap<u64, Ballot>,
                                      id: u64,
                                      followees: Vec<u64>,
                                      vote: Vote| {
            let neuron = make_neuron(id, followees);
            let deciding_voting_power = neuron.deciding_voting_power(now);
            neuron_map.insert(id, neuron);
            ballots.insert(id, make_ballot(deciding_voting_power, vote));
        };

        let add_neuron_without_ballot =
            |neuron_map: &mut BTreeMap<u64, Neuron>, id: u64, followees: Vec<u64>| {
                let neuron = make_neuron(id, followees);
                neuron_map.insert(id, neuron);
            };

        let mut neurons = BTreeMap::new();
        let mut ballots = HashMap::new();
        for id in 1..=5 {
            // Each neuron follows all neurons with a lower id
            let followees = (1..id).collect();

            add_neuron_with_ballot(&mut neurons, &mut ballots, id, followees, Vote::Unspecified);
        }
        // Add another neuron that follows both a neuron with a ballot and without a ballot
        add_neuron_with_ballot(&mut neurons, &mut ballots, 6, vec![1, 7], Vote::Unspecified);

        // Add a neuron without a ballot for neuron 6 to follow.
        add_neuron_without_ballot(&mut neurons, 7, vec![1]);

        let governance_proto = crate::pb::v1::Governance {
            neurons: neurons
                .into_iter()
                .map(|(id, neuron)| (id, neuron.into_proto(now)))
                .collect(),
            proposals: btreemap! {
                1 => ProposalData {
                    id: Some(ProposalId {id: 1}),
                    ballots,
                    ..Default::default()
                }
            },
            ..Default::default()
        };
        let mut governance = Governance::new(
            governance_proto,
            Box::new(MockEnvironment::new(Default::default(), 0)),
            Box::new(StubIcpLedger {}),
            Box::new(StubCMC {}),
        );

        governance
            .cast_vote_and_cascade_follow(
                ProposalId { id: 1 },
                NeuronId { id: 1 },
                Vote::Yes,
                topic,
            )
            .now_or_never()
            .unwrap();

        let deciding_voting_power = |neuron_id| {
            governance
                .neuron_store
                .with_neuron(&neuron_id, |n| n.deciding_voting_power(now))
                .unwrap()
        };
        assert_eq!(
            governance.heap_data.proposals.get(&1).unwrap().ballots,
            hashmap! {
                1 => make_ballot(deciding_voting_power(NeuronId { id: 1 }), Vote::Yes),
                2 => make_ballot(deciding_voting_power(NeuronId { id: 2 }), Vote::Yes),
                3 => make_ballot(deciding_voting_power(NeuronId { id: 3 }), Vote::Yes),
                4 => make_ballot(deciding_voting_power(NeuronId { id: 4 }), Vote::Yes),
                5 => make_ballot(deciding_voting_power(NeuronId { id: 5 }), Vote::Yes),
                6 => make_ballot(deciding_voting_power(NeuronId { id: 6 }), Vote::Unspecified),
            }
        );
    }

    fn add_neuron_with_ballot(
        neuron_store: &mut NeuronStore,
        ballots: &mut HashMap<u64, Ballot>,
        neuron: Neuron,
    ) {
        let cached_stake = neuron.cached_neuron_stake_e8s;
        let id = neuron.id().id;
        neuron_store
            .add_neuron(neuron)
            .expect("Couldn't add neuron");
        ballots.insert(
            id,
            Ballot {
                vote: Vote::Unspecified as i32,
                voting_power: cached_stake,
            },
        );
    }

    #[test]
    fn test_invalid_topic() {
        let err = ProposalVotingStateMachine::try_new(ProposalId { id: 0 }, Topic::Unspecified)
            .unwrap_err();

        assert_eq!(err, "Topic must be specified");
    }

    #[test]
    fn test_is_done() {
        let mut state_machine = ProposalVotingStateMachine {
            proposal_id: ProposalId { id: 0 },
            topic: Topic::Governance,
            neurons_to_check_followers: BTreeSet::new(),
            followers_to_check: BTreeSet::new(),
            recent_neuron_ballots_to_record: BTreeMap::new(),
        };

        assert!(state_machine.is_done());

        state_machine
            .neurons_to_check_followers
            .insert(NeuronId { id: 0 });
        assert!(!state_machine.is_done());
        state_machine.neurons_to_check_followers.clear();

        state_machine.followers_to_check.insert(NeuronId { id: 0 });
        assert!(!state_machine.is_done());
        state_machine.followers_to_check.clear();

        state_machine
            .recent_neuron_ballots_to_record
            .insert(NeuronId { id: 0 }, Vote::Yes);
        assert!(!state_machine.is_done());
        state_machine.recent_neuron_ballots_to_record.clear();
    }

    #[test]
    fn test_continue_processsing() {
        let mut state_machine =
            ProposalVotingStateMachine::try_new(ProposalId { id: 0 }, Topic::NetworkEconomics)
                .unwrap();

        let mut ballots = HashMap::new();
        let mut neuron_store = NeuronStore::new(btreemap! {});

        add_neuron_with_ballot(
            &mut neuron_store,
            &mut ballots,
            make_neuron(1, 101, hashmap! {}),
        );
        add_neuron_with_ballot(
            &mut neuron_store,
            &mut ballots,
            make_neuron(
                2,
                102,
                hashmap! {Topic::NetworkEconomics.into() => Followees {
                    followees: vec![NeuronId { id: 1 }],
                }},
            ),
        );

        state_machine.cast_vote(&mut ballots, NeuronId { id: 1 }, Vote::Yes);
        state_machine.continue_processing(&mut neuron_store, &mut ballots);

        assert_eq!(
            ballots,
            hashmap! {
            1 => Ballot { vote: Vote::Yes as i32, voting_power: 101 },
            2 => Ballot { vote: Vote::Yes as i32, voting_power: 102 }}
        );
        assert_eq!(
            neuron_store
                .with_neuron(&NeuronId { id: 1 }, |n| {
                    n.recent_ballots.first().unwrap().vote
                })
                .unwrap(),
            Vote::Yes as i32
        );
        assert_eq!(
            neuron_store
                .with_neuron(&NeuronId { id: 2 }, |n| {
                    n.recent_ballots.first().unwrap().vote
                })
                .unwrap(),
            Vote::Yes as i32
        );

        assert!(!state_machine.is_done());

        state_machine.continue_processing(&mut neuron_store, &mut ballots);

        assert_eq!(
            ballots,
            hashmap! {
            1 => Ballot { vote: Vote::Yes as i32, voting_power: 101 },
            2 => Ballot { vote: Vote::Yes as i32, voting_power: 102 }}
        );
        assert_eq!(
            neuron_store
                .with_neuron(&NeuronId { id: 1 }, |n| {
                    n.recent_ballots.first().unwrap().vote
                })
                .unwrap(),
            Vote::Yes as i32
        );
        assert_eq!(
            neuron_store
                .with_neuron(&NeuronId { id: 2 }, |n| {
                    n.recent_ballots.first().unwrap().vote
                })
                .unwrap(),
            Vote::Yes as i32
        );
        assert!(state_machine.is_done());
    }

    #[test]
    fn test_cyclic_following_will_terminate() {
        let mut state_machine =
            ProposalVotingStateMachine::try_new(ProposalId { id: 0 }, Topic::NetworkEconomics)
                .unwrap();

        let mut ballots = HashMap::new();
        let mut neuron_store = NeuronStore::new(btreemap! {});

        add_neuron_with_ballot(
            &mut neuron_store,
            &mut ballots,
            make_neuron(
                1,
                101,
                hashmap! {Topic::NetworkEconomics.into() => Followees {
                    followees: vec![NeuronId { id: 2 }],
                }},
            ),
        );
        add_neuron_with_ballot(
            &mut neuron_store,
            &mut ballots,
            make_neuron(
                2,
                102,
                hashmap! {Topic::NetworkEconomics.into() => Followees {
                    followees: vec![NeuronId { id: 1 }],
                }},
            ),
        );

        // We assert it is immediately done after casting an unspecified vote b/c there
        // is no work to do.
        state_machine.cast_vote(&mut ballots, NeuronId { id: 1 }, Vote::Unspecified);
        assert!(state_machine.is_done());

        // We assert it is done after checking both sets of followers
        state_machine.cast_vote(&mut ballots, NeuronId { id: 1 }, Vote::Yes);
        state_machine.continue_processing(&mut neuron_store, &mut ballots);
        state_machine.continue_processing(&mut neuron_store, &mut ballots);
        assert!(state_machine.is_done());
    }
}
