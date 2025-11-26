use crate::{
    governance::{Governance, LOG_PREFIX},
    neuron_store::NeuronStore,
    pb::v1::{Ballot, ProposalData, Topic, Topic::NeuronManagement, Vote},
    storage::with_voting_state_machines_mut,
};
use ic_cdk::{eprintln, println};
#[cfg(not(any(test, feature = "canbench-rs")))]
use ic_nervous_system_long_message::is_message_over_threshold;
#[cfg(test)]
use ic_nervous_system_temporary::Temporary;
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_stable_structures::{StableBTreeMap, Storable, storable::Bound};
use prost::Message;
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, HashMap},
};

const BILLION: u64 = 1_000_000_000;

/// The hard limit for the number of instructions that can be executed in a single call context.
/// This leaves room for 750 thousand neurons with complex following.
const HARD_VOTING_INSTRUCTIONS_LIMIT: u64 = 750 * BILLION;
// For production, we want this higher so that we can process more votes, but without affecting
// the overall responsiveness of the canister. 1 Billion seems like a reasonable compromise.
const SOFT_VOTING_INSTRUCTIONS_LIMIT: u64 = if cfg!(feature = "test") {
    1_000_000
} else {
    BILLION
};

// The following test methods let us test this internally
#[cfg(any(test, feature = "canbench-rs"))]
thread_local! {
    static OVER_SOFT_MESSAGE_LIMIT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static CANBENCH_FAKE_INSTRUCTION_COUNTER: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn temporarily_set_over_soft_message_limit(over: bool) -> Temporary {
    Temporary::new(&OVER_SOFT_MESSAGE_LIMIT, over)
}

// For tests, we want to switch it on and off atomically.  For canbench, we want to
// actually count the instructions.
#[cfg(any(test, feature = "canbench-rs"))]
fn over_soft_message_limit() -> bool {
    if cfg!(test) {
        return OVER_SOFT_MESSAGE_LIMIT.with(|over| over.get());
    } else if cfg!(feature = "canbench-rs") {
        return CANBENCH_FAKE_INSTRUCTION_COUNTER.with(|counter| {
            let current_instruction_counter = ic_cdk::api::instruction_counter();
            let stored_value = counter.get();

            if let Some(limit) = stored_value {
                current_instruction_counter > limit
            } else {
                let limit = ic_cdk::api::instruction_counter() + SOFT_VOTING_INSTRUCTIONS_LIMIT;
                counter.set(Some(limit));
                false // Since it's the first time, assume not over limit
            }
        });
    }
    // We should not get here
    true
}

// Production implementation
#[cfg(not(any(test, feature = "canbench-rs")))]
fn over_soft_message_limit() -> bool {
    is_message_over_threshold(SOFT_VOTING_INSTRUCTIONS_LIMIT)
}

// canbench doesn't currently support query calls inside of benchmarks
// We send a no-op message to self to break up the call context into more messages
#[cfg(feature = "canbench-rs")]
async fn noop_self_call_if_over_instructions(
    message_threshold: u64,
    _panic_threshold: Option<u64>,
) -> Result<(), String> {
    if over_soft_message_limit() {
        let limit = ic_cdk::api::instruction_counter() + message_threshold;
        CANBENCH_FAKE_INSTRUCTION_COUNTER.with(|counter| {
            counter.set(Some(limit));
        });
    }
    Ok(())
}

// Production implementation
#[cfg(not(feature = "canbench-rs"))]
async fn noop_self_call_if_over_instructions(
    message_threshold: u64,
    panic_threshold: Option<u64>,
) -> Result<(), String> {
    ic_nervous_system_long_message::noop_self_call_if_over_instructions(
        message_threshold,
        panic_threshold,
    )
    .await
    .map_err(|e| e.to_string())
}

fn proposal_ballots(
    proposals: &mut BTreeMap<u64, ProposalData>,
    proposal_id: u64,
) -> Result<&mut HashMap<u64, Ballot>, String> {
    match proposals.get_mut(&proposal_id) {
        Some(proposal) => Ok(&mut proposal.ballots),
        None => {
            eprintln!(
                "{} Proposal {} not found, cannot operate on ballots",
                LOG_PREFIX, proposal_id
            );
            Err(format!("Proposal {proposal_id} not found."))
        }
    }
}

impl Governance {
    pub async fn cast_vote_and_cascade_follow(
        &mut self,
        proposal_id: ProposalId,
        voting_neuron_id: NeuronId,
        vote_of_neuron: Vote,
        topic: Topic,
    ) {
        let voting_started = self.env.now();

        if !self.heap_data.proposals.contains_key(&proposal_id.id) {
            // This is a critical error, but there is nothing that can be done about it
            // at this place.  We somehow have a vote for a proposal that doesn't exist.
            eprintln!(
                "error in cast_vote_and_cascade_follow: Proposal not found: {}",
                proposal_id.id
            );
            return;
        }

        // First we cast the ballot.
        self.record_neuron_vote(proposal_id, voting_neuron_id, vote_of_neuron, topic);

        // We process until voting is finished, and then do any other work that fits into the soft
        // limit of the current message.  Votes are guaranteed to be recorded before the function
        // returns, but recent_ballots for neurons might be recorded later in a timer job.  This
        // ensures we return to the caller in a reasonable amount of time.
        let mut is_voting_finished = false;

        while !is_voting_finished {
            // Now we process until we are done or we are over a limit and need to
            // make a self-call.
            with_voting_state_machines_mut(|voting_state_machines| {
                voting_state_machines.with_machine(proposal_id, topic, |machine| {
                    self.process_machine_until_soft_limit(machine, over_soft_message_limit);
                    is_voting_finished = machine.is_voting_finished();
                });
            });

            // This returns an error if we hit the hard limit, which should basically never happen
            // in production, but we need a way out of this loop in the worst case to prevent
            // the canister from being unable to upgrade.
            if let Err(e) = noop_self_call_if_over_instructions(
                SOFT_VOTING_INSTRUCTIONS_LIMIT,
                Some(HARD_VOTING_INSTRUCTIONS_LIMIT),
            )
            .await
            {
                println!(
                    "Error in cast_vote_and_cascade_follow, \
                        voting will be processed in timers: {}",
                    e
                );
                break;
            }
        }
        // We use the time from the beginning of the function to retain the behaviors needed
        // for wait for quiet even when votes can be processed asynchronously.
        self.recompute_proposal_tally(proposal_id, voting_started);
    }

    /// Record a neuron vote into the voting state machine, then do nothing else.
    fn record_neuron_vote(
        &mut self,
        proposal_id: ProposalId,
        voting_neuron_id: NeuronId,
        vote: Vote,
        topic: Topic,
    ) {
        with_voting_state_machines_mut(|voting_state_machines| {
            if let Ok(ballots) = proposal_ballots(&mut self.heap_data.proposals, proposal_id.id) {
                voting_state_machines.with_machine(proposal_id, topic, |machine| {
                    machine.cast_vote(ballots, voting_neuron_id, vote)
                });
            }
        });
    }

    /// Process a single voting state machine until it is over the soft limit or finished, then return
    fn process_machine_until_soft_limit(
        &mut self,
        machine: &mut ProposalVotingStateMachine,
        is_over_soft_limit: fn() -> bool,
    ) {
        let proposal_id = machine.proposal_id;
        let Ok(ballots) = proposal_ballots(&mut self.heap_data.proposals, proposal_id.id) else {
            eprintln!(
                "{} Proposal {} for voting machine not found.  Machine cannot complete work.",
                LOG_PREFIX, proposal_id.id
            );
            return;
        };

        while !machine.is_completely_finished() {
            machine.continue_processing(&mut self.neuron_store, ballots, is_over_soft_limit);

            if is_over_soft_limit() {
                break;
            }
        }
    }

    /// Process all voting state machines.  This function is called in the timer job.
    /// It processes voting state machines until the soft limit is reached or there is no work to do.
    pub async fn process_voting_state_machines(&mut self) {
        let mut proposals_with_new_votes_cast = vec![];
        with_voting_state_machines_mut(|voting_state_machines| {
            loop {
                if voting_state_machines
                    .with_next_machine(|(proposal_id, machine)| {
                        if !machine.is_voting_finished() {
                            proposals_with_new_votes_cast.push(proposal_id);
                        }
                        // We need to keep track of which proposals we processed
                        self.process_machine_until_soft_limit(machine, over_soft_message_limit);
                    })
                    .is_none()
                {
                    break;
                };

                if over_soft_message_limit() {
                    break;
                }
            }
        });

        // Most of the time, we are not going to see new votes cast in this function, but this
        // is here to make sure the normal proposal processing still applies
        for proposal_id in proposals_with_new_votes_cast {
            self.recompute_proposal_tally(proposal_id, self.env.now());
            self.process_proposal(proposal_id.id);

            if let Err(e) = noop_self_call_if_over_instructions(
                SOFT_VOTING_INSTRUCTIONS_LIMIT,
                Some(HARD_VOTING_INSTRUCTIONS_LIMIT),
            )
            .await
            {
                println!(
                    "Used too many instructions in process_voting_state_machines, \
                       exiting before finishing: {}",
                    e
                );
                break;
            }
        }
    }

    /// Recompute the tally for a proposal, using the time provided as the current time.
    fn recompute_proposal_tally(&mut self, proposal_id: ProposalId, now: u64) {
        let voting_period_seconds_fn = self.voting_period_seconds();

        let proposal = match self.heap_data.proposals.get_mut(&proposal_id.id) {
            None => {
                // This is a critical error, but there is nothing that can be done about it
                // at this place.  We somehow have a vote for a proposal that doesn't exist.
                eprintln!(
                    "error in recompute_proposal_tally: Proposal not found: {}",
                    proposal_id.id
                );
                return;
            }
            Some(proposal) => &mut *proposal,
        };
        let topic = proposal.topic();
        proposal.recompute_tally(now, voting_period_seconds_fn(topic));
    }
}

pub(crate) struct VotingStateMachines<Memory>
where
    Memory: ic_stable_structures::Memory,
{
    // Up to one machine per proposal, to avoid having to do unnecessary checks for followers that
    // might follow.  This allows the state machines to be used across multiple messages
    // without duplicating state and memory usage.
    machines: StableBTreeMap<ProposalId, crate::pb::v1::ProposalVotingStateMachine, Memory>,
}

impl<Memory: ic_stable_structures::Memory> VotingStateMachines<Memory> {
    pub(crate) fn new(memory: Memory) -> Self {
        Self {
            machines: StableBTreeMap::init(memory),
        }
    }

    /// Optionally executes callback on the next machine, if one exists.  Otherwise, this does
    /// nothing.
    fn with_next_machine<R>(
        &mut self,
        mut callback: impl FnMut((ProposalId, &mut ProposalVotingStateMachine)) -> R,
    ) -> Option<R> {
        if let Some((proposal_id, proto)) = self.machines.pop_first() {
            let mut machine = ProposalVotingStateMachine::try_from(proto).unwrap();
            let result = callback((proposal_id, &mut machine));
            if !machine.is_completely_finished() {
                self.machines.insert(
                    proposal_id,
                    crate::pb::v1::ProposalVotingStateMachine::from(machine),
                );
            }
            Some(result)
        } else {
            None
        }
    }

    /// Perform a callback with a given voting machine.  If the machine is finished, it is removed
    /// after the callback.
    pub(crate) fn with_machine<R>(
        &mut self,
        proposal_id: ProposalId,
        topic: Topic,
        callback: impl FnOnce(&mut ProposalVotingStateMachine) -> R,
    ) -> R {
        // We use remove here because we delete machines if they're done.
        // This reduces stable memory calls in the case where the machine is completed,
        // as we do not need to get it and then remove it later.
        let mut machine = self
            .machines
            .remove(&proposal_id)
            // This unwrap should be safe because we only write valid machines below.
            .map(|proto| ProposalVotingStateMachine::try_from(proto).unwrap())
            .unwrap_or(ProposalVotingStateMachine::new(proposal_id, topic));

        let result = callback(&mut machine);

        // Save the machine again if it's not finished.
        if !machine.is_completely_finished() {
            self.machines.insert(
                proposal_id,
                crate::pb::v1::ProposalVotingStateMachine::from(machine),
            );
        }
        result
    }

    /// Returns true if the machine has votes to process.
    pub(crate) fn machine_has_votes_to_process(&self, proposal_id: ProposalId) -> bool {
        if let Some(proto) = self.machines.get(&proposal_id) {
            !ProposalVotingStateMachine::try_from(proto)
                .unwrap()
                .is_voting_finished()
        } else {
            false
        }
    }
}

#[derive(Clone, Debug, PartialEq, Default)]
pub(crate) struct ProposalVotingStateMachine {
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

impl From<ProposalVotingStateMachine> for crate::pb::v1::ProposalVotingStateMachine {
    fn from(value: ProposalVotingStateMachine) -> Self {
        Self {
            proposal_id: Some(value.proposal_id),
            topic: value.topic as i32,
            neurons_to_check_followers: value.neurons_to_check_followers.into_iter().collect(),
            followers_to_check: value.followers_to_check.into_iter().collect(),
            recent_neuron_ballots_to_record: value
                .recent_neuron_ballots_to_record
                .into_iter()
                .map(|(n, v)| (n.id, v as i32))
                .collect(),
        }
    }
}

impl TryFrom<crate::pb::v1::ProposalVotingStateMachine> for ProposalVotingStateMachine {
    type Error = String;

    fn try_from(value: crate::pb::v1::ProposalVotingStateMachine) -> Result<Self, Self::Error> {
        Ok(Self {
            proposal_id: value.proposal_id.ok_or("Proposal ID must be specified")?,
            topic: Topic::try_from(value.topic).map_err(|e| e.to_string())?,
            neurons_to_check_followers: value.neurons_to_check_followers.into_iter().collect(),
            followers_to_check: value.followers_to_check.into_iter().collect(),
            recent_neuron_ballots_to_record: value
                .recent_neuron_ballots_to_record
                .into_iter()
                .map(|(n, v)| {
                    let neuron_id = NeuronId::from_u64(n);
                    let vote = Vote::try_from(v).map_err(|e| e.to_string())?; // Propagate the error directly
                    Ok((neuron_id, vote))
                })
                .collect::<Result<_, Self::Error>>()?,
        })
    }
}

impl Storable for crate::pb::v1::ProposalVotingStateMachine {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::from(self.encode_to_vec())
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Self::decode(&bytes[..])
            // Convert from Result to Self. (Unfortunately, it seems that
            // panic is unavoidable in the case of Err.)
            .expect("Unable to deserialize ProposalVotingStateMachine.")
    }

    const BOUND: Bound = Bound::Unbounded;
}

impl ProposalVotingStateMachine {
    fn new(proposal_id: ProposalId, topic: Topic) -> Self {
        Self {
            proposal_id,
            topic,
            neurons_to_check_followers: Default::default(),
            followers_to_check: Default::default(),
            recent_neuron_ballots_to_record: Default::default(),
        }
    }

    /// Returns true if this machine has no more work to do.
    fn is_completely_finished(&self) -> bool {
        self.neurons_to_check_followers.is_empty()
            && self.followers_to_check.is_empty()
            && self.recent_neuron_ballots_to_record.is_empty()
    }

    /// Returns true if all following is processed and all votes are cast on the proposal.
    /// Recent neuron ballots could still be left, however.
    pub(crate) fn is_voting_finished(&self) -> bool {
        self.neurons_to_check_followers.is_empty() && self.followers_to_check.is_empty()
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
        is_over_instructions_limit: fn() -> bool,
    ) {
        let voting_finished = self.is_voting_finished();

        if !voting_finished {
            while let Some(neuron_id) = self.neurons_to_check_followers.pop_first() {
                self.add_followers_to_check(neuron_store, neuron_id, self.topic);

                // Before we check the next one, see if we're over the limit.
                if is_over_instructions_limit() {
                    return;
                }
            }

            // Memory optimization, will not cause tests to fail if removed
            retain_neurons_with_castable_ballots(&mut self.followers_to_check, ballots);

            while let Some(follower) = self.followers_to_check.pop_first() {
                let vote = match neuron_store
                    .neuron_would_follow_ballots(follower, self.topic, ballots)
                {
                    Ok(vote) => vote,
                    Err(e) => {
                        // This is a bad inconsistency, but there is
                        // nothing that can be done about it at this
                        // place.  We somehow have followers recorded that don't exist.
                        eprintln!(
                            "error in cast_vote_and_cascade_follow when gathering induction votes: {:?}",
                            e
                        );
                        Vote::Unspecified
                    }
                };
                // Casting vote immediately might affect other follower votes, which makes
                // voting resolution take fewer iterations.
                // Vote::Unspecified is ignored by cast_vote.
                self.cast_vote(ballots, follower, vote);

                if is_over_instructions_limit() {
                    return;
                }
            }
        } else {
            while let Some((neuron_id, vote)) = self.recent_neuron_ballots_to_record.pop_first() {
                match neuron_store.record_neuron_vote(neuron_id, self.topic, self.proposal_id, vote)
                {
                    Ok(_) => {}
                    Err(e) => {
                        // This is a bad inconsistency, but there is
                        // nothing that can be done about it at this
                        // place.  We somehow have followers recorded that don't exist.
                        eprintln!(
                            "error in cast_vote_and_cascade_follow when gathering induction votes: {:?}",
                            e
                        );
                    }
                };

                if is_over_instructions_limit() {
                    return;
                }
            }
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
    use crate::canister_state::{governance_mut, set_governance_for_tests};
    use crate::test_utils::MockRandomness;
    use crate::{
        governance::{Governance, REWARD_DISTRIBUTION_PERIOD_SECONDS},
        neuron::{DissolveStateAndAge, Neuron, NeuronBuilder},
        neuron_store::NeuronStore,
        pb::v1::{
            Ballot, Followees, Motion, Proposal, ProposalData, Tally, Topic, Vote,
            VotingPowerEconomics, WaitForQuietState, proposal::Action,
        },
        storage::with_voting_state_machines_mut,
        test_utils::{
            ExpectedCallCanisterMethodCallArguments, MockEnvironment, StubCMC, StubIcpLedger,
        },
        voting::{
            ProposalVotingStateMachine, VotingStateMachines,
            temporarily_set_over_soft_message_limit,
        },
    };
    use candid::Encode;
    use futures::FutureExt;
    use ic_base_types::PrincipalId;
    use ic_ledger_core::Tokens;
    use ic_nervous_system_long_message::in_test_temporarily_set_call_context_over_threshold;
    use ic_nervous_system_timers::test::run_pending_timers_every_interval_for_count;
    use ic_nns_common::pb::v1::{NeuronId, ProposalId};
    use ic_nns_constants::GOVERNANCE_CANISTER_ID;
    use ic_nns_governance_api::Governance as ApiGovernance;
    use ic_stable_structures::DefaultMemoryImpl;
    use icp_ledger::Subaccount;
    use maplit::hashmap;
    use std::collections::{BTreeMap, BTreeSet, HashMap};
    use std::sync::Arc;

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
        let dissolve_delay_seconds =
            VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS;
        let aging_since_timestamp_seconds = now - dissolve_delay_seconds;

        let dissolve_state_and_age = DissolveStateAndAge::NotDissolving {
            dissolve_delay_seconds,
            aging_since_timestamp_seconds,
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
        let mut governance = Governance::new(
            Default::default(),
            Arc::new(MockEnvironment::new(Default::default(), 0)),
            Arc::new(StubIcpLedger {}),
            Arc::new(StubCMC {}),
            Box::new(MockRandomness::new()),
        );

        let make_neuron = |id: u64, followees: Vec<u64>| {
            make_neuron(
                id,
                100,
                hashmap! {topic.into() => Followees {
                    followees: followees.into_iter().map(|id| NeuronId { id }).collect(),
                }},
            )
        };

        let add_neuron_with_ballot = |neuron_store: &mut NeuronStore,
                                      ballots: &mut HashMap<u64, Ballot>,
                                      id: u64,
                                      followees: Vec<u64>,
                                      vote: Vote| {
            let neuron = make_neuron(id, followees);
            let deciding_voting_power =
                neuron.deciding_voting_power(&VotingPowerEconomics::DEFAULT, now);
            neuron_store.add_neuron(neuron).unwrap();
            ballots.insert(id, make_ballot(deciding_voting_power, vote));
        };

        let add_neuron_without_ballot =
            |neuron_store: &mut NeuronStore, id: u64, followees: Vec<u64>| {
                let neuron = make_neuron(id, followees);
                neuron_store.add_neuron(neuron).unwrap();
            };

        let mut proposal = ProposalData {
            id: Some(ProposalId { id: 1 }),
            ..Default::default()
        };
        for id in 1..=5 {
            // Each neuron follows all neurons with a lower id
            let followees = (1..id).collect();

            add_neuron_with_ballot(
                &mut governance.neuron_store,
                &mut proposal.ballots,
                id,
                followees,
                Vote::Unspecified,
            );
        }
        // Add another neuron that follows both a neuron with a ballot and without a ballot
        add_neuron_with_ballot(
            &mut governance.neuron_store,
            &mut proposal.ballots,
            6,
            vec![1, 7],
            Vote::Unspecified,
        );

        // Add a neuron without a ballot for neuron 6 to follow.
        add_neuron_without_ballot(&mut governance.neuron_store, 7, vec![1]);

        governance.heap_data.proposals.insert(1, proposal);

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
                .with_neuron(&neuron_id, |n| {
                    n.deciding_voting_power(&VotingPowerEconomics::DEFAULT, now)
                })
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
        let topic = Topic::ApplicationCanisterManagement;

        let make_neuron = |id: u64, followees: Vec<u64>| {
            make_neuron(
                id,
                100,
                hashmap! {topic.into() => Followees {
                    followees: followees.into_iter().map(|id| NeuronId { id }).collect(),
                }},
            )
        };

        let add_neuron_with_ballot = |neuron_store: &mut NeuronStore,
                                      ballots: &mut HashMap<u64, Ballot>,
                                      id: u64,
                                      followees: Vec<u64>,
                                      vote: Vote| {
            let neuron = make_neuron(id, followees);
            let deciding_voting_power =
                neuron.deciding_voting_power(&VotingPowerEconomics::DEFAULT, now);
            neuron_store.add_neuron(neuron).unwrap();
            ballots.insert(id, make_ballot(deciding_voting_power, vote));
        };

        let add_neuron_without_ballot =
            |neuron_store: &mut NeuronStore, id: u64, followees: Vec<u64>| {
                let neuron = make_neuron(id, followees);
                neuron_store.add_neuron(neuron).unwrap();
            };

        let mut governance = Governance::new(
            Default::default(),
            Arc::new(MockEnvironment::new(Default::default(), 234)),
            Arc::new(StubIcpLedger {}),
            Arc::new(StubCMC {}),
            Box::new(MockRandomness::new()),
        );

        let mut proposal = ProposalData {
            id: Some(ProposalId { id: 1 }),
            ..Default::default()
        };

        for id in 1..=5 {
            // Each neuron follows all neurons with a lower id
            let followees = (1..id).collect();

            add_neuron_with_ballot(
                &mut governance.neuron_store,
                &mut proposal.ballots,
                id,
                followees,
                Vote::Unspecified,
            );
        }
        // Add another neuron that follows both a neuron with a ballot and without a ballot
        add_neuron_with_ballot(
            &mut governance.neuron_store,
            &mut proposal.ballots,
            6,
            vec![1, 7],
            Vote::Unspecified,
        );

        // Add a neuron without a ballot for neuron 6 to follow.
        add_neuron_without_ballot(&mut governance.neuron_store, 7, vec![1]);

        governance.heap_data.proposals.insert(1, proposal);

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
                .with_neuron(&neuron_id, |n| {
                    n.deciding_voting_power(&VotingPowerEconomics::DEFAULT, now)
                })
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
        let expected_tally = Tally {
            timestamp_seconds: 234,
            yes: 530,
            no: 0,
            total: 636,
        };
        assert_eq!(
            governance
                .heap_data
                .proposals
                .get(&1)
                .unwrap()
                .latest_tally
                .unwrap(),
            expected_tally
        );
    }

    fn add_neuron_with_ballot(
        neuron_store: &mut NeuronStore,
        ballots: &mut HashMap<u64, Ballot>,
        neuron: Neuron,
    ) {
        let cached_stake = neuron.cached_neuron_stake_e8s;
        let id = neuron.id().id;
        neuron_store.add_neuron(neuron).unwrap();
        ballots.insert(
            id,
            Ballot {
                vote: Vote::Unspecified as i32,
                voting_power: cached_stake,
            },
        );
    }

    #[test]
    fn test_is_completely_finished() {
        let mut state_machine = ProposalVotingStateMachine {
            proposal_id: ProposalId { id: 0 },
            topic: Topic::Governance,
            neurons_to_check_followers: BTreeSet::new(),
            followers_to_check: BTreeSet::new(),
            recent_neuron_ballots_to_record: BTreeMap::new(),
        };

        assert!(state_machine.is_completely_finished());

        state_machine
            .neurons_to_check_followers
            .insert(NeuronId { id: 0 });
        assert!(!state_machine.is_completely_finished());
        state_machine.neurons_to_check_followers.clear();

        state_machine.followers_to_check.insert(NeuronId { id: 0 });
        assert!(!state_machine.is_completely_finished());
        state_machine.followers_to_check.clear();

        state_machine
            .recent_neuron_ballots_to_record
            .insert(NeuronId { id: 0 }, Vote::Yes);
        assert!(!state_machine.is_completely_finished());
        state_machine.recent_neuron_ballots_to_record.clear();
    }

    #[test]
    fn test_continue_processsing() {
        let mut state_machine =
            ProposalVotingStateMachine::new(ProposalId { id: 0 }, Topic::NetworkEconomics);

        let mut ballots = HashMap::new();
        let mut neuron_store = NeuronStore::new(Default::default());

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
        state_machine.continue_processing(&mut neuron_store, &mut ballots, || false);

        assert_eq!(
            ballots,
            hashmap! {
            1 => Ballot { vote: Vote::Yes as i32, voting_power: 101 },
            2 => Ballot { vote: Vote::Yes as i32, voting_power: 102 }}
        );

        // First, we see not finished at all
        assert!(!state_machine.is_completely_finished());
        assert!(!state_machine.is_voting_finished());

        // Now we see voting finished but not recording recent ballots finished
        state_machine.continue_processing(&mut neuron_store, &mut ballots, || false);
        assert!(!state_machine.is_completely_finished());
        assert!(state_machine.is_voting_finished());

        assert_eq!(
            neuron_store
                .with_neuron(&NeuronId { id: 1 }, |n| {
                    n.recent_ballots.first().cloned()
                })
                .unwrap(),
            None
        );
        assert_eq!(
            neuron_store
                .with_neuron(&NeuronId { id: 2 }, |n| {
                    n.recent_ballots.first().cloned()
                })
                .unwrap(),
            None
        );

        state_machine.continue_processing(&mut neuron_store, &mut ballots, || false);
        assert!(state_machine.is_completely_finished());

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
    }

    #[test]
    fn test_machine_has_votes_to_process() {
        let mut voting_state_machines: VotingStateMachines<DefaultMemoryImpl> =
            VotingStateMachines::new(Default::default());
        let proposal_id = ProposalId { id: 0 };
        let topic = Topic::NetworkEconomics;
        let mut state_machine = ProposalVotingStateMachine::new(proposal_id, topic);

        assert!(!voting_state_machines.machine_has_votes_to_process(proposal_id));

        voting_state_machines.machines.insert(
            proposal_id,
            crate::pb::v1::ProposalVotingStateMachine::from(state_machine.clone()),
        );
        assert!(!voting_state_machines.machine_has_votes_to_process(proposal_id));

        state_machine
            .neurons_to_check_followers
            .insert(NeuronId { id: 0 });
        voting_state_machines.machines.insert(
            proposal_id,
            crate::pb::v1::ProposalVotingStateMachine::from(state_machine),
        );
        assert!(voting_state_machines.machine_has_votes_to_process(proposal_id));
    }

    #[test]
    fn test_cyclic_following_will_terminate() {
        let mut state_machine =
            ProposalVotingStateMachine::new(ProposalId { id: 0 }, Topic::NetworkEconomics);

        let mut ballots = HashMap::new();
        let mut neuron_store = NeuronStore::new(Default::default());

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
        assert!(state_machine.is_completely_finished());

        // We assert it is done after checking both sets of followers
        state_machine.cast_vote(&mut ballots, NeuronId { id: 1 }, Vote::Yes);
        state_machine.continue_processing(&mut neuron_store, &mut ballots, || false);
        state_machine.continue_processing(&mut neuron_store, &mut ballots, || false);
        state_machine.continue_processing(&mut neuron_store, &mut ballots, || false);
        assert!(state_machine.is_completely_finished());
    }

    #[test]
    fn test_cast_vote_and_cascade_follow_always_finishes_processing_ballots() {
        let _a = temporarily_set_over_soft_message_limit(true);
        let topic = Topic::NetworkEconomics;
        let mut governance = Governance::new(
            Default::default(),
            Arc::new(MockEnvironment::new(Default::default(), 0)),
            Arc::new(StubIcpLedger {}),
            Arc::new(StubCMC {}),
            Box::new(MockRandomness::new()),
        );

        let mut proposal = ProposalData {
            id: Some(ProposalId { id: 1 }),
            ..Default::default()
        };

        for i in 1..=100 {
            let mut followees = HashMap::new();
            if i != 1 {
                // cascading followees
                followees.insert(
                    topic as i32,
                    Followees {
                        followees: vec![NeuronId { id: i - 1 }],
                    },
                );
            }
            add_neuron_with_ballot(
                &mut governance.neuron_store,
                &mut proposal.ballots,
                make_neuron(i, 100, followees),
            );
        }

        governance.heap_data.proposals.insert(1, proposal);

        // In our test configuration, we always return "true" for is_over_instructions_limit()
        // So our logic is at least resilient to not having enough instructions, and is able
        // to continue working.  Without this, it could be possible to choose wrong settings
        // that make it impossible to advance.
        governance
            .cast_vote_and_cascade_follow(
                ProposalId { id: 1 },
                NeuronId { id: 1 },
                Vote::Yes,
                topic,
            )
            .now_or_never()
            .unwrap();

        with_voting_state_machines_mut(|voting_state_machines| {
            // We are asserting here that the machine is cleaned up after it is done.
            assert!(
                !voting_state_machines.machines.is_empty(),
                "Voting StateMachines? {:?}",
                voting_state_machines.machines.first_key_value()
            );

            voting_state_machines.with_machine(ProposalId { id: 1 }, topic, |machine| {
                assert!(!machine.is_completely_finished());
                assert!(machine.is_voting_finished());
            });
        });

        let ballots = &governance.heap_data.proposals.get(&1).unwrap().ballots;
        assert_eq!(ballots.len(), 100);
        for (_, ballot) in ballots.iter() {
            assert_eq!(ballot.vote, Vote::Yes as i32);
        }
    }

    #[test]
    fn test_cast_vote_and_cascade_breaks_if_over_hard_limit() {
        let topic = Topic::NetworkEconomics;
        let mut governance = Governance::new(
            Default::default(),
            Arc::new(MockEnvironment::new(Default::default(), 0)),
            Arc::new(StubIcpLedger {}),
            Arc::new(StubCMC {}),
            Box::new(MockRandomness::new()),
        );

        let mut proposal = ProposalData {
            id: Some(ProposalId { id: 1 }),
            ..Default::default()
        };

        for i in 1..=10 {
            let mut followees = HashMap::new();
            if i != 1 {
                // cascading followees
                followees.insert(
                    topic as i32,
                    Followees {
                        followees: vec![NeuronId { id: i - 1 }],
                    },
                );
            }
            add_neuron_with_ballot(
                &mut governance.neuron_store,
                &mut proposal.ballots,
                make_neuron(i, 100, followees),
            );
        }

        governance.heap_data.proposals.insert(1, proposal);

        let _e = temporarily_set_over_soft_message_limit(true);
        let _f = in_test_temporarily_set_call_context_over_threshold();
        governance
            .cast_vote_and_cascade_follow(
                ProposalId { id: 1 },
                NeuronId { id: 1 },
                Vote::Yes,
                topic,
            )
            .now_or_never()
            .unwrap();

        with_voting_state_machines_mut(|voting_state_machines| {
            assert!(!voting_state_machines.machines.is_empty());
            assert!(voting_state_machines.machine_has_votes_to_process(ProposalId { id: 1 }));
        });
    }

    #[test]
    fn test_cast_vote_and_cascade_follow_doesnt_record_recent_ballots_after_first_soft_limit() {
        let _a = temporarily_set_over_soft_message_limit(true);
        let topic = Topic::NetworkEconomics;
        let mut governance = Governance::new(
            Default::default(),
            Arc::new(MockEnvironment::new(Default::default(), 0)),
            Arc::new(StubIcpLedger {}),
            Arc::new(StubCMC {}),
            Box::new(MockRandomness::new()),
        );

        let mut proposal = ProposalData {
            id: Some(ProposalId { id: 1 }),
            ..Default::default()
        };

        for i in 1..=9 {
            let mut followees = HashMap::new();
            if i != 1 {
                // cascading followees
                followees.insert(
                    topic as i32,
                    Followees {
                        followees: vec![NeuronId { id: i - 1 }],
                    },
                );
            }
            add_neuron_with_ballot(
                &mut governance.neuron_store,
                &mut proposal.ballots,
                make_neuron(i, 100, followees),
            );
        }

        governance.heap_data.proposals.insert(1, proposal);

        // In test mode, we are always saying we're over the soft-message limit, so we know that
        // this will hit that limit and not record any recent ballots.
        governance
            .cast_vote_and_cascade_follow(
                ProposalId { id: 1 },
                NeuronId { id: 1 },
                Vote::Yes,
                topic,
            )
            .now_or_never()
            .unwrap();

        with_voting_state_machines_mut(|voting_state_machines| {
            assert!(!voting_state_machines.machines.is_empty(),);
        });

        let ballots = &governance.heap_data.proposals.get(&1).unwrap().ballots;
        assert_eq!(ballots.len(), 9);
        for (_, ballot) in ballots.iter() {
            assert_eq!(ballot.vote, Vote::Yes as i32);
        }

        for i in 1..=9 {
            let recent_ballots = governance
                .neuron_store
                .with_neuron(&NeuronId { id: i }, |n| n.recent_ballots.clone())
                .unwrap();
            assert_eq!(recent_ballots.len(), 0, "Neuron {i} has recent ballots");
        }

        // Now let's run the "timer job" to make sure it eventually drains everything.
        for _ in 1..20 {
            governance
                .process_voting_state_machines()
                .now_or_never()
                .unwrap();
        }

        with_voting_state_machines_mut(|voting_state_machines| {
            // We are asserting here that the machine is cleaned up after it is done.
            assert!(
                voting_state_machines.machines.is_empty(),
                "Voting StateMachines? {:?}",
                voting_state_machines.machines.first_key_value()
            );
        });

        for i in 1..=9 {
            let recent_ballots = governance
                .neuron_store
                .with_neuron(&NeuronId { id: i }, |n| n.recent_ballots.clone())
                .unwrap();
            assert_eq!(recent_ballots.len(), 1, "Neuron {i} has recent ballots");
        }
    }

    #[test]
    fn test_process_voting_state_machines_processes_votes_and_executes_proposals() {
        let topic = Topic::Governance;
        let mut governance = Governance::new(
            Default::default(),
            Arc::new(MockEnvironment::new(Default::default(), 1234)),
            Arc::new(StubIcpLedger {}),
            Arc::new(StubCMC {}),
            Box::new(MockRandomness::new()),
        );

        let mut proposal = ProposalData {
            id: Some(ProposalId { id: 1 }),
            proposal: Some(Proposal {
                title: Some("".to_string()),
                summary: "".to_string(),
                url: "".to_string(),
                action: Some(Action::Motion(Motion {
                    motion_text: "".to_string(),
                })),
                self_describing_action: None,
            }),
            ..Default::default()
        };

        for i in 1..=9 {
            let mut followees = HashMap::new();
            if i != 1 {
                // cascading followees
                followees.insert(
                    topic as i32,
                    Followees {
                        followees: vec![NeuronId { id: i - 1 }],
                    },
                );
            }
            add_neuron_with_ballot(
                &mut governance.neuron_store,
                &mut proposal.ballots,
                make_neuron(i, 100, followees),
            );
        }

        governance.heap_data.proposals.insert(1, proposal);

        governance.record_neuron_vote(ProposalId { id: 1 }, NeuronId { id: 1 }, Vote::Yes, topic);

        with_voting_state_machines_mut(|voting_state_machines| {
            assert!(!voting_state_machines.machines.is_empty(),);
            voting_state_machines.with_machine(ProposalId { id: 1 }, topic, |machine| {
                assert!(!machine.is_voting_finished());
            });
        });

        // In test mode, we are always saying we're over the soft-message limit, so we know that
        // this will hit that limit and not record any recent ballots.
        governance
            .process_voting_state_machines()
            .now_or_never()
            .unwrap();

        with_voting_state_machines_mut(|voting_state_machines| {
            assert!(voting_state_machines.machines.is_empty(),);
        });

        let ballots = &governance.heap_data.proposals.get(&1).unwrap().ballots;
        assert_eq!(ballots.len(), 9);
        for (_, ballot) in ballots.iter() {
            assert_eq!(ballot.vote, Vote::Yes as i32);
        }

        for i in 1..=9 {
            let recent_ballots = governance
                .neuron_store
                .with_neuron(&NeuronId { id: i }, |n| n.recent_ballots.clone())
                .unwrap();
            assert_eq!(recent_ballots.len(), 1, "Neuron {i} has recent ballots");
        }

        let proposal = governance.heap_data.proposals.get(&1).unwrap();
        assert_eq!(proposal.latest_tally.unwrap().yes, 900);
        // It is now "decided"
        assert_eq!(proposal.decided_timestamp_seconds, 1234);
    }

    #[test]
    fn test_rewards_distribution_is_blocked_on_votes_not_cast_in_state_machine() {
        let now = 1733433219;
        let topic = Topic::Governance;
        let environment = MockEnvironment::new(
            vec![(
                ExpectedCallCanisterMethodCallArguments::new(
                    GOVERNANCE_CANISTER_ID,
                    "get_build_metadata",
                    Encode!().unwrap(),
                ),
                Ok(vec![]),
            )],
            now,
        );
        let now_setter = environment.now_setter();

        let mut governance = Governance::new(
            ApiGovernance {
                genesis_timestamp_seconds: now - REWARD_DISTRIBUTION_PERIOD_SECONDS,
                ..Default::default()
            },
            Arc::new(environment),
            Arc::new(StubIcpLedger {}),
            Arc::new(StubCMC {}),
            Box::new(MockRandomness::new()),
        );

        let mut proposal = ProposalData {
            id: Some(ProposalId { id: 1 }),
            proposal: Some(Proposal {
                title: Some("".to_string()),
                summary: "".to_string(),
                url: "".to_string(),
                action: Some(Action::Motion(Motion {
                    motion_text: "".to_string(),
                })),
                self_describing_action: None,
            }),
            wait_for_quiet_state: Some(WaitForQuietState {
                current_deadline_timestamp_seconds: now - 100,
            }),
            decided_timestamp_seconds: now - 100,
            ..Default::default()
        };

        for i in 1..=9 {
            let mut followees = HashMap::new();
            if i != 1 {
                // cascading followees
                followees.insert(
                    topic as i32,
                    Followees {
                        followees: vec![NeuronId { id: i - 1 }],
                    },
                );
            }
            add_neuron_with_ballot(
                &mut governance.neuron_store,
                &mut proposal.ballots,
                make_neuron(i, 100_000_000, followees),
            );
        }

        // Neurons should all get rewards.
        for ballot in proposal.ballots.iter_mut() {
            ballot.1.vote = Vote::Yes as i32;
        }

        add_neuron_with_ballot(
            &mut governance.neuron_store,
            &mut proposal.ballots,
            make_neuron(
                100,
                100_000_000,
                hashmap! {
                topic as i32 => Followees { followees: vec![NeuronId { id: 1 }] }},
            ),
        );

        governance.heap_data.proposals.insert(1, proposal);

        assert_eq!(
            governance
                .neuron_store
                .with_neuron(&NeuronId { id: 1 }, |n| n.maturity_e8s_equivalent)
                .unwrap(),
            0
        );

        governance.record_neuron_vote(ProposalId { id: 1 }, NeuronId { id: 100 }, Vote::Yes, topic);

        with_voting_state_machines_mut(|voting_state_machines| {
            voting_state_machines.with_machine(ProposalId { id: 1 }, topic, |machine| {
                assert!(!machine.is_voting_finished());
            });
        });

        assert_eq!(
            governance
                .neuron_store
                .with_neuron(&NeuronId { id: 1 }, |n| n.maturity_e8s_equivalent)
                .unwrap(),
            0
        );

        // Because of how the timers work, we need to shift governance into global state
        // to make this work, so that the timer accesses the same value of governance.
        set_governance_for_tests(governance);
        let governance = governance_mut();
        governance.distribute_voting_rewards_to_neurons(Tokens::from_e8s(100_000_000));
        run_pending_timers_every_interval_for_count(core::time::Duration::from_secs(2), 2);

        assert_eq!(
            governance
                .neuron_store
                .with_neuron(&NeuronId { id: 1 }, |n| n.maturity_e8s_equivalent)
                .unwrap(),
            0
        );

        now_setter(now + REWARD_DISTRIBUTION_PERIOD_SECONDS + 1);
        // Finish processing the vote

        governance
            .process_voting_state_machines()
            .now_or_never()
            .unwrap();
        governance.distribute_voting_rewards_to_neurons(Tokens::from_e8s(100_000_000));
        // Now rewards should be able to be distributed
        run_pending_timers_every_interval_for_count(core::time::Duration::from_secs(2), 2);

        assert_eq!(
            governance
                .neuron_store
                .with_neuron(&NeuronId { id: 1 }, |n| n.maturity_e8s_equivalent)
                .unwrap(),
            5474
        );
    }

    #[test]
    fn test_can_make_decision_is_false_if_expired_but_votes_not_recorded() {
        let now = 99;
        // We are using this value b/c it's irrelevant to the test if
        // wait_for_quiet_state is set.
        let voting_period_seconds = u64::MAX;
        let mut proposal_data = ProposalData {
            id: Some(ProposalId { id: 1 }),
            latest_tally: Some(Tally {
                timestamp_seconds: 100,
                yes: 51,
                no: 0,
                total: 100,
            }),
            wait_for_quiet_state: Some(WaitForQuietState {
                current_deadline_timestamp_seconds: 100,
            }),
            ..Default::default()
        };

        // First we test majority switch
        assert!(proposal_data.can_make_decision(now, voting_period_seconds));
        proposal_data.latest_tally.as_mut().unwrap().yes = 49;
        assert!(!proposal_data.can_make_decision(now, voting_period_seconds));

        let now = 101;
        assert!(proposal_data.can_make_decision(now, voting_period_seconds));

        with_voting_state_machines_mut(|vsm| {
            vsm.with_machine(ProposalId { id: 1 }, Topic::Governance, |machine| {
                // We don't actually care about the vote being persisted, we just need to represent work still to be done.
                machine.cast_vote(
                    &mut hashmap! { 1 => Ballot {vote: Vote::Unspecified as i32, voting_power: 100}},
                    NeuronId { id: 1 },
                    Vote::Yes,
                );
            })
        });
        // Now we should no longer be able to make a decision.
        assert!(!proposal_data.can_make_decision(now, voting_period_seconds));
    }
}
