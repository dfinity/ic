//! The purpose of the Network Nervous System (NNS) is to allow the
//! Internet Computer (IC) network to be governed in an open,
//! decentralized and secure manner. It has complete control over all
//! aspects of the IC network. For example, it can upgrade the protocol
//! and software used by the node machines that host the network, it
//! can induct new node operators and machines into the network, it
//! can create new subnets (special blockchains) to increase network
//! capacity, it can split subnets to divide their load, it can
//! configure economic parameters that control how much must be paid
//! by users for compute capacity, and in extremis it can freeze
//! malicious canister software (smart contracts) in order to protect
//! the network, and many other things. The NNS works by accepting
//! proposals, and deciding to adopt or reject them based on voting
//! activity by “neurons” that network participants have created.
//!
//! Neurons are also used by participants to submit new
//! proposals. After submission, proposals are either adopted or
//! rejected, which can happen almost immediately, or after some
//! delay, depending upon how the totality of neurons vote. Each
//! proposal is an instance of a specific “proposal type”, which
//! determines what information it contains. For each type of
//! proposal, the NNS maintains a corresponding system function, which
//! it invokes whenever an instance of the type is adopted. When a
//! proposal is adopted by the NNS, it invokes the corresponding
//! system function by drawing information from the proposal’s content
//! to fill the parameters. Each type of proposal belongs to a
//! specific “proposal topic”, such as “#NodeAdmin” or
//! “#NetworkEconomics”, which determines details about how it will be
//! processed. To prevent users spamming the NNS, a fee is levied on
//! the neuron that submitted a proposal if it is rejected.
//!
//! The NNS decides whether to adopt or reject proposals by watching
//! how neurons emit votes. Anyone can create a neuron by locking
//! balances of “ICP governance tokens”, a special native utility
//! token that is hosted on a ledger inside the NNS. When a user
//! creates a neuron, the locked balance of ICP can only be unlocked
//! by fully dissolving (“destroying”) the neuron. Users are
//! incentivized to create neurons because they earn rewards when they
//! vote on proposals. Rewards take the form of newly minted ICP that
//! are created by the NNS. The quantity of ICP rewards disbursed to a
//! neuron derive from such factors as the size of the locked balance,
//! the minimum lockup period remaining (the “dissolve delay”), the
//! neuron’s “age”, the proportion of possible votes it has correctly
//! participated in, and the sum of voting activity across all
//! neurons, since the overall total rewards disbursed is capped and
//! must be divided.
//!
//! Each neuron has a currently configured “dissolve delay”. At any
//! moment, this determines how long it will take to dissolve if it is
//! placed into “dissolve mode”. Once a neuron has been placed into
//! “dissolve mode”, its dissolve delay falls over the passage of
//! time, rather like a kitchen timer, until it reaches zero,
//! whereupon its owner can perform a final action to make it dissolve
//! completely, and unlock the balance of ICP. The dissolve delay
//! creates an economic incentive for neuron owners to vote with a
//! view to maximizing the value of their locked ICP balances at a
//! future date. Since the price of ICP is a proxy for the success of
//! the network over the long term, sans short-term volatility, this
//! creates an economic incentive to vote in the best interests of the
//! network. Neuron owners can freely configure higher dissolve
//! delays, up to a maximum delay of 8 years, but cannot configure
//! lower dissolve delays. The NNS pays higher voting rewards the
//! higher the dissolve delay, encouraging users to enter a game in
//! which an economic incentive is created to vote according to a very
//! long term vision.
//!
//! Neuron owners may find it hard to manually direct voting on every
//! proposal submitted to the NNS. Firstly, large volumes of proposals
//! may be submitted to the NNS, often at awkward times, and owners
//! may not be available or have the time necessary to evaluate each
//! one. Secondly, neuron owners may lack the necessary expertise to
//! evaluate proposals themselves. The NNS uses a form of liquid
//! democracy to address these challenges. For any proposal topic, a
//! neuron can be configured to vote automatically by following the
//! votes of a group of neurons, voting to adopt proposals whenever a
//! majority of the followees vote to adopt, and voting to reject
//! whenever that becomes impossible. A catch-all follow rule may also
//! be defined to make a neuron vote automatically on proposals with
//! topics for which no follow rule has been defined. It is assumed
//! that neuron owners will manage how their neurons follow other
//! neurons in the best interests of the network, which is also in
//! their own economic interests, owing to their locked ICP balances.
//!
//! It is expected that a large proportion of the overall supply of
//! ICP will be locked in order to earn rewards. This secures the
//! Internet Computer network’s governance, by making it both
//! difficult and exorbitantly expensive for an attacker to acquire a
//! sufficiently large stake to gain significant influence. Since
//! neuron owners will wish to maximize their rewards by voting on all
//! proposals, most neurons will either be actively managed, or
//! configured to follow other neurons so they can vote
//! automatically. In practice, once trusted neurons have voted on
//! proposals, a majority of the other neurons will also vote as the
//! result of cascading follow relationships. This means the NNS can
//! usually quickly determine whether a majority of the overall voting
//! power represented by all neurons wishes to adopt or reject a
//! proposal, and decide on the proposal accordingly. However, the NNS
//! cannot rely upon obtaining such a majority, since in principle,
//! neuron owners may not define follow rules, or simply choose not to
//! vote.
//!
//! When the treatment of a newly submitted proposal is not quickly
//! decided by a majority of the overall voting power, the NNS must
//! use a technique once described as “Wait For Quiet”. This involves
//! deriving a measure of “voting noise” from the volume of ongoing
//! voting on a proposal, and waiting for it to fall below some
//! threshold (which value is a tuning parameter that the NNS can
//! modify in production according to experience), and then proceeding
//! to tally the votes received that far to decide. Different
//! algorithms can be applied, but most simply, the NNS can use a
//! running average of the votes received every time interval as the
//! measure of “voting noise”. If the threshold is too low, an
//! attacker can delay the NNS from deciding on proposals by voting
//! just as the “noise level” is about to fall beneath the threshold,
//! and it cannot be made too high, or else an attacker might try to
//! DoS the NNS so that it decides on proposals using only a small
//! proportion of the voting power that wanted to participate (since
//! it equates their not being able to vote, with their not wanting to
//! vote). Using Wait For Quiet, the NNS can decide on proposals
//! without need for a quorum of voting power to participate, and it
//! can also always decide upon proposals in a timely manner.

use crate::{
    governance::{Governance, TimeWarp},
    pb::v1::{governance::GovernanceCachedMetrics, ProposalStatus},
};
use candid::DecoderConfig;
use mockall::automock;
use std::{
    collections::{BTreeMap, HashMap},
    io,
};

#[cfg(test)]
pub mod test_utils;

mod account_id_index;
mod audit_event;
mod garbage_collection;
/// The 'governance' module contains the canister (smart contract)
/// that manages neurons, proposals, voting, voter following, voting
/// rewards, and the code necessary to execute accepted proposals.
///
/// The governance canister interfaces with the 'ledger' canister to
/// deal with the transfer of ICP (Internet Computer Protocol) tokens
/// between ledger accounts, and with the 'registry' canister to
/// distribute configuration information to all nodes of all
/// subnetworks that participate in the Internet Computer (IC).
pub mod governance;
pub mod governance_proto_builder;
mod heap_governance_data;
pub mod init;
mod known_neuron_index;
mod migrations;
mod neuron;
pub mod neuron_data_validation;
mod neuron_store;
pub mod neurons_fund;
pub mod pb;
pub mod proposals;
mod reward;
pub mod storage;
mod subaccount_index;

/// Limit the amount of work for skipping unneeded data on the wire when parsing Candid.
/// The value of 10_000 follows the Candid recommendation.
const DEFAULT_SKIPPING_QUOTA: usize = 10_000;

pub fn decoder_config() -> DecoderConfig {
    let mut config = DecoderConfig::new();
    config.set_skipping_quota(DEFAULT_SKIPPING_QUOTA);
    config.set_full_error_message(false);
    config
}

#[automock]
trait Clock {
    fn now(&self) -> u64;
    fn set_time_warp(&mut self, new_time_warp: TimeWarp);
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct IcClock {
    time_warp: TimeWarp,
}

impl IcClock {
    fn new() -> Self {
        let time_warp = TimeWarp { delta_s: 0 };

        Self { time_warp }
    }
}

impl Clock for IcClock {
    fn now(&self) -> u64 {
        // Step 1: Read the real time.
        let real_timestamp_seconds = dfn_core::api::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("IcClock malfunctioned.")
            .as_secs();

        // Step 2: Apply time warp.
        let TimeWarp { delta_s } = self.time_warp;
        let modified_timestamp_seconds = i64::try_from(real_timestamp_seconds)
            .expect("Timestamp does not fit in i64.")
            .saturating_add(delta_s);

        // Step 3: Convert back to u64.
        u64::try_from(modified_timestamp_seconds).unwrap_or_else(|err| {
            panic!(
                "Timestamp no longer fits in u64 {} + {}. err: {}",
                real_timestamp_seconds, delta_s, err,
            );
        })
    }

    fn set_time_warp(&mut self, new_time_warp: TimeWarp) {
        self.time_warp = new_time_warp;
    }
}

trait Metric {
    fn into(self) -> f64;
}

impl Metric for f64 {
    fn into(self) -> f64 {
        self
    }
}

impl Metric for u64 {
    fn into(self) -> f64 {
        self as f64
    }
}

/// Helper function that encodes neuron-related gauge vector metrics grouped into the following buckets:
/// forall n: Neuron.
///     n in bucket_0 <==>        0 <= dissolve_delay(n) < 6 months
///     n in bucket_1 <==> 6 months <= dissolve_delay(n) < 12 months
///     ...
fn encode_dissolve_delay_buckets<W, T>(
    mut builder: ic_metrics_encoder::LabeledMetricsBuilder<W>,
    half_year_buckets: &HashMap<u64, T>,
) where
    W: io::Write,
    T: Metric + Copy,
{
    for (k, v) in half_year_buckets.iter() {
        let lower_bound_months = k * 6;
        let upper_bound_months = (1 + k) * 6;
        builder = builder
            .value(
                &[
                    ("dissolve_delay_ge_months", &lower_bound_months.to_string()),
                    ("dissolve_delay_lt_months", &upper_bound_months.to_string()),
                ],
                (*v).into(),
            )
            .unwrap();
    }
}

/// Encodes
pub fn encode_metrics(
    governance: &Governance,
    w: &mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>,
) -> std::io::Result<()> {
    w.encode_gauge(
        "governance_stable_memory_size_bytes",
        ic_nervous_system_common::stable_memory_size_bytes() as f64,
        "Size of the stable memory allocated by this canister measured in bytes.",
    )?;
    w.encode_gauge(
        "governance_total_memory_size_bytes",
        ic_nervous_system_common::total_memory_size_bytes() as f64,
        "Size of the total memory allocated by this canister measured in bytes.",
    )?;
    w.encode_gauge(
        "governance_proposals_total",
        governance.heap_data.proposals.len() as f64,
        "Total number of proposals that haven't been gc'd.",
    )?;
    w.encode_gauge(
        "governance_ready_to_be_settled_proposals_total",
        governance.num_ready_to_be_settled_proposals() as f64,
        "Total number of proposals that are ready to be settled.",
    )?;
    w.encode_gauge(
        "governance_neurons_total",
        governance.neuron_store.len() as f64,
        "Total number of neurons.",
    )?;
    w.encode_gauge(
        "governance_latest_gc_timestamp_seconds",
        governance.latest_gc_timestamp_seconds as f64,
        "Timestamp of the last proposal gc, in seconds since the Unix epoch.",
    )?;
    w.encode_gauge(
        "governance_locked_neurons_total",
        governance.heap_data.in_flight_commands.len() as f64,
        "Total number of neurons that have been locked for disburse operations.",
    )?;
    w.encode_gauge(
        "governance_latest_reward_event_timestamp_seconds",
        governance.latest_reward_event().actual_timestamp_seconds as f64,
        "Timestamp of the latest reward event, in seconds since the Unix epoch.",
    )?;
    w.encode_gauge(
        "governance_seconds_since_latest_reward_event",
        (governance.env.now() - governance.latest_reward_event().actual_timestamp_seconds) as f64,
        "Seconds since the latest reward event",
    )?;
    w.encode_gauge(
        "governance_last_rewards_event_e8s",
        governance.latest_reward_event().distributed_e8s_equivalent as f64,
        "Total number of rewards in e8s distributed in the latest reward event.",
    )?;
    w.encode_gauge(
        "governance_latest_reward_event_rounds_since_last_distribution",
        governance
            .latest_reward_event()
            .rounds_since_last_distribution
            .unwrap_or(0) as f64,
        "Number of rounds since the last distribution in the latest reward event. Will always be at least 1, except at genesis. If greater than 1, indicates that rollovers occurred.",
    )?;
    w.encode_gauge(
        "governance_latest_reward_round_total_available_e8s",
        governance
            .latest_reward_event()
            .latest_round_available_e8s_equivalent
            .unwrap_or(0) as f64,
        "Total number of available rewards in e8s in the latest reward round. Does not include rollovers. Will be equal to governance_latest_reward_event_total_available_e8s, unless rollovers occurred.",
    )?;
    w.encode_gauge(
        "governance_latest_reward_event_total_available_e8s",
        governance
            .latest_reward_event()
            .total_available_e8s_equivalent as f64,
        "Total number of available rewards in e8s in the latest reward event (including rollovers).",
    )?;

    let total_voting_power = match governance
        .heap_data
        .proposals
        .iter()
        .filter(|(_, proposal_data)| {
            proposal_data
                .proposal
                .as_ref()
                .map(|proposal| !proposal.is_manage_neuron())
                .unwrap_or_default()
        })
        .next_back()
    {
        Some((_, proposal_data)) => match &proposal_data.latest_tally {
            Some(tally) => tally.total as f64,
            None => 0f64,
        },
        None => 0f64,
    };

    w.encode_gauge(
        "governance_voting_power_total",
        total_voting_power,
        "The total voting power, according to the most recent proposal.",
    )?;

    let neuron_store::NeuronIndexesLens {
        subaccount: subaccount_index_len,
        principal: principal_index_len,
        following: following_index_len,
        known_neuron: known_neuron_index_len,
        account_id: account_id_index_len,
    } = governance.neuron_store.stable_indexes_lens();

    w.encode_gauge(
        "governance_subaccount_index_len",
        subaccount_index_len as f64,
        "Total number of entries in the subaccount index",
    )?;
    w.encode_gauge(
        "governance_principal_index_len",
        principal_index_len as f64,
        "Total number of entries in the principal index",
    )?;
    w.encode_gauge(
        "governance_following_index_len",
        following_index_len as f64,
        "Total number of entries in the following index",
    )?;
    w.encode_gauge(
        "governance_known_neuron_index_len",
        known_neuron_index_len as f64,
        "Total number of entries in the known neuron index",
    )?;
    w.encode_gauge(
        "governance_account_id_index_len",
        account_id_index_len as f64,
        "Total number of entries in the account_id index",
    )?;

    w.encode_gauge(
        "governance_stable_memory_neuron_count",
        governance.neuron_store.stable_neuron_store_len() as f64,
        "The number of neurons in stable memory.",
    )?;

    let mut builder = w.gauge_vec(
        "governance_proposal_deadline_timestamp_seconds",
        "The deadline for open proposals, labelled with proposal id",
    )?;

    let open_proposals_deadline = governance
        .heap_data
        .proposals
        .iter()
        .filter(|(_, data)| data.status() == ProposalStatus::Open)
        .map(|(proposal_id, data)| {
            let voting_period = governance.voting_period_seconds()(data.topic());
            let deadline_ts = data.get_deadline_timestamp_seconds(voting_period);
            let proposal_topic = data.topic().as_str_name();
            let proposal_action_type = data
                .proposal
                .as_ref()
                .map(|proposal| proposal.action_type());

            (
                proposal_id,
                (deadline_ts, proposal_topic, proposal_action_type),
            )
        })
        .collect::<BTreeMap<&u64, (u64, &str, Option<String>)>>();

    for (proposal_id, (deadline_ts, proposal_topic, proposal_action_type)) in
        open_proposals_deadline.iter()
    {
        let proposal_id = proposal_id.to_string();
        let mut labels: Vec<(&str, &str)> = vec![
            ("proposal_id", proposal_id.as_str()),
            ("proposal_topic", *proposal_topic),
        ];
        if let Some(proposal_action_type) = proposal_action_type {
            labels.push(("proposal_type", proposal_action_type))
        }
        builder = builder
            .value(labels.as_slice(), Metric::into(*deadline_ts))
            .unwrap();
    }

    if let Some(metrics) = &governance.heap_data.metrics {
        let GovernanceCachedMetrics {
            timestamp_seconds: _,
            total_supply_icp,
            dissolving_neurons_count: _,
            dissolving_neurons_e8s_buckets,
            dissolving_neurons_count_buckets,
            not_dissolving_neurons_count: _,
            not_dissolving_neurons_e8s_buckets,
            not_dissolving_neurons_count_buckets,
            dissolved_neurons_count,
            dissolved_neurons_e8s,
            garbage_collectable_neurons_count,
            neurons_with_invalid_stake_count,
            total_staked_e8s,
            neurons_with_less_than_6_months_dissolve_delay_count,
            neurons_with_less_than_6_months_dissolve_delay_e8s,
            community_fund_total_staked_e8s,
            community_fund_total_maturity_e8s_equivalent,
            neurons_fund_total_active_neurons,
            total_locked_e8s,
            total_maturity_e8s_equivalent,
            total_staked_maturity_e8s_equivalent,
            dissolving_neurons_staked_maturity_e8s_equivalent_buckets,
            dissolving_neurons_staked_maturity_e8s_equivalent_sum: _,
            not_dissolving_neurons_staked_maturity_e8s_equivalent_buckets,
            not_dissolving_neurons_staked_maturity_e8s_equivalent_sum: _,
            seed_neuron_count,
            ect_neuron_count,
            total_staked_e8s_seed,
            total_staked_e8s_ect,
            total_staked_maturity_e8s_equivalent_seed,
            total_staked_maturity_e8s_equivalent_ect,
            dissolving_neurons_e8s_buckets_seed,
            dissolving_neurons_e8s_buckets_ect,
            not_dissolving_neurons_e8s_buckets_seed,
            not_dissolving_neurons_e8s_buckets_ect,
        } = metrics;

        w.encode_gauge(
            "governance_total_locked_e8s",
            *total_locked_e8s as f64,
            "Total number of e8s locked in non-dissolved neurons..",
        )?;

        w.encode_gauge(
            "governance_total_supply_icp",
            *total_supply_icp as f64,
            "Total number of minted ICP, at the time the metrics were last calculated, as reported by the ledger canister.",
        )?;

        w.encode_gauge(
            "governance_total_staked_e8s",
            *total_staked_e8s as f64,
            "Total number of e8s that are staked.",
        )?;

        w.encode_gauge(
            "governance_dissolved_neurons_count",
            *dissolved_neurons_count as f64,
            "Total number of neurons in the \"dissolved\" state.",
        )?;

        w.encode_gauge(
            "governance_dissolved_neurons_e8s",
            *dissolved_neurons_e8s as f64,
            "Total e8s held in neurons that are in the \"dissolved\" state.",
        )?;

        w.encode_gauge(
            "governance_garbage_collectable_neurons_count",
            *garbage_collectable_neurons_count as f64,
            "Total number of neurons that can be garbage collected.",
        )?;

        w.encode_gauge(
            "governance_neurons_with_invalid_stake_count",
            *neurons_with_invalid_stake_count as f64,
            "Total number of neurons having an invalid stake, e.g. less than the minimum allowed stake.",
        )?;

        encode_dissolve_delay_buckets(
            w.gauge_vec(
                "governance_dissolving_neurons_e8s",
                "Total e8s held in dissolving neurons, grouped by dissolve delay",
            )
            .unwrap(),
            dissolving_neurons_e8s_buckets,
        );

        encode_dissolve_delay_buckets(
            w.counter_vec(
                "governance_dissolving_neurons_count",
                "Total number of dissolving neurons, grouped by dissolve delay",
            )
            .unwrap(),
            dissolving_neurons_count_buckets,
        );

        encode_dissolve_delay_buckets(
            w.gauge_vec(
                "governance_not_dissolving_neurons_e8s",
                "Total e8s held in not dissolving neurons, grouped by dissolve delay",
            )
            .unwrap(),
            not_dissolving_neurons_e8s_buckets,
        );

        encode_dissolve_delay_buckets(
            w.counter_vec(
                "governance_not_dissolving_neurons_count",
                "Total number of not dissolving neurons, grouped by dissolve delay",
            )
            .unwrap(),
            not_dissolving_neurons_count_buckets,
        );

        w.encode_gauge(
            "governance_neurons_with_less_than_6_months_dissolve_delay_count",
            *neurons_with_less_than_6_months_dissolve_delay_count as f64,
            "Total number of neurons having a dissolve delay less than 6 months.",
        )?;

        w.encode_gauge(
            "governance_neurons_with_less_than_6_months_dissolve_delay_e8s",
            *neurons_with_less_than_6_months_dissolve_delay_e8s as f64,
            "Total e8s held in neurons that have a dissolve delay less than 6 months.",
        )?;

        w.encode_gauge(
            "governance_community_fund_total_staked_e8s",
            *community_fund_total_staked_e8s as f64,
            "The amount of Neurons' stake committed to the Internet Computer's Neurons' Fund",
        )?;

        w.encode_gauge(
            "governance_community_fund_total_maturity_e8s_equivalent",
            *community_fund_total_maturity_e8s_equivalent as f64,
            "The amount of Neurons' maturity committed to the Internet Computer's Neurons' Fund",
        )?;

        w.encode_gauge(
            "governance_neurons_fund_total_active_neurons",
            *neurons_fund_total_active_neurons as f64,
            "The number of active Neurons that have joined the Internet Computer's Neurons' Fund",
        )?;

        w.encode_gauge(
            "governance_total_maturity_e8s_equivalent",
            *total_maturity_e8s_equivalent as f64,
            "The total amount of Neurons' maturity",
        )?;

        w.encode_gauge(
            "governance_total_staked_maturity_e8s_equivalent",
            *total_staked_maturity_e8s_equivalent as f64,
            "The total amount of Neurons' staked maturity",
        )?;

        w.encode_gauge(
            "governance_seed_neuron_count",
            *seed_neuron_count as f64,
            "The count of Seed Neurons",
        )?;

        w.encode_gauge(
            "governance_ect_neuron_count",
            *ect_neuron_count as f64,
            "The count of ECT Neurons",
        )?;

        w.encode_gauge(
            "governance_total_staked_e8s_seed",
            *total_staked_e8s_seed as f64,
            "Total number of e8s that are staked in Seed Neurons.",
        )?;

        w.encode_gauge(
            "governance_total_staked_e8s_ect",
            *total_staked_e8s_ect as f64,
            "Total number of e8s that are staked in ECT Neurons.",
        )?;

        w.encode_gauge(
            "governance_total_staked_maturity_e8s_equivalent_seed",
            *total_staked_maturity_e8s_equivalent_seed as f64,
            "The total amount of Neurons' staked maturity in Seed Neurons",
        )?;

        w.encode_gauge(
            "governance_total_staked_maturity_e8s_equivalent_ect",
            *total_staked_maturity_e8s_equivalent_ect as f64,
            "The total amount of Neurons' staked maturity in ECT Neurons",
        )?;

        encode_dissolve_delay_buckets(
            w.gauge_vec(
                "governance_dissolving_neurons_e8s_seed",
                "Total e8s held in dissolving Seed neurons, grouped by dissolve delay",
            )
            .unwrap(),
            dissolving_neurons_e8s_buckets_seed,
        );

        encode_dissolve_delay_buckets(
            w.gauge_vec(
                "governance_not_dissolving_neurons_e8s_seed",
                "Total e8s held in not dissolving Seed neurons, grouped by dissolve delay",
            )
            .unwrap(),
            not_dissolving_neurons_e8s_buckets_seed,
        );

        encode_dissolve_delay_buckets(
            w.gauge_vec(
                "governance_dissolving_neurons_e8s_ect",
                "Total e8s held in dissolving ECT neurons, grouped by dissolve delay",
            )
            .unwrap(),
            dissolving_neurons_e8s_buckets_ect,
        );

        encode_dissolve_delay_buckets(
            w.gauge_vec(
                "governance_not_dissolving_neurons_e8s_ect",
                "Total e8s held in not dissolving ECT neurons, grouped by dissolve delay",
            )
            .unwrap(),
            not_dissolving_neurons_e8s_buckets_ect,
        );

        encode_dissolve_delay_buckets(
            w
                .gauge_vec(
                    "governance_dissolving_neurons_staked_maturity_e8s_equivalent",
                    "Total staked maturity e8s equivalent held in dissolving neurons, grouped by neuron dissolve delay",
                )
                .unwrap(),
            dissolving_neurons_staked_maturity_e8s_equivalent_buckets
        );

        encode_dissolve_delay_buckets(
            w
                .gauge_vec(
                    "governance_not_dissolving_neurons_staked_maturity_e8s_equivalent",
                    "Total staked maturity e8s equivalent held in not dissolving neurons, grouped by neuron dissolve delay",
                )
                .unwrap(),
            not_dissolving_neurons_staked_maturity_e8s_equivalent_buckets
        );
    }

    Ok(())
}
