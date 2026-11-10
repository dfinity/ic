use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
};

use anyhow::{Context, anyhow};

use ic_registry_routing_table::{CanisterIdRange, CanisterIdRanges};
use ic_state_layout::canister_id_from_path;
use ic_state_manager::state_sync::types::Manifest;
use ic_state_tool::commands::verify_manifest::parse_manifest;
use ic_types::CanisterId;

#[derive(Debug, Default)]
pub struct PostSplitEstimations {
    pub states_sizes_bytes: Estimates,
    pub canisters_installed: Estimates,
    pub instructions_executed: Estimates,
    pub ingress_messages_executed: Estimates,
    /// Note: it could happen that canisters which communicate with each other end up on different
    /// subnets, meaning that Local-Subnet messages could become Remote-Subnet messages post-split.
    pub remote_subnet_messages_executed_lower_bound: Estimates,
    /// Note: it could happen that canisters which communicate with each other end up on different
    /// subnets, meaning that Local-Subnet messages could become Remote-Subnet messages post-split.
    pub local_subnet_messages_executed_upper_bound: Estimates,
    pub http_outcalls_executed: Estimates,
    pub heartbeats_and_global_timers_executed: Estimates,
    /// Canisters which, since the baseline was collected, sent subnet-local requests to at least
    /// one canister which would end up on the other subnet post-split, keyed by the subnet the
    /// sender would end up on. These are the canisters "broken" by the split: some of their
    /// subnet-local requests would become remote-subnet requests.
    ///
    /// Note: this is a lower bound because the communication metrics do not cover all the
    /// subnet-local requests: some canisters may have not sent any requests since the baseline was
    /// collected, and some could have been pruned from the metrics due to eviction.
    pub canisters_with_broken_local_connections_lower_bound: Estimates<BrokenConnections>,
}

/// For each sender canister, the receiver canisters, along with the number of requests sent since
/// the baseline.
pub type BrokenConnections = BTreeMap<CanisterId, BTreeMap<CanisterId, u64>>;

pub fn estimate(
    canister_id_ranges_to_move: Vec<CanisterIdRange>,
    state_manifest_path: PathBuf,
    load_samples_path: PathBuf,
    load_samples_baseline_path: PathBuf,
    communication_samples_path: PathBuf,
    communication_samples_baseline_path: PathBuf,
) -> anyhow::Result<PostSplitEstimations> {
    let canister_ranges = CanisterIdRanges::try_from(canister_id_ranges_to_move)
        .map_err(|err| anyhow!("Failed to convert canister id ranges: {err:?}"))?;

    let manifest =
        read_manifest(&state_manifest_path).context("Failed to compute the state manifest")?;
    let state_size_estimates = estimate_state_sizes(&manifest, &canister_ranges);

    let mut load_samples =
        read_load_samples(&load_samples_path).context("Failed to read the load samples file")?;
    let load_samples_baseline = read_load_samples(&load_samples_baseline_path)
        .context("Failed to read the load samples baseline file")?;

    for (canister_id, samples) in load_samples.iter_mut() {
        if let Some(reference) = load_samples_baseline.get(canister_id) {
            *samples -= *reference;
        }
    }

    let post_split_estimations = estimate_loads(&load_samples, &canister_ranges);

    let communication_samples = read_communication_samples(&communication_samples_path)
        .context("Failed to read the communication samples file")?;
    let communication_samples_baseline =
        read_communication_samples(&communication_samples_baseline_path)
            .context("Failed to read the communication samples baseline file")?;
    let hosted_canisters = load_samples.keys().copied().collect();
    let broken_canisters = estimate_communication(
        &communication_samples,
        &communication_samples_baseline,
        &hosted_canisters,
        &canister_ranges,
    );

    Ok(PostSplitEstimations {
        states_sizes_bytes: state_size_estimates,
        canisters_with_broken_local_connections_lower_bound: broken_canisters,
        ..post_split_estimations
    })
}

fn read_manifest(path: &Path) -> anyhow::Result<Manifest> {
    let file =
        File::open(path).with_context(|| format!("Failed to open file at {}", path.display()))?;
    let (version, files, chunks, _hash) =
        parse_manifest(file).map_err(|err| anyhow!("Failed to parse the manifest file: {err}"))?;

    Ok(Manifest::new(version, files, chunks))
}

fn estimate_state_sizes(
    manifest: &Manifest,
    canister_ranges_to_move: &CanisterIdRanges,
) -> Estimates {
    let mut estimates = Estimates::default();

    for file in &manifest.file_table {
        let Some(canister_id) = canister_id_from_path(&file.relative_path) else {
            println!("Ignoring {}", file.relative_path.display());
            continue;
        };

        if canister_ranges_to_move.contains(&canister_id) {
            estimates.destination += file.size_bytes
        } else {
            estimates.source += file.size_bytes
        }
    }

    estimates
}

#[derive(Copy, Clone, Debug, serde::Deserialize)]
struct LoadSample {
    canister_id: CanisterId,
    instructions_executed: u64,
    ingress_messages_executed: u64,
    remote_subnet_messages_executed: u64,
    local_subnet_messages_executed: u64,
    http_outcalls_executed: u64,
    heartbeats_and_global_timers_executed: u64,
}

impl std::ops::SubAssign for LoadSample {
    fn sub_assign(&mut self, other: Self) {
        assert_eq!(self.canister_id, other.canister_id);

        *self = Self {
            canister_id: self.canister_id,
            instructions_executed: self.instructions_executed - other.instructions_executed,
            ingress_messages_executed: self.ingress_messages_executed
                - other.ingress_messages_executed,
            remote_subnet_messages_executed: self.remote_subnet_messages_executed
                - other.remote_subnet_messages_executed,
            local_subnet_messages_executed: self.local_subnet_messages_executed
                - other.local_subnet_messages_executed,
            http_outcalls_executed: self.http_outcalls_executed - other.http_outcalls_executed,
            heartbeats_and_global_timers_executed: self.heartbeats_and_global_timers_executed
                - other.heartbeats_and_global_timers_executed,
        };
    }
}

fn read_load_samples(path: &Path) -> anyhow::Result<BTreeMap<CanisterId, LoadSample>> {
    let mut samples = BTreeMap::new();
    let file = File::open(path)
        .with_context(|| format!("Failed to open the file at {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut csv_reader = csv::Reader::from_reader(reader);

    for sample in csv_reader.deserialize::<LoadSample>() {
        let sample = sample.context("Failed to parse a csv row")?;
        samples.insert(sample.canister_id, sample);
    }

    Ok(samples)
}

macro_rules! observe_sample {
    ($load_estimates:expr, $load_sample:expr, $subnet:ident) => {
        let LoadSample {
            canister_id: _,
            instructions_executed,
            ingress_messages_executed,
            remote_subnet_messages_executed,
            local_subnet_messages_executed,
            http_outcalls_executed,
            heartbeats_and_global_timers_executed,
        } = $load_sample;

        $load_estimates.canisters_installed.$subnet += 1;
        $load_estimates.instructions_executed.$subnet += instructions_executed;
        $load_estimates.ingress_messages_executed.$subnet += ingress_messages_executed;
        $load_estimates
            .remote_subnet_messages_executed_lower_bound
            .$subnet += remote_subnet_messages_executed;
        $load_estimates
            .local_subnet_messages_executed_upper_bound
            .$subnet += local_subnet_messages_executed;
        $load_estimates.http_outcalls_executed.$subnet += http_outcalls_executed;
        $load_estimates
            .heartbeats_and_global_timers_executed
            .$subnet += heartbeats_and_global_timers_executed;
    };
}

fn estimate_loads(
    load_samples: &BTreeMap<CanisterId, LoadSample>,
    canister_ranges_to_move: &CanisterIdRanges,
) -> PostSplitEstimations {
    let mut load_estimates = PostSplitEstimations::default();

    for (canister_id, load_sample) in load_samples {
        if canister_ranges_to_move.contains(canister_id) {
            observe_sample!(load_estimates, load_sample, destination);
        } else {
            observe_sample!(load_estimates, load_sample, source);
        }
    }

    load_estimates
}

/// Number of subnet-local requests sent from a sender canister to a receiver canister.
#[derive(Copy, Clone, Debug, serde::Deserialize)]
struct CommunicationSample {
    sender_canister_id: CanisterId,
    receiver_canister_id: CanisterId,
    count: u64,
}

fn read_communication_samples(
    path: &Path,
) -> anyhow::Result<BTreeMap<(CanisterId, CanisterId), u64>> {
    let mut samples = BTreeMap::new();
    let file = File::open(path)
        .with_context(|| format!("Failed to open the file at {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut csv_reader = csv::Reader::from_reader(reader);

    for sample in csv_reader.deserialize::<CommunicationSample>() {
        let CommunicationSample {
            sender_canister_id,
            receiver_canister_id,
            count,
        } = sample.context("Failed to parse a csv row")?;
        samples.insert((sender_canister_id, receiver_canister_id), count);
    }

    Ok(samples)
}

/// Finds the subnet-local requests sent to a canister on the other side of the split, in the time
/// frame between the baseline and the sample, grouped by the subnet the sender would end up on.
/// Only connections between `hosted_canisters` are considered.
fn estimate_communication(
    communication_samples: &BTreeMap<(CanisterId, CanisterId), u64>,
    communication_samples_baseline: &BTreeMap<(CanisterId, CanisterId), u64>,
    hosted_canisters: &BTreeSet<CanisterId>,
    canister_ranges_to_move: &CanisterIdRanges,
) -> Estimates<BrokenConnections> {
    let mut broken_connections = Estimates::<BrokenConnections>::default();

    for (&(sender, receiver), &count) in communication_samples {
        let baseline_count = communication_samples_baseline
            .get(&(sender, receiver))
            .copied()
            .unwrap_or_default();
        // A count lower than the baseline means that the entry was evicted and later recreated
        // since the baseline was collected, so the fresh count is a lower bound on the number of
        // requests sent in the meantime.
        let requests_sent = count.checked_sub(baseline_count).unwrap_or(count);
        let sender_moves = canister_ranges_to_move.contains(&sender);

        if requests_sent == 0
            || !hosted_canisters.contains(&sender)
            || !hosted_canisters.contains(&receiver)
            || sender_moves == canister_ranges_to_move.contains(&receiver)
        {
            continue;
        }

        let sender_subnet_connections = if sender_moves {
            &mut broken_connections.destination
        } else {
            &mut broken_connections.source
        };
        sender_subnet_connections
            .entry(sender)
            .or_default()
            .insert(receiver, requests_sent);
    }

    broken_connections
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct Estimates<T = u64> {
    pub source: T,
    pub destination: T,
}

impl Estimates {
    pub fn total(&self) -> u64 {
        self.source + self.destination
    }
}

impl<T> Estimates<T> {
    pub fn map<U>(&self, f: impl Fn(&T) -> U) -> Estimates<U> {
        Estimates {
            source: f(&self.source),
            destination: f(&self.destination),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimate_communication_finds_requests_sent_across_the_split() {
        let canister = CanisterId::from_u64;
        // Canisters 0..=9 stay on the source subnet, canisters 10..=19 move to the destination.
        let canister_ranges_to_move = CanisterIdRanges::try_from(vec![CanisterIdRange {
            start: canister(10),
            end: canister(19),
        }])
        .unwrap();
        // Canister 13 is not hosted on the subnet anymore (e.g. it was deleted).
        let hosted_canisters = BTreeSet::from([
            canister(1),
            canister(2),
            canister(3),
            canister(11),
            canister(12),
        ]);

        let communication_samples_baseline = BTreeMap::from([
            ((canister(1), canister(11)), 2),
            ((canister(3), canister(12)), 7),
            ((canister(12), canister(2)), 4),
        ]);
        let communication_samples = BTreeMap::from([
            // Broken: sent requests to the destination subnet since the baseline.
            ((canister(1), canister(11)), 5),
            // Broken again: both connections must be reported under the same sender.
            ((canister(1), canister(12)), 1),
            // Not broken: both canisters stay on the source subnet.
            ((canister(2), canister(1)), 10),
            // Not broken: no requests sent since the baseline.
            ((canister(3), canister(12)), 7),
            // Not broken: the receiver is not hosted on the subnet.
            ((canister(2), canister(13)), 3),
            // Not broken: both canisters move to the destination subnet.
            ((canister(11), canister(12)), 1),
            // Broken: the counter is lower than the baseline, i.e. the entry was evicted and
            // recreated since the baseline.
            ((canister(12), canister(2)), 1),
        ]);

        let broken_connections = estimate_communication(
            &communication_samples,
            &communication_samples_baseline,
            &hosted_canisters,
            &canister_ranges_to_move,
        );

        assert_eq!(
            broken_connections,
            Estimates {
                source: BTreeMap::from([(
                    canister(1),
                    BTreeMap::from([(canister(11), 3), (canister(12), 1)])
                )]),
                destination: BTreeMap::from([(canister(12), BTreeMap::from([(canister(2), 1)]))]),
            }
        );
    }
}
