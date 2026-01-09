use std::{
    collections::BTreeMap,
    fmt::Display,
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
pub struct StateSizeEstimates {
    pub states_sizes_bytes: Estimates,
}

pub fn estimate(
    canister_id_ranges_to_move: Vec<CanisterIdRange>,
    state_manifest_path: PathBuf,
    load_samples_path: PathBuf,
    load_samples_baseline_path: PathBuf,
) -> anyhow::Result<(StateSizeEstimates, LoadEstimates)> {
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

    let load_estimates = estimate_loads(&load_samples, &canister_ranges);

    Ok((state_size_estimates, load_estimates))
}

fn read_manifest(path: &Path) -> anyhow::Result<Manifest> {
    let file =
        File::open(path).with_context(|| anyhow!("Failed to open file at {}", path.display()))?;
    let (version, files, chunks, _hash) =
        parse_manifest(file).map_err(|err| anyhow!("Failed to parse the manifest file: {err}"))?;

    Ok(Manifest::new(version, files, chunks))
}

fn estimate_state_sizes(
    manifest: &Manifest,
    canister_ranges_to_move: &CanisterIdRanges,
) -> StateSizeEstimates {
    let mut estimates = StateSizeEstimates::default();

    for file in &manifest.file_table {
        let Some(canister_id) = canister_id_from_path(&file.relative_path) else {
            println!("Ignoring {}", file.relative_path.display());
            continue;
        };

        if canister_ranges_to_move.contains(&canister_id) {
            estimates.states_sizes_bytes.destination += file.size_bytes
        } else {
            estimates.states_sizes_bytes.source += file.size_bytes
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
        .with_context(|| anyhow!("Failed to open the file at {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut csv_reader = csv::Reader::from_reader(reader);

    for sample in csv_reader.deserialize::<LoadSample>() {
        let sample = sample.context("Failed to parse a csv row")?;
        samples.insert(sample.canister_id, sample);
    }

    Ok(samples)
}

#[derive(Debug, Default)]
pub struct LoadEstimates {
    pub instructions_used: Estimates,
    pub ingress_messages_executed: Estimates,
    /// Note: it could happen that canisters which communicate with each other end up on different
    /// subnets, meaning that LocaL-Subnet messages could become Remote-Subnet messages post-split.
    pub remote_subnet_messages_executed_lower_bound: Estimates,
    /// Note: it could happen that canisters which communicate with each other end up on different
    /// subnets, meaning that LocaL-Subnet messages could become Remote-Subnet messages post-split.
    pub local_subnet_messages_executed_upper_bound: Estimates,
    pub http_outcalls_executed: Estimates,
    pub heartbeats_and_global_timers_executed: Estimates,
}

fn estimate_loads(
    load_samples: &BTreeMap<CanisterId, LoadSample>,
    canister_ranges_to_move: &CanisterIdRanges,
) -> LoadEstimates {
    let mut load_estimates = LoadEstimates::default();

    for (canister_id, load_sample) in load_samples {
        if canister_ranges_to_move.contains(canister_id) {
            load_estimates.instructions_used.destination += load_sample.instructions_executed;
            load_estimates.ingress_messages_executed.destination +=
                load_sample.ingress_messages_executed;
            load_estimates
                .remote_subnet_messages_executed_lower_bound
                .destination += load_sample.remote_subnet_messages_executed;
            load_estimates
                .local_subnet_messages_executed_upper_bound
                .destination += load_sample.local_subnet_messages_executed;
            load_estimates.http_outcalls_executed.destination += load_sample.http_outcalls_executed;
            load_estimates
                .heartbeats_and_global_timers_executed
                .destination += load_sample.heartbeats_and_global_timers_executed;
        } else {
            load_estimates.instructions_used.source += load_sample.instructions_executed;
            load_estimates.ingress_messages_executed.source +=
                load_sample.ingress_messages_executed;
            load_estimates
                .remote_subnet_messages_executed_lower_bound
                .source += load_sample.remote_subnet_messages_executed;
            load_estimates
                .local_subnet_messages_executed_upper_bound
                .source += load_sample.local_subnet_messages_executed;
            load_estimates.http_outcalls_executed.source += load_sample.http_outcalls_executed;
            load_estimates.heartbeats_and_global_timers_executed.source +=
                load_sample.heartbeats_and_global_timers_executed;
        }
    }

    load_estimates
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct Estimates {
    pub source: u64,
    pub destination: u64,
}

impl Display for Estimates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let total = (self.source + self.destination) as f64;
        let source_proportion = self.source as f64 / total;
        let destination_proportion = self.destination as f64 / total;

        write!(
            f,
            "source: {} ({:.2}%), destination: {} ({:.2}%)",
            self.source,
            source_proportion * 100.0,
            self.destination,
            destination_proportion * 100.0,
        )
    }
}
