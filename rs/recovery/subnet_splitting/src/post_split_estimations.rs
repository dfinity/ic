use std::{
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
) -> anyhow::Result<(StateSizeEstimates, LoadEstimates)> {
    let canister_ranges = CanisterIdRanges::try_from(canister_id_ranges_to_move)
        .map_err(|err| anyhow!("Failed to convert canister id ranges: {err:?}"))?;

    let manifest =
        read_manifest(&state_manifest_path).context("Failed to compute the state manifest")?;
    let state_size_estimates = estimate_state_sizes(&manifest, &canister_ranges);

    let load_samples =
        read_load_samples(&load_samples_path).context("Failed to read the load sample files")?;
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

#[derive(Debug, serde::Deserialize)]
struct LoadSample {
    canister_id: CanisterId,
    instructions_executed: u64,
    ingress_messages_executed: u64,
    xnet_messages_executed: u64,
    intranet_messages_executed: u64,
    http_outcalls_executed: u64,
}

fn read_load_samples(path: &Path) -> anyhow::Result<Vec<LoadSample>> {
    let mut samples = Vec::new();
    let file = File::open(path)
        .with_context(|| anyhow!("Failed to open the file at {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut csv_reader = csv::Reader::from_reader(reader);

    for sample in csv_reader.deserialize::<LoadSample>() {
        samples.push(sample.context("Failed to parse a csv row")?);
    }

    Ok(samples)
}

#[derive(Debug, Default)]
pub struct LoadEstimates {
    pub instructions_used: Estimates,
    pub ingress_messages_executed: Estimates,
    pub xnet_messages_executed: Estimates,
    pub intranet_messages_executed: Estimates,
    pub http_outcalls_executed: Estimates,
}

fn estimate_loads(
    load_samples: &[LoadSample],
    canister_ranges_to_move: &CanisterIdRanges,
) -> LoadEstimates {
    let mut load_estimates = LoadEstimates::default();

    for load_sample in load_samples {
        if canister_ranges_to_move.contains(&load_sample.canister_id) {
            load_estimates.instructions_used.destination += load_sample.instructions_executed;
            load_estimates.ingress_messages_executed.destination +=
                load_sample.ingress_messages_executed;
            load_estimates.xnet_messages_executed.destination += load_sample.xnet_messages_executed;
            load_estimates.intranet_messages_executed.destination +=
                load_sample.intranet_messages_executed;
            load_estimates.http_outcalls_executed.destination += load_sample.http_outcalls_executed;
        } else {
            load_estimates.instructions_used.source += load_sample.instructions_executed;
            load_estimates.ingress_messages_executed.source +=
                load_sample.ingress_messages_executed;
            load_estimates.xnet_messages_executed.source += load_sample.xnet_messages_executed;
            load_estimates.intranet_messages_executed.source +=
                load_sample.intranet_messages_executed;
            load_estimates.http_outcalls_executed.source += load_sample.http_outcalls_executed;
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
        let (source_proportion, destination_proportion) =
            proportions(self.source, self.destination);

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

/// Returns `a/(a+b)` and `b/(a+b)`.
fn proportions(a: u64, b: u64) -> (f64, f64) {
    let total = (a + b) as f64;

    (a as f64 / total, b as f64 / total)
}
