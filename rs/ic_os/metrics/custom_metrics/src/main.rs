use anyhow::{Context, Result};
use clap::Parser;
use ic_os_metrics_utils::write_registry_to_file;
use prometheus::{IntGauge, Opts, Registry};
use std::fs::File;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};

const INTERRUPT_FILTER: &str = "TLB shootdowns";
const INTERRUPT_SOURCE: &str = "/proc/interrupts";
const CUSTOM_METRICS_PROM: &str = "/run/node_exporter/collector_textfile/custom_metrics.prom";
const TLB_SHOOTDOWN_METRIC_NAME: &str = "sum_tlb_shootdowns";
const TLB_SHOOTDOWN_METRIC_ANNOTATION: &str = "Total TLB shootdowns";

#[derive(Parser)]
struct MetricToolArgs {
    #[arg(
        short = 'm',
        long = "metrics",
        default_value = CUSTOM_METRICS_PROM
    )]
    /// Filename to write the prometheus metrics for node_exporter generation.
    /// Fails badly if the directory doesn't exist.
    metrics_filename: PathBuf,
}

fn get_sum_tlb_shootdowns() -> Result<i64> {
    let path = Path::new(INTERRUPT_SOURCE);
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);

    let mut total_tlb_shootdowns = 0;

    for line in reader.lines() {
        let line = line?;
        if line.contains(INTERRUPT_FILTER) {
            for part in line.split_whitespace().skip(1) {
                if let Ok(value) = part.parse::<i64>() {
                    total_tlb_shootdowns += value;
                }
            }
        }
    }

    Ok(total_tlb_shootdowns)
}

pub fn main() -> Result<()> {
    let opts = MetricToolArgs::parse();
    let tlb_shootdowns = get_sum_tlb_shootdowns()?;

    let registry = Registry::new();
    let gauge = IntGauge::with_opts(Opts::new(
        TLB_SHOOTDOWN_METRIC_NAME,
        TLB_SHOOTDOWN_METRIC_ANNOTATION,
    ))
    .context("Failed to create gauge")?;
    gauge.set(tlb_shootdowns);

    registry
        .register(Box::new(gauge))
        .context("Failed to register gauge")?;

    write_registry_to_file(&registry, &opts.metrics_filename)
}
