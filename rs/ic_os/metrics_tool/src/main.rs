use anyhow::Result;
use clap::Parser;

use std::fs::File;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};

use ic_metrics_tool::{Metric, MetricsWriter};

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

fn get_sum_tlb_shootdowns() -> Result<u64> {
    let path = Path::new(INTERRUPT_SOURCE);
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);

    let mut total_tlb_shootdowns = 0;

    for line in reader.lines() {
        let line = line?;
        if line.contains(INTERRUPT_FILTER) {
            for part in line.split_whitespace().skip(1) {
                if let Ok(value) = part.parse::<u64>() {
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

    let metrics = vec![
        Metric::new(TLB_SHOOTDOWN_METRIC_NAME, tlb_shootdowns as f64)
            .add_annotation(TLB_SHOOTDOWN_METRIC_ANNOTATION),
    ];
    let writer = MetricsWriter::new(opts.metrics_filename);
    writer.write_metrics(&metrics)?;

    Ok(())
}
