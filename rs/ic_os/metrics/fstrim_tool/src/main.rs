use anyhow::Result;
use clap::Parser;

const FSTRIM_COMMAND: &str = "/sbin/fstrim";

#[derive(Parser)]
struct FsTrimArgs {
    #[arg(short = 'm', long = "metrics")]
    /// Filename to write the prometheus metric for node generation.
    /// Fails if directory doesn't exist.
    /// Suggested value: /run/node_exporter/collector_textfile/fstrim.prom
    metrics_filename: String,
    #[arg(short = 't', long = "target")]
    /// Target directory to run `fstrim` on.
    /// Suggested value: /var/lib/ic/crypto
    target: String,
    #[arg(short = 'i', long = "initialize_metrics_only", default_value = "false")]
    /// Do not run the command, only initialize the metrics file with default values.
    /// To be run on node start. If the metrics file exists, only the timestamps will be updated.
    /// If the metrics file does not exist, it will be created.
    init_only: bool,
    #[arg(short = 'd', long = "datadir_target", default_value = "")]
    /// Second target directory to run `fstrim` on, but only if the node is unassigned.
    /// If the node is assigned to a subnet, this directory will be ignored.
    /// Intended to be used with /var/lib/ic/data only, but can be used with any directory.
    datadir_target: String,
}

pub fn main() -> Result<()> {
    let opts = FsTrimArgs::parse();

    ic_fstrim_tool::fstrim_tool(
        FSTRIM_COMMAND,
        opts.metrics_filename,
        opts.target,
        opts.init_only,
        opts.datadir_target,
    )
}
