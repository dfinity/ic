use anyhow::{Context, Error};
use clap::Parser;
use nftables::{
    helper::get_current_ruleset, helper::get_current_ruleset_raw, schema::Counter as NftCounter, schema::NfListObject::Counter,
    schema::NfObject,
};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output};

const SERVICE_NAME: &str = "nft-exporter";

#[derive(Parser)]
#[command(name = SERVICE_NAME)]
struct Cli {
    #[clap(
        long,
        default_value = "/run/node_exporter/collector_textfile/firewall_counters.prom"
    )]
    metrics_file: PathBuf,
}

fn nft_counter_to_metric(counter: NftCounter) -> String {
    format!(
        "# HELP {} Total number of packets the corresponding rule has been applied to.\n\
         # TYPE {} counter\n\
         {} {:?}",
        counter.name, counter.name, counter.name, counter.packets,
    )
}

fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    // Print the PATH environment variable
    if let Ok(path) = std::env::var("PATH") {
        println!("PATH: {}", path);
    }

    // Check which `nft` executable is being used
    let which_output: Output = Command::new("which")
        .arg("nft")
        .output()?;
    println!("which nft: {:?}", which_output);

    let nft_ruleset_raw = get_current_ruleset_raw(Some("/usr/sbin/nft"), None).context("failed to get the current nft ruleset")?;
    println!("{:?}\n\n\n\n\n", nft_ruleset_raw);

    let nft_ruleset =
        get_current_ruleset(None, None).context("failed to get the current nft ruleset")?;

    println!("{:?}", nft_ruleset);

    let mut metrics = Vec::new();
    for nft_object in nft_ruleset.objects.iter() {
        if let NfObject::ListObject(Counter(counter)) = nft_object {
            println!("Counter {}", counter.name);
            metrics.push(nft_counter_to_metric(counter.clone()));
        }
    }
    let metrics_str = metrics.join("\n");

    let mut file = File::create(cli.metrics_file)?;
    file.write_all(metrics_str.as_bytes())?;

    Ok(())
}
