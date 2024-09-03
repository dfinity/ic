use anyhow::{Context, Error};
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

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

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
struct Counter {
    family: String,
    name: String,
    table: String,
    handle: u32,
    packets: u32,
    bytes: u32,
}

impl Counter {
    fn to_metric_str(&self) -> String {
        format!(
            "# HELP {} Total number of packets the corresponding rule has been applied to.\n\
             # TYPE {} counter\n\
             {} {:?}",
            self.name, self.name, self.name, self.packets,
        )
    }
}

fn get_nft_json_ruleset() -> Result<Value, Error> {
    let mut cmd = Command::new("nft");
    cmd.args(["--json", "list", "ruleset"]);
    let output = cmd.output().expect("Failed to execute nft command");

    let output_str = String::from_utf8(output.stdout).expect("Failed to convert output to string");
    let json_output: Value = serde_json::from_str(&output_str).expect("Failed to parse JSON");

    Ok(json_output)
}

fn get_counters(json_nft_ruleset: &Value) -> Result<Vec<Counter>, Error> {
    let mut counters = Vec::new();

    let nftables = json_nft_ruleset
        .get("nftables")
        .and_then(|v| v.as_array())
        .context("Failed to extract 'nftables' value from JSON output")?;
    for item in nftables {
        if let Some(counter_value) = item.as_object().unwrap().get("counter") {
            counters.push(
                serde_json::from_value::<Counter>(counter_value.clone())
                    .context("Failed build Counter struct from JSON")?,
            );
        }
    }

    Ok(counters)
}

fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    // Get the current nft ruleset in JSON format
    let json_ruleset = get_nft_json_ruleset().context("Failed to get JSON ruleset")?;

    // Extract the counters from the JSON ruleset
    let counters = get_counters(&json_ruleset).context("Failed to get the counters")?;

    // Turn the counters into prometheus metrics and write it to a file
    let mut metrics = Vec::new();
    for counter in counters {
        metrics.push(counter.to_metric_str());
    }

    let mut metrics_str = metrics.join("\n");
    metrics_str.push('\n');

    let mut file = File::create(cli.metrics_file)?;
    file.write_all(metrics_str.as_bytes())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_get_counters_single_counter() {
        let json_data = json!({
            "nftables": [
                {
                    "counter": {
                        "family": "ip",
                        "name": "counter_ipv4",
                        "table": "filter",
                        "handle": 1,
                        "packets": 1234,
                        "bytes": 5678
                    }
                }
            ]
        });

        let expected_counters = vec![Counter {
            family: "ip".to_string(),
            name: "counter_ipv4".to_string(),
            table: "filter".to_string(),
            handle: 1,
            packets: 1234,
            bytes: 5678,
        }];

        let counters = get_counters(&json_data).unwrap();
        assert_eq!(counters, expected_counters);
    }

    #[test]
    fn test_get_counters_multiple_counters() {
        let json_data = json!({
            "nftables": [
                {
                    "counter": {
                        "family": "ip",
                        "name": "counter_ipv4",
                        "table": "filter",
                        "handle": 1,
                        "packets": 1234,
                        "bytes": 5678
                    }
                },
                {
                    "counter": {
                        "family": "ip6",
                        "name": "counter_ipv6",
                        "table": "filter",
                        "handle": 2,
                        "packets": 4321,
                        "bytes": 8765
                    }
                }
            ]
        });

        let expected_counters = vec![
            Counter {
                family: "ip".to_string(),
                name: "counter_ipv4".to_string(),
                table: "filter".to_string(),
                handle: 1,
                packets: 1234,
                bytes: 5678,
            },
            Counter {
                family: "ip6".to_string(),
                name: "counter_ipv6".to_string(),
                table: "filter".to_string(),
                handle: 2,
                packets: 4321,
                bytes: 8765,
            },
        ];

        let counters = get_counters(&json_data).unwrap();
        assert_eq!(counters, expected_counters);
    }

    #[test]
    fn test_get_counters_no_counters() {
        let json_data = json!({
            "nftables": []
        });

        let expected_counters: Vec<Counter> = Vec::new();

        let counters = get_counters(&json_data).unwrap();
        assert_eq!(counters, expected_counters);
    }

    #[test]
    fn test_get_counters_invalid_structure() {
        let json_data = json!({
            "invalid_key": []
        });

        let counters = get_counters(&json_data);
        assert!(counters.is_err());
    }

    #[test]
    fn test_get_counters_invalid_counter() {
        let json_data = json!({
            "nftables": [
                {
                    "counter": {
                        "family": "ip",
                        "name": "counter_ipv4",
                        "table": "filter",
                        "bytes": 5678
                    }
                }
            ]
        });

        let counters = get_counters(&json_data);
        assert!(counters.is_err());
    }
}
