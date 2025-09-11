use crate::table::{TableRow, as_table};
use crate::utils::{SnsWithMetadata, get_snses_with_metadata};
use anyhow::Result;
use clap::Parser;
use futures::{StreamExt, stream};
use ic_agent::Agent;
use ic_nervous_system_agent::nns::sns_wasm;
use ic_sns_governance_api::pb::v1::topics::ListTopicsResponse;
use ic_sns_root::types::SnsCanisterType;
use itertools::Itertools;
use serde::{Deserialize, Serialize};

/// The arguments used to configure the health command
#[derive(Debug, Parser)]
pub struct HealthArgs {
    /// Output the SNS information as JSON (instead of a human-friendly table).
    #[clap(long)]
    json: bool,
    /// Includes dapp canisters in the output.
    #[clap(long)]
    include_dapps: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct Cycles {
    cycles: u128,
    freezing_threshold: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct SnsHealthInfo {
    name: String,
    memory_consumption: Vec<(u64, SnsCanisterType)>,
    cycles: Vec<(Cycles, SnsCanisterType)>,
    num_remaining_upgrade_steps: usize,
    automatic_target_version_advancement: Option<bool>,
    /// Information about this SNS's proposal topics. Emitted only if --json is selected.
    proposal_topics: Option<ListTopicsResponse>,
}

impl TableRow for SnsHealthInfo {
    fn column_names() -> Vec<&'static str> {
        vec![
            "Name",
            "Memory",
            "Cycles",
            "Upgrades Remaining",
            "Auto Upgrades",
        ]
    }

    fn column_values(&self) -> Vec<String> {
        const MEMORY_THRESHOLD_GIB: f64 = 2.5;
        const CYCLES_THRESHOLD_TC: f64 = 10.0;
        const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
        const TC: f64 = 1000.0 * 1000.0 * 1000.0 * 1000.0;

        let high_memory_consumption = self
            .memory_consumption
            .iter()
            .filter(|(memory_consumption, _)| {
                (*memory_consumption as f64) > MEMORY_THRESHOLD_GIB * GIB
            })
            .map(|(memory_consumption, canister_type)| {
                format!(
                    "{canister_type}: ({:.2} GiB)",
                    *memory_consumption as f64 / GIB
                )
            })
            .join(", ");

        let high_memory_consumption = if !high_memory_consumption.is_empty() {
            format!("❌ {high_memory_consumption}")
        } else {
            "👍".to_string()
        };

        let low_cycles = self
            .cycles
            .iter()
            .filter(|(cycles, _)| (cycles.cycles as f64) < CYCLES_THRESHOLD_TC * TC)
            .map(|(cycles, canister_type)| {
                format!(
                    "{canister_type}: ({:.2} TC{frozen})",
                    cycles.cycles as f64 / TC,
                    frozen = if cycles.cycles < cycles.freezing_threshold as u128 {
                        " 🥶".to_string()
                    } else {
                        "".to_string()
                    }
                )
            })
            .join(", ");
        let low_cycles = if !low_cycles.is_empty() {
            format!("❌ {low_cycles}")
        } else {
            "👍".to_string()
        };

        let automatic_target_version_advancement_sign =
            match self.automatic_target_version_advancement {
                Some(true) => "🐇",
                Some(false) => "💪",
                None => "🦕",
            };

        vec![
            self.name.clone(),
            high_memory_consumption,
            low_cycles,
            format!("{}", self.num_remaining_upgrade_steps),
            automatic_target_version_advancement_sign.to_string(),
        ]
    }
}

pub async fn exec(args: HealthArgs, agent: &Agent) -> Result<()> {
    eprintln!("Checking SNS's health...");

    let snses = sns_wasm::list_deployed_snses(agent).await?;
    let num_total_snses = snses.len();
    let snses_with_metadata = get_snses_with_metadata(agent, snses).await;

    let num_snses_with_metadata = snses_with_metadata.len();

    let health_info: Vec<SnsHealthInfo> = stream::iter(snses_with_metadata)
        .map(|SnsWithMetadata { sns, name }| async move {
            let summary = sns.root.sns_canisters_summary(agent).await?;
            let statuses = summary
                .into_iter()
                .inspect(|(canister_summary, ctype)| {
                    if canister_summary.is_none() {
                        eprintln!("SNS {name} canister summary is missing {ctype}");
                    }
                })
                .filter_map(|(canister_summary, ctype)| {
                    canister_summary.map(|canister_summary| (canister_summary, ctype))
                })
                .inspect(|(canister_summary, ctype)| {
                    if canister_summary.status.is_none() {
                        eprintln!("SNS {name} canister {ctype} has no status");
                    }
                })
                .filter_map(|(canister_summary, ctype)| {
                    canister_summary
                        .status
                        .map(|canister_summary| (canister_summary, ctype))
                })
                .collect::<Vec<_>>();

            let statuses = if args.include_dapps {
                statuses
            } else {
                statuses
                    .into_iter()
                    .filter(|(_, ctype)| *ctype != SnsCanisterType::Dapp)
                    .collect()
            };

            let (memory_consumption, cycles) = statuses
                .into_iter()
                .map(|(canister_status, ctype)| {
                    (
                        (u64::try_from(canister_status.memory_size.0).unwrap(), ctype),
                        (
                            Cycles {
                                freezing_threshold: u64::try_from(
                                    canister_status.settings.freezing_threshold.0,
                                )
                                .unwrap(),
                                cycles: u128::try_from(canister_status.cycles.0).unwrap(),
                            },
                            ctype,
                        ),
                    )
                })
                .unzip();

            let num_remaining_upgrade_steps = sns
                .remaining_upgrade_steps(agent)
                .await?
                .steps
                .len()
                .saturating_sub(1);

            let automatic_target_version_advancement = sns
                .governance
                .get_nervous_system_parameters(agent)
                .await?
                .automatically_advance_target_version;

            let proposal_topics = if args.json {
                let topics = sns.governance.list_topics(agent).await?;
                Some(topics)
            } else {
                None
            };

            Result::<SnsHealthInfo, anyhow::Error>::Ok(SnsHealthInfo {
                name,
                memory_consumption,
                cycles,
                num_remaining_upgrade_steps,
                automatic_target_version_advancement,
                proposal_topics,
            })
        })
        .buffer_unordered(10)
        .collect::<Vec<Result<_>>>()
        .await
        .into_iter()
        .inspect(|result| {
            if let Err(e) = result {
                println!("Error: {e}")
            }
        })
        .filter_map(Result::ok)
        .sorted_by(|a, b| a.name.cmp(&b.name))
        .collect::<Vec<_>>();

    let output = if args.json {
        serde_json::to_string(&health_info).unwrap()
    } else {
        as_table(health_info.as_ref())
    };
    println!("{output}");

    eprintln!(
        "Out of {num_total_snses} SNSes, {num_snses_with_metadata} had metadata and I checked the health of {num_healthchecked} of them.",
        num_healthchecked = health_info.len()
    );

    Ok(())
}
