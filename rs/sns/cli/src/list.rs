use crate::table::{as_table, TableRow};
use anyhow::Result;
use clap::Parser;
use futures::{stream, StreamExt};
use ic_agent::Agent;
use ic_nervous_system_agent::{
    nns::sns_wasm,
    sns::{
        governance::GovernanceCanister, index::IndexCanister, ledger::LedgerCanister,
        root::RootCanister, swap::SwapCanister, Sns,
    },
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};

#[derive(Debug, Parser)]
pub struct ListArgs {
    #[clap(long)]
    json: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct SnsWithMetadata {
    name: String,
    sns: Sns,
}

impl TableRow for SnsWithMetadata {
    fn column_names() -> Vec<&'static str> {
        vec!["name", "ledger", "governance", "index", "swap", "root"]
    }

    fn column_values(&self) -> Vec<String> {
        vec![
            self.name.clone(),
            self.sns.ledger.canister_id.to_string(),
            self.sns.governance.canister_id.to_string(),
            self.sns.index.canister_id.to_string(),
            self.sns.swap.canister_id.to_string(),
            self.sns.root.canister_id.to_string(),
        ]
    }
}

pub async fn exec(args: ListArgs, agent: &Agent) -> Result<()> {
    let snses = sns_wasm::list_deployed_snses(agent).await?;
    let snses_with_metadata = stream::iter(snses)
        .map(|sns| async move {
            let metadata = sns.governance.metadata(agent).await?;
            Ok((sns, metadata))
        })
        .buffer_unordered(10) // Do up to 10 requests at a time in parallel
        .collect::<Vec<anyhow::Result<_>>>()
        .await;
    let snses_with_metadata = snses_with_metadata
        .into_iter()
        .filter_map(Result::ok)
        .map(|(sns, metadata)| {
            let name = metadata
                .name
                .unwrap_or_else(|| "Unknown".to_string())
                .to_lowercase()
                .replace(" ", "-");
            SnsWithMetadata { name, sns }
        })
        .sorted_by(|a, b| a.name.cmp(&b.name))
        .collect::<Vec<_>>();

    let output = if args.json {
        serde_json::to_string(&snses_with_metadata).unwrap()
    } else {
        as_table(snses_with_metadata.as_ref())
    };

    for SnsWithMetadata {
        name,
        sns:
            Sns {
                ledger: LedgerCanister {
                    canister_id: ledger,
                },
                governance:
                    GovernanceCanister {
                        canister_id: governance,
                    },
                index: IndexCanister { canister_id: index },
                swap: SwapCanister { canister_id: swap },
                root: RootCanister { canister_id: root },
            },
    } in snses_with_metadata
    {
        println!(
            r#"# SNS: {name}
- job_name: sns-{name}-governance
  honor_timestamps: true
  metrics_path: /metrics
  scheme: https
  follow_redirects: true
  enable_http2: true
  static_configs:
    - targets:
        - {governance}.raw.icp0.io
      labels:
        ic: mercury
- job_name: sns-{name}-index
  honor_timestamps: true
  metrics_path: /metrics
  scheme: https
  follow_redirects: true
  enable_http2: true
  static_configs:
    - targets:
        - {index}.raw.icp0.io
      labels:
        ic: mercury
        token: sns-{name}
- job_name: sns-{name}-ledger
  honor_timestamps: true
  metrics_path: /metrics
  scheme: https
  follow_redirects: true
  enable_http2: true
  static_configs:
    - targets:
        - {ledger}.raw.icp0.io
      labels:
        ic: mercury
        token: sns-{name}
- job_name: sns-{name}-root
  honor_timestamps: true
  metrics_path: /metrics
  scheme: https
  follow_redirects: true
  enable_http2: true
  static_configs:
    - targets:
        - {root}.raw.icp0.io
      labels:
        ic: mercury
- job_name: sns-{name}-swap
  honor_timestamps: true
  metrics_path: /metrics
  scheme: https
  follow_redirects: true
  enable_http2: true
  static_configs:
    - targets:
        - {swap}.raw.icp0.io
      labels:
        ic: mercury
"#
        );
    }

    // println!("{}", output);

    Ok(())
}
