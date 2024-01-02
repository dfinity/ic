use crossbeam_channel::Receiver;
use multiservice_discovery_shared::builders::sns_canister_config_structure::SnsCanisterConfigStructure;
use multiservice_discovery_shared::contracts::sns::{Canister, Sns};
use multiservice_discovery_shared::filters::sns_name_regex_filter::SnsNameRegexFilter;
use multiservice_discovery_shared::filters::{TargetGroupFilter, TargetGroupFilterList};
use reqwest::Client;
use slog::{debug, info, warn, Logger};
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

use crate::CliArgs;

pub async fn run_downloader_loop(logger: Logger, cli: CliArgs, stop_signal: Receiver<()>) {
    let interval = crossbeam::channel::tick(cli.poll_interval);

    let client = reqwest::Client::builder()
        .timeout(cli.registry_query_timeout)
        .build()
        .expect("Failed to build reqwest client");

    let mut filters = TargetGroupFilterList::new(vec![]);

    if let Some(regex) = &cli.filter_sns_name_regex {
        filters.add(Box::new(SnsNameRegexFilter::new(regex.clone())))
    }

    let mut current_hash: u64 = 0;

    loop {
        let tick = crossbeam::select! {
            recv(stop_signal) -> _ => {
                info!(logger, "Received shutdown signal in downloader_loop");
                return
            },
            recv(interval) -> msg => msg.expect("tick failed!")
        };
        info!(
            logger,
            "Downloading from {} @ interval {:?}", cli.sd_url, tick
        );

        let response = match client.get(cli.sd_url.clone()).send().await {
            Ok(res) => res,
            Err(e) => {
                warn!(
                    logger,
                    "Failed to download from {} @ interval {:?}: {:?}", cli.sd_url, tick, e
                );
                continue;
            }
        };

        if !response.status().is_success() {
            warn!(
                logger,
                "Received failed status {} @ interval {:?}: {:?}", cli.sd_url, tick, response
            );
            continue;
        }

        let targets: serde_json::Value = match response.json().await {
            Ok(targets) => targets,
            Err(e) => {
                warn!(
                    logger,
                    "Failed to parse response from {} @ interval {:?}: {:?}", cli.sd_url, tick, e
                );
                continue;
            }
        };

        let targets = match &targets["data"] {
            serde_json::Value::Array(ar) => ar,
            _ => {
                warn!(logger, "Didn't receive expected structure of payload");
                continue;
            }
        };
        let mut snses = vec![];
        for target in targets {
            let mut sns = Sns {
                description: target["description"].as_str().unwrap().to_string(),
                enabled: target["enabled"].as_bool().unwrap(),
                root_canister_id: target["root_canister_id"].as_str().unwrap().to_string(),
                name: target["name"].as_str().unwrap().to_string(),
                url: target["url"].as_str().unwrap().to_string(),
                canisters: get_canisters(
                    &cli,
                    target["root_canister_id"].as_str().unwrap().to_string(),
                    &client,
                    logger.clone(),
                )
                .await,
            };
            sns.canisters.push(Canister {
                canister_id: target["root_canister_id"].as_str().unwrap().to_string(),
                canister_type: "root".to_string(),
                module_hash: "".to_string(),
            });

            snses.push(sns)
        }

        let mut hasher = DefaultHasher::new();

        let targets = snses
            .into_iter()
            .filter(|f| filters.filter(f))
            .collect::<Vec<_>>();

        for target in &targets {
            target.hash(&mut hasher);
        }

        let hash = hasher.finish();

        if current_hash != hash {
            info!(
                logger,
                "Received new targets from {} @ interval {:?}", cli.sd_url, tick
            );
            current_hash = hash;

            generate_config(&cli, targets, logger.clone());
        }
    }
}

fn generate_config(cli: &CliArgs, targets: Vec<Sns>, logger: Logger) {
    if std::fs::metadata(&cli.output_dir).is_err() {
        std::fs::create_dir_all(cli.output_dir.parent().unwrap()).unwrap();
        std::fs::File::create(&cli.output_dir).unwrap();
    }

    let config = SnsCanisterConfigStructure {
        script_path: cli.script_path.clone(),
        data_folder: cli.cursors_folder.clone(),
        restart_on_exit: cli.restart_on_exit,
        include_stderr: cli.include_stderr,
    }
    .build(targets);
    let path = cli.output_dir.join("canisters.json");
    match std::fs::write(path, config) {
        Ok(_) => {}
        Err(e) => debug!(logger, "Failed to write config to file"; "err" => format!("{}", e)),
    }
}

async fn get_canisters(
    cli: &CliArgs,
    root_canister_id: String,
    client: &Client,
    logger: Logger,
) -> Vec<Canister> {
    let mut url = cli.sd_url.clone();
    url.path_segments_mut().unwrap().push(&root_canister_id);
    let response = match client.get(url).send().await {
        Ok(resp) => resp,
        Err(e) => {
            warn!(
                logger,
                "Couldn't fetch canisters for sns with root canister id {}:\n{}",
                root_canister_id,
                e
            );
            return vec![];
        }
    };

    let contract: serde_json::Value = match response.json().await {
        Ok(res) => res,
        Err(e) => {
            warn!(
                logger,
                "Couldn't unmarshal from json for sns with root canister id {}:\n{}",
                root_canister_id,
                e
            );
            return vec![];
        }
    };

    match &contract["canisters"] {
        serde_json::Value::Array(ar) => ar
            .iter()
            .map(|val| Canister {
                canister_id: val["canister_id"].as_str().unwrap().to_string(),
                module_hash: val["module_hash"].as_str().unwrap().to_string(),
                canister_type: val["canister_type"].as_str().unwrap().to_string(),
            })
            .collect(),
        other => {
            warn!(
                logger,
                "Unexpected schema for sns with root canister id {}:\n{}", root_canister_id, other
            );
            vec![]
        }
    }
}
