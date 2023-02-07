use std::time::Duration;

use anyhow::bail;
use ic_registry_subnet_type::SubnetType;
use ic_utils::{
    call::SyncCall,
    interfaces::{http_request::HttpResponse, HttpRequestCanister, ManagementCanister},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use slog::{info, Logger};

use crate::{
    driver::{
        ic::InternetComputer,
        test_env::{TestEnv, TestEnvAttribute},
        test_env_api::{
            retry, GetFirstHealthyNodeSnapshot, HasDependencies, HasGroupSetup, HasPublicApiUrl,
            HasTopologySnapshot, HasWasm, IcNodeContainer,
        },
    },
    util::{block_on, delay},
};

use super::sns_deployment::{install_nns, install_sns};

use ic_base_types::PrincipalId;

use anyhow::Result;

// Taken from https://github.com/dfinity/nns-dapp/blob/main/frontend/src/lib/constants/sns.constants.ts
const AGGREGATOR_CANISTER_PATH: &str = "/sns/list/latest/slow.json";
const AGGREGATOR_CANISTER_VERSION: &str = "v1";

pub fn config_fast(env: TestEnv) {
    env.ensure_group_setup_created();
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .add_fast_single_node_subnet(SubnetType::Application)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });

    install_nns(&env, None);

    install_sns(&env);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatorClient {
    canister_id: PrincipalId,
}

impl TestEnvAttribute for AggregatorClient {
    fn attribute_name() -> String {
        "aggregator_client".to_string()
    }
}

impl AggregatorClient {
    fn get_id(canister: &HttpRequestCanister) -> PrincipalId {
        PrincipalId(*canister.canister_id_())
    }

    fn aggregator_http_endpoint() -> String {
        format!("/{AGGREGATOR_CANISTER_VERSION}{AGGREGATOR_CANISTER_PATH}")
    }

    async fn http_get_request<'agent>(
        log: &Logger,
        canister: &HttpRequestCanister<'agent>,
        relative_url: String,
    ) -> Result<HttpResponse> {
        let (response,) = canister
            .http_request("GET", relative_url.clone(), vec![], vec![])
            .call()
            .await
            .unwrap();
        let cid = Self::get_id(canister).to_string();
        match response.status_code {
            200 => {
                info!(
                    log,
                    "200: response from GET `http_request` to {:?} (URL={relative_url})", cid,
                );
                Ok(response)
            }
            code => {
                bail!(
                    "{code}: response from GET `http_request` to {:?} (URL={relative_url})",
                    cid
                )
            }
        }
    }

    pub async fn http_get_favicon<'agent>(
        log: &Logger,
        canister: &HttpRequestCanister<'agent>,
    ) -> Result<Vec<u8>> {
        let url = "/favicon.ico".to_string();
        Self::http_get_request(log, canister, url)
            .await
            .map(|res| res.body)
    }

    pub async fn http_get_asset<'agent>(
        log: &Logger,
        canister: &HttpRequestCanister<'agent>,
    ) -> Result<Vec<u8>> {
        let url = Self::aggregator_http_endpoint();
        Self::http_get_request(log, canister, url)
            .await
            .map(|res| res.body)
    }

    pub fn install_aggregator_and_check_healthy(env: &TestEnv) -> Self {
        let log = env.logger();
        let app_node = env.get_first_healthy_application_node_snapshot();
        let agent = app_node.build_default_agent();
        let canister = {
            let effective_canister_id = app_node.effective_canister_id();
            info!(
                &log,
                "Validating aggregator canister's installation via public endpoint {}",
                app_node.get_public_url().as_str(),
            );
            let p = env.get_dependency_path("external/sns_aggregator/file/sns_aggregator.wasm");
            let p = std::fs::canonicalize(p.clone())
                .unwrap_or_else(|e| panic!("cannot obtain canonical path from {p:?}: {e:?}"));
            let canister_bytes = env.load_wasm(p);
            let canister_id = app_node.with_default_agent({
                let log = log.clone();
                move |agent| async move {
                    info!(
                        log,
                        "Preparing to install canister with effective ID {effective_canister_id:?} ..."
                    );
                    let management_canister = ManagementCanister::create(&agent);
                    let (canister_id,) = management_canister
                        .create_canister()
                        .as_provisional_create_with_amount(None)
                        .with_effective_canister_id(effective_canister_id)
                        .call_and_wait(delay())
                        .await
                        .unwrap();
                    info!(
                        log,
                        "Successfully created canister {canister_id:?} using provisional builder"
                    );
                    management_canister
                        .install_code(&canister_id, &canister_bytes)
                        .call_and_wait(delay())
                        .await
                        .unwrap();
                    info!(log, "Successfully installed canister {canister_id:?}");
                    canister_id
                }
            });
            HttpRequestCanister::create(&agent, canister_id)
        };

        info!(&log, "Try downloading the favicon ...");
        let _ = block_on(Self::http_get_favicon(&log, &canister)).unwrap();
        let get_http_asset = {
            let log = log.clone();
            let canister = canister.clone();
            move || {
                let asset_bytes = block_on(Self::http_get_asset(&log, &canister))?;
                info!(log, "Try parsing the response body ...");
                let asset: Value = serde_json::from_slice(asset_bytes.as_slice())?;
                match asset {
                    Value::Array(snss) if snss.is_empty() => {
                        bail!("The aggregator currently has no SNSs")
                    }
                    _ => Ok(asset),
                }
            }
        };
        let asset = retry(
            log.clone(),
            Duration::from_secs(60 * 2), // 2 minutes
            Duration::from_secs(5),
            get_http_asset,
        )
        .unwrap();
        info!(log, "Obtained asset from aggregator canister: {asset:?}",);
        let aggregator = Self {
            canister_id: Self::get_id(&canister),
        };
        aggregator.write_attribute(env);
        aggregator
    }
}

pub fn install_aggregator_with_checks(env: TestEnv) {
    AggregatorClient::install_aggregator_and_check_healthy(&env);
}
