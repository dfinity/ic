use crate::{
    driver::test_env_api::{
        GetFirstHealthyNodeSnapshot, HasPublicApiUrl, HasTestEnv, READY_WAIT_TIMEOUT, RETRY_BACKOFF,
    },
    retry_with_msg_async,
    util::agent_observes_canister_module,
};
use anyhow::{Context, Result};
use async_trait::async_trait;
use candid::{CandidType, Decode, Deserialize, Encode, Nat, Principal};
use ic_agent::Agent;
use slog::{Logger, info};
use std::collections::BTreeMap;
use std::env;
use tokio::task;

#[async_trait]
pub trait DeployAssetCanister {
    async fn deploy_legacy_asset_canister(&self) -> Result<AssetCanisterClient>;
    async fn deploy_long_asset_canister(&self) -> Result<AssetCanisterClient>;
    async fn deploy_asset_canister(&self, wasm_env_var_name: &str) -> Result<AssetCanisterClient>;
}

#[async_trait]
impl<T> DeployAssetCanister for T
where
    T: HasTestEnv + Send + Sync,
{
    async fn deploy_legacy_asset_canister(&self) -> Result<AssetCanisterClient> {
        self.deploy_asset_canister("ASSET_CANISTER_WASM_PATH").await
    }
    async fn deploy_long_asset_canister(&self) -> Result<AssetCanisterClient> {
        self.deploy_asset_canister("LONG_ASSET_CANISTER_WASM_PATH")
            .await
    }
    async fn deploy_asset_canister(&self, wasm_env_var_name: &str) -> Result<AssetCanisterClient> {
        let env = self.test_env();
        let logger = env.logger();
        let app_node = env.get_first_healthy_application_node_snapshot();

        let canister_id = task::spawn_blocking({
            let app_node = app_node.clone();
            let wasm_env_var_name = wasm_env_var_name.to_string();
            move || {
                app_node.create_and_install_canister_with_arg(
                    &env::var(wasm_env_var_name.clone())
                        .unwrap_or_else(|_| panic!("{wasm_env_var_name} not set")),
                    None,
                )
            }
        })
        .await
        .context("failed to deploy asset canister")?;

        let agent = task::spawn_blocking({
            let env = env.clone();
            move || {
                env.get_first_healthy_application_node_snapshot()
                    .build_default_agent()
            }
        })
        .await
        .context("failed to create asset canister agent")?;

        retry_with_msg_async!(
            format!(
                "agent of {} observes canister module {}",
                app_node.get_public_url().to_string(),
                canister_id.to_string()
            ),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                match agent_observes_canister_module(&agent, &canister_id).await {
                    true => Ok(()),
                    false => panic!("Canister module not available yet"),
                }
            }
        )
        .await
        .context("failed to wait for asset canister to install")?;

        Ok(AssetCanisterClient {
            agent,
            logger,
            canister_id,
        })
    }
}

#[derive(Clone)]
pub struct AssetCanisterClient {
    agent: Agent,
    logger: Logger,
    pub canister_id: Principal,
}

#[derive(Debug, CandidType, Deserialize)]
pub struct CreateBatchRequest {}

#[derive(Debug, CandidType, Deserialize)]
pub struct CreateBatchResponse {
    pub batch_id: Nat,
}

impl AssetCanisterClient {
    async fn create_batch(&self) -> Result<Nat> {
        info!(&self.logger, "Creating asset canister upload batch");
        let encoded_arg = Encode!(&CreateBatchRequest {}).unwrap();
        let res = self
            .agent
            .update(&self.canister_id, "create_batch")
            .with_arg(encoded_arg)
            .call_and_wait()
            .await
            .context("Failed to create batch in asset canister")?;

        let decoded_res = Decode!(&res, CreateBatchResponse)?;
        info!(
            &self.logger,
            "Created asset canister upload batch with id {}", decoded_res.batch_id,
        );
        Ok(decoded_res.batch_id)
    }
}

#[derive(Debug, CandidType, Deserialize)]
pub struct CreateChunkRequest {
    pub batch_id: Nat,
    #[serde(with = "serde_bytes")]
    pub content: Vec<u8>,
}

#[derive(Debug, CandidType, Deserialize)]
pub struct CreateChunkResponse {
    pub chunk_id: Nat,
}

impl AssetCanisterClient {
    async fn create_chunk(&self, arg: &CreateChunkRequest) -> Result<Nat> {
        info!(
            &self.logger,
            "Uploading asset canister chunk to batch with id {}", arg.batch_id,
        );
        let encoded_arg = Encode!(arg).unwrap();
        let res = self
            .agent
            .update(&self.canister_id, "create_chunk")
            .with_arg(encoded_arg)
            .call_and_wait()
            .await
            .context("failed to create chunk in asset canister")?;

        let decoded_res = Decode!(&res, CreateChunkResponse)?;
        info!(
            &self.logger,
            "Uploaded asset canister chunk with id {} to batch with id {}",
            decoded_res.chunk_id,
            arg.batch_id,
        );
        Ok(decoded_res.chunk_id)
    }
}

#[derive(Eq, PartialEq, Ord, PartialOrd, Debug, CandidType)]
pub struct CommitBatchRequest {
    pub batch_id: Nat,
    pub operations: Vec<BatchOperationKind>,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, CandidType)]
pub enum BatchOperationKind {
    #[allow(dead_code)]
    Clear(ClearArguments),
    DeleteAsset(DeleteAssetArguments),
    CreateAsset(CreateAssetArguments),
    UnsetAssetContent(UnsetAssetContentArguments),
    SetAssetContent(SetAssetContentArguments),
    SetAssetProperties(SetAssetPropertiesArguments),
}

pub type HeadersConfig = BTreeMap<String, String>;

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, CandidType)]
pub struct CreateAssetArguments {
    pub key: String,
    pub content_type: String,
    pub max_age: Option<u64>,
    pub headers: Option<HeadersConfig>,
    pub enable_aliasing: Option<bool>,
    pub allow_raw_access: Option<bool>,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, CandidType)]
pub struct SetAssetContentArguments {
    pub key: String,
    pub content_encoding: String,
    pub chunk_ids: Vec<Nat>,
    pub sha256: Option<Vec<u8>>,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, CandidType)]
pub struct UnsetAssetContentArguments {
    pub key: String,
    pub content_encoding: String,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, CandidType)]
pub struct SetAssetPropertiesArguments {
    pub key: String,
    pub max_age: Option<Option<u64>>,
    pub headers: Option<Option<Vec<(String, String)>>>,
    pub allow_raw_access: Option<Option<bool>>,
    pub is_aliased: Option<Option<bool>>,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, CandidType)]
pub struct ClearArguments {}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, CandidType)]
pub struct DeleteAssetArguments {
    pub key: String,
}

impl AssetCanisterClient {
    pub async fn commit_batch(&self, arg: &CommitBatchRequest) -> Result<()> {
        info!(
            &self.logger,
            "Commiting asset canister batch with id {}", arg.batch_id,
        );
        let encoded_arg = Encode!(arg).unwrap();
        self.agent
            .update(&self.canister_id, "commit_batch")
            .with_arg(encoded_arg)
            .call_and_wait()
            .await
            .context("failed to create chunk in asset canister")?;

        info!(
            &self.logger,
            "Committed asset canister batch with id {}", arg.batch_id,
        );
        Ok(())
    }
}

pub struct UploadAssetRequest {
    pub key: String,
    pub content: Vec<u8>,
    pub content_type: String,
    pub content_encoding: String,
    pub sha_override: Option<Vec<u8>>,
}

impl AssetCanisterClient {
    pub async fn upload_asset(&self, args: &UploadAssetRequest) -> Result<()> {
        let batch_id = self.create_batch().await?;
        let chunk_size = 1.9 * 1024.0 * 1024.0; // 1.9mb
        let sha = args.sha_override.clone().unwrap_or_else(|| {
            let mut hasher = ic_crypto_sha2::Sha256::new();
            hasher.write(args.content.as_slice());
            let sha = hasher.finish();
            sha.to_vec()
        });

        let chunks = args.content.chunks(chunk_size as usize);
        let mut chunk_ids = vec![];

        for chunk in chunks.clone() {
            let chunk_id = self
                .create_chunk(&CreateChunkRequest {
                    batch_id: batch_id.clone(),
                    content: chunk.to_vec(),
                })
                .await?;

            chunk_ids.push(chunk_id);
        }

        self.commit_batch(&CommitBatchRequest {
            batch_id,
            operations: vec![
                BatchOperationKind::DeleteAsset(DeleteAssetArguments {
                    key: args.key.clone(),
                }),
                BatchOperationKind::CreateAsset(CreateAssetArguments {
                    key: args.key.clone(),
                    content_type: args.content_type.clone(),
                    max_age: None,
                    headers: None,
                    enable_aliasing: None,
                    allow_raw_access: Some(true),
                }),
                BatchOperationKind::SetAssetContent(SetAssetContentArguments {
                    key: args.key.clone(),
                    content_encoding: args.content_encoding.clone(),
                    chunk_ids,
                    sha256: Some(sha),
                }),
            ],
        })
        .await?;

        Ok(())
    }
}

#[derive(Debug, CandidType)]
pub struct ListAssetsRequest {}

#[derive(Debug, CandidType, Deserialize)]
pub struct AssetEncodingDetails {
    pub content_encoding: String,
    pub sha256: Option<Vec<u8>>,
}

#[derive(Debug, CandidType, Deserialize)]
pub struct AssetDetails {
    pub key: String,
    pub encodings: Vec<AssetEncodingDetails>,
    pub content_type: String,
}

impl AssetCanisterClient {
    pub async fn list_assets(&self) -> Result<Vec<AssetDetails>> {
        let encoded_arg = Encode!(&ListAssetsRequest {}).unwrap();
        let res = self
            .agent
            .query(&self.canister_id, "list")
            .with_arg(encoded_arg)
            .call()
            .await
            .context("Failed to list asset canister assets")?;

        let decoded_res = Decode!(&res, Vec<AssetDetails>)?;

        Ok(decoded_res)
    }
}
