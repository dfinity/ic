use crate::CallCanisters;
use crate::null_request::NullRequest;
use crate::sns::Sns;
use anyhow::anyhow;
use ic_agent::Agent;
use ic_base_types::PrincipalId;
use ic_nns_common::pb::v1::ProposalId;
use ic_nns_constants::SNS_WASM_CANISTER_ID;
use ic_sns_wasm::pb::v1::{
    GetDeployedSnsByProposalIdRequest, GetDeployedSnsByProposalIdResponse, GetWasmRequest,
    GetWasmResponse, ListDeployedSnsesRequest, ListUpgradeStepsRequest, ListUpgradeStepsResponse,
};
use ic_sns_wasm::pb::v1::{
    GetNextSnsVersionRequest, GetSnsSubnetIdsRequest, GetSnsSubnetIdsResponse, SnsVersion,
};
use std::path::{Path, PathBuf};
use tempfile::tempdir;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::io::BufWriter;
use tokio::process::Command;

pub mod requests;

pub async fn query_mainline_sns_upgrade_steps<C: CallCanisters>(
    agent: &C,
) -> Result<ListUpgradeStepsResponse, C::Error> {
    let request = ListUpgradeStepsRequest {
        limit: 0,
        sns_governance_canister_id: None,
        starting_at: None,
    };
    agent.call(SNS_WASM_CANISTER_ID, request).await
}

pub async fn get_deployed_sns_by_proposal_id<C: CallCanisters>(
    agent: &C,
    proposal_id: ProposalId,
) -> Result<GetDeployedSnsByProposalIdResponse, C::Error> {
    let request = GetDeployedSnsByProposalIdRequest {
        proposal_id: proposal_id.id,
    };
    agent.call(SNS_WASM_CANISTER_ID, request).await
}

pub async fn get_wasm<C: CallCanisters>(
    agent: &C,
    sns_canister_wasm_hash: Vec<u8>,
) -> Result<GetWasmResponse, C::Error> {
    let request = GetWasmRequest {
        hash: sns_canister_wasm_hash,
    };
    agent.call(SNS_WASM_CANISTER_ID, request).await
}

pub async fn list_upgrade_steps<C: CallCanisters>(
    agent: &C,
    starting_at: Option<SnsVersion>,
    sns_governance_canister_id: Option<PrincipalId>,
    limit: u32,
) -> Result<ListUpgradeStepsResponse, C::Error> {
    agent
        .call(
            SNS_WASM_CANISTER_ID,
            ListUpgradeStepsRequest {
                starting_at,
                sns_governance_canister_id,
                limit,
            },
        )
        .await
}

/// Queries SNS-W to get the deployed SNSes. The returned SNSes are not guaranteed to be
/// fully initialized (they may have ongoing or failed swaps). Archive canisters are not
/// included in the response (as SNS-W doesn't know about them).
pub async fn list_deployed_snses<C: CallCanisters>(agent: &C) -> Result<Vec<Sns>, C::Error> {
    let response = agent
        .call(SNS_WASM_CANISTER_ID, ListDeployedSnsesRequest {})
        .await?;
    let snses = response
        .instances
        .into_iter()
        .filter_map(|deployed_sns| crate::sns::Sns::try_from(deployed_sns).ok())
        .collect::<Vec<_>>();
    Ok(snses)
}

pub async fn get_sns_subnet_ids<C: CallCanisters>(
    agent: &C,
) -> Result<GetSnsSubnetIdsResponse, C::Error> {
    agent
        .call(SNS_WASM_CANISTER_ID, GetSnsSubnetIdsRequest {})
        .await
}

pub async fn get_git_version_for_sns_hash(
    agent: &Agent,
    ic_wasm_path: &Path,
    hash: &[u8],
) -> anyhow::Result<String> {
    let request = GetWasmRequest {
        hash: hash.to_vec(),
    };
    let response: GetWasmResponse = agent.call(SNS_WASM_CANISTER_ID, request).await?;

    let dir = tempdir()?;
    let wasm_file_gz: PathBuf = write_wasm_to_temp_file(&response, dir.path()).await?;
    let wasm_file: PathBuf = decompress_gzip(&wasm_file_gz).await?;
    let git_commit_id = extract_git_commit_id(&wasm_file, ic_wasm_path).await?;

    Ok(git_commit_id)
}

async fn write_wasm_to_temp_file(
    get_wasm_response: &GetWasmResponse,
    path: &Path,
) -> anyhow::Result<PathBuf> {
    let file_path = path.join("wasm_file.wasm.gz");
    let file = File::create(&file_path).await?;
    let mut writer = BufWriter::new(file);
    writer
        .write_all(&get_wasm_response.wasm.as_ref().unwrap().wasm)
        .await?;
    Ok(file_path)
}

async fn decompress_gzip(file_path: &Path) -> anyhow::Result<PathBuf> {
    let output_path = file_path
        .to_str()
        .ok_or_else(|| anyhow!("Failed to convert file path to string"))?
        .trim_end_matches(".gz");
    let output = Command::new("gzip")
        .arg("-d")
        .arg(file_path)
        .output()
        .await?;
    if !output.status.success() {
        return Err(anyhow!("Failed to decompress: {:?}", output));
    }
    Ok(PathBuf::from(output_path))
}

async fn extract_git_commit_id(
    file_path: &Path,
    ic_wasm_binary_path: &Path,
) -> anyhow::Result<String> {
    if !file_path.exists() {
        return Err(anyhow!("WASM file does not exist"));
    }
    if !ic_wasm_binary_path.exists() {
        return Err(anyhow!("ic-wasm binary does not exist"));
    }

    let output = Command::new(ic_wasm_binary_path)
        .arg(file_path)
        .arg("metadata")
        .arg("git_commit_id")
        .output()
        .await?;

    if !output.status.success() {
        return Err(anyhow!("IC_WASM command failed"));
    }

    let git_commit_id = String::from_utf8(output.stdout)?.trim().to_string();
    Ok(git_commit_id)
}

pub async fn get_next_sns_version<C: CallCanisters>(
    agent: &C,
    current_version: SnsVersion,
    governance_canister_id: Option<PrincipalId>,
) -> Result<Option<SnsVersion>, C::Error> {
    let request = GetNextSnsVersionRequest {
        current_version: Some(current_version),
        governance_canister_id,
    };

    let response = agent.call(SNS_WASM_CANISTER_ID, request).await?;

    Ok(response.next_version)
}

pub async fn get_latest_sns_version_pretty<C: CallCanisters>(
    agent: &C,
) -> Result<Vec<(String, String)>, C::Error> {
    let request = NullRequest::new("get_latest_sns_version_pretty", false);
    agent.call(SNS_WASM_CANISTER_ID, request).await
}
