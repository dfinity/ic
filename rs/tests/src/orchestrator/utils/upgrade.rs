use crate::{
    nns::{
        get_governance_canister, submit_bless_replica_version_proposal,
        submit_update_subnet_replica_version_proposal, vote_execute_proposal_assert_executed,
    },
    orchestrator::utils::ssh_access::{read_remote_file, AuthMean},
    util::{block_on, runtime_from_url},
};
use ic_canister_client::Sender;
use ic_fondue::ic_manager::IcEndpoint;
use ic_http_utils::file_downloader::FileDownloader;
use ic_nns_common::types::NeuronId;
use ic_nns_constants::ids::TEST_NEURON_1_OWNER_KEYPAIR;
use ic_nns_test_utils::ids::TEST_NEURON_1_ID;
use ic_protobuf::registry::replica_version::v1::BlessedReplicaVersions;
use ic_registry_common::registry::RegistryCanister;
use ic_registry_keys::make_blessed_replica_version_key;
use ic_types::{messages::ReplicaHealthStatus, ReplicaVersion, SubnetId};
use prost::Message;
use slog::{info, Logger};
use std::convert::TryFrom;
use std::fs;
use std::path::Path;

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum UpdateImageType {
    Image,
    ImageTest,
    Sha256,
}

pub(crate) fn get_update_image_url(image_type: UpdateImageType, git_revision: &str) -> String {
    match image_type {
        UpdateImageType::Image => {
            format!(
                "https://download.dfinity.systems/ic/{}/guest-os/update-img/update-img.tar.gz",
                git_revision
            )
        }
        UpdateImageType::ImageTest => {
            format!(
                "https://download.dfinity.systems/ic/{}/guest-os/update-img/update-img-test.tar.gz",
                git_revision
            )
        }
        UpdateImageType::Sha256 => {
            format!(
                "https://download.dfinity.systems/ic/{}/guest-os/update-img/SHA256SUMS",
                git_revision
            )
        }
    }
}

pub async fn fetch_update_file_sha256(version_str: &str, is_test_img: bool) -> String {
    let sha_url = get_update_image_url(UpdateImageType::Sha256, version_str);
    let tmp_dir = tempfile::tempdir().unwrap().into_path();
    let mut tmp_file = tmp_dir.clone();
    tmp_file.push("SHA256.txt");

    let file_downloader = FileDownloader::new(None);
    file_downloader
        .download_file(&sha_url, &tmp_file, None)
        .await
        .expect("Download of SHA256SUMS file failed.");
    let contents = fs::read_to_string(tmp_file).expect("Something went wrong reading the file");
    for line in contents.lines() {
        let words: Vec<&str> = line.split(char::is_whitespace).collect();
        let suffix = match is_test_img {
            true => "-img-test.tar.gz",
            false => "-img.tar.gz",
        };
        if words.len() == 2 && words[1].ends_with(suffix) {
            return words[0].to_string();
        }
    }

    panic!("SHA256 hash is not fund in {}", sha_url)
}

pub async fn get_blessed_replica_versions(
    registry_canister: &RegistryCanister,
) -> BlessedReplicaVersions {
    let blessed_vers_result = registry_canister
        .get_value(make_blessed_replica_version_key().as_bytes().to_vec(), None)
        .await
        .unwrap();
    BlessedReplicaVersions::decode(&*blessed_vers_result.0).unwrap()
}

/// Reads the replica version from an unassigned node.
pub(crate) fn fetch_unassigned_node_version(
    node_ip: &std::net::IpAddr,
    readonly_mean: &AuthMean,
) -> Result<String, String> {
    let version_file = Path::new("/opt/ic/share/version.txt");
    let mut version = read_remote_file(node_ip, "readonly", readonly_mean, version_file)?;
    version.retain(|c| !c.is_whitespace());
    Ok(version)
}

/// Waits until the endpoint is healthy and running the given replica version.
/// Panics if the timeout is reached while waiting.
pub(crate) fn assert_assigned_replica_version(
    endpoint: &IcEndpoint,
    expected_version: &str,
    logger: &Logger,
) {
    for i in 1..=50 {
        let fetched_version = get_assigned_replica_version(endpoint).ok();
        info!(logger, "Try: {}. replica version: {:?}", i, fetched_version);
        if Some(expected_version.to_string()) == fetched_version {
            return;
        };
        std::thread::sleep(std::time::Duration::from_secs(10));
    }

    panic!("Couldn't detect the replica version {}", expected_version)
}

/// Gets the replica version from the endpoint if it is healthy.
pub(crate) fn get_assigned_replica_version(endpoint: &IcEndpoint) -> Result<String, String> {
    let version = match block_on(async { endpoint.status().await }) {
        Ok(status) if Some(ReplicaHealthStatus::Healthy) == status.replica_health_status => status,
        Ok(_) => return Err("Replica is not healty".to_string()),
        Err(err) => return Err(err.to_string()),
    }
    .impl_version;
    match version {
        Some(ver) => Ok(ver),
        None => Err("No version found in status".to_string()),
    }
}

pub(crate) async fn bless_replica_version(
    nns_node: &IcEndpoint,
    target_version: &str,
    image_type: UpdateImageType,
    logger: &Logger,
) {
    let upgrade_url = get_update_image_url(image_type, target_version);
    info!(logger, "Upgrade URL: {}", upgrade_url);

    let nns = runtime_from_url(nns_node.url.clone());
    let governance_canister = get_governance_canister(&nns);
    let registry_canister = RegistryCanister::new(vec![nns_node.url.clone()]);
    let test_neuron_id = NeuronId(TEST_NEURON_1_ID);
    let proposal_sender = Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR);
    let blessed_versions = get_blessed_replica_versions(&registry_canister).await;
    info!(logger, "Initial: {:?}", blessed_versions);
    let sha256 =
        fetch_update_file_sha256(target_version, image_type == UpdateImageType::ImageTest).await;

    let replica_version = match image_type == UpdateImageType::ImageTest {
        true => ReplicaVersion::try_from(format!("{}-test", target_version)).unwrap(),
        false => ReplicaVersion::try_from(target_version).unwrap(),
    };
    let proposal_id = submit_bless_replica_version_proposal(
        &governance_canister,
        proposal_sender.clone(),
        test_neuron_id,
        replica_version,
        sha256,
        upgrade_url,
    )
    .await;
    vote_execute_proposal_assert_executed(&governance_canister, proposal_id).await;
    let blessed_versions = get_blessed_replica_versions(&registry_canister).await;
    info!(logger, "Updated: {:?}", blessed_versions);
}

pub async fn update_subnet_replica_version(
    nns_node: &IcEndpoint,
    new_replica_version: &ReplicaVersion,
    subnet_id: SubnetId,
) {
    let nns = runtime_from_url(nns_node.url.clone());
    let governance_canister = get_governance_canister(&nns);
    let test_neuron_id = NeuronId(TEST_NEURON_1_ID);
    let proposal_sender = Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR);
    let proposal2_id = submit_update_subnet_replica_version_proposal(
        &governance_canister,
        proposal_sender.clone(),
        test_neuron_id,
        new_replica_version.clone(),
        subnet_id,
    )
    .await;
    vote_execute_proposal_assert_executed(&governance_canister, proposal2_id).await;
}
