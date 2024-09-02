use anyhow::{bail, Result};
use ic_canister_client::Sender;
use ic_http_utils::file_downloader::FileDownloader;
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR};
use ic_nns_common::types::NeuronId;
use ic_protobuf::registry::replica_version::v1::BlessedReplicaVersions;
use ic_registry_keys::make_blessed_replica_versions_key;
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_system_test_driver::{
    driver::test_env_api::*,
    nns::{
        get_governance_canister, submit_deploy_guestos_to_all_subnet_nodes_proposal,
        submit_update_elected_replica_versions_proposal, vote_execute_proposal_assert_executed,
    },
    util::runtime_from_url,
};
use ic_types::{messages::ReplicaHealthStatus, ReplicaVersion, SubnetId};
use prost::Message;
use slog::{info, Logger};
use std::{convert::TryFrom, fs, io::Read, path::Path};

#[derive(Clone, Copy, PartialEq)]
pub enum UpdateImageType {
    Image,
    ImageTest,
    Sha256,
}

pub fn get_update_image_url(image_type: UpdateImageType, git_revision: &str) -> String {
    match image_type {
        UpdateImageType::Image => {
            format!(
                "http://download.proxy-global.dfinity.network:8080/ic/{}/guest-os/update-img/update-img.tar.zst",
                git_revision
            )
        }
        UpdateImageType::ImageTest => {
            format!(
                "http://download.proxy-global.dfinity.network:8080/ic/{}/guest-os/update-img/update-img-test.tar.zst",
                git_revision
            )
        }
        UpdateImageType::Sha256 => {
            format!(
                "http://download.proxy-global.dfinity.network:8080/ic/{}/guest-os/update-img/SHA256SUMS",
                git_revision
            )
        }
    }
}

pub async fn fetch_update_file_sha256_with_retry(
    log: &Logger,
    version_str: &str,
    is_test_img: bool,
) -> String {
    ic_system_test_driver::retry_with_msg_async!(
        format!("fetch update file sha256 of version {}", version_str),
        log,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            match fetch_update_file_sha256(version_str, is_test_img).await {
                Err(err) => bail!(err),
                Ok(sha) => Ok(sha),
            }
        }
    )
    .await
    .expect("Failed to fetch sha256 file.")
}

pub async fn fetch_update_file_sha256(
    version_str: &str,
    is_test_img: bool,
) -> Result<String, String> {
    let sha_url = get_update_image_url(UpdateImageType::Sha256, version_str);
    let tmp_dir = tempfile::tempdir().unwrap().into_path();
    let mut tmp_file = tmp_dir.clone();
    tmp_file.push("SHA256.txt");

    let file_downloader = FileDownloader::new(None);
    file_downloader
        .download_file(&sha_url, &tmp_file, None)
        .await
        .map_err(|err| format!("Download of SHA256SUMS file failed: {:?}", err))?;
    let contents = fs::read_to_string(tmp_file)
        .map_err(|err| format!("Something went wrong reading the file: {:?}", err))?;
    for line in contents.lines() {
        let words: Vec<&str> = line.split(char::is_whitespace).collect();
        let suffix = match is_test_img {
            true => "-img-test.tar.zst",
            false => "-img.tar.zst",
        };
        if words.len() == 2 && words[1].ends_with(suffix) {
            return Ok(words[0].to_string());
        }
    }

    Err(format!("SHA256 hash is not found in {}", sha_url))
}

pub async fn get_blessed_replica_versions(
    registry_canister: &RegistryCanister,
) -> BlessedReplicaVersions {
    let blessed_vers_result = registry_canister
        .get_value(
            make_blessed_replica_versions_key().as_bytes().to_vec(),
            None,
        )
        .await
        .unwrap();
    BlessedReplicaVersions::decode(&*blessed_vers_result.0).unwrap()
}

/// Reads the replica version from an unassigned node.
pub fn fetch_unassigned_node_version(endpoint: &IcNodeSnapshot) -> Result<String> {
    let sess = endpoint.block_on_ssh_session()?;
    let version_file = Path::new("/opt/ic/share/version.txt");
    let mut chan = sess.scp_recv(version_file)?.0;
    let mut version = String::new();
    chan.read_to_string(&mut version)?;
    version.retain(|c| !c.is_whitespace());
    Ok(version)
}

/// Waits until the node is healthy and running the given replica version.
/// Panics if the timeout is reached while waiting.
pub fn assert_assigned_replica_version(
    node: &IcNodeSnapshot,
    expected_version: &str,
    logger: Logger,
) {
    info!(
        logger,
        "Waiting until the node {} is healthy and running replica version {}",
        node.get_ip_addr(),
        expected_version
    );

    #[derive(PartialEq)]
    enum State {
        Uninitialized,
        OldVersion,
        Reboot,
        OldVersionAgain,
        Finished,
    }
    let mut state = State::Uninitialized;
    let result = ic_system_test_driver::retry_with_msg!(
        format!(
            "Check if node {} is healthy and running replica version {}",
            node.get_ip_addr(),
            expected_version
        ),
        logger.clone(),
        secs(600),
        secs(10),
        || match get_assigned_replica_version(node) {
            Ok(ver) if ver == expected_version => {
                state = State::Finished;
                Ok(())
            }
            Ok(ver) => {
                if state == State::Uninitialized || state == State::OldVersion {
                    state = State::OldVersion
                } else {
                    state = State::OldVersionAgain
                }
                bail!(
                    "Node is running the old replica version: {}. Expected: {}",
                    ver,
                    expected_version
                )
            }
            Err(err) => {
                state = State::Reboot;
                bail!("Error reading replica version: {:?}", err)
            }
        }
    );
    if let Err(error) = result {
        info!(logger, "Error: {}", error);
        match state {
            State::Uninitialized => panic!("No version is fetched at all!"),
            State::OldVersion => panic!("Replica was running the old version only!"),
            State::Reboot => {
                panic!("Replica did reboot, but never came back online!")
            }
            State::OldVersionAgain => panic!("Replica rebooted to a wrong version!"),
            State::Finished => {} // All went well eventually
        }
    }
}

/// Gets the replica version from the node if it is healthy.
pub fn get_assigned_replica_version(node: &IcNodeSnapshot) -> Result<String, String> {
    let version = match node.status() {
        Ok(status) if Some(ReplicaHealthStatus::Healthy) == status.replica_health_status => status,
        Ok(status) => return Err(format!("Replica is not healthy: {:?}", status)),
        Err(err) => return Err(err.to_string()),
    }
    .impl_version;
    match version {
        Some(ver) => Ok(ver),
        None => Err("No version found in status".to_string()),
    }
}

async fn bless_replica_version_with_sha(
    nns_node: &IcNodeSnapshot,
    target_version: &str,
    image_type: UpdateImageType,
    logger: &Logger,
    sha256: &String,
    upgrade_url: Vec<String>,
) {
    let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance_canister = get_governance_canister(&nns);

    let proposal_sender = Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR);
    let test_neuron_id = NeuronId(TEST_NEURON_1_ID);

    let replica_version = match image_type == UpdateImageType::ImageTest {
        true => ReplicaVersion::try_from(format!("{}-test", target_version)).unwrap(),
        false => ReplicaVersion::try_from(target_version).unwrap(),
    };

    let registry_canister = RegistryCanister::new(vec![nns_node.get_public_url()]);
    let blessed_versions = get_blessed_replica_versions(&registry_canister).await;
    info!(logger, "Initial: {:?}", blessed_versions);

    info!(
        logger,
        "Blessing replica version {} with sha256 {} and upgrade urls: {:?}",
        replica_version,
        sha256,
        &upgrade_url
    );

    let proposal_id = submit_update_elected_replica_versions_proposal(
        &governance_canister,
        proposal_sender.clone(),
        test_neuron_id,
        replica_version,
        sha256.clone(),
        upgrade_url,
        vec![],
    )
    .await;
    vote_execute_proposal_assert_executed(&governance_canister, proposal_id).await;

    let blessed_versions = get_blessed_replica_versions(&registry_canister).await;
    info!(logger, "Updated: {:?}", blessed_versions);
}

pub async fn bless_replica_version(
    nns_node: &IcNodeSnapshot,
    target_version: &str,
    image_type: UpdateImageType,
    logger: &Logger,
    sha256: &String,
    upgrade_url: Vec<String>,
) {
    bless_replica_version_with_sha(
        nns_node,
        target_version,
        image_type,
        logger,
        sha256,
        upgrade_url,
    )
    .await;
}

pub async fn bless_public_replica_version(
    nns_node: &IcNodeSnapshot,
    target_version: &str,
    image_type: UpdateImageType,
    url_image_type: UpdateImageType, // normally it is the same as above, unless we want to have bogus url
    logger: &Logger,
) {
    let upgrade_url = get_update_image_url(url_image_type, target_version);
    info!(logger, "Upgrade URL: {}", upgrade_url);

    let sha256 = fetch_update_file_sha256_with_retry(
        logger,
        target_version,
        image_type == UpdateImageType::ImageTest,
    )
    .await;

    bless_replica_version_with_sha(
        nns_node,
        target_version,
        image_type,
        logger,
        &sha256,
        vec![upgrade_url.clone()],
    )
    .await;
}

pub async fn bless_replica_version_with_urls(
    nns_node: &IcNodeSnapshot,
    target_version: &str,
    image_type: UpdateImageType,
    release_package_urls: Vec<String>,
    sha256: String,
    logger: &Logger,
) {
    let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance_canister = get_governance_canister(&nns);
    let registry_canister = RegistryCanister::new(vec![nns_node.get_public_url()]);
    let test_neuron_id = NeuronId(TEST_NEURON_1_ID);
    let proposal_sender = Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR);
    let blessed_versions = get_blessed_replica_versions(&registry_canister).await;
    info!(logger, "Initial: {:?}", blessed_versions);

    let replica_version = match image_type == UpdateImageType::ImageTest {
        true => ReplicaVersion::try_from(format!("{}-test", target_version)).unwrap(),
        false => ReplicaVersion::try_from(target_version).unwrap(),
    };

    info!(
        logger,
        "Blessing replica version {} with sha256 {}", replica_version, sha256
    );

    let proposal_id = submit_update_elected_replica_versions_proposal(
        &governance_canister,
        proposal_sender.clone(),
        test_neuron_id,
        replica_version,
        sha256,
        release_package_urls,
        vec![],
    )
    .await;
    vote_execute_proposal_assert_executed(&governance_canister, proposal_id).await;
    let blessed_versions = get_blessed_replica_versions(&registry_canister).await;
    info!(logger, "Updated: {:?}", blessed_versions);
}

pub async fn deploy_guestos_to_all_subnet_nodes(
    nns_node: &IcNodeSnapshot,
    new_replica_version: &ReplicaVersion,
    subnet_id: SubnetId,
) {
    let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance_canister = get_governance_canister(&nns);
    let test_neuron_id = NeuronId(TEST_NEURON_1_ID);
    let proposal_sender = Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR);
    let proposal_id = submit_deploy_guestos_to_all_subnet_nodes_proposal(
        &governance_canister,
        proposal_sender.clone(),
        test_neuron_id,
        new_replica_version.clone(),
        subnet_id,
    )
    .await;
    vote_execute_proposal_assert_executed(&governance_canister, proposal_id).await;
}
