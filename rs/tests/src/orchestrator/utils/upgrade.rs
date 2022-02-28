use crate::orchestrator::utils::ssh_access::{read_remote_file, AuthMean};
use ic_http_utils::file_downloader::FileDownloader;
use ic_protobuf::registry::replica_version::v1::BlessedReplicaVersions;
use ic_registry_common::registry::RegistryCanister;
use ic_registry_keys::make_blessed_replica_version_key;
use prost::Message;
use std::fs;
use std::path::Path;

pub async fn fetch_update_file_sha256(sha_url: &str, is_test_img: bool) -> String {
    let tmp_dir = tempfile::tempdir().unwrap().into_path();
    let mut tmp_file = tmp_dir.clone();
    tmp_file.push("SHA256.txt");

    let file_downloader = FileDownloader::new(None);
    file_downloader
        .download_file(sha_url, &tmp_file, None)
        .await
        .expect("Download of SHA256SUMS file failed.");
    let contents = fs::read_to_string(tmp_file).expect("Something went wrong reading the file");
    for line in contents.lines() {
        let words: Vec<&str> = line.split(char::is_whitespace).collect();
        let suffix = if is_test_img {
            "-img-test.tar.gz"
        } else {
            "-img.tar.gz"
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

pub(crate) fn fetch_node_version(
    node_ip: &std::net::IpAddr,
    readonly_mean: &AuthMean,
) -> Result<String, String> {
    let version_file = Path::new("/opt/ic/share/version.txt");
    let mut version = read_remote_file(node_ip, "readonly", readonly_mean, version_file)?;
    version.retain(|c| !c.is_whitespace());
    Ok(version)
}
