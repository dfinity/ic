/* tag::catalog[]

Title:: Unassigned nodes configuration updates

Goal:: Ensure we can set SSH readonly keys and upgrade the unassigned nodes.

Description::
We deploy an IC with a set of unassigned nodes. Then we make a proposal and add an
SSH key for the read-only access and set the replica version for unassigned nodes.
Then we make sure that unassgined nodes eventually upgrade to that version by
leveraging the SSH access.

Runbook::
. Deploy an IC with unassgined nodes
. Deploy a config for unassgined nodes with one SSH key and a replica version.
. ssh into one of the unassgined nodes and read the version file.

Success::
. At least one unassgined node has SSH enabled and runs the expected version.

end::catalog[] */

use core::time;
use std::{convert::TryFrom, path::Path, thread};

use ic_fondue::{
    ic_instance::InternetComputer,
    ic_manager::{IcControl, IcHandle},
};

use crate::{
    nns::{
        self, submit_bless_replica_version_proposal,
        submit_update_unassigned_node_version_proposal, vote_execute_proposal_assert_executed,
        NnsExt,
    },
    ssh_access_to_nodes::{
        get_updateunassignednodespayload, update_ssh_keys_for_all_unassigned_nodes,
    },
    ssh_access_utils::{
        generate_key_strings, read_remote_file, wait_until_authentication_is_granted, AuthMean,
    },
    util::{
        block_on, get_random_nns_node_endpoint, get_random_unassigned_node_endpoint,
        get_update_image_url, runtime_from_url, UpdateImageType,
    },
};
use ic_canister_client::Sender;
use ic_http_utils::file_downloader::FileDownloader;
use ic_nns_common::types::NeuronId;
use ic_nns_constants::ids::TEST_NEURON_1_OWNER_KEYPAIR;
use ic_nns_test_utils::ids::TEST_NEURON_1_ID;
use ic_protobuf::registry::replica_version::v1::BlessedReplicaVersions;
use ic_registry_common::registry::RegistryCanister;
use ic_registry_keys::make_blessed_replica_version_key;
use ic_registry_subnet_type::SubnetType;
use ic_types::ReplicaVersion;
use prost::Message;
use slog::info;
use std::fs;

pub fn config() -> InternetComputer {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .with_unassigned_nodes(1)
}

pub fn test(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let mut rng = ctx.rng.clone();

    ctx.install_nns_canisters(&handle, true);

    // choose a random node from the nns subnet
    let nns_endpoint = get_random_nns_node_endpoint(&handle, &mut rng);
    block_on(nns_endpoint.assert_ready(ctx));

    // choose a random unassigned node
    let unassigned_node = get_random_unassigned_node_endpoint(&handle, &mut rng);
    let unassigned_node_ip = unassigned_node.ip_address().unwrap();
    block_on(unassigned_node.assert_ready(ctx));

    // obtain readonly access
    let (readonly_private_key, readonly_public_key) = generate_key_strings();
    let payload = get_updateunassignednodespayload(Some(vec![readonly_public_key.clone()]));
    block_on(update_ssh_keys_for_all_unassigned_nodes(
        nns_endpoint,
        payload,
    ));
    let readonly_mean = AuthMean::PrivateKey(readonly_private_key);
    wait_until_authentication_is_granted(&unassigned_node_ip, "readonly", &readonly_mean);
    info!(ctx.logger, "SSH authorization succeeded");

    // fetch the current replica version and deduce the new one
    let original_version = fetch_node_version(&unassigned_node_ip, &readonly_mean).unwrap();
    info!(ctx.logger, "Original replica version: {}", original_version);
    let upgrade_url = get_update_image_url(UpdateImageType::ImageTest, &original_version);
    info!(ctx.logger, "Upgrade URL: {}", upgrade_url);
    let sha_url = get_update_image_url(UpdateImageType::Sha256, &original_version);
    info!(ctx.logger, "SHA256 URL: {}", sha_url);
    let target_version = format!("{}-test", original_version);
    let new_replica_version = ReplicaVersion::try_from(target_version.clone()).unwrap();
    info!(
        ctx.logger,
        "Target replica version: {}", new_replica_version
    );

    let registry_canister = RegistryCanister::new(vec![nns_endpoint.url.clone()]);

    block_on(async {
        // initial parameters
        let reg_ver = registry_canister.get_latest_version().await.unwrap();
        info!(ctx.logger, "Registry version: {}", reg_ver);
        let blessed_versions = blessed_replica_versions(&registry_canister).await;
        info!(ctx.logger, "Initial: {:?}", blessed_versions);
        let sha256 = fetch_update_file_sha256(&sha_url, true).await;
        info!(ctx.logger, "Update image SHA256: {}", sha256);

        // prepare for the 1. proposal
        let nns = runtime_from_url(nns_endpoint.url.clone());
        let governance_canister = nns::get_governance_canister(&nns);

        let test_neuron_id = NeuronId(TEST_NEURON_1_ID);
        let proposal_sender = Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR);

        let proposal_id = submit_bless_replica_version_proposal(
            &governance_canister,
            proposal_sender.clone(),
            test_neuron_id,
            new_replica_version.clone(),
            sha256,
            upgrade_url,
        )
        .await;
        vote_execute_proposal_assert_executed(&governance_canister, proposal_id).await;

        // was registry updated?
        let reg_ver2 = registry_canister.get_latest_version().await.unwrap();
        info!(ctx.logger, "Registry version: {}", reg_ver2);
        assert!(reg_ver < reg_ver2);

        // new blessed versions
        let blessed_versions = blessed_replica_versions(&registry_canister).await;
        info!(ctx.logger, "Updated: {:?}", blessed_versions);

        // proposal to upgrade the unassigned nodes
        let proposal2_id = submit_update_unassigned_node_version_proposal(
            &governance_canister,
            proposal_sender.clone(),
            test_neuron_id,
            target_version.clone(),
            readonly_public_key.clone(),
        )
        .await;
        vote_execute_proposal_assert_executed(&governance_canister, proposal2_id).await;

        // was registry updated?
        let reg_ver3 = registry_canister.get_latest_version().await.unwrap();
        info!(ctx.logger, "Registry version: {}", reg_ver3);
        assert!(reg_ver2 < reg_ver3);
    });

    // wait for the unassigned node to be updated
    let mut i = 0;
    let actual_version = loop {
        i += 1;
        if i >= 100 {
            break None;
        }
        let fetched_version = match fetch_node_version(&unassigned_node_ip, &readonly_mean) {
            Ok(ver) => ver,
            Err(_) => {
                info!(ctx.logger, "Try: {}. Waiting for the host to boot...", i);
                thread::sleep(time::Duration::from_secs(20));
                continue; // if the host is down, try again to fetch the version
            }
        };
        info!(
            ctx.logger,
            "Try: {}. Unassigned node replica version: {}", i, fetched_version
        );
        if fetched_version == target_version {
            break Some(fetched_version);
        }
        thread::sleep(time::Duration::from_secs(10));
    };
    assert_eq!(actual_version, Some(target_version));
}

pub async fn blessed_replica_versions(
    registry_canister: &RegistryCanister,
) -> BlessedReplicaVersions {
    let blessed_vers_result = registry_canister
        .get_value(make_blessed_replica_version_key().as_bytes().to_vec(), None)
        .await
        .unwrap();
    BlessedReplicaVersions::decode(&*blessed_vers_result.0).unwrap()
}

fn fetch_node_version(
    node_ip: &std::net::IpAddr,
    readonly_mean: &AuthMean,
) -> Result<String, String> {
    let version_file = Path::new("/opt/ic/share/version.txt");
    let mut version = read_remote_file(node_ip, "readonly", readonly_mean, version_file)?;
    version.retain(|c| !c.is_whitespace());
    Ok(version)
}

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
