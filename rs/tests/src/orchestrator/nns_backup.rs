/* tag::catalog[]

Title:: NNS Backup

Goal:: Ensure NNS backup and replay tools work

Description::
In this test we deploy a one node NNS network and trigger an upgrade (we do this
to obtain a "cut" in the backup, so that we can not only test the recovery from
the backup created by a single version, but also across multiple versions.
After the upgrade, we pull the backed up artifacts and run the replay tool on them.

Runbook::
. set up the testnet (nns + subnet installation)
. trigger an upgrade of the nns subnet
. pull backed up artifacts and run replay tool on them

Success::
. the replay tool was able to restore the state from all pulled backup artifacts, including those created after the upgrade.

end::catalog[] */

use crate::{
    nns::NnsExt,
    orchestrator::utils::{
        backup::Backup,
        ssh_access::{
            generate_key_strings, get_updatesubnetpayload_with_keys, update_subnet_record,
            wait_until_authentication_is_granted, AuthMean,
        },
        upgrade::{
            assert_assigned_replica_version, bless_replica_version, get_assigned_replica_version,
            update_subnet_replica_version, UpdateImageType,
        },
    },
    util::{
        assert_endpoints_reachability, block_on, get_random_nns_node_endpoint, EndpointsStatus,
    },
};
use ic_fondue::{
    ic_manager::{IcControl, IcHandle},
    prod_tests::ic::{InternetComputer, Subnet},
};
use ic_registry_subnet_type::SubnetType;
use ic_types::{Height, ReplicaVersion};
use std::convert::TryFrom;
use std::io::{Read, Write};
use std::net::IpAddr;

const DKG_INTERVAL: u64 = 19;
const SUBNET_SIZE: usize = 4;

pub fn config() -> InternetComputer {
    InternetComputer::new().add_subnet(
        Subnet::fast(SubnetType::System, SUBNET_SIZE)
            .with_dkg_interval_length(Height::from(DKG_INTERVAL)),
    )
}

pub fn test(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let mut rng = ctx.rng.clone();

    ctx.install_nns_canisters(&handle, true);

    block_on(async {
        let all_nodes: Vec<_> = handle.as_permutation(&mut rng).collect();
        assert_endpoints_reachability(&all_nodes, EndpointsStatus::AllReachable).await
    });

    let nns_node = get_random_nns_node_endpoint(&handle, &mut rng);
    let node_ip: IpAddr = nns_node.ip_address().unwrap();
    let subnet_id = nns_node.subnet_id().unwrap();
    let replica_version = get_assigned_replica_version(nns_node).unwrap();

    // Update the registry with two new pairs of keys.
    let (backup_private_key, backup_public_key) = generate_key_strings();
    let payload = get_updatesubnetpayload_with_keys(subnet_id, None, Some(vec![backup_public_key]));
    block_on(update_subnet_record(nns_node, payload));

    let backup_mean = AuthMean::PrivateKey(backup_private_key.clone());
    wait_until_authentication_is_granted(&node_ip, "backup", &backup_mean);

    let backup = Backup::new(node_ip, backup_private_key, subnet_id, ctx.logger.clone());

    // Pull an early version of the registry
    backup.rsync_local_store();

    // Bless the test replica version
    block_on(bless_replica_version(
        nns_node,
        &replica_version,
        UpdateImageType::ImageTest,
        &ctx.logger,
    ));

    // Proposal to upgrade the subnet replica version
    let test_version = format!("{}-test", replica_version);
    block_on(update_subnet_replica_version(
        nns_node,
        &ReplicaVersion::try_from(test_version.clone()).unwrap(),
        subnet_id,
    ));

    // Wait until the upgrade happens and the backup keys are made available:
    assert_assigned_replica_version(nns_node, &test_version, &ctx.logger);
    wait_until_authentication_is_granted(&node_ip, "backup", &backup_mean);

    // Sync the data necessary for the backup
    backup.sync_ic_json5_file();
    backup.rsync_spool();

    // Let's hijack the stdout from the replay tool for later analysis.
    let mut shh = shh::stdout().unwrap();

    backup.replay(&replica_version);

    // Check that the replay correctly recognized an upgrade.
    let mut buffer = String::new();
    shh.read_to_string(&mut buffer).unwrap();
    // Drop shh here to enable writing to stdout again.
    drop(shh);
    std::io::stdout().write_all(buffer.as_bytes()).unwrap();
    if !buffer.contains("Please use the replay tool of version") {
        panic!("The replay tool did not report an upgrade.");
    }
    if buffer.contains("does not correspond") {
        panic!("State computation diverged pre-upgrade.");
    }

    // The replay above would last a bit, let's pull some more artefacts afterwards
    // and replay with the new version.
    backup.rsync_spool();
    let mut shh = shh::stdout().unwrap();
    backup.replay(&test_version);

    // Ensure we were able to find at least one CUP.
    let mut buffer = String::new();
    shh.read_to_string(&mut buffer).unwrap();
    // Drop shh here to enable writing to stdout again.
    drop(shh);
    std::io::stdout().write_all(buffer.as_bytes()).unwrap();
    if !buffer.contains("Found a CUP") {
        panic!("No CUP is produced post-upgrade");
    }
    if buffer.contains("does not correspond") {
        panic!("State computation diverged post-upgrade.");
    }
}
