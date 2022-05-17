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

use crate::driver::ic::{InternetComputer, Subnet};
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
use core::time;
use ic_fondue::ic_manager::IcHandle;
use ic_registry_subnet_type::SubnetType;
use ic_replay::player::ReplayError;
use ic_types::{Height, ReplicaVersion};
use slog::info;
use std::convert::TryFrom;
use std::net::IpAddr;
use std::thread;

const DKG_INTERVAL: u64 = 19;

pub fn config() -> InternetComputer {
    InternetComputer::new().add_subnet(
        Subnet::fast_single_node(SubnetType::System)
            .with_dkg_interval_length(Height::from(DKG_INTERVAL)),
    )
}

pub fn test(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let log = ctx.logger.clone();

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

    info!(
        log,
        "nns_backup_test: Pull an early version of the registry"
    );
    backup.rsync_local_store();

    info!(log, "nns_backup_test: Bless the test replica version");
    block_on(bless_replica_version(
        nns_node,
        &replica_version,
        UpdateImageType::ImageTest,
        &ctx.logger,
    ));

    info!(
        log,
        "nns_backup_test: Proposal to upgrade the subnet replica version"
    );
    let test_version = format!("{}-test", replica_version);
    block_on(update_subnet_replica_version(
        nns_node,
        &ReplicaVersion::try_from(test_version.clone()).unwrap(),
        subnet_id,
    ));

    info!(
        log,
        "nns_backup_test: Wait until the upgrade happens and the backup keys are made available"
    );
    assert_assigned_replica_version(nns_node, &test_version, &ctx.logger);
    wait_until_authentication_is_granted(&node_ip, "backup", &backup_mean);

    info!(
        log,
        "nns_backup_test: Sync the data necessary for the backup"
    );
    backup.sync_ic_json5_file();
    backup.rsync_spool();

    let upgrade_height = match backup.replay(&replica_version) {
        Err(ReplayError::UpgradeDetected((h, _))) => h,
        Err(ReplayError::StateDivergence(height)) => panic!(
            "State computation diverged pre-upgrade at height {}",
            height
        ),
        _ => panic!("No upgrade was detected"),
    };

    info!(
        log,
        "nns_backup_test: Check that the replay correctly recognized an upgrade."
    );

    for _ in 0..20 {
        info!(
            log,
            "nns_backup_test: Let's pull some more artefacts and replay with the new version."
        );
        backup.rsync_spool();
        match backup.replay(&test_version) {
            Ok((height, _)) => {
                if height > upgrade_height {
                    return;
                }
            }
            e => panic!("Unexpected error {:?}", e),
        };
        thread::sleep(time::Duration::from_secs(10));
    }

    info!(log, "nns_backup_test: Panic if we couldn't find a CUP");
    // Panic if we couldn't find a CUP
    panic!("No CUP is produced post-upgrade");
}
