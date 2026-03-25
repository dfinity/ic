// Tests that setup-shared-data.sh correctly repairs a corrupted XFS shared-data
// partition on reboot.  The test deploys a single-node IC, then:
//
// Corrupts the XFS internal journal while the filesystem is still mounted
// (reads the log start and size from the superblock, then overwrites the
// entire log region via oflag=direct), then hard-kills the VM.  The dirty +
// corrupted log makes the test mount in setup-shared-data.sh fail.
// → setup-shared-data.sh must invoke `xfs_repair -L` to recover.

use anyhow::Result;
use chrono::Utc;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::InternetComputer;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::*;
use ic_system_test_driver::systest;
use nested::util::block_on_bash_script_and_log;
use slog::{error, info};
use std::time::Duration;

const POST_KILL_SLEEP_DURATION: Duration = Duration::from_secs(5);

fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

fn test(env: TestEnv) {
    let log = &env.logger();
    let node = &env.get_first_healthy_system_node_snapshot();
    let node_id = node.node_id;
    let vm = node.vm();

    info!(log, "Writing /var/lib/ic/data/proof-I-was-here.txt ...");

    let now = Utc::now().to_rfc3339();
    block_on_bash_script_and_log(
        log,
        node,
        &format!(
            "echo '{now}' | sudo tee /var/lib/ic/data/proof-I-was-here.txt && sync && ls -la /var/lib/ic/data",
        ),
    );

    // Corrupt the XFS journal by
    // reading the log start offset (sb_logstart at byte offset 48, 8 bytes
    // big-endian) and log size (sb_logblocks at byte offset 96, 4 bytes
    // big-endian) from the superblock, then overwriting the entire log
    // region via oflag=direct (bypasses the page cache).
    // After a hard vm.kill() the log corrupted, so the kernel refuses to mount it
    // ("Structure needs cleaning") — triggering the `xfs_repair -L`
    // recovery path in setup-shared-data.sh.
    info!(
        log,
        "Corrupting XFS journal on /dev/mapper/store-shared--data ..."
    );
    node.await_status_is_healthy().expect("Node not healthy");
    // Stop services so they don't race with our dd, then read the log
    // start block and size from the superblock and corrupt the entire log.
    let out = node
        .block_on_bash_script(
            "sudo systemctl stop \
               ic-replica.service \
               ic-btc-mainnet-adapter.service \
               ic-btc-mainnet-adapter.socket \
               ic-btc-testnet-adapter.service \
               ic-btc-testnet-adapter.socket \
               ic-doge-mainnet-adapter.service \
               ic-doge-mainnet-adapter.socket \
               ic-doge-testnet-adapter.service \
               ic-doge-testnet-adapter.socket \
               ic-https-outcalls-adapter.service; \
         sudo umount /var/lib/ic/data; \
         DEV=/dev/mapper/store-shared--data; \
         LOG_START_HEX=$(sudo od -A n -j 48 -N 8 -t x1 $DEV | tr -d ' \\n'); \
         LOG_START=$(printf '%d' 0x$LOG_START_HEX); \
         LOG_BLOCKS_HEX=$(sudo od -A n -j 96 -N 4 -t x1 $DEV | tr -d ' \\n'); \
         LOG_BLOCKS=$(printf '%d' 0x$LOG_BLOCKS_HEX); \
         echo \"XFS log: start=$LOG_START blocks=$LOG_BLOCKS\"; \
         sudo dd if=/dev/urandom of=$DEV bs=4096 count=$LOG_BLOCKS seek=$LOG_START oflag=direct conv=notrunc",
        )
        .expect("Failed to corrupt XFS journal");
    info!(log, "Corruption command output:\n{out}");

    info!(log, "Killing node after XFS journal corruption ...");
    vm.kill();
    node.await_status_is_unavailable()
        .expect("Node still healthy");
    std::thread::sleep(POST_KILL_SLEEP_DURATION);

    info!(log, "Starting node after XFS journal corruption ...");
    vm.start();

    node.await_can_login_as_admin_via_ssh()
        .expect("Failed to login as admin via SSH");

    let journal = node
        .block_on_bash_script("sudo journalctl -u setup-shared-data.service -b --no-pager")
        .expect("Failed to read setup-shared-data.service journal");
    info!(log, "setup-shared-data.service journal:\n{journal}");
    assert!(
        journal.contains("xfs_repair -L"),
        "Expected 'xfs_repair -L' in setup-shared-data.service journal after journal corruption, \
         but got:\n{journal}"
    );

    info!(log, "ls -la /var/lib/ic/data ...");
    block_on_bash_script_and_log(log, node, "ls -la /var/lib/ic/data");
    let proof = node
        .block_on_bash_script("cat /var/lib/ic/data/proof-I-was-here.txt")
        .expect("Failed to read proof-I-was-here.txt");
    assert_eq!(
        proof.trim(),
        now,
        "Content of proof file does not match expected timestamp. \
         Expected: {now}, Actual: {proof}"
    );

    info!(log, "systemctl --failed:");
    block_on_bash_script_and_log(log, node, "systemctl --failed");
    info!(
        log,
        "sudo journalctl -u ic-replica.service -b --no-pager | tail -50:"
    );
    block_on_bash_script_and_log(
        log,
        node,
        "sudo journalctl -u ic-replica.service -b --no-pager | tail -50",
    );
    info!(log, "sudo journalctl -u 'systemd-fsck@*' -b --no-pager:");
    block_on_bash_script_and_log(
        log,
        node,
        "sudo journalctl -u 'systemd-fsck@*' -b --no-pager",
    );
    info!(log, "systemctl status var-lib-ic-data.mount:");
    block_on_bash_script_and_log(log, node, "systemctl status var-lib-ic-data.mount");

    if let Err(err) = node.await_status_is_healthy() {
        error!(
            log,
            "Node {node_id} not healthy after XFS journal corruption: {err:?}. Dumping journal ..."
        );
        block_on_bash_script_and_log(log, node, "journalctl -b");
        panic!("Node was not healthy after XFS journal corruption!")
    }
    block_on_bash_script_and_log(log, node, "findmnt /var/lib/ic/data");
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .without_assert_no_replica_restarts()
        .execute_from_args()?;
    Ok(())
}
