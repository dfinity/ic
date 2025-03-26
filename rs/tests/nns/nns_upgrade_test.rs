// nns_upgrade_test is a manual system-test that deploys an IC with a NNS that is recovered from the latest mainnet state.
//
// To run the test you need to be authorised to SSH into zh1-pyr07.zh1.dfinity.network which contains the NNS backups.
//
// Run the test using:
//
//   test_tmpdir="/tmp/$(whoami)/test_tmpdir"; echo "test_tmpdir=$test_tmpdir"; rm -rf "$test_tmpdir"; ict test nns_upgrade_test --set-required-host-features=dc=zh1 -- --test_tmpdir="$test_tmpdir" --flaky_test_attempts=1
//
// Make sure to pick a DC in --set-required-host-features=dc=zh1 which is close to
// where you are running the test from. Shipping state across the Atlantic can double the
// time it takes to setup the IC with the recovered NNS.
//
// If you're running this on a devenv VM make sure to point --test_tmpdir to
// host-backed storage like /tmp/$(whoami) to avoid the >7GB backup being downloaded to
// and procecessed on CEPH-backed storage.
//
// It will take a bit over 20 minutes to setup the recovered NNS.
// Wait for a message like the following before interacting with the recovered NNS:
//
//   2023-08-21 18:03:06.784 INFO[setup:rs/tests/nns/nns_upgrade_test.rs:516:0]
//     Successfully recovered NNS at http://[2a0b:21c0:4003:2:5004:41ff:feea:7cef]:8080/.
//     Interact with it using NeuronId(5453944968753393786).

use anyhow::Result;
use ic_mainnet_nns_recovery::{setup, OVERALL_TIMEOUT, PER_TEST_TIMEOUT};
use ic_system_test_driver::driver::group::SystemTestGroup;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_overall_timeout(OVERALL_TIMEOUT)
        .with_timeout_per_test(PER_TEST_TIMEOUT)
        .with_setup(setup)
        .execute_from_args()?;
    Ok(())
}
