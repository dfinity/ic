// Set up a testnet containing:
//  - One 1-node NNS subnet running with the latest mainnet NNS state
//  - One API BN
//  - One HTTP gateway
//
// This is achieved by creating an initial NNS subnet and an unasigned node. We recover the initial
// NNS on the unassigned node while also using the mainnet state, previously downloaded from the
// backup pod. The API BN is then patched to re-register itself to the new NNS since the latter do
// not know of its existence.
// We also add a test neuron who is followed by the mainnet neurons with large stake such that any
// proposal can later be passed instantly.
//
// If the testnet is created with `--set-required-host-features=dmz`, the testnet will be made
// public. External nodes can register themselves through the URL of the HTTP gateway. Note that
// their node operator principals must be added to the registry through a proposal (with enough node
// allowance).
//
// If you do not want the testnet to be public, it is recommended to create it with
// `--set-required-host-features=dc=zh1` to be deployed physically closer to the backup pod.
// Note that the NNS backup is over 15GB so it will require around 3 minutes to download, 15 minutes
// to unpack and 59G of disk space.
//
// ```
// TODO: SSH_AUTH_SOCK in Bazel or here?
// $ ict testnet create mainnet_nns --lifetime-mins 180 --verbose --set-required-host-features=dc=zh1 -- --test_tmpdir=./mainnet_nns
// ```
//
// Additional configuration:
//  - --test_env=DKG_INTERVAL=<dkg_interval> (default: 499)
//  - --test_env=NNS_STATE_ON_BACKUP_POD=<path_on_remote_backup_pod> (default: dev@zh1-pyr07.zh1.dfinity.network:/home/dev/nns_state.tar.zst)
//
// To get access to P8s and Grafana look for the following lines in the ict console output:
//
//     prometheus: Prometheus Web UI at http://prometheus.mainnet-nns--1758812276301.testnet.farm.dfinity.systems,
//     grafana: Grafana at http://grafana.mainnet-nns--1758812276301.testnet.farm.dfinity.systems,
//     progress_clock: IC Progress Clock at http://grafana.mainnet-nns--1758812276301.testnet.farm.dfinity.systems/d/ic-progress-clock/ic-progress-clock?refresh=10s&from=now-5m&to=now,
//
// Happy testing!

use anyhow::Result;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_testnet_mainnet_nns::setup;
use std::time::Duration;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_timeout_per_test(Duration::from_secs(90 * 60))
        .with_setup(setup)
        .execute_from_args()?;
    Ok(())
}
