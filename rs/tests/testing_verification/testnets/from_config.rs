// Set up a testnet from json files, mostly useful for scripting and automating outside of system tests
//
// Example file:
// {
//   "subnets": [
//     {
//       "subnet_type": "application",
//       "num_nodes": 4
//     },
//     {
//       "subnet_type": "application",
//       "num_nodes": 4
//     },
//     {
//       "subnet_type": "system",
//       "num_nodes": 4
//     }
//   ],
//   "num_unassigned_nodes": 0,
//   "initial_version": "7dee90107a88b836fc72e78993913988f4f73ca2"
// }
// All replica nodes use the following resources: 64 vCPUs, 480GiB of RAM, and 500 GiB disk, but can be configured in the file.
//
// You can setup this testnet with a lifetime of 180 mins by executing the following commands:
//
//   $ ./gitlab-ci/tools/docker-run
//   $ ict testnet create --lifetime-mins=180 --from-ic-config-path <(cat <<EOF
// {
//   "subnets": [
//     {
//       "subnet_type": "application",
//       "num_nodes": 1
//    },
//     {
//       "subnet_type": "system",
//       "num_nodes": 1
//     }
//   ],
//   "num_unassigned_nodes": 2
// }
// EOF
// )
//
// Note that you can get the  address of the IC node from the ict console output:
//
//   {
//     nodes: [
//       {
//         id: y4g5e-dpl4n-swwhv-la7ec-32ngk-w7f3f-pr5bt-kqw67-2lmfy-agipc-zae,
//         ipv6: 2a0b:21c0:4003:2:5034:46ff:fe3c:e76f
//       }
//     ],
//     subnet_id: 5hv4k-srndq-xgw53-r6ldt-wtv4x-6xvbj-6lvpf-sbu5n-sqied-63bgv-eqe,
//     subnet_type: application
//   },
//
// To get access to P8s and Grafana look for the following lines in the ict console output:
//
//     prometheus: Prometheus Web UI at http://prometheus.from_config--1692597750709.testnet.farm.dfinity.systems,
//     grafana: Grafana at http://grafana.from_config--1692597750709.testnet.farm.dfinity.systems,
//     progress_clock: IC Progress Clock at http://grafana.from_config--1692597750709.testnet.farm.dfinity.systems/d/ic-progress-clock/ic-progress-clock?refresh=10su0026from=now-5mu0026to=now,
//
// Happy testing!

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_tests::os_qualification_utils::{IcConfig, IC_CONFIG};

fn main() -> anyhow::Result<()> {
    let mut config = std::env::var(IC_CONFIG)
        .unwrap_or_else(|_| panic!("Failed to fetch `{}` from env", IC_CONFIG));

    if config.starts_with('\'') {
        config = config[1..config.len() - 1].to_string();
    }

    let parsed: IcConfig = serde_json::from_str(&config)
        .unwrap_or_else(|_| panic!("Failed to parse json from envrionment: \n{}", config));

    SystemTestGroup::new()
        .with_setup(|env| ic_tests::os_qualification_utils::setup(env, parsed))
        .execute_from_args()?;
    Ok(())
}
