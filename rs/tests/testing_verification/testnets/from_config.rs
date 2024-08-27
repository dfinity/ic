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
//   $ ./ci/tools/docker-run
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

use ic_consensus_system_test_utils::rw_message::install_nns_with_customizations_and_check_progress;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::{
    boundary_node::BoundaryNode,
    group::SystemTestGroup,
    ic::{InternetComputer, Node, Subnet},
    node_software_version::NodeSoftwareVersion,
    prometheus_vm::{HasPrometheus, PrometheusVm},
    test_env::TestEnv,
    test_env_api::{get_dependency_path, HasTopologySnapshot, NnsCustomizations},
};
use serde::Deserialize;
use slog::info;
use url::Url;

fn main() -> anyhow::Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .execute_from_args()?;
    Ok(())
}

const IC_VERSION_FILE: &str = "ENV_DEPS__IC_VERSION_FILE";
const CUSTOM_REVISION: &str = "custom_revision";

const CUSTOM_DISK_IMG_TAR_URL: &str = "custom_disk_img_tar_url";
const DEV_DISK_IMG_TAR_ZST_CAS_URL: &str = "ENV_DEPS__DEV_DISK_IMG_TAR_ZST_CAS_URL";

const CUSTOM_DISK_IMG_SHA: &str = "custom_disk_img_sha";
const DEV_DISK_IMG_TAR_ZST_SHA256: &str = "ENV_DEPS__DEV_DISK_IMG_TAR_ZST_SHA256";

const IC_CONFIG: &str = "IC_CONFIG";

const TAR_EXTENSION: &str = ".tar.zst";

pub fn setup(env: TestEnv) {
    let mut config = std::env::var(IC_CONFIG)
        .unwrap_or_else(|_| panic!("Failed to fetch `{}` from env", IC_CONFIG));

    if config.starts_with('\'') {
        config = config[1..config.len() - 1].to_string();
    }

    let parsed: IcConfig = serde_json::from_str(&config)
        .unwrap_or_else(|_| panic!("Failed to parse json from envrionment: \n{}", config));

    let mut ic = InternetComputer::new();
    if let Some(v) = parsed.initial_version {
        ic = ic.with_initial_replica(NodeSoftwareVersion {
            replica_version: v.clone().try_into().unwrap(),
            replica_url: Url::parse("https://unimportant.com").unwrap(),
            replica_hash: "".to_string(),
            orchestrator_url: Url::parse("https://unimportant.com").unwrap(),
            orchestrator_hash: "".to_string(),
        });
        write_file_and_update_env_variable(
            &env,
            vec![
                (
                    CUSTOM_REVISION,
                    v.to_string(),
                    IC_VERSION_FILE,
                ),
                (
                    CUSTOM_DISK_IMG_TAR_URL,
                    format!("http://download.proxy-global.dfinity.network:8080/ic/{}/guest-os/disk-img/disk-img.tar.zst", v),
                    DEV_DISK_IMG_TAR_ZST_CAS_URL,
                ),
                (
                    CUSTOM_DISK_IMG_SHA,
                    fetch_shasum_for_disk_img(v.to_string()),
                    DEV_DISK_IMG_TAR_ZST_SHA256,
                ),
            ],
        );
    }
    if let Some(subnets) = parsed.subnets {
        subnets.iter().for_each(|s| {
            let su = match s {
                ConfigurableSubnet::Simple(s) => Subnet::new(s.subnet_type).add_nodes(s.num_nodes),
                ConfigurableSubnet::Complex(s) => *s.to_owned(),
            };
            ic = ic.clone().add_subnet(su)
        })
    }
    if let Some(u) = parsed.unassigned_nodes {
        match u {
            ConfigurableUnassignedNodes::Simple(un) => ic = ic.clone().with_unassigned_nodes(un),
            ConfigurableUnassignedNodes::Complex(uns) => uns
                .into_iter()
                .for_each(|un| ic = ic.clone().with_unassigned_node(un)),
        }
    }

    PrometheusVm::default()
        .start(&env)
        .expect("Failed to start prometheus VM");
    ic.setup_and_start(&env)
        .expect("Failed to setup IC under test");

    install_nns_with_customizations_and_check_progress(
        env.topology_snapshot(),
        NnsCustomizations::default(),
    );

    if let Some(boundary_nodes) = parsed.boundary_nodes {
        boundary_nodes.iter().for_each(|bn| {
            match bn {
                ConfigurableBoundaryNode::Simple(bn) => BoundaryNode::new(bn.name.clone()),
                ConfigurableBoundaryNode::Complex(b) => *b.to_owned(),
            }
            .allocate_vm(&env)
            .expect("Allocation of BoundaryNode failed.")
            .for_ic(&env, "")
            .use_real_certs_and_dns()
            .start(&env)
            .expect("Failed to setup BoundaryNode VM")
        })
    }

    env.sync_with_prometheus();
}

fn write_file_and_update_env_variable(env: &TestEnv, pairs: Vec<(&str, String, &str)>) {
    for (file_name, value_in_file, env_variable) in pairs {
        let path = get_dependency_path(file_name);
        std::fs::write(&path, value_in_file)
            .unwrap_or_else(|_| panic!("Failed to write to path: {}", path.display()));
        std::env::set_var(env_variable, file_name);
        info!(
            env.logger(),
            "Overriden env variable `{}` to value: {}",
            env_variable,
            path.display()
        )
    }
}

fn fetch_shasum_for_disk_img(version: String) -> String {
    let url = format!(
        "http://download.proxy-global.dfinity.network:8080/ic/{}/guest-os/disk-img/SHA256SUMS",
        version
    );
    let response = reqwest::blocking::get(&url)
        .unwrap_or_else(|e| panic!("Failed to fetch url `{}` with err: {:?}", &url, e));
    if !response.status().is_success() {
        panic!(
            "Received non-success response status: {:?}",
            response.status()
        )
    }

    String::from_utf8(
        response
            .bytes()
            .expect("Failed to deserialize bytes")
            .to_vec(),
    )
    .expect("Failed to convert to UTF8")
    .lines()
    .find(|l| l.ends_with(TAR_EXTENSION))
    .unwrap_or_else(|| {
        panic!(
            "Failed to find a hash ending with `{}` from: {}",
            &url, TAR_EXTENSION
        )
    })
    .split_whitespace()
    .next()
    .expect("The format of hash should contain whitespace")
    .to_string()
}

#[derive(Deserialize, Debug)]
struct IcConfig {
    subnets: Option<Vec<ConfigurableSubnet>>,
    unassigned_nodes: Option<ConfigurableUnassignedNodes>,
    boundary_nodes: Option<Vec<ConfigurableBoundaryNode>>,
    initial_version: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum ConfigurableSubnet {
    Simple(SubnetSimple),
    Complex(Box<Subnet>),
}

#[derive(Deserialize, Debug)]
struct SubnetSimple {
    subnet_type: SubnetType,
    num_nodes: usize,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum ConfigurableBoundaryNode {
    Simple(BoundaryNodeSimple),
    Complex(Box<BoundaryNode>),
}

#[derive(Deserialize, Debug)]
struct BoundaryNodeSimple {
    name: String,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum ConfigurableUnassignedNodes {
    Simple(usize),
    Complex(Vec<Node>),
}
