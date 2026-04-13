// Set up a testnet containing:
//   one 1-node System/NNS subnet, 60 unassigned nodes (2 per DC in 30 datacenters),
//   one API boundary node, one ic-gateway, and a p8s (with grafana) VM.
// All replica nodes use the following resources: 6 vCPUs, 24GiB of RAM, and 50 GiB disk.
//
// You can setup this testnet by executing the following commands:
//
//   $ ./ci/tools/docker-run
//   $ ict testnet create cloud_engine --output-dir=./cloud_engine -- --test_tmpdir=./cloud_engine
//
// The --output-dir=./cloud_engine will store the debug output of the test driver in the specified directory.
// The --test_tmpdir=./cloud_engine will store the remaining test output in the specified directory.
// This is useful to have access to in case you need to SSH into an IC node for example like:
//
//   $ ssh -i cloud_engine/_tmp/*/setup/ssh/authorized_priv_keys/admin admin@
//
// Note that you can get the  address of the IC node from the ict console output:
//
//   {
//     "nodes": [
//       {
//         "id": "...",
//         "ipv6": "..."
//       }
//     ],
//     "subnet_id": "...",
//     "subnet_type": "cloud_engine"
//   }
//
// To get access to P8s and Grafana look for the following lines in the ict console output:
//
//     prometheus: Prometheus Web UI at http://prometheus.cloud_engine--1692597750709.testnet.farm.dfinity.systems,
//     grafana: Grafana at http://grafana.cloud_engine--1692597750709.testnet.farm.dfinity.systems,
//     progress_clock: IC Progress Clock at http://grafana.cloud_engine--1692597750709.testnet.farm.dfinity.systems/d/ic-progress-clock/ic-progress-clock?refresh=10su0026from=now-5mu0026to=now,
//
// Happy testing!

use anyhow::Result;

use ic_consensus_system_test_utils::rw_message::install_nns_with_customizations_and_check_progress;
use ic_protobuf::registry::{
    dc::v1::{DataCenterRecord, Gps},
    node::v1::NodeRewardType,
};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::{
    farm::HostFeature,
    group::SystemTestGroup,
    ic::{InternetComputer, Node, NodeOperatorConfig, Subnet},
    ic_gateway_vm::{HasIcGatewayVm, IC_GATEWAY_VM_NAME, IcGatewayVm},
    test_env::TestEnv,
    test_env_api::HasTopologySnapshot,
};
use ic_types::{Height, PrincipalId};
use nns_dapp::{
    install_ii_nns_dapp_and_subnet_rental_with_dummy_auth, nns_dapp_customizations,
    set_authorized_subnets,
};
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

/// dm1-dmz datacenter and network constants
const DM1_DMZ_DC: &str = "dm1-dmz";
const DM1_DMZ_NETWORK: Ipv4Addr = Ipv4Addr::new(23, 142, 184, 224);
const DM1_DMZ_PREFIX: u8 = 28;
const DM1_DMZ_GATEWAY: Ipv4Addr = Ipv4Addr::new(23, 142, 184, 238);

struct DcConfig {
    id: &'static str,
    region: &'static str,
    owner: &'static str,
    latitude: f32,
    longitude: f32,
}

const DATA_CENTERS: &[DcConfig] = &[
    DcConfig {
        id: "Fremont",
        region: "North America,US,California",
        owner: "Hurricane Electric",
        latitude: 37.549,
        longitude: -121.989,
    },
    DcConfig {
        id: "Brussels",
        region: "Europe,BE,Brussels Capital",
        owner: "Digital Realty",
        latitude: 50.839,
        longitude: 4.348,
    },
    DcConfig {
        id: "HongKong 1",
        region: "Asia,HK,HongKong",
        owner: "Unicom",
        latitude: 22.284,
        longitude: 114.269,
    },
    DcConfig {
        id: "Sterling",
        region: "North America,US,Virginia",
        owner: "CyrusOne",
        latitude: 39.004,
        longitude: -77.408,
    },
    DcConfig {
        id: "Tokyo",
        region: "Asia,JP,Tokyo",
        owner: "Equinix",
        latitude: 35.682,
        longitude: 139.692,
    },
    DcConfig {
        id: "London",
        region: "Europe,GB,London",
        owner: "Telehouse",
        latitude: 51.508,
        longitude: -0.076,
    },
    DcConfig {
        id: "Frankfurt",
        region: "Europe,DE,Hessen",
        owner: "Interxion",
        latitude: 50.110,
        longitude: 8.682,
    },
    DcConfig {
        id: "Singapore",
        region: "Asia,SG,Singapore",
        owner: "Equinix",
        latitude: 1.290,
        longitude: 103.851,
    },
    DcConfig {
        id: "Sao Paulo",
        region: "South America,BR,Sao Paulo",
        owner: "Ascenty",
        latitude: -23.550,
        longitude: -46.633,
    },
    DcConfig {
        id: "Sydney",
        region: "Oceania,AU,New South Wales",
        owner: "Equinix",
        latitude: -33.868,
        longitude: 151.207,
    },
    DcConfig {
        id: "Toronto",
        region: "North America,CA,Ontario",
        owner: "eStruxture",
        latitude: 43.651,
        longitude: -79.347,
    },
    DcConfig {
        id: "Mumbai",
        region: "Asia,IN,Maharashtra",
        owner: "Nxtra",
        latitude: 19.076,
        longitude: 72.878,
    },
    DcConfig {
        id: "Seoul",
        region: "Asia,KR,Seoul",
        owner: "KINX",
        latitude: 37.566,
        longitude: 126.978,
    },
    DcConfig {
        id: "Amsterdam",
        region: "Europe,NL,North Holland",
        owner: "Equinix",
        latitude: 52.370,
        longitude: 4.895,
    },
    DcConfig {
        id: "Paris",
        region: "Europe,FR,Ile-de-France",
        owner: "Interxion",
        latitude: 48.864,
        longitude: 2.349,
    },
    DcConfig {
        id: "Stockholm",
        region: "Europe,SE,Stockholm",
        owner: "Interxion",
        latitude: 59.330,
        longitude: 18.069,
    },
    DcConfig {
        id: "Zurich",
        region: "Europe,CH,Zurich",
        owner: "Green",
        latitude: 47.376,
        longitude: 8.540,
    },
    DcConfig {
        id: "Dublin",
        region: "Europe,IE,Dublin",
        owner: "Equinix",
        latitude: 53.350,
        longitude: -6.260,
    },
    DcConfig {
        id: "Chicago",
        region: "North America,US,Illinois",
        owner: "Equinix",
        latitude: 41.878,
        longitude: -87.630,
    },
    DcConfig {
        id: "Dallas",
        region: "North America,US,Texas",
        owner: "DataBank",
        latitude: 32.777,
        longitude: -96.797,
    },
    DcConfig {
        id: "Los Angeles",
        region: "North America,US,California",
        owner: "CoreSite",
        latitude: 34.052,
        longitude: -118.244,
    },
    DcConfig {
        id: "Miami",
        region: "North America,US,Florida",
        owner: "Equinix",
        latitude: 25.762,
        longitude: -80.192,
    },
    DcConfig {
        id: "Bogota",
        region: "South America,CO,Bogota",
        owner: "Equinix",
        latitude: 4.711,
        longitude: -74.072,
    },
    DcConfig {
        id: "Cape Town",
        region: "Africa,ZA,Western Cape",
        owner: "Teraco",
        latitude: -33.925,
        longitude: 18.424,
    },
    DcConfig {
        id: "Nairobi",
        region: "Africa,KE,Nairobi",
        owner: "PAIX",
        latitude: -1.286,
        longitude: 36.817,
    },
    DcConfig {
        id: "Warsaw",
        region: "Europe,PL,Masovia",
        owner: "Equinix",
        latitude: 52.230,
        longitude: 21.012,
    },
    DcConfig {
        id: "Madrid",
        region: "Europe,ES,Madrid",
        owner: "Interxion",
        latitude: 40.417,
        longitude: -3.704,
    },
    DcConfig {
        id: "Milan",
        region: "Europe,IT,Lombardy",
        owner: "Equinix",
        latitude: 45.464,
        longitude: 9.190,
    },
    DcConfig {
        id: "Osaka",
        region: "Asia,JP,Osaka",
        owner: "Equinix",
        latitude: 34.694,
        longitude: 135.502,
    },
    DcConfig {
        id: "Jakarta",
        region: "Asia,ID,Jakarta",
        owner: "DCI",
        latitude: -6.175,
        longitude: 106.845,
    },
];

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
    let dm1_dmz_features = vec![HostFeature::DC(DM1_DMZ_DC.to_string()), HostFeature::DMZ];

    let mut ic = InternetComputer::new()
        .with_required_host_features(dm1_dmz_features.clone())
        .add_subnet(
            Subnet::new(SubnetType::System)
                .add_nodes(1)
                // To speed up subnet creation
                .with_dkg_interval_length(Height::from(10)),
        );

    // Build unassigned nodes distributed across 30 datacenters.
    // Each datacenter gets its own node operator with 2 unassigned nodes.
    // let mut cloud_engine_subnet = Subnet::new(SubnetType::CloudEngine);
    for (i, dc) in DATA_CENTERS.iter().enumerate() {
        let operator_principal = PrincipalId::new_user_test_id(1000 + i as u64);
        let provider_principal = PrincipalId::new_user_test_id(2000 + i as u64);

        ic = ic
            .add_data_center(DataCenterRecord {
                id: dc.id.to_string(),
                region: dc.region.to_string(),
                owner: dc.owner.to_string(),
                gps: Some(Gps {
                    latitude: dc.latitude,
                    longitude: dc.longitude,
                }),
            })
            .add_node_operator(NodeOperatorConfig {
                name: format!("operator_{}", dc.id),
                principal_id: operator_principal,
                node_provider_principal_id: Some(provider_principal),
                node_allowance: 2,
                dc_id: dc.id.to_string(),
                rewardable_nodes: BTreeMap::from([("type4.1".to_string(), 2)]),
            });

        // 1 CloudEngine node per DC
        // cloud_engine_subnet = cloud_engine_subnet.add_node(
        //     Node::new()
        //         .with_node_operator_principal_id(operator_principal)
        //         .with_node_reward_type(NodeRewardType::Type4),
        // );

        // 1 unassigned node per DC
        ic = ic.with_unassigned_node(
            Node::new()
                .with_node_operator_principal_id(operator_principal)
                .with_node_reward_type(NodeRewardType::Type4),
        );
    }

    ic = ic
        //.add_subnet(cloud_engine_subnet)
        .with_api_boundary_nodes_playnet(1);

    ic.setup_and_start(&env)
        .expect("Failed to setup IC under test");
    install_nns_with_customizations_and_check_progress(
        env.topology_snapshot(),
        nns_dapp_customizations(),
    );
    // deploy ic-gateway on dm1-dmz with static IPv4
    let mut ic_gateway_vm =
        IcGatewayVm::new(IC_GATEWAY_VM_NAME).with_required_host_features(dm1_dmz_features);
    if let Ok(ic_gw_ipv4) = std::env::var("IC_GW_IPV4") {
        let ip: Ipv4Addr = ic_gw_ipv4
            .parse()
            .unwrap_or_else(|e| panic!("invalid IC_GW_IPV4 address '{ic_gw_ipv4}': {e}"));
        let mask: u32 = !((1_u32 << (32 - DM1_DMZ_PREFIX)) - 1);
        assert_eq!(
            u32::from(ip) & mask,
            u32::from(DM1_DMZ_NETWORK),
            "IC_GW_IPV4 address {ip} is not within {DM1_DMZ_NETWORK}/{DM1_DMZ_PREFIX}"
        );
        let address = format!("{ip}/{DM1_DMZ_PREFIX}");
        ic_gateway_vm = ic_gateway_vm.with_ipv4_config(&address, &DM1_DMZ_GATEWAY.to_string());
    }
    ic_gateway_vm
        .start(&env)
        .expect("failed to setup ic-gateway");
    let ic_gateway = env.get_deployed_ic_gateway(IC_GATEWAY_VM_NAME).unwrap();
    let ic_gateway_url = ic_gateway.get_public_url();

    // sets the application subnets as "authorized" for canister creation by CMC
    set_authorized_subnets(&env);

    // install II, NNS dapp, and Subnet Rental Canister
    install_ii_nns_dapp_and_subnet_rental_with_dummy_auth(&env, &ic_gateway_url, None);
}
