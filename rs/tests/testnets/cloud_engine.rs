// Set up a testnet containing:
//   one 1-node System/NNS subnet, by default 20 unassigned nodes distributed
//   round-robin across 30 datacenters (so each of the first 20 DCs gets 1 node),
//   one API boundary node, one ic-gateway, and a p8s (with grafana) VM.
// All replica nodes use the following resources: 6 vCPUs, 24GiB of RAM, and 50 GiB disk.
//
// The number of unassigned nodes can be overridden via the NUM_UNASSIGNED_NODES
// env var (e.g. NUM_UNASSIGNED_NODES=60 will spin up 60 unassigned nodes,
// distributed round-robin across the 30 DCs, yielding 2 nodes per DC).
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

/// Node providers used in this testnet. Each data center is owned by exactly
/// one node provider (1 node provider per DC). Providers can own multiple DCs
/// and do not need to own the same number of DCs / nodes.
#[derive(Clone, Copy, Debug)]
enum NodeProvider {
    // Required because of DFINITY-capitalization-check pre-commit
    #[allow(clippy::upper_case_acronyms)]
    DFINITY,
    Alusion,
    OneSixtyTwoDigitalCapital,
    DecentralizedEntitiesFoundation,
}

impl NodeProvider {
    /// Stable test principal id for each provider. These are deterministic and
    /// only intended for the testnet setup.
    fn principal_id(&self) -> PrincipalId {
        // Use a separate id range (3000+) from node operators (1000+) so that
        // the principals don't overlap.
        match self {
            NodeProvider::DFINITY => PrincipalId::new_user_test_id(3000),
            NodeProvider::Alusion => PrincipalId::new_user_test_id(3001),
            NodeProvider::OneSixtyTwoDigitalCapital => PrincipalId::new_user_test_id(3002),
            NodeProvider::DecentralizedEntitiesFoundation => PrincipalId::new_user_test_id(3003),
        }
    }
}

struct DcConfig {
    id: &'static str,
    region: &'static str,
    owner: &'static str,
    latitude: f32,
    longitude: f32,
    /// The node provider that owns this data center. Every DC has exactly one
    /// node provider, but one node provider may own many DCs.
    node_provider: NodeProvider,
}

const DATA_CENTERS: &[DcConfig] = &[
    DcConfig {
        id: "Fremont",
        region: "North America,US,California",
        owner: "Hurricane Electric",
        latitude: 37.549,
        longitude: -121.989,
        node_provider: NodeProvider::DFINITY,
    },
    DcConfig {
        id: "Brussels",
        region: "Europe,BE,Brussels Capital",
        owner: "Digital Realty",
        latitude: 50.839,
        longitude: 4.348,
        node_provider: NodeProvider::DFINITY,
    },
    DcConfig {
        id: "HongKong 1",
        region: "Asia,HK,HongKong",
        owner: "Unicom",
        latitude: 22.284,
        longitude: 114.269,
        node_provider: NodeProvider::DFINITY,
    },
    DcConfig {
        id: "Sterling",
        region: "North America,US,Virginia",
        owner: "CyrusOne",
        latitude: 39.004,
        longitude: -77.408,
        node_provider: NodeProvider::DFINITY,
    },
    DcConfig {
        id: "Tokyo",
        region: "Asia,JP,Tokyo",
        owner: "Equinix",
        latitude: 35.682,
        longitude: 139.692,
        node_provider: NodeProvider::DFINITY,
    },
    DcConfig {
        id: "London",
        region: "Europe,GB,London",
        owner: "Telehouse",
        latitude: 51.508,
        longitude: -0.076,
        node_provider: NodeProvider::DFINITY,
    },
    DcConfig {
        id: "Frankfurt",
        region: "Europe,DE,Hessen",
        owner: "Interxion",
        latitude: 50.110,
        longitude: 8.682,
        node_provider: NodeProvider::DFINITY,
    },
    DcConfig {
        id: "Singapore",
        region: "Asia,SG,Singapore",
        owner: "Equinix",
        latitude: 1.290,
        longitude: 103.851,
        node_provider: NodeProvider::DFINITY,
    },
    DcConfig {
        id: "Sao Paulo",
        region: "South America,BR,Sao Paulo",
        owner: "Ascenty",
        latitude: -23.550,
        longitude: -46.633,
        node_provider: NodeProvider::DFINITY,
    },
    DcConfig {
        id: "Sydney",
        region: "Oceania,AU,New South Wales",
        owner: "Equinix",
        latitude: -33.868,
        longitude: 151.207,
        node_provider: NodeProvider::Alusion,
    },
    DcConfig {
        id: "Toronto",
        region: "North America,CA,Ontario",
        owner: "eStruxture",
        latitude: 43.651,
        longitude: -79.347,
        node_provider: NodeProvider::Alusion,
    },
    DcConfig {
        id: "Mumbai",
        region: "Asia,IN,Maharashtra",
        owner: "Nxtra",
        latitude: 19.076,
        longitude: 72.878,
        node_provider: NodeProvider::Alusion,
    },
    DcConfig {
        id: "Seoul",
        region: "Asia,KR,Seoul",
        owner: "KINX",
        latitude: 37.566,
        longitude: 126.978,
        node_provider: NodeProvider::Alusion,
    },
    DcConfig {
        id: "Amsterdam",
        region: "Europe,NL,North Holland",
        owner: "Equinix",
        latitude: 52.370,
        longitude: 4.895,
        node_provider: NodeProvider::Alusion,
    },
    DcConfig {
        id: "Paris",
        region: "Europe,FR,Ile-de-France",
        owner: "Interxion",
        latitude: 48.864,
        longitude: 2.349,
        node_provider: NodeProvider::Alusion,
    },
    DcConfig {
        id: "Stockholm",
        region: "Europe,SE,Stockholm",
        owner: "Interxion",
        latitude: 59.330,
        longitude: 18.069,
        node_provider: NodeProvider::Alusion,
    },
    DcConfig {
        id: "Zurich",
        region: "Europe,CH,Zurich",
        owner: "Green",
        latitude: 47.376,
        longitude: 8.540,
        node_provider: NodeProvider::Alusion,
    },
    DcConfig {
        id: "Dublin",
        region: "Europe,IE,Dublin",
        owner: "Equinix",
        latitude: 53.350,
        longitude: -6.260,
        node_provider: NodeProvider::OneSixtyTwoDigitalCapital,
    },
    DcConfig {
        id: "Chicago",
        region: "North America,US,Illinois",
        owner: "Equinix",
        latitude: 41.878,
        longitude: -87.630,
        node_provider: NodeProvider::OneSixtyTwoDigitalCapital,
    },
    DcConfig {
        id: "Dallas",
        region: "North America,US,Texas",
        owner: "DataBank",
        latitude: 32.777,
        longitude: -96.797,
        node_provider: NodeProvider::OneSixtyTwoDigitalCapital,
    },
    DcConfig {
        id: "Los Angeles",
        region: "North America,US,California",
        owner: "CoreSite",
        latitude: 34.052,
        longitude: -118.244,
        node_provider: NodeProvider::OneSixtyTwoDigitalCapital,
    },
    DcConfig {
        id: "Miami",
        region: "North America,US,Florida",
        owner: "Equinix",
        latitude: 25.762,
        longitude: -80.192,
        node_provider: NodeProvider::OneSixtyTwoDigitalCapital,
    },
    DcConfig {
        id: "Bogota",
        region: "South America,CO,Bogota",
        owner: "Equinix",
        latitude: 4.711,
        longitude: -74.072,
        node_provider: NodeProvider::OneSixtyTwoDigitalCapital,
    },
    DcConfig {
        id: "Cape Town",
        region: "Africa,ZA,Western Cape",
        owner: "Teraco",
        latitude: -33.925,
        longitude: 18.424,
        node_provider: NodeProvider::OneSixtyTwoDigitalCapital,
    },
    DcConfig {
        id: "Nairobi",
        region: "Africa,KE,Nairobi",
        owner: "PAIX",
        latitude: -1.286,
        longitude: 36.817,
        node_provider: NodeProvider::DecentralizedEntitiesFoundation,
    },
    DcConfig {
        id: "Warsaw",
        region: "Europe,PL,Masovia",
        owner: "Equinix",
        latitude: 52.230,
        longitude: 21.012,
        node_provider: NodeProvider::DecentralizedEntitiesFoundation,
    },
    DcConfig {
        id: "Madrid",
        region: "Europe,ES,Madrid",
        owner: "Interxion",
        latitude: 40.417,
        longitude: -3.704,
        node_provider: NodeProvider::DecentralizedEntitiesFoundation,
    },
    DcConfig {
        id: "Milan",
        region: "Europe,IT,Lombardy",
        owner: "Equinix",
        latitude: 45.464,
        longitude: 9.190,
        node_provider: NodeProvider::DecentralizedEntitiesFoundation,
    },
    DcConfig {
        id: "Osaka",
        region: "Asia,JP,Osaka",
        owner: "Equinix",
        latitude: 34.694,
        longitude: 135.502,
        node_provider: NodeProvider::DecentralizedEntitiesFoundation,
    },
    DcConfig {
        id: "Jakarta",
        region: "Asia,ID,Jakarta",
        owner: "DCI",
        latitude: -6.175,
        longitude: 106.845,
        node_provider: NodeProvider::DecentralizedEntitiesFoundation,
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

    // Build unassigned nodes distributed across the 30 datacenters.
    // Each datacenter gets its own node operator. The total number of unassigned
    // nodes defaults to 20 and can be overridden via the NUM_UNASSIGNED_NODES
    // env var. Nodes are distributed round-robin across DATA_CENTERS in order:
    // node index i is placed in DC (i % NUM_DCS). This means with the default
    // of 20 nodes the first 20 DCs each get 1 node, and with 60 nodes each DC
    // gets 2 nodes.
    //
    // Reward types are assigned in a circular rotation across all nodes globally:
    // node index 0 -> type4.1, 1 -> type4.2, 2 -> type4.3, 3 -> type4.1, ...
    // With a total that is a multiple of 3 this yields equal counts of each
    // reward type.
    const CLOUD_ENGINE_REWARD_TYPES: &[(NodeRewardType, &str)] = &[
        (NodeRewardType::Type4dot1, "type4.1"),
        (NodeRewardType::Type4dot2, "type4.2"),
        (NodeRewardType::Type4dot3, "type4.3"),
    ];
    const DEFAULT_NUM_UNASSIGNED_NODES: usize = 20;

    let num_unassigned_nodes: usize = match std::env::var("NUM_UNASSIGNED_NODES") {
        Ok(v) => v
            .parse()
            .unwrap_or_else(|e| panic!("invalid NUM_UNASSIGNED_NODES value '{v}': {e}")),
        Err(_) => DEFAULT_NUM_UNASSIGNED_NODES,
    };

    // Compute, for each DC, the list of (node_index, reward_type) pairs that
    // belong to that DC after the round-robin distribution. The global node
    // index is preserved so that the reward-type rotation is identical to a
    // simple sequential walk over all nodes.
    let mut nodes_per_dc: Vec<Vec<(usize, (NodeRewardType, &'static str))>> =
        vec![Vec::new(); DATA_CENTERS.len()];
    for node_idx in 0..num_unassigned_nodes {
        let dc_idx = node_idx % DATA_CENTERS.len();
        let reward = CLOUD_ENGINE_REWARD_TYPES[node_idx % CLOUD_ENGINE_REWARD_TYPES.len()];
        nodes_per_dc[dc_idx].push((node_idx, reward));
    }

    // let mut cloud_engine_subnet = Subnet::new(SubnetType::CloudEngine);
    for (i, dc) in DATA_CENTERS.iter().enumerate() {
        // Each DC has its own node operator (1 node operator per DC), but the
        // node provider is shared across all DCs owned by that provider.
        let operator_principal = PrincipalId::new_user_test_id(1000 + i as u64);
        let provider_principal = dc.node_provider.principal_id();

        let dc_nodes = &nodes_per_dc[i];

        // Aggregate rewardable_nodes counts per type string for this operator.
        let mut rewardable_nodes: BTreeMap<String, u32> = BTreeMap::new();
        for (_, (_, type_str)) in dc_nodes {
            *rewardable_nodes.entry(type_str.to_string()).or_insert(0) += 1;
        }

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
                node_allowance: dc_nodes.len() as u64,
                dc_id: dc.id.to_string(),
                rewardable_nodes,
            });

        // Add unassigned nodes for this DC using the circularly-assigned types.
        for (_, (reward_type, _)) in dc_nodes {
            ic = ic.with_unassigned_node(
                Node::new()
                    .with_node_operator_principal_id(operator_principal)
                    .with_node_reward_type(*reward_type),
            );
        }
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
