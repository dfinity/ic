// Set up a testnet containing:
//   one 1-node System/NNS subnet, by default 20 unassigned nodes distributed
//   round-robin across 20 datacenters spread across 4 cloud providers (5 DCs
//   each in AWS, Azure, GCP, and Hetzner), so by default each DC gets 1 node,
//   one API boundary node, one ic-gateway, and a p8s (with grafana) VM.
// All replica nodes use the following resources: 6 vCPUs, 24GiB of RAM, and 50 GiB disk.
//
// The number of unassigned nodes can be overridden via the NUM_UNASSIGNED_NODES
// env var (e.g. NUM_UNASSIGNED_NODES=60 will spin up 60 unassigned nodes,
// distributed round-robin across the 20 DCs, yielding 3 nodes per DC). When
// the count is not a multiple of the number of DCs, the leading DCs receive
// one extra node each.
//
// You can setup this testnet by executing the following commands (preferably from a devenv in dm1-idx1):
//
//   $ ./ci/tools/docker-run
//   $ bazel run //rs/tests/testnets:cloud_engine --test_tmpdir=./cloud_engine -- --keepalive
//
// The --test_tmpdir=./cloud_engine will store the remaining test output in the specified directory.
// This is useful to have access to in case you need to SSH into an IC node for example like:
//
//   $ ssh -i cloud_engine/_tmp/*/setup/ssh/authorized_priv_keys/admin admin@
//
// Note that you can get the address of the IC node from the bazel output by looking for farm_vm_created_event.
//
// To get access to P8s and Grafana look for the following lines in the output:
//
//     prometheus: Prometheus Web UI at http://prometheus.cloud_engine--1692597750709.testnet.farm.dfinity.systems,
//     grafana: Grafana at http://grafana.cloud_engine--1692597750709.testnet.farm.dfinity.systems,
//     progress_clock: IC Progress Clock at http://grafana.cloud_engine--1692597750709.testnet.farm.dfinity.systems/d/ic-progress-clock/ic-progress-clock?refresh=10su0026from=now-5mu0026to=now,
//
// Happy testing!

use anyhow::{Result, anyhow};

use candid::Principal;
use ic_consensus_system_test_utils::rw_message::install_nns_with_customizations_and_check_progress;
use ic_nervous_system_common_test_keys::TEST_NEURON_1_OWNER_PRINCIPAL;
use ic_protobuf::registry::{
    dc::v1::{DataCenterRecord, Gps},
    node::v1::NodeRewardType,
};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::{
    group::SystemTestGroup,
    ic::{InternetComputer, Node, NodeOperatorConfig, Subnet},
    ic_gateway_vm::{HasIcGatewayVm, IC_GATEWAY_VM_NAME, IcGatewayVm},
    test_env::TestEnv,
    test_env_api::{HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer},
};
use ic_system_test_driver::util::block_on;
use ic_types::{Height, PrincipalId};
use ic_utils::interfaces::ManagementCanister;
use nns_dapp::{
    install_ii_nns_dapp_and_subnet_rental_with_dummy_auth, nns_dapp_customizations,
    set_authorized_subnets,
};
use std::collections::BTreeMap;

/// Cycles to fund the demo application canister with. 300T cycles.
const DEMO_CANISTER_CYCLES: u128 = 300_000_000_000_000;

/// Cycles to fund the whale application canister with. 100_000T (100 quadrillion) cycles.
const WHALE_CANISTER_CYCLES: u128 = 100_000_000_000_000_000;

/// Node providers used in this testnet. Each data center is owned by exactly
/// one node provider (1 node provider per DC). Providers can own multiple DCs
/// and do not need to own the same number of DCs / nodes.
#[derive(Clone, Copy, Debug)]
enum NodeProvider {
    // Required because of DFINITY-capitalization-check pre-commit
    #[allow(clippy::upper_case_acronyms)]
    DFINITY,
}

impl NodeProvider {
    /// Stable test principal id for each provider. These are deterministic and
    /// only intended for the testnet setup.
    fn principal_id(&self) -> PrincipalId {
        // Use a separate id range (3000+) from node operators (1000+) so that
        // the principals don't overlap.
        match self {
            NodeProvider::DFINITY => PrincipalId::new_user_test_id(3000),
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

/// 20 datacenter regions distributed across 4 cloud providers (AWS, Azure,
/// GCP, Hetzner) with 5 regions each, spread across the globe. The `id` is
/// the cloud provider's region code, and lat/long are taken from the public
/// location of the region (or the city the region is named after).
const DATA_CENTERS: &[DcConfig] = &[
    // -------- AWS (5) --------
    DcConfig {
        id: "aws-us-east-1",
        region: "North America,US,Virginia",
        owner: "Amazon Web Services",
        latitude: 38.945,
        longitude: -77.448,
        node_provider: NodeProvider::DFINITY,
    },
    DcConfig {
        id: "aws-us-west-2",
        region: "North America,US,Oregon",
        owner: "Amazon Web Services",
        latitude: 45.871,
        longitude: -119.688,
        node_provider: NodeProvider::DFINITY,
    },
    DcConfig {
        id: "aws-sa-east-1",
        region: "South America,BR,Sao Paulo",
        owner: "Amazon Web Services",
        latitude: -23.550,
        longitude: -46.633,
        node_provider: NodeProvider::DFINITY,
    },
    DcConfig {
        id: "aws-eu-west-1",
        region: "Europe,IE,Dublin",
        owner: "Amazon Web Services",
        latitude: 53.350,
        longitude: -6.260,
        node_provider: NodeProvider::DFINITY,
    },
    DcConfig {
        id: "aws-ap-northeast-1",
        region: "Asia,JP,Tokyo",
        owner: "Amazon Web Services",
        latitude: 35.682,
        longitude: 139.692,
        node_provider: NodeProvider::DFINITY,
    },
    // -------- Azure (5) --------
    DcConfig {
        id: "azure-eastus",
        region: "North America,US,Virginia",
        owner: "Microsoft Azure",
        latitude: 37.371,
        longitude: -79.819,
        node_provider: NodeProvider::DFINITY,
    },
    DcConfig {
        id: "azure-westus2",
        region: "North America,US,Washington",
        owner: "Microsoft Azure",
        latitude: 47.233,
        longitude: -119.852,
        node_provider: NodeProvider::DFINITY,
    },
    DcConfig {
        id: "azure-westeurope",
        region: "Europe,NL,Noord-Holland",
        owner: "Microsoft Azure",
        latitude: 52.374,
        longitude: 4.890,
        node_provider: NodeProvider::DFINITY,
    },
    DcConfig {
        id: "azure-southeastasia",
        region: "Asia,SG,Singapore",
        owner: "Microsoft Azure",
        latitude: 1.352,
        longitude: 103.820,
        node_provider: NodeProvider::DFINITY,
    },
    DcConfig {
        id: "azure-australiaeast",
        region: "Oceania,AU,New South Wales",
        owner: "Microsoft Azure",
        latitude: -33.868,
        longitude: 151.207,
        node_provider: NodeProvider::DFINITY,
    },
    // -------- GCP (5) --------
    DcConfig {
        id: "gcp-us-central1",
        region: "North America,US,Iowa",
        owner: "Google Cloud Platform",
        latitude: 41.260,
        longitude: -95.860,
        node_provider: NodeProvider::DFINITY,
    },
    DcConfig {
        id: "gcp-us-east4",
        region: "North America,US,Virginia",
        owner: "Google Cloud Platform",
        latitude: 39.029,
        longitude: -77.490,
        node_provider: NodeProvider::DFINITY,
    },
    DcConfig {
        id: "gcp-europe-west3",
        region: "Europe,DE,Hessen",
        owner: "Google Cloud Platform",
        latitude: 50.110,
        longitude: 8.682,
        node_provider: NodeProvider::DFINITY,
    },
    DcConfig {
        id: "gcp-asia-southeast1",
        region: "Asia,SG,Singapore",
        owner: "Google Cloud Platform",
        latitude: 1.352,
        longitude: 103.820,
        node_provider: NodeProvider::DFINITY,
    },
    DcConfig {
        id: "gcp-southamerica-east1",
        region: "South America,BR,Sao Paulo",
        owner: "Google Cloud Platform",
        latitude: -23.550,
        longitude: -46.633,
        node_provider: NodeProvider::DFINITY,
    },
    // -------- Hetzner (5) --------
    DcConfig {
        id: "hetzner-fsn1",
        region: "Europe,DE,Hessen",
        owner: "Hetzner Online",
        latitude: 50.554,
        longitude: 9.681,
        node_provider: NodeProvider::DFINITY,
    },
    DcConfig {
        id: "hetzner-nbg1",
        region: "Europe,DE,Bayern",
        owner: "Hetzner Online",
        latitude: 49.452,
        longitude: 11.077,
        node_provider: NodeProvider::DFINITY,
    },
    DcConfig {
        id: "hetzner-hel1",
        region: "Europe,FI,Uusimaa",
        owner: "Hetzner Online",
        latitude: 60.169,
        longitude: 24.938,
        node_provider: NodeProvider::DFINITY,
    },
    DcConfig {
        id: "hetzner-ash",
        region: "North America,US,Virginia",
        owner: "Hetzner Online",
        latitude: 39.044,
        longitude: -77.487,
        node_provider: NodeProvider::DFINITY,
    },
    DcConfig {
        id: "hetzner-hil",
        region: "North America,US,Oregon",
        owner: "Hetzner Online",
        latitude: 45.523,
        longitude: -122.989,
        node_provider: NodeProvider::DFINITY,
    },
];

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
    let mut ic = InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .add_nodes(1)
                // To speed up subnet creation
                .with_dkg_interval_length(Height::from(10)),
        )
        // A small 1-node Application subnet, used to host a demo canister.
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .add_nodes(1)
                .with_dkg_interval_length(Height::from(10)),
        );

    // Build unassigned nodes distributed across the 20 datacenters (5 each in
    // AWS, Azure, GCP and Hetzner). Each datacenter gets its own node operator.
    // The total number of unassigned nodes defaults to 20 and can be overridden
    // via the NUM_UNASSIGNED_NODES env var. Nodes are distributed round-robin
    // across DATA_CENTERS in order: node index i is placed in DC
    // (i % NUM_DCS). With the default of 20 nodes each of the 20 DCs gets
    // exactly one node; with 60 nodes each DC would get 3 nodes; if the
    // count is not a multiple of NUM_DCS the leading DCs receive one extra
    // node each.
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
    // Deploy ic-gateway on any Farm host (no public/DMZ access needed).
    IcGatewayVm::new(IC_GATEWAY_VM_NAME)
        .start(&env)
        .expect("failed to setup ic-gateway");
    let ic_gateway = env.get_deployed_ic_gateway(IC_GATEWAY_VM_NAME).unwrap();
    let ic_gateway_url = ic_gateway.get_public_url();

    // sets the application subnets as "authorized" for canister creation by CMC
    set_authorized_subnets(&env);

    // install II, NNS dapp, and Subnet Rental Canister
    install_ii_nns_dapp_and_subnet_rental_with_dummy_auth(&env, &ic_gateway_url, None);

    // Create an empty (no wasm installed) canister on the Application subnet,
    // fund it with 300T cycles and set its controllers to
    // TEST_NEURON_1_OWNER_PRINCIPAL and the anonymous principal.
    create_empty_canister_on_app_subnet(&env, DEMO_CANISTER_CYCLES, "demo");

    // Create a second empty canister on the Application subnet, seeded with
    // 100_000T cycles (a "whale" canister), same controllers as the demo one.
    create_empty_canister_on_app_subnet(&env, WHALE_CANISTER_CYCLES, "whale");
}

/// Creates an empty canister (no wasm installed) on the (single) Application
/// subnet, funds it with `cycles` via the provisional API, and sets its
/// controllers to `TEST_NEURON_1_OWNER_PRINCIPAL` and the anonymous principal.
fn create_empty_canister_on_app_subnet(env: &TestEnv, cycles: u128, label: &str) {
    let topology = env.topology_snapshot();
    let app_subnet = topology
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .expect("no Application subnet found in topology");
    let app_node = app_subnet
        .nodes()
        .next()
        .expect("Application subnet has no nodes");
    let effective_canister_id = app_node.effective_canister_id();

    let test_neuron_principal = Principal::from(*TEST_NEURON_1_OWNER_PRINCIPAL);
    let anonymous_principal = Principal::anonymous();

    let canister_id = block_on(async {
        let agent = app_node.build_default_agent_async().await;
        let mgr = ManagementCanister::create(&agent);
        let (canister_id,) = mgr
            .create_canister()
            .as_provisional_create_with_amount(Some(cycles))
            .with_effective_canister_id(effective_canister_id)
            .with_controller(test_neuron_principal)
            .with_controller(anonymous_principal)
            .call_and_wait()
            .await
            .map_err(|err| anyhow!("failed to create demo canister: {err}"))
            .unwrap();
        canister_id
    });

    let log = env.logger();
    slog::info!(
        log,
        "Created empty {label} canister {canister_id} on Application subnet with {cycles} cycles; \
         controllers: TEST_NEURON_1_OWNER_PRINCIPAL ({}) and anonymous",
        *TEST_NEURON_1_OWNER_PRINCIPAL
    );
}
