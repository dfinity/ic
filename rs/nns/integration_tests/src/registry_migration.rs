// TODO(DRE-6385): Remove this test once PBR is fully rolled out to mainnet.
use candid::{Decode, Encode};
use ic_base_types::{CanisterId, PrincipalId};
use ic_crypto_sha2::Sha256;
use ic_nervous_system_clients::canister_status::CanisterStatusType;
use ic_nervous_system_common::ONE_MONTH_SECONDS;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_constants::{
    GOVERNANCE_CANISTER_ID, NODE_REWARDS_CANISTER_ID, REGISTRY_CANISTER_ID, ROOT_CANISTER_ID,
};
use ic_nns_governance_api::{
    ListNodeProvidersResponse, MonthlyNodeProviderRewards, NetworkEconomics, ProposalActionRequest,
    RewardNodeProviders, Vote, VotingPowerEconomics,
};
use ic_nns_test_utils::state_test_helpers::{
    get_canister_status, manage_network_economics, nns_cast_vote, nns_create_super_powerful_neuron,
    nns_propose_upgrade_nns_canister, query, wait_for_canister_upgrade_to_succeed,
};
use ic_nns_test_utils::state_test_helpers::{
    nns_get_most_recent_monthly_node_provider_rewards, nns_wait_for_proposal_execution,
    scrape_metrics,
};
use ic_nns_test_utils_golden_nns_state::new_state_machine_with_golden_nns_state_or_panic;
use ic_node_rewards_canister_api::provider_rewards_calculation::GetNodeProvidersRewardsCalculationRequest;
use ic_protobuf::registry::dc::v1::DataCenterRecord;
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_registry_keys::make_node_operator_record_key;
use ic_registry_transport::pb::v1::high_capacity_registry_get_value_response;
use ic_registry_transport::{Error, deserialize_get_value_response, serialize_get_value_request};
use ic_state_machine_tests::StateMachine;
use icp_ledger::Tokens;
use itertools::Itertools;
use prost::Message;
use std::cmp::PartialEq;
use std::collections::BTreeMap;
use std::fmt::Display;
use std::{
    env,
    fmt::{Debug, Formatter},
    fs,
    str::FromStr,
};

struct RegistryCanisterUpdate {
    nns_canister_name: String,
    canister_id: CanisterId,
    environment_variable_name: &'static str,
    wasm_path: String,
    wasm_content: Vec<u8>,
    wasm_hash: [u8; 32],
}

impl RegistryCanisterUpdate {
    fn new(nns_canister_name: &str) -> Self {
        #[rustfmt::skip]
        let (canister_id, environment_variable_name) = match nns_canister_name {
            "governance"     => (GOVERNANCE_CANISTER_ID, "GOVERNANCE_CANISTER_WASM_PATH"),
            "registry"       => (REGISTRY_CANISTER_ID, "REGISTRY_CANISTER_WASM_PATH"),
            _ => panic!("Not a known NNS canister type: {nns_canister_name}",),
        };

        let nns_canister_name = nns_canister_name.to_string();
        let wasm_path = env::var(environment_variable_name)
            .unwrap_or_else(|err| panic!("{err}: {environment_variable_name}",));
        let wasm_content = fs::read(&wasm_path).unwrap();
        let wasm_hash = Sha256::hash(&wasm_content);

        Self {
            nns_canister_name,
            canister_id,
            environment_variable_name,
            wasm_path,
            wasm_content,
            wasm_hash,
        }
    }

    pub fn update(
        &self,
        state_machine: &StateMachine,
        neuron_controller: PrincipalId,
        neuron_id: NeuronId,
    ) {
        println!("\nCurrent canister: {}", self.nns_canister_name);

        let controller = PrincipalId::from(ROOT_CANISTER_ID);

        // Assert that the upgrade we are about to perform would
        // actually change the code in the canister. (This is "just" a
        // pre-flight check).
        let status_result = get_canister_status(
            state_machine,
            controller,
            self.canister_id,
            CanisterId::ic_00(), // callee: management (virtual) canister.
        )
        .unwrap();
        assert_eq!(
            status_result.status,
            CanisterStatusType::Running,
            "{status_result:#?}",
        );
        assert_ne!(
            status_result.module_hash.as_ref().unwrap(),
            &self.wasm_hash,
            "Current code is the same as what is running in mainnet?!\n{status_result:#?}",
        );
        println!("Proposing to upgrade NNS {}", self.nns_canister_name);

        let proposal_id = nns_propose_upgrade_nns_canister(
            state_machine,
            neuron_controller,
            neuron_id,
            self.canister_id,
            self.wasm_content.clone(),
            vec![],
        );

        // Impersonate some public neurons to vote on the proposal. Note that we do not
        // check whether votes succeed, as the governance upgrade can start at any point
        // which will make the canister unresponsive.
        vote_yes_with_well_known_public_neurons(state_machine, proposal_id.id);

        // Verify result(s): In a short while, the canister should
        // be running the new code.
        wait_for_canister_upgrade_to_succeed(
            state_machine,
            self.canister_id,
            &self.wasm_hash,
            controller,
        );
        println!(
            "Attempt to upgrade {} was successful.",
            self.nns_canister_name
        );
    }
}

impl Debug for RegistryCanisterUpdate {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let Self {
            nns_canister_name,
            canister_id,
            environment_variable_name,
            wasm_path,
            wasm_hash,
            wasm_content: _,
        } = self;

        let wasm_hash = wasm_hash.map(|element| format!("{element:02X}")).join("");
        let wasm_hash = &wasm_hash;

        formatter
            .debug_struct("NnsCanisterUpgrade")
            .field("nns_canister_name", nns_canister_name)
            .field("wasm_path", wasm_path)
            .field("wasm_hash", wasm_hash)
            .field("canister_id", canister_id)
            .field("environment_variable_name", environment_variable_name)
            .finish()
    }
}

/// Returns a list of well-known public neurons. Impersonating these neurons to vote a certain way
/// should be able to make the proposals pass instantly.
fn get_well_known_public_neurons() -> Vec<(NeuronId, PrincipalId)> {
    [
        (
            27,
            "4vnki-cqaaa-aaaaa-aaaaa-aaaaa-aaaaa-aaaaa-aaaaa-aaaaa-aaaaa-aae",
        ),
        (
            28,
            "4vnki-cqaaa-aaaaa-aaaaa-aaaaa-aaaaa-aaaaa-aaaaa-aaaaa-aaaaa-aae",
        ),
    ]
    .into_iter()
    .map(|(id, principal_str)| {
        let id = NeuronId { id };
        let principal = PrincipalId::from_str(principal_str).unwrap();
        (id, principal)
    })
    .collect()
}

fn vote_yes_with_well_known_public_neurons(state_machine: &StateMachine, proposal_id: u64) {
    for (voter_neuron_id, voter_controller) in get_well_known_public_neurons() {
        // Note that the voting can fail if the proposal already reaches absolute
        // majority and the NNS Governance starts to upgrade.
        let _ = nns_cast_vote(
            state_machine,
            voter_controller,
            voter_neuron_id,
            proposal_id,
            Vote::Yes,
        );
    }
}

#[test]
fn test_registry_migration_with_golden_state() {
    let nns_canister_upgrade_sequence: Vec<RegistryCanisterUpdate> =
        vec![RegistryCanisterUpdate::new("registry")];

    // Step 1: Prepare the world

    // Step 1.1: Load golden nns state into a StateMachine.
    let state_machine = new_state_machine_with_golden_nns_state_or_panic();

    // Step 1.2: Create a super powerful Neuron.
    println!("Creating super powerful Neuron.");
    let neuron_controller = PrincipalId::new_self_authenticating(&[1, 2, 3, 4]);
    let neuron_id = nns_create_super_powerful_neuron(
        &state_machine,
        neuron_controller,
        // Note that this number is chosen so that such an increase in voting power does not reach
        // 50% of the current voting power, which would be considered a spike and triggers a defense
        // mechanism designed to prevent a sudden takeover of the NNS.
        Tokens::from_tokens(100_000_000).unwrap(),
    );
    println!("Done creating super powerful Neuron.");

    // Step 1.3: Modify Network Economics so that the new neuron can vote.
    let proposal_id = manage_network_economics(
        &state_machine,
        NetworkEconomics {
            voting_power_economics: Some(VotingPowerEconomics {
                neuron_minimum_dissolve_delay_to_vote_seconds: Some(
                    VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS,
                ),
                ..Default::default()
            }),
            ..Default::default()
        },
        neuron_controller,
        neuron_id,
    );
    vote_yes_with_well_known_public_neurons(&state_machine, proposal_id.id);
    nns_wait_for_proposal_execution(&state_machine, proposal_id.id);

    let principals_target: Vec<PrincipalId> = vec![
        "3nu7r-l6i5c-jlmhi-fmmhm-4wcw4-ndlwb-yovrx-o3wxh-suzew-hvbbo-7qe",
        "ujq4k-55epc-pg2bt-jt2f5-6vaq3-diru7-edprm-42rd2-j7zzd-yjaai-2qe",
        "bmlhw-kinr6-7cyv5-3o3v6-ic6tw-pnzk3-jycod-6d7sw-owaft-3b6k3-kqe",
        "spsu4-5hl4t-bfubp-qvoko-jprw4-wt7ou-nlnbk-gb5ib-aqnoo-g4gl6-kae",
        "redpf-rrb5x-sa2it-zhbh7-q2fsp-bqlwz-4mf4y-tgxmj-g5y7p-ezjtj-5qe",
        "2rqo7-ot2kv-upof3-odw3y-sjckb-qeibt-n56vj-7b4pt-bvrtg-zay53-4qe",
    ]
    .into_iter()
    .map(|s| PrincipalId::from_str(s).unwrap())
    .collect();

    for target in principals_target.clone() {
        let key = make_node_operator_record_key(target);
        let (record, _) =
            get_value::<NodeOperatorRecord>(&state_machine, &key.as_bytes().to_vec(), None)
                .unwrap();

        let operator = NodeOperator::try_from(record).unwrap();
        println!("Before Migration NodeOperator key {}: {}", key, operator);
    }

    // Advance time to trigger rewarding event

    state_machine.advance_time(std::time::Duration::from_secs(ONE_MONTH_SECONDS));
    for _ in 0..100 {
        state_machine.advance_time(std::time::Duration::from_secs(1));
        state_machine.tick();
    }

    let rewards = nns_get_most_recent_monthly_node_provider_rewards(&state_machine);
    let xdr_permyriad_per_icp = rewards
        .clone()
        .unwrap()
        .xdr_conversion_rate
        .unwrap()
        .xdr_permyriad_per_icp
        .unwrap();
    let rewards_before = rewards
        .unwrap()
        .rewards
        .into_iter()
        .map(|r| {
            (
                r.node_provider.unwrap().id.unwrap(),
                (
                    r.amount_e8s / 100000000 * xdr_permyriad_per_icp,
                    r.amount_e8s / 100000000,
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();

    nns_canister_upgrade_sequence.iter().for_each(|canisters| {
        canisters.update(&state_machine, neuron_controller, neuron_id);
    });

    state_machine.advance_time(std::time::Duration::from_secs(ONE_MONTH_SECONDS));
    for _ in 0..100 {
        state_machine.advance_time(std::time::Duration::from_secs(1));
        state_machine.tick();
    }

    let rewards = nns_get_most_recent_monthly_node_provider_rewards(&state_machine);
    let xdr_permyriad_per_icp = rewards
        .clone()
        .unwrap()
        .xdr_conversion_rate
        .unwrap()
        .xdr_permyriad_per_icp
        .unwrap();
    let rewards_after = rewards
        .unwrap()
        .rewards
        .into_iter()
        .map(|r| {
            (
                r.node_provider.unwrap().id.unwrap(),
                (
                    r.amount_e8s / 100000000 * xdr_permyriad_per_icp,
                    r.amount_e8s / 100000000,
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();

    println!(
        "Rewards before migration: {}",
        rewards_before
            .into_iter()
            .map(|(k, (xdr, icp))| format!(" principal {}, XDRP: {} ICP:{}", k, xdr, icp))
            .join("\n")
    );
    println!(
        "Rewards after migration: {}",
        rewards_after
            .into_iter()
            .map(|(k, (xdr, icp))| format!(" principal {}, XDRP: {} ICP:{}", k, xdr, icp))
            .join("\n")
    );
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeOperator {
    pub node_operator_principal_id: PrincipalId,
    pub node_allowance: u64,
    pub node_provider_principal_id: PrincipalId,
    pub dc_id: String,
    pub rewardable_nodes: std::collections::BTreeMap<String, u32>,
    pub ipv6: Option<String>,
    pub max_rewardable_nodes: std::collections::BTreeMap<String, u32>,
}

impl Display for NodeOperator {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "NodeOperator {{ node_operator_principal_id: {}, node_allowance: {}, node_provider_principal_id: {}, dc_id: {}, rewardable_nodes: {:?}, ipv6: {:?}, max_rewardable_nodes: {:?} }}",
            self.node_operator_principal_id,
            self.node_allowance,
            self.node_provider_principal_id,
            self.dc_id,
            self.rewardable_nodes,
            self.ipv6,
            self.max_rewardable_nodes,
        )
    }
}

impl TryFrom<NodeOperatorRecord> for NodeOperator {
    type Error = String;

    fn try_from(value: NodeOperatorRecord) -> Result<Self, Self::Error> {
        Ok(NodeOperator {
            node_operator_principal_id: PrincipalId::try_from(
                value.node_operator_principal_id.clone(),
            )
            .map_err(|e| format!("Failed to convert node_operator_principal_id: {}", e))?,
            node_allowance: value.node_allowance,
            node_provider_principal_id: PrincipalId::try_from(
                value.node_provider_principal_id.clone(),
            )
            .map_err(|e| format!("Failed to convert node_provider_principal_id: {}", e))?,
            dc_id: value.dc_id,
            rewardable_nodes: value.rewardable_nodes,
            ipv6: value.ipv6,
            max_rewardable_nodes: value.max_rewardable_nodes,
        })
    }
}
fn fetch_all_node_operators_data(state_machine: &StateMachine) -> Vec<NodeOperator> {
    query(
        &state_machine,
        GOVERNANCE_CANISTER_ID,
        "list_node_providers",
        Encode!().unwrap(),
    )
    .map(|result| Decode!(&result, ListNodeProvidersResponse).unwrap())
    .unwrap()
    .node_providers
    .into_iter()
    .map(|node_provider| {
        let node_provider_id = node_provider.id.unwrap();
        let node_operators = query(
            &state_machine,
            REGISTRY_CANISTER_ID,
            "get_node_operators_and_dcs_of_node_provider",
            Encode!(&node_provider_id).unwrap(),
        )
        .map(|result| {
            Decode!(
                &result,
                Result<Vec<(DataCenterRecord, NodeOperatorRecord)>, String>
            )
            .unwrap()
        })
        .unwrap()
        .unwrap();

        (node_provider_id, node_operators)
    })
    .flat_map(|(np_id, records)| {
        records
            .into_iter()
            .map(move |(_, operator_record)| operator_record.try_into().unwrap())
    })
    .collect()
}

pub fn get_value<T: Message + Default>(
    state_machine: &StateMachine,
    key: &[u8],
    version: Option<u64>,
) -> Result<(T, u64), Error> {
    let current_result: Vec<u8> = query(
        state_machine,
        REGISTRY_CANISTER_ID,
        "get_value",
        serialize_get_value_request(key.to_vec(), version).unwrap(),
    )
    .unwrap();

    let response = deserialize_get_value_response(current_result)?;

    let Some(content) = response.content else {
        return Err(Error::MalformedMessage(format!(
            "The `content` field of the get_value response is not populated (key = {key:?}).",
        )));
    };

    let content: Vec<u8> = match content {
        high_capacity_registry_get_value_response::Content::Value(value) => value,

        _ => {
            panic!("Unexpected content variant in high_capacity_registry_get_value_response");
        }
    };

    // Decode the value as proper type
    let value = T::decode(content.as_slice()).unwrap();
    Ok((value, response.version))
}
