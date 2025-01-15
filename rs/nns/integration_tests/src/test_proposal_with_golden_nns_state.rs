use candid::Encode;
use cycles_minting_canister::CyclesCanisterInitPayload;
use ic_base_types::{CanisterId, PrincipalId};
use ic_crypto_sha2::Sha256;
use ic_nervous_system_clients::canister_status::CanisterStatusType;
use ic_nns_common::pb::v1::ProposalId;
use ic_nns_constants::{
    CYCLES_LEDGER_CANISTER_ID, CYCLES_MINTING_CANISTER_ID, GENESIS_TOKEN_CANISTER_ID,
    GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID, LIFELINE_CANISTER_ID, REGISTRY_CANISTER_ID,
    ROOT_CANISTER_ID, SNS_WASM_CANISTER_ID,
};
use ic_nns_governance_api::pb::v1::{ListNeuronsResponse, Neuron};
use ic_nns_test_utils::{
    common::modify_wasm_bytes,
    state_test_helpers::{
        adopt_proposal, get_canister_status, list_neurons_by_principal,
        nns_create_super_powerful_neuron, nns_get_network_economics_parameters,
        nns_governance_adopt_proposal, nns_governance_get_proposal_info_as_anonymous,
        nns_governance_make_proposal, nns_propose_upgrade_nns_canister,
        nns_wait_for_proposal_execution, update_neuron, wait_for_canister_upgrade_to_succeed,
    },
};
use ic_nns_test_utils_golden_nns_state::new_state_machine_with_golden_nns_state_or_panic;
use std::{
    env,
    fmt::{Debug, Formatter},
    fs,
};

struct NnsCanisterUpgrade {
    nns_canister_name: String,
    canister_id: CanisterId,
    environment_variable_name: &'static str,
    wasm_path: String,
    wasm_content: Vec<u8>,
    module_arg: Vec<u8>,
    wasm_hash: [u8; 32],
}

impl NnsCanisterUpgrade {
    fn new(nns_canister_name: &str) -> Self {
        #[rustfmt::skip]
        let (canister_id, environment_variable_name) = match nns_canister_name {
            // NNS Backend
            "cycles-minting" => (CYCLES_MINTING_CANISTER_ID,"CYCLES_MINTING_CANISTER_WASM_PATH"),
            "genesis-token"  => (GENESIS_TOKEN_CANISTER_ID,"GENESIS_TOKEN_CANISTER_WASM_PATH"),
            "governance"     => (GOVERNANCE_CANISTER_ID, "GOVERNANCE_CANISTER_WASM_PATH"),
            "governance-test" => (GOVERNANCE_CANISTER_ID, "GOVERNANCE_CANISTER_TEST_WASM_PATH"),
            "ledger"         => (LEDGER_CANISTER_ID, "LEDGER_CANISTER_WASM_PATH"),
            "lifeline"       => (LIFELINE_CANISTER_ID, "LIFELINE_CANISTER_WASM_PATH"),
            "registry"       => (REGISTRY_CANISTER_ID, "REGISTRY_CANISTER_WASM_PATH"),
            "root"           => (ROOT_CANISTER_ID, "ROOT_CANISTER_WASM_PATH"),
            "sns-wasm"       => (SNS_WASM_CANISTER_ID, "SNS_WASM_CANISTER_WASM_PATH"),

            _ => panic!("Not a known NNS canister type: {}", nns_canister_name,),
        };

        let module_arg = if nns_canister_name == "cycles-minting" {
            Encode!(
                &(Some(CyclesCanisterInitPayload {
                    cycles_ledger_canister_id: Some(CYCLES_LEDGER_CANISTER_ID),
                    ledger_canister_id: None,
                    governance_canister_id: None,
                    minting_account_id: None,
                    last_purged_notification: None,
                    exchange_rate_canister: None,
                }))
            )
            .unwrap()
        } else {
            Encode!(&()).unwrap()
        };

        let nns_canister_name = nns_canister_name.to_string();
        let wasm_path = env::var(environment_variable_name)
            .unwrap_or_else(|err| panic!("{}: {}", err, environment_variable_name,));
        let wasm_content = fs::read(&wasm_path).unwrap();
        let wasm_hash = Sha256::hash(&wasm_content);

        Self {
            nns_canister_name,
            canister_id,
            environment_variable_name,
            wasm_path,
            wasm_content,
            module_arg,
            wasm_hash,
        }
    }

    fn modify_wasm_but_preserve_behavior(&mut self) {
        let old_wasm_hash = self.wasm_hash;

        self.wasm_content = modify_wasm_bytes(&self.wasm_content, 42);
        self.wasm_hash = Sha256::hash(&self.wasm_content);

        assert_ne!(self.wasm_hash, old_wasm_hash, "{:#?}", self);
    }

    fn controller_principal_id(&self) -> PrincipalId {
        let result = if self.nns_canister_name == "root" {
            LIFELINE_CANISTER_ID
        } else {
            ROOT_CANISTER_ID
        };

        PrincipalId::from(result)
    }
}

impl Debug for NnsCanisterUpgrade {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let Self {
            nns_canister_name,
            canister_id,
            environment_variable_name,
            wasm_path,
            wasm_hash,
            module_arg,

            wasm_content: _,
        } = self;

        let wasm_hash = wasm_hash.map(|element| format!("{:02X}", element)).join("");
        let wasm_hash = &wasm_hash;

        let module_arg = module_arg
            .iter()
            .map(|element| format!("{:02X}", element))
            .collect::<Vec<_>>()
            .join("");
        let module_arg = &module_arg;

        formatter
            .debug_struct("NnsCanisterUpgrade")
            .field("nns_canister_name", nns_canister_name)
            .field("wasm_path", wasm_path)
            .field("wasm_hash", wasm_hash)
            .field("module_arg", module_arg)
            .field("canister_id", canister_id)
            .field("environment_variable_name", environment_variable_name)
            .finish()
    }
}

#[test]
fn test_proposal_with_golden_nns_state() {
    // Step 1: Prepare the world

    // Make sure we can get a test version of NNS Governance. This enables modifying NNS neurons.
    let NnsCanisterUpgrade {
        nns_canister_name,
        canister_id,
        wasm_content,
        module_arg,
        wasm_hash,

        wasm_path: _,
        environment_variable_name: _,
    } = NnsCanisterUpgrade::new("governance-test");

    // Step 1.1: Load golden nns state into a StateMachine.
    // TODO: Use PocketIc instead of StateMachine.
    let state_machine = new_state_machine_with_golden_nns_state_or_panic();

    // Save initial state for the ultimate assertion of this test.
    let old_network_economics = nns_get_network_economics_parameters(&state_machine);

    // Step 1.2: Create a super powerful Neuron.
    println!("Creating super powerful Neuron.");
    let neuron_controller = PrincipalId::new_self_authenticating(&[1, 2, 3, 4]);
    let proposer_neuron_id = nns_create_super_powerful_neuron(&state_machine, neuron_controller);

    // Step 2: Upgrade the Governance canister to a test version.
    println!("Proposing to upgrade NNS Governance ...");

    let _proposal_id = nns_propose_upgrade_nns_canister(
        &state_machine,
        neuron_controller,
        proposer_neuron_id,
        canister_id,
        wasm_content.clone(),
        module_arg.clone(),
        true,
    );

    // Step 3: Verify result(s): In a short while, the canister should be running the new code.
    wait_for_canister_upgrade_to_succeed(
        &state_machine,
        canister_id,
        &wasm_hash,
        ROOT_CANISTER_ID.get(),
    );
    println!("Upgrading NNS Governance to a test version succeeded!");

    // Step 4. Vote the desired proposal through.
    let proposal_id = ProposalId { id: 134803 };

    adopt_proposal(&state_machine, proposal_id).unwrap();
    nns_wait_for_proposal_execution(&state_machine, proposal_id.id);

    let new_network_economics = nns_get_network_economics_parameters(&state_machine);

    assert_eq!(new_network_economics, old_network_economics);
}
