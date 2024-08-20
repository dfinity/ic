use candid::Encode;
use cycles_minting_canister::{CyclesCanisterInitPayload, CYCLES_LEDGER_CANISTER_ID};
use ic_base_types::{CanisterId, PrincipalId};
use ic_crypto_sha2::Sha256;
use ic_nervous_system_clients::canister_status::CanisterStatusType;
use ic_nns_constants::{
    CYCLES_MINTING_CANISTER_ID, GENESIS_TOKEN_CANISTER_ID, GOVERNANCE_CANISTER_ID,
    LEDGER_CANISTER_ID, LIFELINE_CANISTER_ID, REGISTRY_CANISTER_ID, ROOT_CANISTER_ID,
    SNS_WASM_CANISTER_ID,
};
use ic_nns_test_utils::{
    common::modify_wasm_bytes,
    state_test_helpers::{
        get_canister_status, nns_create_super_powerful_neuron, nns_propose_upgrade_nns_canister,
        wait_for_canister_upgrade_to_succeed,
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
                    cycles_ledger_canister_id: Some(
                        CanisterId::try_from(CYCLES_LEDGER_CANISTER_ID).unwrap()
                    ),
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
fn test_upgrade_canisters_with_golden_nns_state() {
    // Step 0: Read configuration. To wit, what canisters does the user want to upgrade in this
    // test? To do this, they set the NNS_CANISTER_UPGRADE_SEQUENCE environment variable.

    let mut nns_canister_upgrade_sequence = env::var("NNS_CANISTER_UPGRADE_SEQUENCE").expect(
        "This test requires that the NNS_CANISTER_UPGRADE_SEQUENCE environment\n\
             variable to be set to something like 'governance,registry'.\n\
             That is, it should be a comma separated list of canister names.\n\
             Alternatively, 'all' is equivalent to\n\
             'cycles-minting,genesis-token,governance,ledger,lifeline,registry,root,sns-wasm'\n\
             (these are all the supported canister names, a large subset of\n\
             those listed in rs/nns/canister_ids.json).",
    );

    if nns_canister_upgrade_sequence == "all" {
        nns_canister_upgrade_sequence = [
            "cycles-minting",
            "genesis-token",
            "governance",
            "ledger",
            "lifeline",
            "registry",
            "root",
            "sns-wasm",
        ]
        .join(",");
    }

    let mut nns_canister_upgrade_sequence = nns_canister_upgrade_sequence
        .split(',')
        .map(NnsCanisterUpgrade::new)
        .collect::<Vec<NnsCanisterUpgrade>>();

    // Step 1: Prepare the world

    // Step 1.1: Load golden nns state into a StateMachine.
    // TODO: Use PocketIc instead of StateMachine.
    let state_machine = new_state_machine_with_golden_nns_state_or_panic();

    // Step 1.2: Create a super powerful Neuron.
    println!("Creating super powerful Neuron.");
    let neuron_controller = PrincipalId::new_self_authenticating(&[1, 2, 3, 4]);
    let neuron_id = nns_create_super_powerful_neuron(&state_machine, neuron_controller);
    println!("Done creating super powerful Neuron.");

    let mut repetition_number = 1;
    // In order that nns_canister_upgrade_sequence can be modified outside this
    // lambda, this lambda takes it as an argument, rather than "inheriting" it
    // from the outer scope.
    let mut perform_sequence_of_upgrades =
        |nns_canister_upgrade_sequence: &[NnsCanisterUpgrade]| {
            for nns_canister_upgrade in nns_canister_upgrade_sequence {
                let NnsCanisterUpgrade {
                    nns_canister_name,
                    canister_id,
                    wasm_content,
                    module_arg,
                    wasm_hash,

                    wasm_path: _,
                    environment_variable_name: _,
                } = nns_canister_upgrade;
                println!("\nCurrent canister: {}", nns_canister_name);

                // Step 1.3: Assert that the upgrade we are about to perform would
                // actually change the code in the canister. (This is "just" a
                // pre-flight check).
                let status_result = get_canister_status(
                    &state_machine,
                    nns_canister_upgrade.controller_principal_id(),
                    *canister_id,
                    CanisterId::ic_00(), // callee: management (virtual) canister.
                )
                .unwrap();
                assert_eq!(
                    status_result.status,
                    CanisterStatusType::Running,
                    "{:#?}",
                    status_result,
                );
                assert_ne!(
                    status_result.module_hash.as_ref().unwrap(),
                    &wasm_hash,
                    "Current code is the same as what is running in mainnet?!\n{:#?}",
                    status_result,
                );

                // Step 2: Call code under test: Upgrade the (current) canister.
                println!(
                    "Proposing to upgrade NNS {} (attempt {})...",
                    nns_canister_name, repetition_number,
                );
                let _proposal_id = nns_propose_upgrade_nns_canister(
                    &state_machine,
                    neuron_controller,
                    neuron_id,
                    *canister_id,
                    wasm_content.clone(),
                    module_arg.clone(),
                    false,
                );

                // Step 3: Verify result(s): In a short while, the canister should
                // be running the new code.
                wait_for_canister_upgrade_to_succeed(
                    &state_machine,
                    *canister_id,
                    wasm_hash,
                    nns_canister_upgrade.controller_principal_id(),
                );
                println!(
                    "Attempt {} to upgrade {} was successful.",
                    repetition_number, nns_canister_name
                );
            }

            repetition_number += 1;
        };

    perform_sequence_of_upgrades(&nns_canister_upgrade_sequence);

    // Modify all WASMs, but preserve their behavior.
    for nns_canister_upgrade in &mut nns_canister_upgrade_sequence {
        nns_canister_upgrade.modify_wasm_but_preserve_behavior();
    }

    perform_sequence_of_upgrades(&nns_canister_upgrade_sequence);
}
