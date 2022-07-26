//! Contains the logic for deploying SNS canisters

use candid::parser::value::IDLValue;
use candid::Decode;
use candid::Encode;
use ic_base_types::{CanisterId, PrincipalId};
use ic_nns_constants::ROOT_CANISTER_ID as NNS_ROOT_CANISTER_ID;
use ic_nns_constants::SNS_WASM_CANISTER_ID;
use ic_sns_init::pb::v1::SnsInitPayload;
use ic_sns_init::{SnsCanisterIds, SnsCanisterInitPayloads};
use ic_sns_wasm::pb::v1::DeployNewSnsRequest;
use std::str::FromStr;

use crate::{call_dfx, get_identity, hex_encode_candid, DeployArgs};

const SNS_CREATION_FEE: u64 = 50_000_000_000_000;

/// If SNS canisters have already been created, return their canister IDs, else create the
/// SNS canisters and return their canister IDs.
pub fn lookup_or_else_create_canisters(args: &DeployArgs) -> SnsCanisterIds {
    let sns_canister_ids = match lookup(args) {
        Some(sns_canister_ids) => {
            println!("SNS canisters already allocated");
            sns_canister_ids
        }
        None => {
            println!(
                "SNS canisters not found, creating SNS canisters with {:?} cycles each",
                args.initial_cycles_per_canister
            );
            create_canisters(args)
        }
    };

    println!("SNS canister IDs:\n{:?}", &sns_canister_ids);
    sns_canister_ids
}

/// If all the SNS canisters have already been created, return them.
fn lookup(args: &DeployArgs) -> Option<SnsCanisterIds> {
    Some(SnsCanisterIds {
        governance: get_canister_id("sns_governance", args)?,
        ledger: get_canister_id("sns_ledger", args)?,
        root: get_canister_id("sns_root", args)?,
        swap: get_canister_id("sns_swap", args)?,
    })
}

/// Call `dfx canister create` to allocate canister IDs for all SNS canisters.
fn create_canisters(args: &DeployArgs) -> SnsCanisterIds {
    println!("Creating SNS canisters...");
    let cycles = format!("{}", args.initial_cycles_per_canister.unwrap_or_default());

    call_dfx(&[
        "canister",
        "--network",
        &args.network,
        "create",
        "--all",
        "--with-cycles",
        &cycles,
    ]);
    lookup(args).expect("SNS canisters failed to be created")
}

/// Return the canister ID of the canister given by `canister_name`
pub fn get_canister_id(canister_name: &str, args: &DeployArgs) -> Option<PrincipalId> {
    println!(
        "dfx canister --network {} id {}",
        &args.network, canister_name
    );
    let output = call_dfx(&["canister", "--network", &args.network, "id", canister_name]);

    let canister_id = String::from_utf8(output.stdout)
        .map_err(|e| {
            if args.verbose {
                println!(
                    "Could not parse the output of 'dfx canister id {}' as a string, error: {}",
                    canister_name, e
                )
            }
        })
        .ok()?;

    PrincipalId::from_str(canister_id.trim())
        .map_err(|e| {
            if args.verbose {
                println!(
                    "Could not parse the output of 'dfx canister id {}' as a PrincipalId, error: {}",
                    canister_name, e
                )
            }
        })
        .ok()
}

/// Responsible for deploying using SNS-WASM canister (for protected SNS subnet)
pub struct SnsWasmSnsDeployer {
    pub args: DeployArgs,
    pub sns_init_payload: SnsInitPayload,
    pub sns_wasms_canister_id: PrincipalId,
    pub wallet_canister: CanisterId,
}

impl SnsWasmSnsDeployer {
    pub fn new(args: DeployArgs, sns_init_payload: SnsInitPayload) -> Self {
        let sns_wasms_canister_id = args
            .override_sns_wasm_canister_id_for_tests
            .as_ref()
            .map(|principal| PrincipalId::from_str(principal).unwrap())
            .unwrap_or_else(|| SNS_WASM_CANISTER_ID.get());

        let wallet_canister = CanisterId::new(get_identity("get-wallet", &args.network))
            .expect("Could not convert wallet identity to CanisterId format");

        Self {
            args,
            sns_init_payload,
            sns_wasms_canister_id,
            wallet_canister,
        }
    }

    /// Deploy this to the specified network using the SNS-WASM canister
    pub fn deploy(&self) {
        let request = DeployNewSnsRequest {
            sns_init_payload: Some(self.sns_init_payload.clone()),
        };

        // Get a string representing the IDL of a DeployNewSnsRequest by
        // encoding it to bytes and decoding it to an IDLValue. The decoded
        // IDLValue does not know the field names, but that's ok.
        let request_idl = format!(
            "({},)",
            Decode!(
                &Encode!(&request).expect("Couldn't encode DeployNewSnsRequest"),
                IDLValue
            )
            .expect("Couldn't decode DeployNewSnsRequest")
        );

        call_dfx(&[
            "canister",
            "--network",
            &self.args.network,
            "--wallet",
            &format!("{}", self.wallet_canister),
            "call",
            "--with-cycles",
            &SNS_CREATION_FEE.to_string(),
            &self.sns_wasms_canister_id.to_string(),
            "deploy_new_sns",
            &request_idl,
        ]);
    }
}

/// Responsible for deploying SNS canisters
pub struct DirectSnsDeployerForTests {
    pub args: DeployArgs,
    pub sns_canister_payloads: SnsCanisterInitPayloads,
    pub sns_canisters: SnsCanisterIds,
    pub wallet_canister: PrincipalId,
    pub dfx_identity: PrincipalId,
}

impl DirectSnsDeployerForTests {
    pub fn new(args: DeployArgs, sns_init_payload: SnsInitPayload) -> Self {
        let sns_canisters = lookup_or_else_create_canisters(&args);
        let sns_canister_payloads = match sns_init_payload.build_canister_payloads(&sns_canisters) {
            Ok(payload) => payload,
            Err(e) => panic!("Could not build canister init payloads: {}", e),
        };

        let wallet_canister = get_identity("get-wallet", &args.network);
        let dfx_identity = get_identity("get-principal", &args.network);

        Self {
            args,
            sns_canister_payloads,
            sns_canisters,
            wallet_canister,
            dfx_identity,
        }
    }

    /// Deploy an SNS
    pub fn deploy(&self) {
        self.install_sns_canisters();
        self.set_sns_canister_controllers();
        self.validate_deployment();
    }

    /// Validate that the SNS deployment executed successfully
    fn validate_deployment(&self) {
        println!("Validating deployment...");
        self.print_nervous_system_parameters();
        self.print_ledger_metadata();
        self.print_token_symbol();
        self.print_token_name();
    }

    /// Call Governance's `get_nervous_system_parameters` method and print the result
    fn print_nervous_system_parameters(&self) {
        println!("Governance Nervous System Parameters:");
        call_dfx(&[
            "canister",
            "--network",
            &self.args.network,
            "call",
            "sns_governance",
            "get_nervous_system_parameters",
            "(null)",
        ]);
    }

    /// Call the Ledger's `icrc1_metadata` method and print the result
    fn print_ledger_metadata(&self) {
        println!("Ledger metadata:");
        call_dfx(&[
            "canister",
            "--network",
            &self.args.network,
            "call",
            "sns_ledger",
            "icrc1_metadata",
            "(record {})",
        ]);
    }

    /// Call the Ledger's `symbol` method and print the result
    fn print_token_symbol(&self) {
        println!("Ledger token symbol:");
        call_dfx(&[
            "canister",
            "--network",
            &self.args.network,
            "call",
            "sns_ledger",
            "icrc1_symbol",
            "()",
        ]);
    }

    /// Call the Ledger's `name` method and print the result
    fn print_token_name(&self) {
        println!("Ledger token name:");
        call_dfx(&[
            "canister",
            "--network",
            &self.args.network,
            "call",
            "sns_ledger",
            "icrc1_name",
            "()",
        ]);
    }

    /// Set the SNS canister controllers appropriately.
    ///
    /// Governance and Ledger must be controlled only by Root, and Root must be controlled
    /// only by Governance.
    fn set_sns_canister_controllers(&self) {
        println!("Setting SNS canister controllers...");

        // Governance must be controlled by only Root
        self.add_controller(self.sns_canisters.root, "sns_governance");

        // Root must be controlled by only Governance
        self.add_controller(self.sns_canisters.governance, "sns_root");

        // Ledger must be controlled by only Root
        self.add_controller(self.sns_canisters.root, "sns_ledger");

        // Swap must be controlled by the NNS root canister and control itself.
        self.add_controller(NNS_ROOT_CANISTER_ID.get(), "sns_swap");
        self.add_controller(self.sns_canisters.swap, "sns_swap");

        // Remove default controllers from SNS canisters
        for sns_canister in ["sns_governance", "sns_root", "sns_ledger", "sns_swap"] {
            self.remove_controller(self.wallet_canister, sns_canister);
            self.remove_controller(self.dfx_identity, sns_canister);
        }
    }

    /// Add `controller` as a new controller of the canister given by `canister_name`.
    /// Panics if the new controller can't be added.
    fn add_controller(&self, controller: PrincipalId, canister_name: &str) {
        let output = call_dfx(&[
            "canister",
            "--network",
            &self.args.network,
            "update-settings",
            "--add-controller",
            &controller.to_string(),
            canister_name,
        ]);

        if !output.status.success() {
            panic!(
                "Failed to add {} as a controller of {}",
                &controller, canister_name
            );
        }
    }

    /// Remove `controller` as a controller of the canister given by `canister_name`
    fn remove_controller(&self, controller: PrincipalId, canister_name: &str) {
        call_dfx(&[
            "canister",
            "--network",
            &self.args.network,
            "update-settings",
            "--remove-controller",
            &controller.to_string(),
            canister_name,
        ]);
    }

    /// Install the SNS canisters
    fn install_sns_canisters(&self) {
        self.install_governance();
        self.install_ledger();
        self.install_root();
        self.install_swap();
    }

    /// Install and initialize Governance
    fn install_governance(&self) {
        let init_args = hex_encode_candid(&self.sns_canister_payloads.governance);
        self.install_canister("sns_governance", &init_args);
    }

    /// Install and initialize Ledger
    fn install_ledger(&self) {
        let init_args = hex_encode_candid(&self.sns_canister_payloads.ledger);
        self.install_canister("sns_ledger", &init_args);
    }

    /// Install and initialize Root
    fn install_root(&self) {
        let init_args = hex_encode_candid(&self.sns_canister_payloads.root);
        self.install_canister("sns_root", &init_args);
    }

    /// Install and initialize Swap
    fn install_swap(&self) {
        let init_args = hex_encode_candid(&self.sns_canister_payloads.swap);
        self.install_canister("sns_swap", &init_args);
    }
    /// Install the given canister
    fn install_canister(&self, sns_canister_name: &str, init_args: &str) {
        call_dfx(&[
            "canister",
            "--network",
            &self.args.network,
            "install",
            "--argument-type=raw",
            "--argument",
            init_args,
            sns_canister_name,
        ]);
    }
}
