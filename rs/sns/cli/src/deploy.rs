//! Contains the logic for deploying SNS canisters

use ic_base_types::{CanisterId, PrincipalId};
use ic_sns_governance::init::GovernanceCanisterInitPayloadBuilder;
use ic_sns_governance::pb::v1::{Governance, NeuronPermissionList, NeuronPermissionType};
use ic_sns_root::pb::v1::SnsRootCanister;
use ledger_canister::{ArchiveOptions, LedgerCanisterInitPayload, Tokens};
use maplit::hashset;
use std::str::FromStr;

use crate::{call_dfx, get_identity, hex_encode_candid, DeployArgs};

/// The canister IDs of all SNS canisters
#[derive(Debug)]
pub struct SnsCanisterIds {
    pub governance: PrincipalId,
    pub ledger: PrincipalId,
    pub root: PrincipalId,
}

impl SnsCanisterIds {
    /// If SNS canisters have already been created, return their canister IDs, else create the
    /// SNS canisters and return their canister IDs.
    pub fn lookup_or_else_create_canisters(args: &DeployArgs) -> Self {
        let sns_canister_ids = match Self::lookup(args) {
            Some(sns_canister_ids) => {
                println!("SNS canisters already allocated");
                sns_canister_ids
            }
            None => {
                println!(
                    "SNS canisters not found, creating SNS canisters with {:?} cycles each",
                    args.initial_cycles_per_canister
                );
                Self::create_canisters(args)
            }
        };

        println!("SNS canister IDs:\n{:?}", &sns_canister_ids);
        sns_canister_ids
    }

    /// If all the SNS canisters have already been created, return them.
    fn lookup(args: &DeployArgs) -> Option<Self> {
        Some(SnsCanisterIds {
            governance: get_canister_id("sns_governance", args)?,
            ledger: get_canister_id("sns_ledger", args)?,
            root: get_canister_id("sns_root", args)?,
        })
    }

    /// Call `dfx canister create` to allocate canister IDs for all SNS canisters.
    fn create_canisters(args: &DeployArgs) -> Self {
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
        Self::lookup(args).expect("SNS canisters failed to be created")
    }
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

/// Responsible for deploying SNS canisters
pub struct SnsDeployer {
    pub args: DeployArgs,
    pub sns_canisters: SnsCanisterIds,
    pub wallet_canister: PrincipalId,
    pub dfx_identity: PrincipalId,
}

impl SnsDeployer {
    pub fn new(args: DeployArgs) -> Self {
        let sns_canisters = SnsCanisterIds::lookup_or_else_create_canisters(&args);
        let wallet_canister = get_identity("get-wallet", &args.network);
        let dfx_identity = get_identity("get-principal", &args.network);

        Self {
            args,
            sns_canisters,
            wallet_canister,
            dfx_identity,
        }
    }

    /// Deploy an SNS
    pub fn deploy(&self) {
        self.args.validate();
        self.install_sns_canisters();
        self.set_sns_canister_controllers();
        self.validate_deployment();
    }

    /// Validate that the SNS deployment executed successfully
    fn validate_deployment(&self) {
        println!("Validating deployment...");
        self.print_nervous_system_parameters();
        self.print_ledger_transfer_fee();
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

    /// Call the Ledger's `transfer_fee` method and print the result
    fn print_ledger_transfer_fee(&self) {
        println!("Ledger transfer_fee:");
        call_dfx(&[
            "canister",
            "--network",
            &self.args.network,
            "call",
            "sns_ledger",
            "transfer_fee",
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
            "symbol",
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
            "name",
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

        // Remove default controllers from SNS canisters
        for sns_canister in ["sns_governance", "sns_root", "sns_ledger"] {
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
    }

    /// Install and initialize Governance
    fn install_governance(&self) {
        let init_args = hex_encode_candid(self.governance_init_args());
        self.install_canister("sns_governance", &init_args);
    }

    /// Install and initialize Ledger
    fn install_ledger(&self) {
        let init_args = hex_encode_candid(self.ledger_init_args());
        self.install_canister("sns_ledger", &init_args);
    }

    /// Install and initialize Root
    fn install_root(&self) {
        let init_args = hex_encode_candid(self.root_init_args());
        self.install_canister("sns_root", &init_args);
    }

    /// Constuct the params used to initialize a SNS Governance canister.
    fn governance_init_args(&self) -> Governance {
        let mut governance = GovernanceCanisterInitPayloadBuilder::new().build();
        governance.ledger_canister_id = Some(self.sns_canisters.ledger);
        governance.root_canister_id = Some(self.sns_canisters.root);

        let parameters = governance
            .parameters
            .as_mut()
            .expect("NervousSystemParameters not set");

        let all_permissions = NeuronPermissionList {
            permissions: NeuronPermissionType::all(),
        };
        parameters.neuron_claimer_permissions = Some(all_permissions.clone());
        parameters.neuron_grantable_permissions = Some(all_permissions);

        if let Some(neuron_minimum_stake_e8s) = self.args.neuron_minimum_stake_e8s {
            parameters.neuron_minimum_stake_e8s = Some(neuron_minimum_stake_e8s);
        }

        if let Some(proposal_reject_cost_e8s) = self.args.proposal_reject_cost_e8s {
            parameters.reject_cost_e8s = Some(proposal_reject_cost_e8s);
        }

        governance.neurons = self.args.get_initial_neurons(parameters);

        governance
    }

    /// Construct the params used to initialize a SNS Ledger canister.
    fn ledger_init_args(&self) -> LedgerCanisterInitPayload {
        let root_canister_id = CanisterId::new(self.sns_canisters.root).unwrap();

        let mut payload = LedgerCanisterInitPayload::builder()
            .minting_account(self.sns_canisters.governance.into())
            .token_symbol_and_name(&self.args.token_symbol, &self.args.token_name)
            .archive_options(ArchiveOptions {
                trigger_threshold: 2000,
                num_blocks_to_archive: 1000,
                // 1 GB, which gives us 3 GB space when upgrading
                node_max_memory_size_bytes: Some(1024 * 1024 * 1024),
                // 128kb
                max_message_size_bytes: Some(128 * 1024),
                controller_id: root_canister_id,
                // TODO: allow users to set this value
                // 10 Trillion cycles
                cycles_for_archive_creation: Some(10_000_000_000_000),
            })
            .build()
            .unwrap();

        payload.transfer_fee = self.args.transaction_fee_e8s.map(Tokens::from_e8s);
        payload.initial_values = self
            .args
            .get_initial_accounts(self.sns_canisters.governance);

        let governance_canister_id = CanisterId::new(self.sns_canisters.governance).unwrap();
        let ledger_canister_id = CanisterId::new(self.sns_canisters.ledger).unwrap();
        payload.send_whitelist = hashset! { governance_canister_id, ledger_canister_id };

        payload
    }

    /// Constuct the params used to initialize a SNS Root canister.
    fn root_init_args(&self) -> SnsRootCanister {
        SnsRootCanister {
            governance_canister_id: Some(self.sns_canisters.governance),
        }
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
