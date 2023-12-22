//! Contains the logic for deploying SNS canisters

#[cfg(test)]
use std::io::BufReader;
use std::{
    fs::{create_dir_all, OpenOptions},
    io::{BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::anyhow;
use candid::{types::value::IDLValue, Decode, Encode};
use serde_json::{json, Value as JsonValue};
use tempfile::NamedTempFile;

use crate::{
    call_dfx, call_dfx_or_panic, get_identity, hex_encode_candid, DeployArgs, DeployTestflightArgs,
};
use ic_base_types::{CanisterId, PrincipalId};
use ic_nns_constants::{ROOT_CANISTER_ID as NNS_ROOT_CANISTER_ID, SNS_WASM_CANISTER_ID};
use ic_sns_governance::pb::v1::ListNeuronsResponse;
use ic_sns_init::{pb::v1::SnsInitPayload, SnsCanisterIds, SnsCanisterInitPayloads};
use ic_sns_root::pb::v1::ListSnsCanistersResponse;
use ic_sns_wasm::pb::v1::{
    DeployNewSnsRequest, DeployNewSnsResponse, SnsCanisterIds as SnsWSnsCanisterIds,
};

/// If SNS canisters have already been created, return their canister IDs, else create the
/// SNS canisters and return their canister IDs.
pub fn lookup_or_else_create_canisters(
    verbose: bool,
    network: &String,
    initial_cycles_per_canister: Option<u64>,
) -> SnsCanisterIds {
    let sns_canister_ids = match lookup(verbose, network) {
        Some(sns_canister_ids) => {
            println!("SNS canisters already allocated");
            sns_canister_ids
        }
        None => {
            println!(
                "SNS canisters not found, creating SNS canisters with {:?} cycles each",
                initial_cycles_per_canister
            );
            create_canisters(verbose, network, initial_cycles_per_canister)
        }
    };

    println!("SNS canister IDs:\n{:?}", &sns_canister_ids);
    sns_canister_ids
}

/// If all the SNS canisters have already been created, return them.
fn lookup(verbose: bool, network: &String) -> Option<SnsCanisterIds> {
    Some(SnsCanisterIds {
        governance: get_canister_id("sns_governance", verbose, network)?,
        ledger: get_canister_id("sns_ledger", verbose, network)?,
        root: get_canister_id("sns_root", verbose, network)?,
        swap: get_canister_id("sns_swap", verbose, network)?,
        index: get_canister_id("sns_index", verbose, network)?,
    })
}

/// Call `dfx canister create` to allocate canister IDs for all SNS canisters.
fn create_canisters(
    verbose: bool,
    network: &String,
    initial_cycles_per_canister: Option<u64>,
) -> SnsCanisterIds {
    println!("Creating SNS canisters...");
    let cycles = format!("{}", initial_cycles_per_canister.unwrap_or_default());

    call_dfx_or_panic(&[
        "canister",
        "--network",
        network,
        "create",
        "--all",
        "--with-cycles",
        &cycles,
    ]);
    lookup(verbose, network).expect("SNS canisters failed to be created")
}

/// Return the canister ID of the canister given by `canister_name`
pub fn get_canister_id(
    canister_name: &str,
    verbose: bool,
    network: &String,
) -> Option<PrincipalId> {
    println!("dfx canister --network {} id {}", &network, canister_name);
    let output = call_dfx(&["canister", "--network", network, "id", canister_name]);

    let canister_id = String::from_utf8(output.stdout)
        .map_err(|e| {
            if verbose {
                println!(
                    "Could not parse the output of 'dfx canister id {}' as a string, error: {}",
                    canister_name, e
                )
            }
        })
        .ok()?;

    PrincipalId::from_str(canister_id.trim())
        .map_err(|e| {
            if verbose {
                println!(
                    "Could not parse the output of 'dfx canister id {}' as a PrincipalId, error: {}",
                    canister_name, e
                )
            }
        })
        .ok()
}

/// Merges the given JSON into a JSON file.
/// - If the file is missing or empty, the JSON is simply written to the file.
pub fn merge_into_json_file<P>(path: P, value: &JsonValue) -> anyhow::Result<()>
where
    P: AsRef<Path>,
{
    // Read the file, keeping the file pointer for the later write.
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    // Merge in the JSON value
    // ... If there is existing JSON we need to hold it in this scope:
    #[allow(unused_assignments)]
    let mut modified_contents = JsonValue::Null;
    // ... Get a pointer to the updated data:
    let new_json = if contents.is_empty() {
        value
    } else {
        modified_contents = serde_json::from_str(&contents)?;
        json_patch::merge(&mut modified_contents, value);
        &modified_contents
    };
    // Truncate the file and write the new contents.
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;

    let mut writer = BufWriter::new(file);
    writeln!(&mut writer, "{}", &serde_json::to_string_pretty(&new_json)?)?;
    writer.flush()?;
    Ok(())
}

fn parse_deploy_new_sns_response(buffer: &[u8]) -> anyhow::Result<SnsWSnsCanisterIds> {
    let mut hex = buffer.to_vec();
    while hex
        .last()
        .map(|&c| !c.is_ascii_hexdigit())
        .unwrap_or_default()
    {
        hex.pop().unwrap();
    }
    let decoded = Decode!(
        &hex::decode(hex).expect("cannot parse dfx output as hex"),
        DeployNewSnsResponse
    )
    .expect("cannot parse dfx output as DeployNewSnsResponse");

    let DeployNewSnsResponse {
        canisters, error, ..
    } = decoded;

    if error.is_some() {
        Err(anyhow!(error.unwrap().message))
    } else {
        canisters.ok_or_else(|| anyhow!("DeployNewSnsResponse should contain SNS canister IDs"))
    }
}

fn dfx_canister_ids_json(
    network_name: &str,
    sns_canister_ids: SnsWSnsCanisterIds,
) -> anyhow::Result<JsonValue> {
    // this is what dfx does to make the network name "OS-friendly"
    let network_name = &network_name.replace(|c: char| !c.is_ascii_alphanumeric(), "_");
    Ok(json!({
        "sns_governance": json!({network_name: sns_canister_ids.governance.expect("SNS root does not return governance canister ID")}),
        "sns_index": json!({network_name: sns_canister_ids.index.expect("SNS root does not return index canister ID")}),
        "sns_ledger": json!({network_name: sns_canister_ids.ledger.expect("SNS root does not return ledger canister ID")}),
        "sns_root": json!({network_name: sns_canister_ids.root.expect("SNS root does not return root canister ID")}),
        "sns_swap": json!({network_name: sns_canister_ids.swap.expect("SNS root does not return swap canister ID")}),
    }))
}

fn sns_quill_canister_ids_json(sns_canister_ids: SnsWSnsCanisterIds) -> anyhow::Result<JsonValue> {
    Ok(json!({
        "governance_canister_id": sns_canister_ids.governance.expect("SNS root does not return governance canister ID"),
        "index_canister_id": sns_canister_ids.index.expect("SNS root does not return index canister ID"),
        "ledger_canister_id": sns_canister_ids.ledger.expect("SNS root does not return ledger canister ID"),
        "root_canister_id": sns_canister_ids.root.expect("SNS root does not return root canister ID"),
        "swap_canister_id": sns_canister_ids.swap.expect("SNS root does not return swap canister ID"),
    }))
}

/// Responsible for deploying using SNS-WASM canister (for protected SNS subnet)
pub struct SnsWasmSnsDeployer {
    pub args: DeployArgs,
    pub sns_init_payload: SnsInitPayload,
    pub sns_wasms_canister: String,
    pub wallet_canister: CanisterId,
}

impl SnsWasmSnsDeployer {
    pub fn new(args: DeployArgs, sns_init_payload: SnsInitPayload) -> Self {
        let sns_wasms_canister = args
            .override_sns_wasm_canister_id_for_tests
            .as_ref()
            .map(|id_or_name| id_or_name.to_string())
            .unwrap_or_else(|| SNS_WASM_CANISTER_ID.get().to_string());

        let wallet_canister = args
            .wallet_canister_override
            .as_ref()
            .map(|id| CanisterId::unchecked_from_principal(*id))
            .unwrap_or_else(|| {
                CanisterId::unchecked_from_principal(get_identity("get-wallet", &args.network))
            });

        Self {
            args,
            sns_init_payload,
            sns_wasms_canister,
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

        let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
        writeln!(temp_file, "{}", request_idl).expect("Failed to write to temp file");

        let output = {
            let wallet_canister = format!("{}", self.wallet_canister);
            let sns_creation_fee = self.args.with_cycles.to_string();
            let mut args = vec![
                "canister",
                "--network",
                &self.args.network,
                "--wallet",
                &wallet_canister,
                "call",
                "--with-cycles",
                &sns_creation_fee,
                &self.sns_wasms_canister,
                "deploy_new_sns",
                "--output",
                "raw",
                "--argument-file",
                temp_file
                    .path()
                    .to_str()
                    .expect("Expected temp file's path to exist"),
            ];
            if let Some(path) = self.args.candid.as_ref() {
                args.push("--candid");
                args.push(path);
            }
            call_dfx(&args)
        };

        if !output.status.success() {
            panic!("Failed to create SNS");
        }
        self.save_canister_ids(&output.stdout)
            .expect("Failed to save to SNS canister IDs");
    }

    /// Records the created canister IDs in canister_ids.json and sns_canister_ids.json
    pub fn save_canister_ids(&self, buffer: &[u8]) -> anyhow::Result<()> {
        let sns_canister_ids = parse_deploy_new_sns_response(buffer)?;

        let canisters_file = {
            let path = &self.args.save_to;
            if let Some(dir) = path.parent() {
                create_dir_all(dir)
                    .map_err(|err| {
                        format!(
                            "Failed to create directory for {}: {err}",
                            path.to_string_lossy()
                        )
                    })
                    .unwrap();
            }
            path
        };
        merge_into_json_file(
            canisters_file,
            &dfx_canister_ids_json(&self.args.network, sns_canister_ids)?,
        )
        .expect("cannot write SNS canister IDs to file");

        let sns_canisters_file = {
            let path = &self.args.sns_canister_ids_save_to;
            if let Some(dir) = path.parent() {
                create_dir_all(dir)
                    .map_err(|err| {
                        format!(
                            "Failed to create directory for {}: {err}",
                            path.to_string_lossy()
                        )
                    })
                    .unwrap();
            }
            path
        };
        merge_into_json_file(
            sns_canisters_file,
            &sns_quill_canister_ids_json(sns_canister_ids)?,
        )
        .expect("cannot write SNS canister IDs to file");

        Ok(())
    }
}

#[test]
fn should_save_canister_ids() {
    let sample_response = r#"4449444c046c03bd869d8b0401c897a799077fec80e5e909026e686e036c05a2dcbbdd040193d5f8e20401a9cbadc3090192b6d2f00b01a2d2bea80c01010001011d0f3453137346b2a448ef6b0f0ee389ca465f237da654397fd7216ba1020101010a000000000000000f010101010a0000000000000012010101010a0000000000000011010101010a000000000000000e010101010a00000000000000100101
    "#;
    let network_name = "foo";
    let expected_dfx_json_str = r#"
      { "sns_root": { "foo": "q3fc5-haaaa-aaaaa-aaahq-cai" }
      , "sns_swap": { "foo": "si2b5-pyaaa-aaaaa-aaaja-cai" }
      , "sns_ledger": { "foo": "sbzkb-zqaaa-aaaaa-aaaiq-cai" }
      , "sns_governance": { "foo": "sgymv-uiaaa-aaaaa-aaaia-cai" }
      , "sns_index": { "foo": "q4eej-kyaaa-aaaaa-aaaha-cai" }
      }
    "#;
    let expected_sns_quill_json_str = r#"
      { "root_canister_id": "q3fc5-haaaa-aaaaa-aaahq-cai"
      , "swap_canister_id": "si2b5-pyaaa-aaaaa-aaaja-cai"
      , "ledger_canister_id": "sbzkb-zqaaa-aaaaa-aaaiq-cai"
      , "governance_canister_id": "sgymv-uiaaa-aaaaa-aaaia-cai"
      , "index_canister_id": "q4eej-kyaaa-aaaaa-aaaha-cai"
      }
    "#;
    let expected_dfx_json = serde_json::from_str(expected_dfx_json_str).unwrap();
    let expected_sns_quill_json = serde_json::from_str(expected_sns_quill_json_str).unwrap();

    fn assert_same_json(expected: &JsonValue, actual: &JsonValue, message: &str) {
        let diff = json_patch::diff(expected, actual);
        assert_eq!(json_patch::Patch(Vec::new()), diff, "{}", message);
    }

    // Test the individual steps:
    // .. First parse the response and prepare the JSON representation:
    let sns_canister_ids = parse_deploy_new_sns_response(sample_response.as_bytes()).unwrap();
    let actual_dfx_json = dfx_canister_ids_json(network_name, sns_canister_ids).unwrap();
    let actual_sns_quill_json = sns_quill_canister_ids_json(sns_canister_ids).unwrap();
    // ... verify that the representation has no semantic differences
    assert_same_json(
        &expected_dfx_json,
        &actual_dfx_json,
        "The jsonification is wrong",
    );
    assert_same_json(
        &expected_sns_quill_json,
        &actual_sns_quill_json,
        "The jsonification is wrong",
    );
    // ... verify that writing to an empty file dumps the data without modification
    let file = NamedTempFile::new().unwrap();
    merge_into_json_file(file.path(), &actual_dfx_json).expect("Failed to save changes to file");
    let file_content =
        serde_json::from_reader(&mut BufReader::new(file.reopen().unwrap())).unwrap();
    assert_same_json(
        &expected_dfx_json,
        &file_content,
        "Save to file doesn't work",
    );
}

/// Responsible for deploying SNS canisters
pub struct DirectSnsDeployerForTests {
    pub network: String,
    pub sns_canister_ids_save_to: PathBuf,
    pub wasms_dir: PathBuf,
    pub sns_canister_payloads: SnsCanisterInitPayloads,
    pub sns_canisters: SnsCanisterIds,
    pub wallet_canister: PrincipalId,
    pub dfx_identity: PrincipalId,
    pub testflight: bool,
}

impl DirectSnsDeployerForTests {
    pub fn new(args: DeployArgs, sns_init_payload: SnsInitPayload) -> Self {
        let sns_canisters = lookup_or_else_create_canisters(
            args.verbose,
            &args.network,
            args.initial_cycles_per_canister,
        );
        // TODO - add version hash to test upgrade path locally?  Where would we find that?
        // TODO[NNS1-2592]: set neurons_fund_participation_constraints to a non-trivial value.
        let sns_canister_payloads =
            match sns_init_payload.build_canister_payloads(&sns_canisters, None, false) {
                Ok(payload) => payload,
                Err(e) => panic!("Could not build canister init payloads: {}", e),
            };

        let wallet_canister = get_identity("get-wallet", &args.network);
        let dfx_identity = get_identity("get-principal", &args.network);

        Self {
            network: args.network,
            sns_canister_ids_save_to: args.sns_canister_ids_save_to,
            wasms_dir: args.wasms_dir,
            sns_canister_payloads,
            sns_canisters,
            wallet_canister,
            dfx_identity,
            testflight: false,
        }
    }

    pub fn new_testflight(args: DeployTestflightArgs, sns_init_payload: SnsInitPayload) -> Self {
        let sns_canisters = lookup_or_else_create_canisters(
            args.verbose,
            &args.network,
            Some(args.initial_cycles_per_canister),
        );
        // TODO - add version hash to test upgrade path locally?  Where would we find that?
        // TODO[NNS1-2592]: set neurons_fund_participation_constraints to a non-trivial value.
        let sns_canister_payloads =
            match sns_init_payload.build_canister_payloads(&sns_canisters, None, true) {
                Ok(payload) => payload,
                Err(e) => panic!("Could not build canister init payloads: {}", e),
            };

        let wallet_canister = get_identity("get-wallet", &args.network);
        let dfx_identity = get_identity("get-principal", &args.network);

        Self {
            network: args.network,
            sns_canister_ids_save_to: args.sns_canister_ids_save_to,
            wasms_dir: args.wasms_dir,
            sns_canister_payloads,
            sns_canisters,
            wallet_canister,
            dfx_identity,
            testflight: true,
        }
    }

    /// Deploy an SNS
    pub fn deploy(&self) {
        self.install_sns_canisters();
        self.set_sns_canister_controllers();
        self.save_canister_ids();
        self.validate_deployment();
    }

    /// Records the created canister IDs in sns_canister_ids.json
    pub fn save_canister_ids(&self) {
        let canisters_file = {
            let path = &self.sns_canister_ids_save_to;
            if let Some(dir) = path.parent() {
                create_dir_all(dir)
                    .map_err(|err| {
                        format!(
                            "Failed to create directory for {}: {err}",
                            path.to_string_lossy()
                        )
                    })
                    .unwrap();
            }
            path
        };

        let output = call_dfx(&[
            "canister",
            "--network",
            &self.network,
            "call",
            "--output",
            "raw",
            "sns_root",
            "list_sns_canisters",
            "(record {})",
        ]);
        let mut hex = output.stdout;
        while hex.last() == Some(&b'\n') || hex.last() == Some(&b'\r') {
            hex.pop().unwrap();
        }
        let sns_canister_ids = Decode!(
            &hex::decode(hex).expect("cannot parse dfx output as hex"),
            ListSnsCanistersResponse
        )
        .expect("cannot parse dfx output as ListSnsCanistersResponse");
        let sns_quill_canister_ids_json = json!({
            "governance_canister_id": sns_canister_ids.governance.expect("SNS root does not return governance canister ID"),
            "index_canister_id": sns_canister_ids.index.expect("SNS root does not return index canister ID"),
            "ledger_canister_id": sns_canister_ids.ledger.expect("SNS root does not return ledger canister ID"),
            "root_canister_id": sns_canister_ids.root.expect("SNS root does not return root canister ID"),
            "swap_canister_id": sns_canister_ids.swap.expect("SNS root does not return swap canister ID"),
        });
        merge_into_json_file(canisters_file, &sns_quill_canister_ids_json)
            .expect("cannot write SNS canister IDs to file");
    }

    /// Validate that the SNS deployment executed successfully
    fn validate_deployment(&self) {
        println!("Validating deployment...");
        self.print_nervous_system_parameters();
        self.print_ledger_metadata();
        self.print_token_symbol();
        self.print_token_name();
        self.print_developer_neuron_ids();
    }

    /// Call Governance's `get_nervous_system_parameters` method and print the result
    fn print_nervous_system_parameters(&self) {
        println!("Governance Nervous System Parameters:");
        call_dfx_or_panic(&[
            "canister",
            "--network",
            &self.network,
            "call",
            "sns_governance",
            "get_nervous_system_parameters",
            "(null)",
        ]);
    }

    /// Call the Ledger's `icrc1_metadata` method and print the result
    fn print_ledger_metadata(&self) {
        println!("Ledger metadata:");
        call_dfx_or_panic(&[
            "canister",
            "--network",
            &self.network,
            "call",
            "sns_ledger",
            "icrc1_metadata",
            "(record {})",
        ]);
    }

    /// Call the Ledger's `symbol` method and print the result
    fn print_token_symbol(&self) {
        println!("Ledger token symbol:");
        call_dfx_or_panic(&[
            "canister",
            "--network",
            &self.network,
            "call",
            "sns_ledger",
            "icrc1_symbol",
            "()",
        ]);
    }

    /// Call the Ledger's `name` method and print the result
    fn print_token_name(&self) {
        println!("Ledger token name:");
        call_dfx_or_panic(&[
            "canister",
            "--network",
            &self.network,
            "call",
            "sns_ledger",
            "icrc1_name",
            "()",
        ]);
    }

    /// Call the Governance's `list_neurons` method and print the developer neuron IDs in hex
    fn print_developer_neuron_ids(&self) {
        let arg = format!(
            "(record {{of_principal = opt principal\"{}\"; limit = 0}})",
            self.dfx_identity,
        );
        let output = call_dfx(&[
            "canister",
            "--network",
            &self.network,
            "call",
            "--output",
            "raw",
            "sns_governance",
            "list_neurons",
            &arg,
        ]);
        let mut hex = output.stdout;
        while hex.last() == Some(&b'\n') || hex.last() == Some(&b'\r') {
            hex.pop().unwrap();
        }
        let neurons = Decode!(
            &hex::decode(hex).expect("cannot parse dfx output as hex"),
            ListNeuronsResponse
        )
        .expect("cannot parse dfx output as ListNeuronsResponse");
        let ids: Vec<String> = neurons
            .neurons
            .iter()
            .map(|n| hex::encode(&n.id.as_ref().expect("developer neuron has no ID").id))
            .collect();
        println!("Developer neuron IDs:");
        println!("{}", ids.join(", "));
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

        // Index must be controlled by only Root
        self.add_controller(self.sns_canisters.root, "sns_index");

        // Remove default controllers from SNS canisters if not in testflight
        if !self.testflight {
            for sns_canister in [
                "sns_governance",
                "sns_root",
                "sns_ledger",
                "sns_swap",
                "sns_index",
            ] {
                self.remove_controller(self.wallet_canister, sns_canister);
                self.remove_controller(self.dfx_identity, sns_canister);
            }
        }
    }

    /// Add `controller` as a new controller of the canister given by `canister_name`.
    /// Panics if the new controller can't be added.
    fn add_controller(&self, controller: PrincipalId, canister_name: &str) {
        let output = call_dfx(&[
            "canister",
            "--network",
            &self.network,
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
        call_dfx_or_panic(&[
            "canister",
            "--network",
            &self.network,
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
        self.install_index();
    }

    /// Install and initialize Governance
    fn install_governance(&self) {
        let init_args = hex_encode_candid(&self.sns_canister_payloads.governance);
        self.install_canister("sns_governance", "sns-governance-canister", &init_args);
    }

    /// Install and initialize Ledger
    fn install_ledger(&self) {
        let init_args = hex_encode_candid(&self.sns_canister_payloads.ledger);
        self.install_canister("sns_ledger", "ic-icrc1-ledger", &init_args);
    }

    /// Install and initialize Root
    fn install_root(&self) {
        let init_args = hex_encode_candid(&self.sns_canister_payloads.root);
        self.install_canister("sns_root", "sns-root-canister", &init_args);
    }

    /// Install and initialize Swap
    fn install_swap(&self) {
        let init_args = hex_encode_candid(&self.sns_canister_payloads.swap);
        self.install_canister("sns_swap", "sns-swap-canister", &init_args);
    }

    /// Install and initialize Index
    fn install_index(&self) {
        let init_args = hex_encode_candid(&self.sns_canister_payloads.index);
        self.install_canister("sns_index", "ic-icrc1-index", &init_args);
    }

    /// Install the given canister
    fn install_canister(&self, sns_canister_name: &str, wasm_name: &str, init_args: &str) {
        let mut wasm = self.wasms_dir.clone();
        wasm.push(format!("{}.wasm", wasm_name));
        call_dfx_or_panic(&[
            "canister",
            "--network",
            &self.network,
            "install",
            "--argument-type=raw",
            "--argument",
            init_args,
            "--wasm",
            &wasm.into_os_string().into_string().unwrap(),
            sns_canister_name,
        ]);
    }
}
