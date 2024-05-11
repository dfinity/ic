use crate::{
    deploy::DirectSnsDeployerForTests, init_config_file::InitConfigFileArgs,
    prepare_canisters::PrepareCanistersArgs, propose::ProposeArgs,
};
use anyhow::{anyhow, Context};
use candid::{CandidType, Decode, Encode, IDLArgs};
use clap::Parser;
use ic_base_types::PrincipalId;
use ic_crypto_sha2::Sha256;
use ic_nervous_system_common_test_keys::TEST_NEURON_1_OWNER_KEYPAIR;
use ic_nervous_system_proto::pb::v1::GlobalTimeOfDay;
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, SNS_WASM_CANISTER_ID};
use ic_nns_governance::{
    pb::v1::{
        manage_neuron::{self, NeuronIdOrSubaccount},
        manage_neuron_response::{self, MakeProposalResponse},
        ManageNeuron, ManageNeuronResponse, Proposal,
    },
    proposals::create_service_nervous_system::ExecutedCreateServiceNervousSystemProposal,
};
use ic_sns_init::pb::v1::SnsInitPayload;
use ic_sns_wasm::pb::v1::{AddWasmRequest, SnsCanisterType, SnsWasm};
use std::{
    fmt::{Debug, Display},
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{exit, Command, Output},
    str::FromStr,
    sync::Once,
    time::{SystemTime, UNIX_EPOCH},
};
use tempfile::NamedTempFile;

pub mod deploy;
pub mod init_config_file;
pub mod prepare_canisters;
pub mod propose;
pub mod unit_helpers;

#[cfg(test)]
mod tests;

/// We use a giant tail to avoid colliding with/stomping on identity that a user
/// might have created for themselves.
const TEST_NEURON_1_OWNER_DFX_IDENTITY_NAME: &str =
    "test-neuron-1-owner__b2ucp-4x6ou-zvxwi-niymn-pvllt-rdxqr-wi4zj-jat5l-ijt2s-vv4f5-4ae";

#[derive(Debug, Parser)]
#[clap(
    name = "sns-cli",
    about = "Initialize, deploy and interact with an SNS.",
    version
)]
pub struct CliArgs {
    #[clap(subcommand)]
    pub sub_command: SubCommand,
}

#[derive(Debug, Parser)]
pub enum SubCommand {
    /// Deploy an sns directly to a subnet, skipping the sns-wasms canister.
    /// The SNS canisters remain controlled by the developer after deployment.
    /// For use in tests only.
    DeployTestflight(DeployTestflightArgs),
    /// Add a wasms for one of the SNS canisters, skipping the NNS proposal,
    /// for tests.
    AddSnsWasmForTests(AddSnsWasmForTestsArgs),
    /// Manage the config file where the initial sns parameters are set.
    InitConfigFile(InitConfigFileArgs),
    /// Make changes to canisters you own to prepare for SNS Decentralization
    PrepareCanisters(PrepareCanistersArgs),
    /// Submit an NNS proposal to create new SNS.
    Propose(ProposeArgs),
}

/// The arguments used to configure a SNS testflight deployment
#[derive(Debug, Parser)]
pub struct DeployTestflightArgs {
    /// Print all error and info messages.
    #[structopt(long)]
    verbose: bool,

    /// The network to deploy to. This can be "local", "ic", or the URL of an IC network.
    #[structopt(default_value = "local", long)]
    network: String,

    /// The initial config file, this file should have all the necessary parameters to deploy an SNS.
    /// See command "init-config-file"
    #[clap(long, value_parser = clap::value_parser!(std::path::PathBuf))]
    pub init_config_file: Option<PathBuf>,

    /// The canister ID of the wallet to use on this subnet.
    ///
    /// This is needed in testnet scenarios or if you want to use a different wallet than the one
    /// currently set for your dfx identity.
    #[clap(long)]
    pub wallet_canister_override: Option<PrincipalId>,

    /// The amount of cycles to initialize each SNS canister with. This can be omitted when
    /// deploying locally.
    #[structopt(default_value = "500000000000", long)]
    initial_cycles_per_canister: u64,

    /// Saves the SNS canister IDs in the specified json file for sns-quill.
    ///
    /// Default: sns_canister_ids.json
    #[structopt(default_value = "sns_canister_ids.json", long)]
    sns_canister_ids_save_to: PathBuf,

    /// The directory with SNS canister WASMs.
    #[structopt(default_value = ".", long)]
    wasms_dir: PathBuf,
}

#[derive(Debug, Parser)]
pub struct AddSnsWasmForTestsArgs {
    #[clap(long, value_parser = clap::value_parser!(std::path::PathBuf))]
    pub wasm_file: PathBuf,

    pub canister_type: String,

    /// The canister ID of SNS-WASMS to use instead of the default
    ///
    /// This is useful for testing CLI commands against local replicas without fully deployed NNS
    #[clap(long)]
    pub override_sns_wasm_canister_id_for_tests: Option<String>,

    #[structopt(default_value = "local", long)]
    pub network: String,
}

pub(crate) fn generate_sns_init_payload(
    path: &Path,
) -> Result<SnsInitPayload, std::string::String> {
    let configuration = read_create_service_nervous_system_from_init_yaml(path)?;

    SnsInitPayload::try_from(configuration)
        // This shouldn't be possible -> we could just unwrap here, and there
        // should be no danger of panic, but we handle Err anyway, because if
        // err is returned, it still makes sense to just return that.
        //
        // The reason Err should be impossible is
        // try_convert_to_create_service_nervous_system itself call
        // SnsInitPayload::try_from as part of its validation.
        .map_err(|err| format!("Invalid configuration in {:?}: {}", path, err))
}

fn read_create_service_nervous_system_from_init_yaml(
    path: &Path,
) -> Result<ic_nns_governance::pb::v1::CreateServiceNervousSystem, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|err| format!("Unable to read {:?}: {}", path, err))?;
    let configuration =
        serde_yaml::from_str::<crate::init_config_file::friendly::SnsConfigurationFile>(&contents)
            .map_err(|err| format!("Unable to parse contents of {:?}: {}", path, err))?;
    let base_path = path.parent().ok_or_else(|| {
        format!(
            "Configuration file path ({:?}) has no parent, it seems.",
            path,
        )
    })?;
    let configuration = configuration
        .try_convert_to_create_service_nervous_system(base_path)
        .map_err(|err| format!("Invalid configuration in {:?}: {}", path, err))?;
    Ok(configuration)
}

impl DeployTestflightArgs {
    pub(crate) fn generate_sns_init_payload(&self) -> Result<SnsInitPayload, String> {
        match &self.init_config_file {
            Some(init_config_file) => {
                let mut create_service_nervous_system =
                    read_create_service_nervous_system_from_init_yaml(init_config_file)?;

                // disable neurons_fund_participation, if it's enabled
                if create_service_nervous_system
                    .swap_parameters
                    .as_ref()
                    .unwrap()
                    .neurons_fund_participation()
                {
                    println!("Neuron's fund participation was enabled in {}, but is not supported by SNS testflight. Proceeding as if it was disabled.", init_config_file.display());
                    create_service_nervous_system
                        .swap_parameters
                        .as_mut()
                        .unwrap()
                        .neurons_fund_participation = Some(false);
                }

                // convert to ExecutedCreateServiceNervousSystemProposal
                let executed_create_service_nervous_system =
                    ExecutedCreateServiceNervousSystemProposal {
                        current_timestamp_seconds: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        create_service_nervous_system,
                        random_swap_start_time: GlobalTimeOfDay {
                            seconds_after_utc_midnight: Some(0),
                        },
                        neurons_fund_participation_constraints: None,
                        // `proposal_id` only exists to be exposed to the user for audit purposes, which don't apply here.
                        // But it's required, so we can just use any arbitrary value.
                        proposal_id: 10,
                    };

                // Last step: more conversion (this time, to the desired type: SnsInitPayload).
                SnsInitPayload::try_from(executed_create_service_nervous_system)
                    // This shouldn't be possible -> we could just unwrap here, and there
                    // should be no danger of panic, but we handle Err anyway, because if
                    // err is returned, it still makes sense to just return that.
                    //
                    // The reason Err should be impossible is
                    // try_convert_to_create_service_nervous_system itself call
                    // SnsInitPayload::try_from as part of its validation.
                    .map_err(|err| {
                        format!("Invalid configuration in {:?}: {}", init_config_file, err)
                    })
            }
            None => {
                panic!("The init_config_file is required for the DeployTestflightArgs.");
            }
        }
    }
}

impl AddSnsWasmForTestsArgs {
    pub fn get_wasm_file_bytes(&self) -> Vec<u8> {
        let mut file = File::open(&self.wasm_file).expect("Couldn't open wasm file");
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).expect("Couldn't read wasm file");
        buf
    }
}

/// Deploy an SNS with the given DeployTestflightArgs, skipping sns-wasm.
/// The SNS canisters remain controlled by the developer after deployment.
pub fn deploy_testflight(args: DeployTestflightArgs) {
    let sns_init_payload = args.generate_sns_init_payload().unwrap_or_else(|err| {
        eprintln!(
            "Error encountered when generating the SnsInitPayload: {}",
            err
        );
        exit(1);
    });
    DirectSnsDeployerForTests::new_testflight(args, sns_init_payload).deploy()
}

pub fn add_sns_wasm_for_tests(args: AddSnsWasmForTestsArgs) {
    let sns_wasm_bytes = args.get_wasm_file_bytes();
    let sns_wasm_hash = {
        let mut state = Sha256::new();
        state.write(&sns_wasm_bytes);
        state.finish()
    };

    let sns_canister_type = match args.canister_type.as_str() {
        "archive" => SnsCanisterType::Archive,
        "root" => SnsCanisterType::Root,
        "governance" => SnsCanisterType::Governance,
        "ledger" => SnsCanisterType::Ledger,
        "swap" => SnsCanisterType::Swap,
        "index" => SnsCanisterType::Index,
        _ => panic!("Unknown canister type."),
    };

    let add_sns_wasm_request = AddWasmRequest {
        wasm: Some(SnsWasm {
            wasm: sns_wasm_bytes,
            canister_type: sns_canister_type as i32,
            // Will be filled in by SNS Governance
            proposal_id: None,
        }),
        hash: sns_wasm_hash.to_vec(),
    };

    let sns_wasms_canister_id = args
        .override_sns_wasm_canister_id_for_tests
        .as_ref()
        .map(|principal| PrincipalId::from_str(principal).unwrap())
        .unwrap_or_else(|| SNS_WASM_CANISTER_ID.get());

    let idl = IDLArgs::from_bytes(&Encode!(&add_sns_wasm_request).unwrap()).unwrap();
    let mut argument_file = NamedTempFile::new().expect("Could not open temp file");
    argument_file
        .write_all(format!("{}", idl).as_bytes())
        .expect("Could not write wasm to temp file");
    let argument_path = argument_file.path().as_os_str().to_str().unwrap();

    call_dfx_or_panic(&[
        "canister",
        "--network",
        &args.network,
        "call",
        "--argument-file",
        argument_path,
        &sns_wasms_canister_id.to_string(),
        "add_wasm",
    ]);
}

/// Return the `PrincipalId` of the given dfx identity
pub(crate) fn get_identity(identity: &str, network: &str) -> PrincipalId {
    println!("dfx identity {}", identity);
    let output = call_dfx(&["identity", "--network", network, identity]);

    let canister_id = String::from_utf8(output.stdout).unwrap_or_else(|_| {
        panic!(
            "Could not parse the output of 'dfx identity {}' as a string",
            identity
        )
    });

    PrincipalId::from_str(canister_id.trim()).unwrap_or_else(|_| {
        panic!(
            "Could not parse the output of 'dfx identity {}' as a PrincipalId",
            identity
        )
    })
}

#[must_use]
struct SaveOriginalDfxIdentityAndRestoreOnExit {
    original_identity: String,
}

impl SaveOriginalDfxIdentityAndRestoreOnExit {
    fn new_or_panic() -> Self {
        let original_identity = String::from_utf8(call_dfx(&["identity", "whoami"]).stdout)
            .expect("Unable to determine which dfx identity is currently in use.")
            .trim_end()
            .to_string();

        Self { original_identity }
    }
}

impl Drop for SaveOriginalDfxIdentityAndRestoreOnExit {
    fn drop(&mut self) {
        // Restore the current identity to what it was originally (when self was
        // created).
        call_dfx_or_panic(&["identity", "use", &self.original_identity]);
    }
}

/// The argument is not actually used. As the name implies, it is required just
/// to make sure that the caller has saved and will restore the prior dfx
/// identity.
fn use_test_neuron_1_owner_identity(
    _caller_must_checkpoint: &SaveOriginalDfxIdentityAndRestoreOnExit,
) -> Result<(), String> {
    import_test_neuron_1_owner()?;

    let (_stdout, _stderr) = run_command(&[
        "dfx",
        "identity",
        "use",
        TEST_NEURON_1_OWNER_DFX_IDENTITY_NAME,
    ])
    .map_err(|err| err.new_report())?;

    Ok(())
}

fn import_test_neuron_1_owner() -> Result<(), String> {
    // Step 1: Save secret key belonging to TEST_NEURON_1_OWNER to a (temporary) pem file.
    let contents: String = TEST_NEURON_1_OWNER_KEYPAIR.to_pem();
    let mut pem_file = NamedTempFile::new().expect("Unable to create a temporary file.");
    pem_file
        .write_all(contents.as_bytes())
        .map_err(|err| format!("{}\n\nUnable to write to (temporary) file.", err))?;
    let pem_file_path = pem_file
        .path()
        .to_str()
        .ok_or("Unable to convert path of TEST_NEURON_1_OWNER's pem file to a String?!")?;

    // Step 2: Call dfx identity import.
    let command = [
        "dfx",
        "identity",
        "import",
        "--force",
        // Needed to avoid forcing the user to choose a password (with an
        // invisible prompt).
        "--storage-mode=plaintext",
        TEST_NEURON_1_OWNER_DFX_IDENTITY_NAME,
        pem_file_path,
    ];
    let result = run_command(&command);

    // Step 3: Convert result.
    result.map(|_ok| ()).map_err(|err| {
        format!(
            "{}\n\
             \n\
             Unable to import test-neuron-1-owner dfx identity from pem file.",
            err,
        )
    })
}

/// Declaratively associates a couple of data with a request type:
///   1. response type
///   2. method name
///
/// Once you implement this (on a foreign request type), you do not need to
/// redundantly specify the name of the associated method, nor do you need to
/// specify how to decode the response.
///
/// Used by Canister::call.
///
/// Look at `impl Request for ManageNeuron` as an example. This is quite simple
/// to implement, really.
trait Request {
    type Response;
    const METHOD_NAME: &'static str;
    // Perhaps, we can also require fn name() and fn response_name() ?
}

/// A nice way to make canister calls (via dfx).
///
/// How to use this:
///
///   1. Prepare: `impl Request for YourRequestType`. See `trait Request`.
///   2. Construct Canister by calling `Canister::new`.
///   3. Call the `call` method on the Canister object (from the previous step).
///      This uses the information that you provided in step 1 to make canister
///      method calls nice.
///
/// Example: see NnsGovernanceCanister::make_proposal.
#[derive(Clone, Debug)]
struct Canister {
    network: String,
    name: String,
}

impl Canister {
    /// Arguments are like those that are passed to `dfx canister`.
    pub(crate) fn new(network: &str, name: &str) -> Self {
        // TODO: Validate arguments.

        let network = network.to_string();
        let name = name.to_string();

        Self { network, name }
    }

    pub(crate) fn call<Req>(&self, request: &Req) -> Result<Req::Response, anyhow::Error>
    where
        Req: Request + CandidType,
        <Req as Request>::Response: CandidType + for<'a> candid::Deserialize<'a>,
    {
        // Step 1: Write request to temporary argument file, which we'll later
        // pass to `dfx canister call --argument-file`.
        let request = Encode!(&request).context("Unable to serialize the request")?;
        let request = IDLArgs::from_bytes(&request).context("Unable to format request")?;
        let request = format!("{}", request);
        let mut argument_file =
            NamedTempFile::new().context("Could not create temporary argument file.")?;
        argument_file
            .write_all(request.as_bytes())
            .context("Unable to write request to local file")?;
        let argument_file = argument_file
            .path()
            .as_os_str()
            .to_str()
            .ok_or_else(|| anyhow!("Unable to convert path of argument file to a string."))?;

        // Step 2: The real work of making the call takes place here.
        let command = [
            "dfx",
            "canister",
            "--network",
            &self.network,
            "call",
            &self.name,
            Req::METHOD_NAME,
            "--argument-file",
            argument_file,
            "--output=raw",
        ];
        let result = run_command(&command);

        // Step 3: Handle errors.
        let (stdout, _stderr) = result.map_err(|err| match err {
            RunCommandError::UnableToRunCommand { error, .. } => {
                anyhow::Error::from(error).context("Unable to run dfx command.")
            }
            RunCommandError::UnsuccessfulExit { output, .. } => {
                anyhow!("dfx command exited unsuccessfully. {:?}", output)
            }
        })?;

        // Step 4: Decode and return response (finally!).

        let response = stdout.trim_end();
        let response = hex::decode(response)
            .with_context(|| format!("Unable to hex decode the response:\n{:?}.", response,))?;
        Decode!(&response, Req::Response).with_context(|| {
            format!(
                "Candid deserialization of response failed. Response:\n{:?}",
                response,
            )
        })
    }
}

struct NnsGovernanceCanister {
    canister: Canister,
}

impl NnsGovernanceCanister {
    pub(crate) fn new(network: &str) -> Self {
        let canister = Canister::new(network, &GOVERNANCE_CANISTER_ID.to_string());

        Self { canister }
    }

    /// Neuron used is the one whose subaccount is associated with the current dfx principal with nonce = 0.
    #[allow(clippy::result_large_err)]
    pub(crate) fn make_proposal(
        &self,
        proposer: &NeuronIdOrSubaccount,
        proposal: &Proposal,
    ) -> Result<MakeProposalResponse, anyhow::Error> {
        impl Request for ManageNeuron {
            type Response = ManageNeuronResponse;
            const METHOD_NAME: &'static str = "manage_neuron";
        }

        // Step 1: Construct request.
        let neuron_id_or_subaccount = Some(proposer.clone());
        let manage_neuron_request = ManageNeuron {
            id: None,
            neuron_id_or_subaccount,
            command: Some(manage_neuron::Command::MakeProposal(Box::new(
                proposal.clone(),
            ))),
        };

        // Step 2: Make the actual call.
        let manage_neuron_response = self
            .canister
            .call(&manage_neuron_request)
            .context("Failed calling the canister")?;

        // Step 3: Unwrap the response.
        match manage_neuron_response.command {
            Some(manage_neuron_response::Command::MakeProposal(response)) => Ok(response),
            _ => Err(anyhow!(
                "Received an invalid response: {:?}",
                manage_neuron_response
            )),
        }
    }
}

fn fetch_canister_controllers_or_exit(network: &str, canister_id: PrincipalId) -> Vec<PrincipalId> {
    let command = [
        "dfx",
        "canister",
        "--network",
        network,
        "info",
        &canister_id.to_string(),
    ];
    let (stdout, _stderr) = run_command(&command).unwrap_or_else(|err| {
        eprintln!("{}", err);
        std::process::exit(1);
    });

    // Parse dfx output. More precisely, look for a line that begins with
    // "Controllers:".
    for line in stdout.lines() {
        let tail = match line.strip_prefix("Controllers:") {
            None => continue,
            Some(tail) => tail,
        };

        return tail
            .trim()
            .split(' ')
            .map(|controller_principal_id| {
                PrincipalId::from_str(controller_principal_id.trim()).unwrap_or_else(|err| {
                    eprintln!(
                        "stdout:\n\
                         {}\n\
                         Unable to parse {:?} as a principal ID from the `Controllers:` \
                         output line of dfx canister info. err = {:?}",
                        stdout, controller_principal_id, err,
                    );
                    std::process::exit(1);
                })
            })
            .collect();
    }

    // No lines in stdout matched -> fail :(
    eprintln!(
        "Unable to determine controllers of {} based on output of dfx:\n{}",
        canister_id, stdout,
    );
    std::process::exit(1);
}

enum RunCommandError<'a> {
    UnableToRunCommand {
        command: &'a [&'a str],
        error: std::io::Error,
    },

    UnsuccessfulExit {
        command: &'a [&'a str],
        output: std::process::Output,
    },
}

impl<'a> Display for RunCommandError<'a> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "{}", self.new_report())
    }
}

impl<'a> RunCommandError<'a> {
    fn new_report(&self) -> String {
        match self {
            RunCommandError::UnableToRunCommand { command, error } => {
                RunCommandError::new_unable_to_run_command_report(command, error)
            }
            RunCommandError::UnsuccessfulExit { command, output } => {
                RunCommandError::new_unsuccessful_exit_report(command, output)
            }
        }
    }

    fn new_unable_to_run_command_report(command: &[&str], error: &std::io::Error) -> String {
        format!(
            "command:\n\
             {}\n\
             \n\
             error:\n\
             {}\n\
             \n\
             `{}` command did not run at all.",
            command.join(" \\n  "),
            error,
            command[0],
        )
    }

    fn new_unsuccessful_exit_report(command: &[&str], output: &std::process::Output) -> String {
        let std::process::Output {
            status,
            stdout,
            stderr,
        } = output;

        let stdout = String::from_utf8_lossy(stdout);
        let stderr = String::from_utf8_lossy(stderr);

        format!(
            "command:\n\
             {}\n\
             \n\
             stdout:\n\
             {}\n\
             \n\
             stderr:\n\
             {}\n\
             \n\
             status: {}",
            command.join(" \\n  "),
            stdout,
            stderr,
            status,
        )
    }
}

fn run_command<'a>(command: &'a [&'a str]) -> Result<(String, String), RunCommandError<'a>> {
    let child = std::process::Command::new(command[0])
        .args(&command[1..command.len()])
        // STDOUT contains data that needs to be processed by the parent.
        .stdout(std::process::Stdio::piped())
        // STDERR may contain information for the end user (e.g., password prompt).
        .stderr(std::process::Stdio::inherit())
        // STDIN may be required for the end user to type in their DFX identity password.
        .stdin(std::process::Stdio::inherit())
        .spawn()
        .map_err(|error| RunCommandError::UnableToRunCommand { command, error })?;

    let output = child
        .wait_with_output()
        .map_err(|error| RunCommandError::UnableToRunCommand { command, error })?;

    let std::process::Output {
        status,
        stdout,
        stderr,
    } = &output;

    if !status.success() {
        return Err(RunCommandError::UnsuccessfulExit { command, output });
    }

    let stdout = String::from_utf8_lossy(stdout).to_string();
    let stderr = String::from_utf8_lossy(stderr).to_string();
    Ok((stdout, stderr))
}

static DFX_INIT: Once = Once::new();

/// Calls `dfx` with the given args
#[must_use]
fn call_dfx(args: &[&str]) -> Output {
    let dfx_cmd = if Path::new("./dfx").exists() {
        "./dfx"
    } else {
        "dfx"
    };
    DFX_INIT.call_once(|| {
        let version_output = Command::new(dfx_cmd)
            .args(["--version"])
            .output()
            .expect("Failed to execute dfx command");
        println!(
            "Invoking dfx with `{dfx_cmd}`. dfx version: {}",
            String::from_utf8_lossy(&version_output.stdout).trim()
        );
    });

    let output = Command::new(dfx_cmd)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("dfx failed when called with args: {:?}: {}", args, e));

    // Some dfx commands output stderr instead of stdout, so we assign it for use in both
    // success and error cases below.
    let std_err = String::from_utf8_lossy(&output.stderr);

    if output.status.success() {
        print!("{}", String::from_utf8_lossy(&output.stdout));
        print!("{}", std_err);
    } else {
        println!(
            "dfx failed when called with args: {:?}, error: {}",
            args, std_err
        );
    }

    output
}

fn call_dfx_or_panic(args: &[&str]) {
    let output = call_dfx(args);

    // No need to include diagnostics, because call_dfx already prints stderr.
    assert!(output.status.success());
}

/// Given a `CandidType`, return the hex encoding of this object.
pub(crate) fn hex_encode_candid(candid: impl CandidType) -> String {
    let bytes = Encode!(&candid).unwrap();
    hex::encode(bytes)
}
