use crate::{
    deploy::{DirectSnsDeployerForTests, SnsWasmSnsDeployer},
    init_config_file::{InitConfigFileArgs, SnsCliInitConfig, SnsInitialTokenDistributionConfig},
    prepare_canisters::PrepareCanistersArgs,
    propose::ProposeArgs,
};
use candid::{CandidType, Decode, Encode, IDLArgs};
use clap::Parser;
use ic_base_types::PrincipalId;
use ic_crypto_sha2::Sha256;
use ic_nervous_system_common_test_keys::TEST_NEURON_1_OWNER_KEYPAIR;
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, SNS_WASM_CANISTER_ID};
use ic_nns_governance::pb::v1::{
    manage_neuron::{self, NeuronIdOrSubaccount},
    manage_neuron_response::{self, MakeProposalResponse},
    ManageNeuron, ManageNeuronResponse, Proposal,
};
use ic_sns_init::pb::v1::{
    sns_init_payload::InitialTokenDistribution, AirdropDistribution, DeveloperDistribution,
    FractionalDeveloperVotingPower, NeuronDistribution, SnsInitPayload, SwapDistribution,
    TreasuryDistribution,
};
use ic_sns_wasm::pb::v1::{AddWasmRequest, SnsCanisterType, SnsWasm};
use icp_ledger::{AccountIdentifier, BinaryAccountBalanceArgs};
use std::{
    fmt::{Debug, Display},
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{exit, Command, Output},
    str::FromStr,
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
    /// Deploy an sns through the sns-wasms canister.
    Deploy(DeployArgs),
    /// Deploy an sns directly to a subnet, skipping the sns-wasms canister.
    /// For use in tests only.
    DeploySkippingSnsWasmsForTests(DeployArgs),
    /// Deploy an sns directly to a subnet, skipping the sns-wasms canister.
    /// The SNS canisters remain controlled by the developer after deployment.
    /// For use in tests only.
    DeployTestflight(DeployTestflightArgs),
    /// Add a wasms for one of the SNS canisters, skipping the NNS proposal,
    /// for tests.
    AddSnsWasmForTests(AddSnsWasmForTestsArgs),
    /// Display the balance of a given account.
    AccountBalance(AccountBalanceArgs),
    /// Manage the config file where the initial sns parameters are set.
    InitConfigFile(InitConfigFileArgs),
    /// Make changes to canisters you own to prepare for SNS Decentralization
    PrepareCanisters(PrepareCanistersArgs),
    /// Submit an NNS proposal to create new SNS.
    Propose(ProposeArgs),
}

/// The arguments used to configure a SNS deployment
#[derive(Debug, Parser)]
pub struct DeployArgs {
    /// Print all error and info messages.
    #[structopt(long)]
    verbose: bool,

    /// The network to deploy to. This can be "local", "ic", or the URL of an IC network.
    #[structopt(default_value = "local", long)]
    network: String,

    /// The initial config file, this file should have all the necessary parameters to deploy an SNS.
    /// See command "init-config-file"
    #[clap(long, parse(from_os_str))]
    pub init_config_file: PathBuf,

    /// The canister ID or name (via dfx.json) of SNS-WASMS to use instead of the default
    ///
    /// This is useful for testing CLI commands against local replicas without fully deployed NNS
    #[clap(long)]
    pub override_sns_wasm_canister_id_for_tests: Option<String>,

    /// The canister ID of the wallet to use on this subnet.
    ///
    /// This is needed in testnet scenarios or if you want to use a different wallet than the one
    /// currently set for your dfx identity.
    #[clap(long)]
    pub wallet_canister_override: Option<PrincipalId>,

    /// The SNS-WASMS canister candid, used to parse canister IDs from the response.
    ///
    /// Corresponds to the dfx canister call --candid flag.
    #[clap(long)]
    pub candid: Option<String>,

    /// The amount of cycles to initialize each SNS canister with. This can be omitted when
    /// deploying locally.
    #[structopt(long)]
    initial_cycles_per_canister: Option<u64>,

    /// Saves the returned canister IDs in the specified json file.
    ///
    /// Default: canister_ids.json
    #[structopt(default_value = "canister_ids.json", long)]
    save_to: PathBuf,

    /// Saves the SNS canister IDs in the specified json file for sns-quill.
    ///
    /// Default: sns_canister_ids.json
    #[structopt(default_value = "sns_canister_ids.json", long)]
    sns_canister_ids_save_to: PathBuf,

    /// The fee to provide
    #[structopt(default_value = "180000000000000", long)]
    with_cycles: u64,

    /// The directory with SNS canister WASMs.
    #[structopt(default_value = ".", long)]
    wasms_dir: PathBuf,
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
    #[clap(long, parse(from_os_str))]
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

/// The arguments used to display the account balance of a user
#[derive(Debug, Parser)]
pub struct AccountBalanceArgs {
    /// The principal ID of the account owner to display their main account balance (note that
    /// subaccounts are not yet supported). If not specified, the principal of the current dfx
    /// identity is used.
    #[clap(long)]
    pub principal_id: Option<String>,

    /// The network to deploy to. This can be "local", "ic", or the URL of an IC network.
    #[structopt(default_value = "local", long)]
    network: String,
}

#[derive(Debug, Parser)]
pub struct AddSnsWasmForTestsArgs {
    #[clap(long, parse(from_os_str))]
    wasm_file: PathBuf,

    canister_type: String,

    /// The canister ID of SNS-WASMS to use instead of the default
    ///
    /// This is useful for testing CLI commands against local replicas without fully deployed NNS
    #[clap(long)]
    pub override_sns_wasm_canister_id_for_tests: Option<String>,

    #[structopt(default_value = "local", long)]
    network: String,
}

impl DeployArgs {
    pub fn generate_sns_init_payload(&self) -> Result<SnsInitPayload, String> {
        generate_sns_init_payload(&self.init_config_file)
    }
}

pub fn generate_sns_init_payload(path: &Path) -> Result<SnsInitPayload, std::string::String> {
    // First, try format v1. If serde_yaml::Error occurred, try format v2.
    generate_sns_init_payload_v1(path).or_else(|previous_err| {
        use GenerateSnsInitPayloadV1Error as E;
        match previous_err {
            E::Misc(err) => Err(err),
            E::Yaml(_) => generate_sns_init_payload_v2(path),
        }
    })
}

enum GenerateSnsInitPayloadV1Error {
    Yaml(serde_yaml::Error),
    Misc(String),
}

fn generate_sns_init_payload_v1(
    path: &Path,
) -> Result<SnsInitPayload, GenerateSnsInitPayloadV1Error> {
    // Read the file.
    let file = File::open(path).map_err(|err| {
        GenerateSnsInitPayloadV1Error::Misc(format!("Unable to read {:?}: {}", path, err))
    })?;

    // Parse its contents.
    let mut sns_cli_init_config: SnsCliInitConfig =
        serde_yaml::from_reader(file).map_err(GenerateSnsInitPayloadV1Error::Yaml)?;

    // Normalize logo path: if relative, convert it to absolute, using the
    // directory where the configuration file lives as the base (as opposed to
    // the current working directory of the runner).
    sns_cli_init_config.sns_governance.logo =
        sns_cli_init_config.sns_governance.logo.map(|logo_path| {
            if logo_path.is_absolute() {
                logo_path
            } else {
                path.parent().unwrap().join(logo_path)
            }
        });

    // Convert.
    let sns_init_payload = SnsInitPayload::try_from(sns_cli_init_config)
        .map_err(GenerateSnsInitPayloadV1Error::Misc)?;

    // Validate.
    sns_init_payload
        .validate_legacy_init()
        .map_err(GenerateSnsInitPayloadV1Error::Misc)?;

    // Ship it!
    Ok(sns_init_payload)
}

fn generate_sns_init_payload_v2(path: &Path) -> Result<SnsInitPayload, String> {
    // Read the file.
    let contents = std::fs::read_to_string(path)
        .map_err(|err| format!("Unable to read {:?}: {}", path, err))?;

    // Parse its contents.
    let configuration =
        serde_yaml::from_str::<crate::init_config_file::friendly::SnsConfigurationFile>(&contents)
            .map_err(|err| format!("Unable to parse contents of {:?}: {}", path, err))?;

    // Convert (to CreateServiceNervousSysytem).
    let base_path = path.parent().ok_or_else(|| {
        format!(
            "Configuration file path ({:?}) has no parent, it seems.",
            path,
        )
    })?;
    let configuration = configuration
        .try_convert_to_create_service_nervous_system(base_path)
        .map_err(|err| format!("Invalid configuration in {:?}: {}", path, err))?;

    // Last step: more conversion (this time, to the desired type: SnsInitPayload).
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

impl DeployTestflightArgs {
    pub fn generate_sns_init_payload(&self) -> Result<SnsInitPayload, String> {
        match &self.init_config_file {
            Some(init_config_file) => generate_sns_init_payload(init_config_file),
            None => {
                let developer_identity = get_identity("get-principal", &self.network);
                let developer_neuron = NeuronDistribution {
                    controller: Some(developer_identity),
                    stake_e8s: 1500000000,
                    memo: 0,
                    dissolve_delay_seconds: 15780000,
                    vesting_period_seconds: None,
                };
                let developer_dist = DeveloperDistribution {
                    developer_neurons: vec![developer_neuron],
                };
                let treasury_dist = TreasuryDistribution {
                    total_e8s: 5000000000,
                };
                let swap_dist = SwapDistribution {
                    total_e8s: 6000000000,
                    initial_swap_amount_e8s: 3000000000,
                };
                let airdrop_dist = AirdropDistribution {
                    airdrop_neurons: vec![],
                };
                let dists = FractionalDeveloperVotingPower {
                    developer_distribution: Some(developer_dist),
                    treasury_distribution: Some(treasury_dist),
                    swap_distribution: Some(swap_dist),
                    airdrop_distribution: Some(airdrop_dist),
                };
                let initial_token_distribution = SnsInitialTokenDistributionConfig {
                    initial_token_distribution: Some(
                        InitialTokenDistribution::FractionalDeveloperVotingPower(dists),
                    ),
                };
                let mut sns_init_config = SnsCliInitConfig {
                    initial_token_distribution,
                    ..Default::default()
                };
                sns_init_config.sns_ledger.token_name = Some("MyTestToken".to_string());
                sns_init_config.sns_ledger.token_symbol = Some("MTT".to_string());
                sns_init_config
                    .sns_governance
                    .fallback_controller_principal_ids = vec![developer_identity.to_string()];
                sns_init_config.sns_governance.url = Some("https://example.com".to_string());
                sns_init_config.sns_governance.name = Some("My_Test_Token".to_string());
                sns_init_config.sns_governance.description =
                    Some("MyTestTokenDescription".to_string());
                sns_init_config.try_into()
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

/// Deploy via SNS-WASM canister.
pub fn deploy(args: DeployArgs) {
    let sns_init_payload = args.generate_sns_init_payload().unwrap_or_else(|err| {
        eprintln!(
            "Error encountered when generating the SnsInitPayload: {}",
            err
        );
        exit(1);
    });
    SnsWasmSnsDeployer::new(args, sns_init_payload).deploy();
}

/// Deploy an SNS with the given DeployArgs, skipping sns-wasm.
pub fn deploy_skipping_sns_wasms_for_tests(args: DeployArgs) {
    let sns_init_payload = args.generate_sns_init_payload().unwrap_or_else(|err| {
        eprintln!(
            "Error encountered when generating the SnsInitPayload: {}",
            err,
        );
        exit(1);
    });
    DirectSnsDeployerForTests::new(args, sns_init_payload).deploy()
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
        _ => panic!("Uknown canister type."),
    };

    let add_sns_wasm_request = AddWasmRequest {
        wasm: Some(SnsWasm {
            wasm: sns_wasm_bytes,
            canister_type: sns_canister_type as i32,
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

/// Print the Ledger account balance of the principal in `AccountBalanceArgs` if given, else
/// print the account balance of the principal of the current dfx identity.
pub fn print_account_balance(args: AccountBalanceArgs) {
    let principal_id = if let Some(principal_str) = args.principal_id {
        PrincipalId::from_str(&principal_str)
            .unwrap_or_else(|_| panic!("Could not parse {} as a PrincipalId", principal_str))
    } else {
        get_identity("get-principal", &args.network)
    };

    let account: AccountIdentifier = principal_id.into();
    let account_balance_args = BinaryAccountBalanceArgs {
        account: account.to_address(),
    };

    let idl = IDLArgs::from_bytes(&Encode!(&account_balance_args).unwrap()).unwrap();

    call_dfx_or_panic(&[
        "canister",
        "--network",
        &args.network,
        "call",
        "sns_ledger",
        "account_balance",
        &format!("{}", idl),
    ]);
}

/// Return the `PrincipalId` of the given dfx identity
pub fn get_identity(identity: &str, network: &str) -> PrincipalId {
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
    // Step 1: Save secret key belonging to TEST_NEURON_1_ONWER to a (temporary) pem file.
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

#[derive(Debug)]
enum CanisterCallError {
    UnableToPrepareDfxCall(String),
    UnableToCallDfx(std::io::Error),
    DfxBadExit(std::process::Output),
    ResponseDecodeFail(String),
}

impl Canister {
    /// Arguments are like those that are passed to `dfx canister`.
    pub fn new(network: &str, name: &str) -> Self {
        // TODO: Validate arguments.

        let network = network.to_string();
        let name = name.to_string();

        Self { network, name }
    }

    pub fn call<Req>(&self, request: &Req) -> Result<Req::Response, CanisterCallError>
    where
        Req: Request + CandidType,
        <Req as Request>::Response: CandidType + for<'a> candid::Deserialize<'a>,
    {
        // Step 1: Write request to temporary argument file, which we'll later
        // pass to `dfx canister call --argument-file`.
        let request = Encode!(&request).map_err(|err| {
            CanisterCallError::UnableToPrepareDfxCall(format!(
                "Unable to serialize request: {}",
                err,
            ))
        })?;
        let request = IDLArgs::from_bytes(&request).map_err(|err| {
            CanisterCallError::UnableToPrepareDfxCall(format!("Unable to format request: {}", err,))
        })?;
        let request = format!("{}", request);
        let mut argument_file = NamedTempFile::new().map_err(|err| {
            CanisterCallError::UnableToPrepareDfxCall(format!(
                "Could not create temporary argument file: {}",
                err,
            ))
        })?;
        argument_file.write_all(request.as_bytes()).map_err(|err| {
            CanisterCallError::UnableToPrepareDfxCall(format!(
                "Unable to write request to local file: {}",
                err,
            ))
        })?;
        let argument_file = argument_file.path().as_os_str().to_str().ok_or_else(|| {
            CanisterCallError::UnableToPrepareDfxCall(
                "Unable to determine the path of the argument file.".to_string(),
            )
        })?;

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
                CanisterCallError::UnableToCallDfx(error)
            }
            RunCommandError::UnsuccessfulExit { output, .. } => {
                CanisterCallError::DfxBadExit(output)
            }
        })?;

        // Step 4: Decode and return response (finally!).

        let response = stdout.trim_end();
        let response = hex::decode(response).map_err(|err| {
            CanisterCallError::ResponseDecodeFail(format!(
                "Unable to hex decode the response. reason: {}. response:\n{:?}",
                err, response,
            ))
        })?;
        Decode!(&response, Req::Response).map_err(|err| {
            CanisterCallError::ResponseDecodeFail(format!(
                "Candid deserialization of response failed. reason: {}. response:\n{:?}",
                err, response,
            ))
        })
    }
}

struct NnsGovernanceCanister {
    canister: Canister,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum MakeProposalError {
    CanisterCallError(CanisterCallError),
    InvalidResponse(ManageNeuronResponse),
}

impl NnsGovernanceCanister {
    pub fn new(network: &str) -> Self {
        let canister = Canister::new(network, &GOVERNANCE_CANISTER_ID.to_string());

        Self { canister }
    }

    /// Neuron used is the one whose subaccount is associated with the current dfx principal with nonce = 0.
    #[allow(clippy::result_large_err)]
    pub fn make_proposal(
        &self,
        proposer: &NeuronIdOrSubaccount,
        proposal: &Proposal,
    ) -> Result<MakeProposalResponse, MakeProposalError> {
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
            .map_err(MakeProposalError::CanisterCallError)?;

        // Step 3: Unwrap the response.
        match manage_neuron_response.command {
            Some(manage_neuron_response::Command::MakeProposal(response)) => Ok(response),
            _ => Err(MakeProposalError::InvalidResponse(manage_neuron_response)),
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
                RunCommandError::new_unsuccesful_exit_report(command, output)
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

    fn new_unsuccesful_exit_report(command: &[&str], output: &std::process::Output) -> String {
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
    let output = std::process::Command::new(command[0])
        .args(&command[1..command.len()])
        .output()
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

/// Calls `dfx` with the given args
#[must_use]
fn call_dfx(args: &[&str]) -> Output {
    let output = Command::new("dfx")
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
pub fn hex_encode_candid(candid: impl CandidType) -> String {
    let bytes = Encode!(&candid).unwrap();
    hex::encode(bytes)
}
