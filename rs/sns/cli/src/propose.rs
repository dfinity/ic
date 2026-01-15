use crate::{
    MakeProposalResponse, NnsGovernanceCanister, SaveOriginalDfxIdentityAndRestoreOnExit,
    fetch_canister_controllers, get_identity, use_test_neuron_1_owner_identity,
};
use anyhow::{Context, Result, anyhow, bail};
use clap::{ArgGroup, Parser};
use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_common::ledger::compute_neuron_staking_subaccount_bytes;
use ic_nervous_system_common_test_keys::TEST_NEURON_1_ID;
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_nns_constants::ROOT_CANISTER_ID;
use ic_nns_governance_api::{
    MakeProposalRequest, ProposalActionRequest, manage_neuron::NeuronIdOrSubaccount,
};
use itertools::Itertools;
use std::{
    collections::HashSet,
    fmt::{Debug, Display, Formatter},
    fs::{OpenOptions, write},
    path::{Path, PathBuf},
};

#[cfg(test)]
mod propose_tests;

#[derive(Debug, Parser)]
#[clap(group(ArgGroup::new("neuron-selection").multiple(false).required(true)))]
pub struct ProposeArgs {
    /// The network to deploy to. This can be "local", "ic", or the URL of an IC
    /// network.
    #[structopt(default_value = "local", long)]
    network: String,

    /// Path to a configuration file specifying the SNS to be created.
    #[clap(default_value = "sns_init.yaml", value_parser = clap::value_parser!(std::path::PathBuf))]
    pub init_config_file: PathBuf,

    /// The neuron with which to make the proposal. The current dfx identity
    /// must be able to operate this neuron. If not specified, it will be
    /// assumed that the current dfx identity has a neuron with memo == 0.
    /// --neuron_memo is an alternative to this.
    #[clap(long, group = "neuron-selection")]
    pub neuron_id: Option<u64>,

    /// This is an alternative to --neuron_id for specifying which neuron to
    /// make the proposal with. This is used in conjunction with the current
    /// principal to calculate the subaccount (belonging to the NNS governance
    /// canister) that holds the ICP that backs the proposing neuron.
    #[clap(long, group = "neuron-selection")]
    pub neuron_memo: Option<u64>,

    /// This is a "secret menu" item. It is (yet) another alternative to
    /// --neuron_id (and --neuron_memo). As the name implies, this is only
    /// useful when running against a local instance of NNS (when deployed as
    /// described in the sns-testing Github repo). In addition to specifying
    /// which neuron to propose with, this also controls the principal that
    /// sends the request.
    #[clap(long, group = "neuron-selection")]
    pub test_neuron_proposer: bool,

    /// An optional flag to save the ProposalId of a successfully submitted
    /// CreateServiceNervousSystem proposal to the filesystem. The file must
    /// be writeable, and will be created if it does not exist.    
    /// The ProposalId will be saved in JSON format. For example:
    ///
    ///  {
    ///      "id": 10
    ///  }
    #[clap(long)]
    pub save_to: Option<PathBuf>,

    /// If this flag is set, the proposal will be submitted without asking for
    /// confirmation. This is useful for automated scripts.
    #[clap(long)]
    pub skip_confirmation: bool,
}

pub fn exec(args: ProposeArgs) -> Result<()> {
    let ProposeArgs {
        network,
        init_config_file,
        neuron_id,
        neuron_memo,
        save_to,
        test_neuron_proposer,
        skip_confirmation,
    } = args;
    // We automatically skip confirming with the user if the network is "local", to save time during testing.
    let skip_confirmation = skip_confirmation || network == "local";

    // Step 0: Load configuration
    let proposal = load_configuration_and_validate(&network, &init_config_file)?;

    // Step 1: Ensure the save-to file exists and is writeable if specified.
    // We do this check without writing the file to ensure the best chance of successfully
    // saving the data to a file after the Proposal is submitted.
    if let Some(save_to) = &save_to {
        ensure_file_exists_and_is_writeable(save_to.as_path())?
    }

    // Step 2: Verify with the user that they want to proceed.
    inform_user_of_sns_behavior(&proposal, skip_confirmation)?;

    // Step 2: Send the proposal.
    eprintln!("Loaded configuration.");
    eprintln!(
        "Sending proposal with title {:?} to NNS (--network={})...",
        proposal.title.as_ref().unwrap_or(&"".to_string()),
        network,
    );
    let checkpoint = SaveOriginalDfxIdentityAndRestoreOnExit::new_or_panic();
    let proposer = if let Some(id) = neuron_id {
        NeuronIdOrSubaccount::NeuronId(NeuronId { id })
    } else if test_neuron_proposer {
        use_test_neuron_1_owner_identity(&checkpoint)
            .context("Failed to (import and) use test-neuron-1-owner dfx identity")?;

        NeuronIdOrSubaccount::NeuronId(NeuronId {
            id: TEST_NEURON_1_ID,
        })
    } else {
        let subaccount = compute_neuron_staking_subaccount_bytes(
            get_identity("get-principal", &network),
            neuron_memo.unwrap_or_default(),
        );
        NeuronIdOrSubaccount::Subaccount(subaccount.to_vec())
    };
    let result = NnsGovernanceCanister::new(&network).make_proposal(&proposer, &proposal);

    // Step 3: Report result.
    println!();
    match result {
        Ok(MakeProposalResponse {
            proposal_id: Some(proposal_id),
            message,
        }) => {
            println!("🚀 Success!");
            if let Some(message) = message {
                println!("Message from NNS governance: {message:?}");
            }
            if network == "ic" {
                println!("View the proposal here:");
                println!(
                    "https://dashboard.internetcomputer.org/proposal/{}",
                    proposal_id.id
                );
            } else {
                // TODO: Support other networks.
                println!("Proposal ID: {}", proposal_id.id);
            }

            if let Some(save_to) = &save_to
                && let Err(err) = save_proposal_id_to_file(save_to.as_path(), &proposal_id)
            {
                bail!("{}", err);
            };
        }
        err => {
            bail!(
                "{err:?}\n\
                \n\
                💔 Something went wrong. Look up slightly for diagnostics.\n\
                Perhaps, share the above error with the community at\n\
                https://forum.dfinity.org/c/tokenization"
            )
        }
    };

    Ok(())
}

fn functions_disallowed_in_pre_initialization_swap() -> Vec<&'static str> {
    vec![
        "ManageNervousSystemParameters",
        "TransferSnsTreasuryFunds",
        "MintSnsTokens",
        "UpgradeSnsControlledCanister",
        "RegisterDappCanisters",
        "DeregisterDappCanisters",
    ]
}

fn confirmation_messages(proposal: &MakeProposalRequest) -> Result<Vec<String>> {
    let csns = match &proposal.action {
        Some(ProposalActionRequest::CreateServiceNervousSystem(csns)) => csns,
        _ => {
            return Err(anyhow!(
                "Internal error: Somehow a proposal was made not of type CreateServiceNervousSystem",
            ));
        }
    };
    let fallback_controllers = csns
        .fallback_controller_principal_ids
        .iter()
        .map(|id| format!("  - {id}"))
        .join("\n");
    let dapp_canister_controllers = if !csns.dapp_canisters.is_empty() {
        let canisters = csns
            .dapp_canisters
            .iter()
            .filter_map(|canister| canister.id.as_ref())
            .map(|id| format!("  - {id}"))
            .join("\n");
        format!(
            r#"A CreateServiceNervousSystem proposal will be submitted.
If adopted, this proposal will create an SNS, which will control these canisters:
{canisters}
If these canisters do not have NNS root as a co-controller when the proposal is adopted, the SNS launch will be aborted.
Otherwise, when the proposal is adopted, the SNS will be created and the SNS and NNS will have sole control over those canisters.
Then, if the swap completes successfully, the SNS will take sole control. If the swap fails, control will be given to the fallback controllers:
{fallback_controllers}"#
        )
    } else {
        r#"A CreateServiceNervousSystem proposal will be submitted. If adopted, this proposal will create an SNS that controls no canisters."#.to_string()
    };

    let disallowed_types = functions_disallowed_in_pre_initialization_swap()
        .into_iter()
        .map(|t| format!("  - {t}"))
        .join("\n");
    let allowed_proposals = format!(
        r#"After the proposal is adopted, a swap is started. While the swap is running, the SNS will be in a restricted mode.
Within this restricted mode, some proposal actions will not be allowed:
{disallowed_types}
Once the swap is completed, the SNS will be in normal mode and these proposal actions will become available again."#
    );

    Ok(vec![dapp_canister_controllers, allowed_proposals])
}

fn inform_user_of_sns_behavior(
    proposal: &MakeProposalRequest,
    skip_confirmation: bool,
) -> Result<()> {
    let messages = confirmation_messages(proposal)?;
    for message in messages {
        println!();
        println!("{message}");
        confirm_understanding(skip_confirmation)?;
    }
    Ok(())
}

fn confirm_understanding(skip_confirmation: bool) -> Result<()> {
    use std::io::{self, Write};

    if skip_confirmation {
        return Ok(());
    }

    let mut input = String::new();
    print!("I understand [y/N]: ");
    io::stdout().flush().unwrap(); // Make sure the prompt is displayed before input

    match io::stdin().read_line(&mut input) {
        Ok(_) => {
            let input = input.trim().to_lowercase(); // Clean and normalize the input
            if input == "y" || input == "yes" {
                println!("Confirmed.");
                Ok(())
            } else {
                bail!("Exiting.")
            }
        }
        Err(error) => {
            bail!("Error reading input: {}", error)
        }
    }
}

fn load_configuration_and_validate(
    network: &str,
    configuration_file_path: &PathBuf,
) -> Result<MakeProposalRequest> {
    // Read the file.
    let init_config_file = std::fs::read_to_string(configuration_file_path).map_err(|err| {
        let current_dir = std::env::current_dir().expect("cannot read env::current_dir");
        anyhow!(
            "Unable to read the SNS configuration file {:?}:\n{}",
            current_dir.join(configuration_file_path),
            err,
        )
    })?;

    // Parse its contents.
    let init_config_file = serde_yaml::from_str::<
        crate::init_config_file::friendly::SnsConfigurationFile,
    >(&init_config_file)
    .map_err(|err| {
        anyhow!(
            "Unable to parse the SNS configuration file ({:?}):\n{}",
            init_config_file,
            err,
        )
    })?;
    let base_path = match configuration_file_path.parent() {
        Some(ok) => ok,
        None => {
            // This shouldn't happen since we were already able to read from
            // configuration_file_path.
            bail!(
                "Configuration file path ({:?}) has no parent.",
                configuration_file_path,
            );
        }
    };
    let proposal = init_config_file
        .try_convert_to_nns_proposal(base_path)
        .map_err(|err| {
            anyhow!(
                "Unable to parse the SNS configuration file. err = {:?}.\n\
                 init_config_file:\n{:#?}",
                err,
                init_config_file,
            )
        })?;

    // Validate that NNS root is one of the controllers of all dapp canisters,
    // as listed in the configuration file.
    let canister_ids = match &proposal.action {
        Some(ProposalActionRequest::CreateServiceNervousSystem(csns)) => csns
            .dapp_canisters
            .iter()
            .map(|canister| -> Result<CanisterId> {
                let canister_id: PrincipalId = canister.id.ok_or_else(|| {
                    anyhow!(
                        "Internal error: Canister.id was found to be None while \
                        validating the CreateServiceNervousSystem.dapp_canisters \
                        field.",
                    )
                })?;

                CanisterId::try_from(canister_id)
                    .map_err(|err| anyhow!("{err}"))
                    .context(format!(
                        "Internal error: Unable to Convert PrincipalId ({canister_id}) to CanisterId."
                    ))
            })
            .collect::<Result<Vec<_>>>()?,
        _ => {
            return Err(anyhow!(
                "Internal error: Somehow a proposal was made not of type CreateServiceNervousSystem",
            ));
        }
    };

    all_canisters_have_all_required_controllers(network, &canister_ids, &[ROOT_CANISTER_ID.get()])?;

    // Return as the result.
    Ok(proposal)
}

struct CanistersWithMissingControllers {
    inspected_canister_count: usize,
    defective_canister_ids: Vec<CanisterId>,
}

impl Display for CanistersWithMissingControllers {
    fn fmt(&self, formatter: &mut Formatter) -> std::fmt::Result {
        let CanistersWithMissingControllers {
            inspected_canister_count,
            defective_canister_ids,
        } = self;

        write!(
            formatter,
            "Not all dapp canisters are controlled by the NNS root canister.\n\
             Use `sns prepare-canisters add-nns-root` to make the necessary changes.\n\
             Defective canisters ({} out of {}):\n  \
             - {}",
            inspected_canister_count,
            defective_canister_ids.len(),
            defective_canister_ids
                .iter()
                .map(CanisterId::to_string)
                .collect::<Vec<_>>()
                .join("\n  - "),
        )
    }
}

fn all_canisters_have_all_required_controllers(
    network: &str,
    canister_ids: &[CanisterId],
    required_controllers: &[PrincipalId],
) -> Result<()> {
    let required_controllers = HashSet::<_, std::collections::hash_map::RandomState>::from_iter(
        required_controllers.iter().cloned(),
    );
    // Identify canisters which are not controlled by the NNS root canister.
    let defective_canister_ids = canister_ids
        .iter()
        .filter(|canister_id| {
            let canister_id = PrincipalId::from(**canister_id);
            let controllers =
                HashSet::from_iter(fetch_canister_controllers(network, canister_id).unwrap());
            let ok = controllers.is_superset(&required_controllers);
            !ok
        })
        .cloned()
        .collect::<Vec<_>>();

    let ok = defective_canister_ids.is_empty();
    if ok {
        return Ok(());
    }

    let inspected_canister_count = canister_ids.len();
    Err(anyhow!(
        "{}",
        CanistersWithMissingControllers {
            inspected_canister_count,
            defective_canister_ids,
        }
    ))
}

#[derive(Clone, Eq, PartialEq, Debug)]
enum SaveToErrors {
    FileOpenFailed(PathBuf, String),
    FileWriteFailed(PathBuf, String),
    InvalidData(String),
}

impl std::error::Error for SaveToErrors {}

impl Display for SaveToErrors {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let error_string = match self {
            SaveToErrors::FileOpenFailed(path_buf, reason) => {
                format!("could not open file for writing {path_buf:?} due to {reason}")
            }
            SaveToErrors::FileWriteFailed(path_buf, reason) => {
                format!("could not write to file {path_buf:?} due to {reason}")
            }
            SaveToErrors::InvalidData(reason) => {
                format!("could not format data to JSON scheme due to {reason}")
            }
        };

        write!(
            f,
            "Unable to save ProposalId to file because {error_string}. \
            The proposal may or may not have been submitted"
        )
    }
}

/// Ensure that a path to a file exists (by creating it if it does not) and is writeable.
fn ensure_file_exists_and_is_writeable(path: &Path) -> Result<(), SaveToErrors> {
    // Make sure the file is writeable. Create it if it does not exist.
    match OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)
    {
        Ok(_) => (),
        Err(e) => {
            return Err(SaveToErrors::FileOpenFailed(
                path.to_path_buf(),
                e.to_string(),
            ));
        }
    }

    Ok(())
}

/// Save a `ProposalId` to a file in JSON format
fn save_proposal_id_to_file(path: &Path, proposal_id: &ProposalId) -> Result<(), SaveToErrors> {
    let json_str = serde_json::to_string(&proposal_id)
        .map_err(|e| SaveToErrors::InvalidData(e.to_string()))?;

    write(path, json_str)
        .map_err(|e| SaveToErrors::FileWriteFailed(path.to_path_buf(), e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::init_config_file::friendly::SnsConfigurationFile;
    use pretty_assertions::assert_eq;

    #[test]
    fn confirmation_messages_test() {
        // Step 1: Prepare the world.
        let test_root_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let test_root_dir = Path::new(&test_root_dir);

        let contents: String =
            std::fs::read_to_string(test_root_dir.join("test_sns_init_v2.yaml")).unwrap();
        let sns_configuration_file =
            serde_yaml::from_str::<SnsConfigurationFile>(&contents).unwrap();

        // Step 2: Call code under test.
        let create_service_nervous_system = sns_configuration_file
            .try_convert_to_create_service_nervous_system(test_root_dir)
            .unwrap();

        let proposal = MakeProposalRequest {
            title: Some("Test Proposal".to_string()),
            action: Some(ProposalActionRequest::CreateServiceNervousSystem(
                create_service_nervous_system,
            )),
            summary: "Test Proposal Summary".to_string(),
            url: "https://example.com".to_string(),
        };

        let observed_messages = confirmation_messages(&proposal).unwrap();
        let expected_messages = vec![
            r#"A CreateServiceNervousSystem proposal will be submitted.
If adopted, this proposal will create an SNS, which will control these canisters:
  - c2n4r-wni5m-dqaaa-aaaap-4ai
  - ucm27-3lxwy-faaaa-aaaap-4ai
If these canisters do not have NNS root as a co-controller when the proposal is adopted, the SNS launch will be aborted.
Otherwise, when the proposal is adopted, the SNS will be created and the SNS and NNS will have sole control over those canisters.
Then, if the swap completes successfully, the SNS will take sole control. If the swap fails, control will be given to the fallback controllers:
  - 5zxxw-63ouu-faaaa-aaaap-4ai"#,
            r#"After the proposal is adopted, a swap is started. While the swap is running, the SNS will be in a restricted mode.
Within this restricted mode, some proposal actions will not be allowed:
  - ManageNervousSystemParameters
  - TransferSnsTreasuryFunds
  - MintSnsTokens
  - UpgradeSnsControlledCanister
  - RegisterDappCanisters
  - DeregisterDappCanisters
Once the swap is completed, the SNS will be in normal mode and these proposal actions will become available again."#,
        ];
        assert_eq!(observed_messages, expected_messages);
    }

    #[test]
    fn confirmation_messages_no_dapp_canisters() {
        // Step 1: Prepare the world.
        let test_root_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let test_root_dir = Path::new(&test_root_dir);

        let contents: String =
            std::fs::read_to_string(test_root_dir.join("test_sns_init_v2.yaml")).unwrap();
        let sns_configuration_file =
            serde_yaml::from_str::<SnsConfigurationFile>(&contents).unwrap();

        // Step 2: Call code under test.
        let create_service_nervous_system = {
            let mut create_service_nervous_system = sns_configuration_file
                .try_convert_to_create_service_nervous_system(test_root_dir)
                .unwrap();
            create_service_nervous_system.dapp_canisters = vec![];
            create_service_nervous_system
        };

        let proposal = MakeProposalRequest {
            title: Some("Test Proposal".to_string()),
            action: Some(ProposalActionRequest::CreateServiceNervousSystem(
                create_service_nervous_system,
            )),
            summary: "Test Proposal Summary".to_string(),
            url: "https://example.com".to_string(),
        };

        let observed_message = &confirmation_messages(&proposal).unwrap()[0];
        let expected_message = r#"A CreateServiceNervousSystem proposal will be submitted. If adopted, this proposal will create an SNS that controls no canisters."#;
        assert_eq!(observed_message, expected_message);
    }
}
