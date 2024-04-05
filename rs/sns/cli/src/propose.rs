use crate::{
    fetch_canister_controllers_or_exit, get_identity, use_test_neuron_1_owner_identity,
    MakeProposalResponse, NnsGovernanceCanister, SaveOriginalDfxIdentityAndRestoreOnExit,
};
use clap::{ArgGroup, Parser};
use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_common::ledger::compute_neuron_staking_subaccount_bytes;
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_nns_constants::ROOT_CANISTER_ID;
use ic_nns_governance::{
    init::TEST_NEURON_1_ID,
    pb::v1::{manage_neuron::NeuronIdOrSubaccount, proposal::Action, Proposal},
};
use std::{
    collections::HashSet,
    fmt::{Debug, Display, Formatter},
    fs::{write, OpenOptions},
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
}

pub fn exec(args: ProposeArgs) {
    let ProposeArgs {
        network,
        init_config_file,
        neuron_id,
        neuron_memo,
        save_to,
        test_neuron_proposer,
    } = args;

    // Step 0: Load configuration
    let proposal = load_configuration_and_validate_or_exit(&network, &init_config_file);

    // Step 1: Ensure the save-to file exists and is writeable if specified.
    // We do this check without writing the file to ensure the best chance of successfully
    // saving the data to a file after the Proposal is submitted.
    if let Some(save_to) = &save_to {
        if let Err(err) = ensure_file_exists_and_is_writeable(save_to.as_path()) {
            eprintln!("{}", err);
            std::process::exit(1);
        }
    }

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
        if let Err(err) = use_test_neuron_1_owner_identity(&checkpoint) {
            eprintln!(
                "{}\n\
                 \n\
                 Failed to (import and) use test-neuron-1-owner dfx identity.",
                err,
            );
            std::process::exit(1);
        }
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
                println!("Message from NNS governance: {:?}", message);
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

            if let Some(save_to) = &save_to {
                if let Err(err) = save_proposal_id_to_file(save_to.as_path(), &proposal_id) {
                    eprintln!("{}", err);
                    std::process::exit(1);
                };
            }
        }
        err => {
            println!("{:?}", err);
            println!();
            println!("💔 Something went wrong. Look up slightly for diagnostics.");
            println!("Perhaps, share the above error with the community at");
            println!("https://forum.dfinity.org/c/tokenization");
            std::process::exit(1)
        }
    };
}

fn load_configuration_and_validate_or_exit(
    network: &str,
    configuration_file_path: &PathBuf,
) -> Proposal {
    // Read the file.
    let init_config_file = std::fs::read_to_string(configuration_file_path).unwrap_or_else(|err| {
        let current_dir = std::env::current_dir().expect("cannot read env::current_dir");
        eprintln!(
            "Unable to read the SNS configuration file {:?}:\n{}",
            current_dir.join(configuration_file_path),
            err,
        );
        std::process::exit(1);
    });

    // Parse its contents.
    let init_config_file = serde_yaml::from_str::<
        crate::init_config_file::friendly::SnsConfigurationFile,
    >(&init_config_file)
    .unwrap_or_else(|err| {
        eprintln!(
            "Unable to parse the SNS configuration file ({:?}):\n{}",
            init_config_file, err,
        );
        std::process::exit(1);
    });
    let base_path = match configuration_file_path.parent() {
        Some(ok) => ok,
        None => {
            // This shouldn't happen since we were already able to read from
            // configuration_file_path.
            eprintln!(
                "Configuration file path ({:?}) has no parent.",
                configuration_file_path,
            );
            std::process::exit(1);
        }
    };
    let proposal = init_config_file
        .try_convert_to_nns_proposal(base_path)
        .unwrap_or_else(|err| {
            eprintln!(
                "Unable to parse the SNS configuration file. err = {:?}.\n\
                 init_config_file:\n{:#?}",
                err, init_config_file,
            );
            std::process::exit(1);
        });

    // Validate that NNS root is one of the controllers of all dapp canisters,
    // as listed in the configuration file.
    let canister_ids = match &proposal.action {
        Some(Action::CreateServiceNervousSystem(csns)) => csns
            .dapp_canisters
            .iter()
            .map(|canister| {
                let canister_id: PrincipalId = canister.id.unwrap_or_else(|| {
                    eprintln!(
                        "Internal error: Canister.id was found to be None while \
                        validating the CreateServiceNervousSystem.dapp_canisters \
                        field.",
                    );
                    std::process::exit(1);
                });

                CanisterId::try_from(canister_id).unwrap_or_else(|err| {
                    eprintln!(
                        "{}\n\
                     \n\
                     Internal error: Unable to Convert PrincipalId ({}) to CanisterId.",
                        err, canister_id,
                    );
                    std::process::exit(1);
                })
            })
            .collect::<Vec<_>>(),
        _ => {
            eprintln!(
                "Internal error: Somehow a proposal was made not of type CreateServiceNervousSystem",
            );
            std::process::exit(1);
        }
    };

    all_canisters_have_all_required_controllers(network, &canister_ids, &[ROOT_CANISTER_ID.get()])
        .unwrap_or_else(|err| {
            eprintln!("{}", err);
            std::process::exit(1);
        });

    // Return as the result.
    proposal
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
) -> Result<(), CanistersWithMissingControllers> {
    let required_controllers = HashSet::<_, std::collections::hash_map::RandomState>::from_iter(
        required_controllers.iter().cloned(),
    );
    // Identify canisters which are not controlled by the NNS root canister.
    let defective_canister_ids = canister_ids
        .iter()
        .filter(|canister_id| {
            let canister_id = PrincipalId::from(**canister_id);
            let controllers =
                HashSet::from_iter(fetch_canister_controllers_or_exit(network, canister_id));
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
    Err(CanistersWithMissingControllers {
        inspected_canister_count,
        defective_canister_ids,
    })
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum SaveToErrors {
    FileOpenFailed(PathBuf, String),
    FileWriteFailed(PathBuf, String),
    InvalidData(String),
}

impl Display for SaveToErrors {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let error_string = match self {
            SaveToErrors::FileOpenFailed(path_buf, reason) => {
                format!(
                    "could not open file for writing {:?} due to {}",
                    path_buf, reason
                )
            }
            SaveToErrors::FileWriteFailed(path_buf, reason) => {
                format!("could not write to file {:?} due to {}", path_buf, reason)
            }
            SaveToErrors::InvalidData(reason) => {
                format!("could not format data to JSON scheme due to {}", reason)
            }
        };

        write!(
            f,
            "Unable to save ProposalId to file because {}. \
            The proposal may or may not have been submitted",
            error_string
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
            ))
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
