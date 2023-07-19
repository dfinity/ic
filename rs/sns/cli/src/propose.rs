use crate::{
    fetch_canister_controllers_or_exit, get_identity, use_test_neuron_1_owner_identity,
    MakeProposalResponse, NnsGovernanceCanister, SaveOriginalDfxIdentityAndRestoreOnExit,
};
use clap::Parser;
use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_common::ledger::compute_neuron_staking_subaccount_bytes;
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_nns_constants::ROOT_CANISTER_ID;
use ic_nns_governance::pb::v1::{manage_neuron::NeuronIdOrSubaccount, CreateServiceNervousSystem};
use ic_nns_test_utils::ids::TEST_NEURON_1_ID;
use std::{
    collections::HashSet,
    fmt::{Debug, Display},
    path::PathBuf,
};

#[derive(Debug, Parser)]
pub struct ProposeArgs {
    /// The network to deploy to. This can be "local", "ic", or the URL of an IC
    /// network.
    #[structopt(default_value = "local", long)]
    network: String,

    /// Path to a configuration file specifying the SNS to be created.
    #[clap(parse(from_os_str), default_value = "sns_init.yaml")]
    pub init_config_file: PathBuf,

    /// The neuron with which to make the proposal. The current dfx identity
    /// must be able to operate this neuron. If not specified, it will be
    /// assumed that the current dfx identity has a neuron with memo == 0.
    /// --neuron_memo is an alternative to this.
    #[clap(long)]
    pub neuron_id: Option<u64>,

    /// This is an alternative to --neuron_id for specifying which neuron to
    /// make the proposal with. This is used in conjunction with the current
    /// principal to calculate the subaccount (belonging to the NNS governance
    /// canister) that holds the ICP that backs the proposing neuron.
    #[clap(long)]
    pub neuron_memo: Option<u64>,

    /// This is a "secret menu" item. It is (yet) another alternative to
    /// --neuron_id (and --neuron_memo). As the name implies, this is only
    /// useful when running against a local instance of NNS (when deployed as
    /// described in the sns-testing Github repo). In addition to specifying
    /// which neuron to propose with, this also controls the principal that
    /// sends the request.
    #[clap(long)]
    pub test_neuron_proposer: bool,
}

pub fn exec(args: ProposeArgs) {
    let ProposeArgs {
        network,
        init_config_file,
        neuron_id,
        neuron_memo,
        test_neuron_proposer,
    } = args;

    // Step 0: Validate arguments.
    let neuron_specifier_count = [
        neuron_id.is_some(),
        neuron_memo.is_some(),
        test_neuron_proposer,
    ]
    .into_iter()
    .filter(|count_this| *count_this)
    .count();
    if neuron_specifier_count > 1 {
        eprintln!(
            "--neuron-id, --neuron-memo, and --test-neuron-proposer are \
             mutually exclusive (yet more than one of them was used)."
        );
        std::process::exit(1);
    }

    // Step 1: Load configuration
    let proposal =
        load_configuration_and_validate_or_exit(&network, &init_config_file).upgrade_to_proposal();

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
            proposal_id: Some(ProposalId { id }),
        }) => {
            println!("🚀 Success!");
            if network == "ic" {
                println!("View the proposal here:");
                println!("https://dashboard.internetcomputer.org/proposal/{}", id);
            } else {
                // TODO: Support other networks.
                println!("Proposal ID: {}", id);
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
) -> CreateServiceNervousSystem {
    // Read the file.
    let init_config_file = std::fs::read_to_string(configuration_file_path).unwrap_or_else(|err| {
        eprintln!(
            "Unable to read the SNS configuration file ({:?}):\n{}",
            configuration_file_path, err,
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
    let create_service_nervous_system = init_config_file
        .try_convert_to_create_service_nervous_system(base_path)
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
    let canister_ids = &create_service_nervous_system
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
        .collect::<Vec<_>>();
    all_canisters_have_all_required_controllers(
        network,
        canister_ids,
        &[PrincipalId::try_from(ROOT_CANISTER_ID)
            .expect("Internal error: could not convert ROOT_CANISTER_ID to PrincipalId.")],
    )
    .unwrap_or_else(|err| {
        eprintln!("{}", err);
        std::process::exit(1);
    });

    // Return as the result.
    create_service_nervous_system
}

struct CanistersWithMissingControllers {
    inspected_canister_count: usize,
    defective_canister_ids: Vec<CanisterId>,
}

impl Display for CanistersWithMissingControllers {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
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
            let controllers = HashSet::from_iter(
                fetch_canister_controllers_or_exit(network, canister_id).into_iter(),
            );
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
