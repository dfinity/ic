use crate::neuron_id_to_candid_subaccount::ParsedSnsNeuron;
use anyhow::Result;
use candid::{CandidType, Encode, Nat, Principal};
use candid_utils::{
    printing,
    validation::{encode_upgrade_args, encode_upgrade_args_without_service},
};
use clap::Parser;
use core::convert::From;
use cycles_minting_canister::{CanisterSettingsArgs, CreateCanister, SubnetSelection};
use ic_base_types::{CanisterId, PrincipalId};
use ic_management_canister_types_private::{BoundedVec, CanisterInstallMode};
use ic_nervous_system_agent::{
    CallCanisters, CanisterInfo, Request,
    management_canister::{self, delete_canister, stop_canister},
    nns,
    sns::{self, Sns, governance::SubmittedProposal, root::SnsCanisters},
};
use ic_nns_constants::CYCLES_LEDGER_CANISTER_ID;
use ic_sns_governance_api::pb::v1::{
    ChunkedCanisterWasm, Proposal, ProposalData, ProposalId, UpgradeSnsControlledCanister,
    get_proposal_response,
    proposal::{self, Action},
};
use ic_wasm::{metadata, utils::parse_wasm};
use itertools::{Either, Itertools};
use serde::Deserialize;
use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use thiserror::Error;

const RAW_WASM_HEADER: [u8; 4] = [0, 0x61, 0x73, 0x6d];
const GZIPPED_WASM_HEADER: [u8; 3] = [0x1f, 0x8b, 0x08];

// TODO: Compute more precisely the cycles amount needed for the store canister.
// The cycle fee for create request is 0.1T cycles.
pub const CANISTER_CREATE_FEE: u128 = 100_000_000_000_u128;

pub const STORE_CANISTER_INITIAL_CYCLES_BALANCE: u128 = 1_000_000_000_000_u128; // 1T

/// The arguments used to configure the upgrade_sns_controlled_canister command.
#[derive(Debug, Parser)]
pub struct UpgradeSnsControlledCanisterArgs {
    /// SNS neuron ID (subaccount) to be used for proposing the upgrade.
    ///
    /// If not specified, the proposal payload will be printed at the end.
    #[clap(long)]
    pub sns_neuron_id: Option<ParsedSnsNeuron>,

    /// ID of the target canister to be upgraded.
    #[clap(long)]
    pub target_canister_id: CanisterId,

    /// Path to a ICP WASM module file (may be gzipped).
    #[clap(long)]
    pub wasm_path: PathBuf,

    /// Upgrade argument for the Candid service.
    #[clap(long)]
    pub candid_arg: Option<String>,

    /// URL (starting with https://) of a web page with a public announcement of this upgrade.
    #[clap(long)]
    pub proposal_url: url::Url,

    /// Human-readable text explaining why this upgrade is being done (may be markdown).
    #[clap(long)]
    pub summary: String,
}

/// The arguments used to configure the refund_after_sns_controlled_canister_upgrade command.
#[derive(Debug, Parser)]
pub struct RefundAfterSnsControlledCanisterUpgradeArgs {
    /// ID of the target canister that was to be upgraded using upgrade-sns-controlled-canister.
    #[clap(long)]
    pub target_canister_id: CanisterId,

    /// ID of the proposal created by upgrade-sns-controlled-canister. Must be
    #[clap(long)]
    pub proposal_id: u64,
}

pub struct Wasm {
    path: PathBuf,
    bytes: Vec<u8>,
    module_hash: [u8; 32],
}

impl Wasm {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn module_hash(&self) -> [u8; 32] {
        self.module_hash
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl TryFrom<PathBuf> for Wasm {
    type Error = String;

    fn try_from(path: PathBuf) -> Result<Self, Self::Error> {
        let mut file = match File::open(&path) {
            Err(err) => {
                return Err(format!(
                    "Cannot open Wasm file under {}: {}",
                    path.display(),
                    err,
                ));
            }
            Ok(file) => file,
        };

        // Create a buffer to store the file's content
        let mut bytes = Vec::new();

        // Read the file's content into the buffer
        if let Err(err) = file.read_to_end(&mut bytes) {
            return Err(format!("Cannot read Wasm file {}: {}", path.display(), err,));
        }

        // Smoke test: Is this a ICP Wasm?
        if !bytes.starts_with(&RAW_WASM_HEADER) && !bytes.starts_with(&GZIPPED_WASM_HEADER) {
            return Err("The file does not look like a valid ICP Wasm module.".to_string());
        }

        let module_hash = ic_crypto_sha2::Sha256::hash(&bytes);

        Ok(Self {
            path,
            bytes,
            module_hash,
        })
    }
}

/// Attempts to validate `args` against the Candid service defined in `wasm`.
///
/// If `args` is Some, returns the byte encoding of `args` in the Ok result.
///
/// This function prints warnings into STDERR.
pub fn validate_candid_arg_for_wasm(wasm: &Wasm, args: Option<String>) -> Result<Option<Vec<u8>>> {
    let wasm_module = parse_wasm(wasm.bytes(), false)?;

    print!("Checking that the Wasm metadata contains Candid service definition ... ");
    std::io::stdout().flush().unwrap();

    let candid_service = metadata::list_metadata(&wasm_module)
        .into_iter()
        .find_map(|section| {
            let mut section = section.split(' ').collect::<Vec<&str>>();
            if section.is_empty() {
                // This cannot practically happen, as it would imply that all characters of
                // the section are whitespaces.
                return None;
            }

            // Consume this section's visibility specification, e.g. "icp:public" or "icp:private".
            let _visibility = section.remove(0).to_string();

            // The conjunction of the remaining parts are the section's name.
            let name = section.join(" ");

            if name != "candid:service" {
                return None;
            }

            // Read the actual contents of this section.
            metadata::get_metadata(&wasm_module, &name).map(|contents| contents.to_vec())
        })
        .map(|bytes: Vec<u8>| std::str::from_utf8(&bytes).unwrap().to_string());

    let canister_arg = if let Some(candid_service) = candid_service {
        println!("✔️");

        print!("Validating the upgrade arg against the Candid service definition ... ");
        std::io::stdout().flush().unwrap();
        let candid_arg_bytes = encode_upgrade_args(candid_service, args).unwrap();
        println!("✔️");

        candid_arg_bytes
    } else {
        eprintln!(
            "\n\
            ⚠️ Skipping upgrade argument validation: Wasm file has no Candid definition! \n\
            ⚠️ Please consider adding it as follows:\n\
            cargo install ic-wasm\n\
            ic-wasm -o augmented-{} {} metadata -v public candid:service -f service.did",
            wasm.path().display(),
            wasm.path().display(),
        );

        // Proceed with whatever argument the user has specified without validation.
        args.map(|args| encode_upgrade_args_without_service(args).unwrap())
    };

    std::io::stdout().flush().unwrap();
    std::io::stderr().flush().unwrap();

    Ok(canister_arg)
}

/// Attempts to create an empty canister on the same subnet as `next_to`.
///
/// Returns the ID of the newly created canister in the Ok result.
pub async fn create_canister_next_to<C: CallCanisters>(
    agent: &C,
    next_to: CanisterId,
    controllers: Vec<PrincipalId>,
    cycles_amount: u128,
    name: &str,
) -> Result<CanisterId> {
    // This is expected to be `None` if we're running against a local replica.
    let subnet_selection = nns::registry::get_subnet_for_canister(agent, next_to)
        .await
        .map(|subnet| SubnetSelection::Subnet { subnet })
        .ok();

    let canister_id = cycles_ledger_create_canister(
        agent,
        cycles_amount,
        subnet_selection,
        Some(CanisterSettingsArgs {
            controllers: Some(BoundedVec::new(controllers)),
            ..Default::default()
        }),
    )
    .await
    .map_err(|err| {
        if let CreateCanisterError::InsufficientFunds { balance } = err {
            let err = format!(
                "Requested creating the {name} canister with {cycles_amount} cycles, but the caller identity has \
                 only {balance} cycles on the cycles ledger. Please buy more cycles using \
                 `dfx cycles convert --amount AMOUNT --network NETWORK` and try again.",
            );
            anyhow::anyhow!(err)
        } else {
            anyhow::anyhow!(format!("{:?}", err))
        }
    })?
    .canister_id;

    CanisterId::try_from_principal_id(canister_id).map_err(|err| anyhow::anyhow!(err))
}

#[derive(Debug, Error)]
pub enum UpgradeSnsControlledCanisterError<AgentError> {
    #[error("agent interaction failed: {0}")]
    Agent(AgentError),
    #[error("observed bad state: {0}")]
    Client(String),
}

impl<E: std::error::Error> From<E> for UpgradeSnsControlledCanisterError<E> {
    fn from(err: E) -> Self {
        Self::Agent(err)
    }
}

pub struct UpgradeSnsControlledCanisterInfo {
    pub wasm_module_hash: Vec<u8>,
    pub proposal_id: Option<ProposalId>,
}

pub async fn find_sns<C: CallCanisters>(
    agent: &C,
    caller_principal: PrincipalId,
    target_canister_id: CanisterId,
    target_controllers: BTreeSet<PrincipalId>,
) -> Result<Option<Sns>, UpgradeSnsControlledCanisterError<C::Error>> {
    let (user_controllers, canister_controllers): (Vec<_>, Vec<_>) =
        target_controllers.into_iter().partition_map(|controller| {
            if controller.is_self_authenticating() {
                Either::Left(controller)
            } else {
                Either::Right(controller)
            }
        });

    if user_controllers.contains(&caller_principal) {
        println!(
            "\n\
                ⚠️ the target is controlled by the caller, which means it is not decentralized.\n\
                ⚠️ Proceed upgrading it directly."
        );

        Ok(None)
    } else {
        assert!(
            !canister_controllers.is_empty(),
            "The target canister is not controlled by an SNS."
        );

        assert_eq!(
            canister_controllers.len(),
            1,
            "The target canister has more than one canister controller!"
        );

        let canister_id = *canister_controllers.first().unwrap();

        // TODO: Check that this is indeed an SNS canister controlling the target.
        //
        // This is expected to be `None` if we're running against a local replica.
        // let root_subnet = nns::registry::get_subnet_for_canister(agent, canister_id)
        //     .await
        //     .ok();
        // let sns_subnets = sns_w.list_sns_subnets().await.unwrap();
        // assert!(
        //     sns_subnets.contains(&root_subnet),
        //     "Target canister is not controlled by an SNS!",
        // );

        let root_canister = sns::root::RootCanister { canister_id };

        let response = root_canister.list_sns_canisters(agent).await?;
        let SnsCanisters {
            sns,
            dapps,
            extensions,
        } = response
            .try_into()
            .map_err(UpgradeSnsControlledCanisterError::Client)?;

        let mut sns_controlled_canisters = dapps;
        sns_controlled_canisters.extend(extensions.iter());

        // Check that the target is indeed controlled by this SNS.
        if !BTreeSet::from_iter(&sns_controlled_canisters[..]).contains(&target_canister_id.get()) {
            return Err(UpgradeSnsControlledCanisterError::Client(format!(
                "{} is not one of the canisters controlled by the SNS with Root canister {}",
                target_canister_id.get(),
                root_canister.canister_id,
            )));
        }

        Ok(Some(sns))
    }
}

pub async fn exec<C: CallCanisters>(
    args: UpgradeSnsControlledCanisterArgs,
    agent: &C,
) -> Result<UpgradeSnsControlledCanisterInfo, UpgradeSnsControlledCanisterError<C::Error>> {
    let UpgradeSnsControlledCanisterArgs {
        sns_neuron_id,
        target_canister_id,
        wasm_path,
        candid_arg,
        proposal_url,
        summary,
    } = args;

    let caller_principal = PrincipalId(agent.caller()?);

    print!("Getting target canister info ... ");
    std::io::stdout().flush().unwrap();
    let CanisterInfo {
        module_hash: Some(current_module_hash),
        controllers: target_controllers,
    } = agent.canister_info(target_canister_id).await?
    else {
        return Err(UpgradeSnsControlledCanisterError::Client(format!(
            "Before upgrading, please install the target, e.g.: {}",
            suggested_install_command(&wasm_path, &candid_arg)
        )));
    };
    println!("✔️");

    let target_controllers = target_controllers
        .into_iter()
        .map(PrincipalId)
        .collect::<BTreeSet<_>>();

    print!("Finding the SNS controlling this target canister ... ");
    std::io::stdout().flush().unwrap();
    let sns = find_sns(
        agent,
        caller_principal,
        target_canister_id,
        target_controllers,
    )
    .await?;
    println!("✔️");

    print!("Checking that we have a viable Wasm for this upgrade ... ");
    std::io::stdout().flush().unwrap();
    let wasm = Wasm::try_from(wasm_path).unwrap();
    assert_ne!(
        wasm.module_hash().to_vec(),
        current_module_hash,
        "Target canister is already running Wasm module with SHA256 {}. Nothing to do.",
        format_full_hash(&wasm.module_hash()),
    );
    println!("✔️");

    // Save `candid_arg` for reference, in case we need it for error reporting later on.
    let upgrade_args = candid_arg.clone();

    let canister_upgrade_arg = validate_candid_arg_for_wasm(&wasm, upgrade_args).unwrap();

    print!("Creating a store canister on the same subnet as the target ... ");
    std::io::stdout().flush().unwrap();
    let store_canister_controllers = if let Some(sns) = &sns {
        vec![
            caller_principal,
            sns.root.canister_id,
            sns.governance.canister_id,
        ]
    } else {
        vec![caller_principal]
    };
    let cycles_amount = STORE_CANISTER_INITIAL_CYCLES_BALANCE;
    let store_canister_id = create_canister_next_to(
        agent,
        target_canister_id,
        store_canister_controllers,
        cycles_amount,
        "store",
    )
    .await
    .unwrap();
    println!("✔️");

    print!("Uploading the chunks into the store canister ... ");
    std::io::stdout().flush().unwrap();
    let chunk_hashes_list = management_canister::upload_wasm(
        agent,
        store_canister_id,
        wasm.bytes().to_vec(),
        Some(
            |chunk_index: usize, num_chunks: usize, chunk_hash: &Vec<u8>| {
                print!(
                    "\n  Uploaded chunk {chunk_index}/{num_chunks}: {}",
                    format_full_hash(chunk_hash)
                );
                std::io::stdout().flush().unwrap();
            },
        ),
    )
    .await?
    .into_iter()
    .map(|chunk_hash| chunk_hash.hash)
    .collect();
    println!("✔️");

    let Some(sns) = &sns else {
        unimplemented!(
            "Direct canister upgrades are not implemented yet. Please use DFX:\n{}",
            suggested_install_command(wasm.path(), &candid_arg)
        );
    };

    print!("Forming SNS proposal to upgrade target canister ... ");
    std::io::stdout().flush().unwrap();
    let sns_governance = sns::governance::GovernanceCanister {
        canister_id: sns.governance.canister_id,
    };
    let proposal = Proposal {
        title: format!(
            "Upgrade SNS-controlled canister {}",
            target_canister_id.get()
        ),
        summary,
        url: proposal_url.to_string(),
        action: Some(Action::UpgradeSnsControlledCanister(
            UpgradeSnsControlledCanister {
                canister_id: Some(target_canister_id.get()),
                new_canister_wasm: vec![],
                canister_upgrade_arg,
                mode: Some(CanisterInstallMode::Upgrade as i32),
                chunked_canister_wasm: Some(ChunkedCanisterWasm {
                    wasm_module_hash: wasm.module_hash().to_vec(),
                    store_canister_id: Some(store_canister_id.get()),
                    chunk_hashes_list,
                }),
            },
        )),
    };

    let proposal_id = if let Some(sns_neuron_id) = sns_neuron_id {
        let manage_neuron_response = sns_governance
            .submit_proposal(agent, sns_neuron_id.0, proposal)
            .await?;
        let SubmittedProposal { proposal_id } = SubmittedProposal::try_from(manage_neuron_response)
            .map_err(|err| UpgradeSnsControlledCanisterError::Client(err.to_string()))?;
        println!("✔️");

        let proposal_url = format!(
            "https://nns.ic0.app/proposal/?u={}&proposal={}",
            sns.root.canister_id, proposal_id.id,
        );
        println!(
            "Successfully proposed to upgrade SNS-controlled canister, see details here:\n\
                {proposal_url}",
        );

        Some(proposal_id)
    } else {
        println!("✔️");
        let proposal_str = printing::pretty(&proposal).unwrap();
        println!("{proposal_str}");

        None
    };

    Ok(UpgradeSnsControlledCanisterInfo {
        wasm_module_hash: wasm.module_hash().to_vec(),
        proposal_id,
    })
}

pub async fn refund<C: CallCanisters>(
    args: RefundAfterSnsControlledCanisterUpgradeArgs,
    agent: &C,
) -> Result<(), UpgradeSnsControlledCanisterError<C::Error>> {
    let RefundAfterSnsControlledCanisterUpgradeArgs {
        target_canister_id,
        proposal_id,
    } = args;

    let proposal_id = ProposalId { id: proposal_id };

    let caller_principal = PrincipalId(agent.caller()?);

    print!("Getting target canister info ... ");
    std::io::stdout().flush().unwrap();
    let CanisterInfo {
        controllers: target_controllers,
        module_hash: _,
    } = agent
        .canister_info(target_canister_id)
        .await
        .map_err(|err| {
            UpgradeSnsControlledCanisterError::Client(format!(
                "Cannot refund cycles, target canister {} does not seem to be installed: {}",
                target_canister_id.get(),
                err
            ))
        })?;
    println!("✔️");

    let target_controllers = target_controllers
        .into_iter()
        .map(PrincipalId)
        .collect::<BTreeSet<_>>();

    print!("Finding the SNS controlling this target canister ... ");
    std::io::stdout().flush().unwrap();
    let sns = find_sns(
        agent,
        caller_principal,
        target_canister_id,
        target_controllers,
    )
    .await?;
    let sns = match sns {
        Some(sns) => sns,
        None => {
            return Err(UpgradeSnsControlledCanisterError::Client(format!(
                "Cannot find SNS controlling target canister {}",
                target_canister_id.get()
            )));
        }
    };
    println!("✔️");

    print!("Fetching the store canister ID ... ");
    std::io::stdout().flush().unwrap();
    let sns_governance = sns::governance::GovernanceCanister {
        canister_id: sns.governance.canister_id,
    };
    let get_proposal_result = sns_governance
        .get_proposal(agent, proposal_id)
        .await
        .map_err(UpgradeSnsControlledCanisterError::Agent)?
        .result
        .ok_or("Missing GetProposalResponse.result")
        .map_err(|err| UpgradeSnsControlledCanisterError::Client(err.to_string()))?;

    let proposal = match get_proposal_result {
        get_proposal_response::Result::Error(err) => {
            return Err(UpgradeSnsControlledCanisterError::Client(format!(
                "{err:?}"
            )));
        }
        get_proposal_response::Result::Proposal(ProposalData {
            proposal,
            executed_timestamp_seconds,
            failed_timestamp_seconds,
            ..
        }) if executed_timestamp_seconds > 0 || failed_timestamp_seconds > 0 => proposal,
        get_proposal_response::Result::Proposal(_) => {
            return Err(UpgradeSnsControlledCanisterError::Client(format!(
                "Proposal {} is still live; please repeat this command after it executes or fails.",
                proposal_id.id,
            )));
        }
    };

    let store_canister_id = match proposal {
        Some(Proposal {
            action:
                Some(proposal::Action::UpgradeSnsControlledCanister(UpgradeSnsControlledCanister {
                    chunked_canister_wasm:
                        Some(ChunkedCanisterWasm {
                            store_canister_id: Some(store_canister_id),
                            ..
                        }),
                    ..
                })),
            ..
        }) => store_canister_id,
        _ => {
            return Err(UpgradeSnsControlledCanisterError::Client(format!(
                "Proposal {} is invalid or does not correspond to an SNS-controlled canister upgrade
                with chunked Wasm.",
                proposal_id.id,
            )));
        }
    };
    println!("✔️");

    // TODO: Implement the actual reimbursement.

    print!("Deleting the store canister {store_canister_id} ... ");
    std::io::stdout().flush().unwrap();
    stop_canister(
        agent,
        CanisterId::unchecked_from_principal(store_canister_id),
    )
    .await
    .map_err(UpgradeSnsControlledCanisterError::Agent)?;
    delete_canister(
        agent,
        CanisterId::unchecked_from_principal(store_canister_id),
    )
    .await
    .map_err(UpgradeSnsControlledCanisterError::Agent)?;
    println!("✔️");

    Ok(())
}

pub type BlockIndex = Nat;

#[derive(CandidType, Deserialize, Debug, Clone)]
pub enum CreateCanisterError {
    InsufficientFunds {
        balance: Nat,
    },
    TooOld,
    CreatedInFuture {
        ledger_time: u64,
    },
    TemporarilyUnavailable,
    Duplicate {
        duplicate_of: Nat,
        // If the original transaction created a canister then this field will contain the canister id.
        canister_id: Option<Principal>,
    },
    FailedToCreate {
        fee_block: Option<BlockIndex>,
        refund_block: Option<BlockIndex>,
        error: String,
    },
    GenericError {
        message: String,
        error_code: Nat,
    },
}

// ```candid
// type CreateCanisterArgs = record {
//     from_subaccount : opt vec nat8;
//     created_at_time : opt nat64;
//     amount : nat;
//     creation_args : opt CmcCreateCanisterArgs;
// };
// ```
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct CreateCanisterArgs {
    from_subaccount: Option<Vec<u8>>,
    created_at_time: Option<u64>,
    amount: Nat,
    creation_args: Option<CreateCanister>,
}

// ```candid
// type CreateCanisterSuccess = record {
//     block_id : BlockIndex;
//     canister_id : principal;
// };
// ```
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct CreateCanisterSuccess {
    block_id: BlockIndex,
    canister_id: PrincipalId,
}

impl Request for CreateCanisterArgs {
    fn method(&self) -> &'static str {
        "create_canister"
    }

    fn update(&self) -> bool {
        true
    }

    fn payload(&self) -> std::result::Result<Vec<u8>, candid::Error> {
        Encode!(self)
    }

    type Response = Result<CreateCanisterSuccess, CreateCanisterError>;
}

pub async fn cycles_ledger_create_canister<C: CallCanisters>(
    agent: &C,
    cycles_amount: u128,
    subnet_selection: Option<SubnetSelection>,
    settings: Option<CanisterSettingsArgs>,
) -> Result<CreateCanisterSuccess, CreateCanisterError> {
    let request = CreateCanisterArgs {
        from_subaccount: None,
        created_at_time: None,
        amount: Nat::from(cycles_amount),
        creation_args: Some(CreateCanister {
            subnet_selection,
            settings,
            ..Default::default()
        }),
    };
    agent
        .call(CYCLES_LEDGER_CANISTER_ID, request)
        .await
        .expect("Cannot create canister")
}

fn format_full_hash(hash: &[u8]) -> String {
    hash.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn suggested_install_command(wasm_path_str: &Path, candid_arg: &Option<String>) -> String {
    let arg_suggestion = if let Some(candid_arg) = candid_arg {
        format!(" --argument '{candid_arg}'")
    } else {
        "".to_string()
    };
    format!(
        "dfx canister install --mode auto --wasm {} CANISTER_NAME{}",
        wasm_path_str.display(),
        arg_suggestion,
    )
}
