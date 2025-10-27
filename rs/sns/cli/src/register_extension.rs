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
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_management_canister_types_private::BoundedVec;
use ic_nervous_system_agent::{
    CallCanisters, Request, management_canister,
    sns::{self, Sns, governance::SubmittedProposal, root::SnsCanisters},
};
use ic_nns_constants::CYCLES_LEDGER_CANISTER_ID;
use ic_sns_governance_api::{
    pb::v1::{
        ChunkedCanisterWasm, ExtensionInit, PreciseValue, Proposal, ProposalId, RegisterExtension,
        proposal::Action,
    },
    precise_value::parse_precise_value,
};
use ic_wasm::{metadata, utils::parse_wasm};
use serde::Deserialize;
use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    str::FromStr,
};
use thiserror::Error;

const RAW_WASM_HEADER: [u8; 4] = [0, 0x61, 0x73, 0x6d];
const GZIPPED_WASM_HEADER: [u8; 3] = [0x1f, 0x8b, 0x08];

// TODO: Compute more precisely the cycles amount needed for the store canister.
// The cycle fee for create request is 0.1T cycles.
pub const CANISTER_CREATE_FEE: u128 = 100_000_000_000_u128;

pub const EXTENSION_CANISTER_INITIAL_CYCLES_BALANCE: u128 = 30_000_000_000_000_u128; // 30T

#[derive(Debug, Parser)]
pub struct RegisterExtensionArgs {
    /// SNS neuron ID (subaccount) to be used for proposing the upgrade.
    ///
    /// If not specified, the proposal payload will be printed at the end.
    #[clap(long)]
    pub sns_neuron_id: Option<ParsedSnsNeuron>,

    /// The Root canister ID of the SNS to which the extension is being registered.
    #[clap(long)]
    pub sns_root_canister_id: CanisterId,

    /// The ID of the subnet on which the extension canister will be created.
    ///
    /// Some extensions may require a specific subnet to operate correctly.
    ///
    /// The default is the fiduciary subnet.
    #[clap(long)]
    pub subnet_id: Option<PrincipalId>,

    /// Path to a ICP WASM module file (may be gzipped).
    #[clap(long)]
    pub wasm_path: PathBuf,

    /// URL (starting with https://) of a web page with a public announcement of this upgrade.
    #[clap(long)]
    pub proposal_url: url::Url,

    /// Human-readable text explaining why this upgrade is being done (may be markdown).
    #[clap(long)]
    pub summary: String,

    /// JSON-encoded initialization arguments for the extension.
    #[clap(long, value_parser = parse_precise_value)]
    pub extension_init: Option<PreciseValue>,

    /// The name of the dfx network to use.
    /// TODO[NNS1-4150]: This is currently used because of bad handling
    /// of the input arguments in the dfx. Once that is fixed,
    /// this should be removed.
    #[clap(long)]
    pub network: Option<String>,
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
pub async fn create_extension_canister<C: CallCanisters>(
    agent: &C,
    subnet_id: Option<PrincipalId>,
    controllers: Vec<PrincipalId>,
    cycles_amount: u128,
    name: &str,
) -> Result<CanisterId> {
    let subnet = if let Some(subnet) = subnet_id {
        subnet
    } else {
        PrincipalId::from_str("pzp6e-ekpqk-3c5x7-2h6so-njoeq-mt45d-h3h6c-q3mxf-vpeq5-fk5o7-yae")
            .unwrap()
    };

    let subnet = SubnetId::new(subnet);

    let subnet_selection = Some(SubnetSelection::Subnet { subnet });

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

pub struct RegisterExtensionInfo {
    pub wasm_module_hash: Vec<u8>,
    pub proposal_id: Option<ProposalId>,
    pub extension_canister_id: CanisterId,
}

pub async fn find_sns<C: CallCanisters>(
    agent: &C,
    sns_root_canister_id: CanisterId,
) -> Result<Option<Sns>, UpgradeSnsControlledCanisterError<C::Error>> {
    let canister_id = sns_root_canister_id.get();

    let root_canister = sns::root::RootCanister { canister_id };

    let response = root_canister.list_sns_canisters(agent).await?;
    let SnsCanisters {
        sns,
        dapps: _,
        extensions: _,
    } = SnsCanisters::try_from(response).map_err(UpgradeSnsControlledCanisterError::Client)?;

    Ok(Some(sns))
}

pub async fn exec<C: CallCanisters>(
    args: RegisterExtensionArgs,
    agent: &C,
) -> Result<RegisterExtensionInfo, UpgradeSnsControlledCanisterError<C::Error>> {
    let RegisterExtensionArgs {
        sns_neuron_id,
        sns_root_canister_id,
        subnet_id,
        wasm_path,
        proposal_url,
        summary,
        extension_init,
        network: _,
    } = args;

    let caller_principal = PrincipalId(agent.caller()?);

    print!("Checking that we have a viable Wasm ... ");
    std::io::stdout().flush().unwrap();
    let wasm = Wasm::try_from(wasm_path).unwrap();
    println!("✔️");

    let sns = find_sns(agent, sns_root_canister_id).await?.unwrap();

    print!("Creating the extension canister ... ");
    std::io::stdout().flush().unwrap();
    let extension_canister_controllers = vec![
        caller_principal,
        sns.root.canister_id,
        sns.governance.canister_id,
    ];
    let cycles_amount = EXTENSION_CANISTER_INITIAL_CYCLES_BALANCE;
    let extension_canister_id = create_extension_canister(
        agent,
        subnet_id,
        extension_canister_controllers,
        cycles_amount,
        "my-extension-canister",
    )
    .await
    .unwrap();
    println!("✔️");

    print!("Uploading the chunks into the store canister ... ");
    std::io::stdout().flush().unwrap();
    let chunk_hashes_list = management_canister::upload_wasm(
        agent,
        extension_canister_id,
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

    print!("Forming SNS proposal to register the extension canister ... ");
    std::io::stdout().flush().unwrap();
    let sns_governance = sns::governance::GovernanceCanister {
        canister_id: sns.governance.canister_id,
    };

    let proposal = Proposal {
        title: format!(
            "Register SNS extension canister {}",
            extension_canister_id.get()
        ),
        summary,
        url: proposal_url.to_string(),
        action: Some(Action::RegisterExtension(RegisterExtension {
            chunked_canister_wasm: Some(ChunkedCanisterWasm {
                wasm_module_hash: wasm.module_hash().to_vec(),
                store_canister_id: Some(extension_canister_id.get()),
                chunk_hashes_list,
            }),
            extension_init: Some(ExtensionInit {
                value: extension_init,
            }),
        })),
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
            "Successfully proposed to register an SNS extension, see details here:\n\
                {proposal_url}",
        );

        Some(proposal_id)
    } else {
        println!("✔️");
        let proposal_str = printing::pretty(&proposal).unwrap();
        println!("{proposal_str}");

        None
    };

    Ok(RegisterExtensionInfo {
        wasm_module_hash: wasm.module_hash().to_vec(),
        proposal_id,
        extension_canister_id,
    })
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
