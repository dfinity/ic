use anyhow::{bail, Context, Result};
use candid::{CandidType, Deserialize, Encode, Principal};
use clap::Parser;
use cycles_minting_canister::{CanisterSettingsArgs, SubnetSelection};
use ic_agent::Agent;
use ic_base_types::{CanisterId, PrincipalId};
use ic_management_canister_types::BoundedVec;
use ic_nervous_system_agent::{nns, sns::root::RootCanister, CallCanisters, Request};
use ic_sns_governance::pb::v1::NeuronId;
use std::{collections::BTreeSet, fs::File, io::Read, path::PathBuf};

const RAW_WASM_HEADER: [u8; 4] = [0, 0x61, 0x73, 0x6d];
const GZIPPED_WASM_HEADER: [u8; 3] = [0x1f, 0x8b, 0x08];
const CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB

/// The arguments used to configure the upgrade_sns_controlled_canister command.
#[derive(Debug, Parser)]
pub struct UpgradeSnsControlledCanisterArgs {
    #[clap(long)]
    root_canister_id: CanisterId,

    #[clap(long)]
    sns_neuron_id: NeuronId,

    #[clap(long)]
    target_canister_id: CanisterId,

    #[clap(long)]
    wasm_path: PathBuf,

    #[clap(long)]
    candid_arg: Option<String>,
}

fn load_wasm(wasm_path: PathBuf) -> Result<Vec<u8>> {
    let mut file = File::open(&wasm_path).context("Cannot open file.")?;

    // Create a buffer to store the file's content
    let mut bytes = Vec::new();

    // Read the file's content into the buffer
    file.read_to_end(&mut bytes).context("Cannot read file.")?;

    // Smoke test: Is this a ICP Wasm?
    if bytes.len() < 4 || bytes[..4] != RAW_WASM_HEADER[..] && bytes[..3] != GZIPPED_WASM_HEADER[..]
    {
        bail!("The file does not look like a valid ICP Wasm module.");
    }

    Ok(bytes)
}

// ```candid
// type upload_chunk_args = record {
//     canister_id : principal;
//     chunk : blob;
// };
// ```
#[derive(CandidType, Deserialize, Debug, Clone)]
struct UploadChunkArgs {
    pub canister_id: Principal,
    pub chunk: Vec<u8>,
}

// ```candid
// type chunk_hash = record {
//   hash : blob;
// };
// ```
#[derive(CandidType, Deserialize, Debug, Clone)]
struct ChunkHash {
    pub hash: Vec<u8>,
}

// ```candid
// type upload_chunk_result = chunk_hash;
// ```
type UploadChunksResult = ChunkHash;

impl Request for UploadChunkArgs {
    fn method(&self) -> &'static str {
        "upload_chunk"
    }

    fn update(&self) -> bool {
        true
    }

    fn payload(&self) -> Vec<u8> {
        Encode!(self).unwrap()
    }

    type Response = UploadChunksResult;
}

async fn upload_chunk<C: CallCanisters>(
    agent: &C,
    store_canister_id: CanisterId,
    chunk: Vec<u8>,
) -> Result<ChunkHash, C::Error> {
    let response = agent
        .call(
            Principal::management_canister(),
            UploadChunkArgs {
                canister_id: store_canister_id.get().0,
                chunk,
            },
        )
        .await?;

    Ok(response)
}

// ```candid
// type stored_chunks_args = record {
//     canister_id : canister_id;
// };
// ```
#[derive(CandidType, Deserialize, Debug, Clone)]
struct StoredChunksArgs {
    pub canister_id: Principal,
}

// ```
// type chunk_hash = record {
//   hash : blob;
// };
// type stored_chunks_result = vec chunk_hash;
// ```
type StoredChunksResult = Vec<ChunkHash>;

impl Request for StoredChunksArgs {
    fn method(&self) -> &'static str {
        "stored_chunks"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Vec<u8> {
        Encode!(self).unwrap()
    }

    type Response = StoredChunksResult;
}

async fn stored_chunks<C: CallCanisters>(
    agent: &C,
    store_canister_id: CanisterId,
) -> Result<Vec<ChunkHash>, C::Error> {
    let response = agent
        .call(
            Principal::management_canister(),
            StoredChunksArgs {
                canister_id: store_canister_id.get().0,
            },
        )
        .await?;

    Ok(response)
}

fn format_full_hash(hash: &[u8]) -> String {
    hash.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

async fn upload_wasm_as_chunks(
    agent: &Agent,
    store_canister_id: CanisterId,
    wasm_bytes: Vec<u8>,
    num_chunks_expected: usize,
) -> Result<Vec<ChunkHash>> {
    let mut uploaded_chunk_hashes = Vec::new();

    for chunk in wasm_bytes.chunks(CHUNK_SIZE) {
        let uploaded_chunk_hash = upload_chunk(agent, store_canister_id, chunk.to_vec()).await?;

        uploaded_chunk_hashes.push(uploaded_chunk_hash);
    }

    // Smoke test
    {
        let stored_chunk_hashes = stored_chunks(agent, store_canister_id).await?;

        let stored_chunk_hashes = stored_chunk_hashes
            .into_iter()
            .map(|chunk_hash| format_full_hash(&chunk_hash.hash))
            .collect::<Vec<_>>();

        let stored_chunk_hashes = BTreeSet::from_iter(stored_chunk_hashes.iter());

        let uploaded_chunk_hashes = uploaded_chunk_hashes
            .iter()
            .map(|chunk_hash| format_full_hash(&chunk_hash.hash))
            .collect::<Vec<_>>();
        let uploaded_chunk_hashes = BTreeSet::from_iter(uploaded_chunk_hashes.iter());

        assert!(uploaded_chunk_hashes.is_subset(&stored_chunk_hashes));
        assert_eq!(uploaded_chunk_hashes.len(), num_chunks_expected);
    }

    Ok(uploaded_chunk_hashes)
}

pub async fn exec(args: UpgradeSnsControlledCanisterArgs, agent: &Agent) -> Result<()> {
    eprintln!("Preparing to propose an SNS-controlled canister upgrade ...");

    // 1. Check that we have a viable Wasm.
    let UpgradeSnsControlledCanisterArgs {
        root_canister_id,
        sns_neuron_id,
        target_canister_id,
        wasm_path,
        candid_arg,
    } = args;

    let wasm_bytes = load_wasm(wasm_path)?;
    let sha256_hash = ic_crypto_sha2::Sha256::hash(&wasm_bytes);

    // 2. Check that the target is controlled by the SNS specified via the Root canister ID.
    let root_canister = RootCanister {
        canister_id: root_canister_id.get(),
    };
    let (sns, dapps) = root_canister.list_sns_canisters(agent).await?;

    if !BTreeSet::from_iter(&dapps[..]).contains(&target_canister_id.get()) {
        bail!(
            "{} is not one of the canisters controlled by the SNS with Root canister {}",
            target_canister_id,
            root_canister_id,
        );
    }

    // 3. Create a store canister on the same subnet as the target.
    let subnet = nns::registry::get_subnet_for_canister(agent, target_canister_id).await?;

    let store_canister_id = nns::cmc::create_canister(
        agent,
        Some(SubnetSelection::Subnet { subnet }),
        Some(CanisterSettingsArgs {
            controllers: Some(BoundedVec::new(vec![
                PrincipalId(agent.get_principal()),
                root_canister_id.get(),
                sns.governance.canister_id,
            ])),
            ..Default::default()
        }),
    )
    .await?;

    // 4. Upload the chinks into the store canister.
    let num_chunks_expected = {
        let num_full_chunks = wasm_bytes.len() / CHUNK_SIZE;
        let remainder = wasm_bytes.len() % CHUNK_SIZE;
        if remainder == 0 {
            num_full_chunks
        } else {
            num_full_chunks + 1
        }
    };
    let uploaded_chunk_hashes =
        upload_wasm_as_chunks(agent, store_canister_id, wasm_bytes, num_chunks_expected).await?;
}
