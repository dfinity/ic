use crate::{
    player::ReplayError,
    validator::{InvalidArtifact, ReplayValidator},
};
use ic_artifact_pool::consensus_pool::ConsensusPoolImpl;
use ic_config::artifact_pool::BACKUP_GROUP_SIZE;
use ic_consensus_dkg::DkgKeyManager;
use ic_consensus_utils::pool_reader::PoolReader;
use ic_crypto_for_verification_only::CryptoComponentForVerificationOnly;
use ic_interfaces::{
    consensus_pool::{ChangeAction, Mutations, ValidatedConsensusArtifact},
    p2p::consensus::{MutablePool, UnvalidatedArtifact},
};
use ic_interfaces_registry::RegistryClient;
use ic_protobuf::{proxy::ProxyDecodeError, types::v1 as pb};
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_types::{
    Height, RegistryVersion, SubnetId,
    consensus::{
        BlockProposal, CatchUpPackage, ConsensusMessage, ConsensusMessageHashable, Finalization,
        HasHeight, Notarization, RandomBeacon, RandomTape,
    },
    time::UNIX_EPOCH,
};
use prost::Message;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    convert::TryFrom,
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};

// A set of backup artifacts corresponding to a single height.
pub(super) struct HeightArtifacts {
    path: PathBuf,
    contains_cup: bool,
    proposals: Vec<String>,
    finalizations: Vec<String>,
    notarizations: Vec<String>,
}

// Reads the file at `path` and the returns the content as bytes.
fn read_file(path: &Path) -> Vec<u8> {
    let mut buffer = Vec::new();
    let mut file =
        fs::File::open(path).unwrap_or_else(|err| panic!("Couldn't open file {path:?}: {err:?}"));
    file.read_to_end(&mut buffer)
        .unwrap_or_else(|err| panic!("Couldn't read file {path:?}: {err:?}"));
    buffer
}

// Renames the file at `path` and by adding a prefix 'invalid_'.
pub(crate) fn rename_file(original_file: &Path) {
    let file_name = original_file
        .file_name()
        .expect("File name is missing")
        .to_str()
        .expect("File name is not a proper string");
    let renamed_file = original_file.with_file_name(format!("invalid_{file_name}"));
    println!("Renaming {original_file:?} to {renamed_file:?}");
    fs::rename(original_file, renamed_file).expect("Error renaming a file");
}

/// All possible exits from the deserialization loop of the artifacts. All
/// exits except for `Done` require for the upper layers to catch up.
pub(crate) enum ExitPoint {
    /// CUPHeightWasFinalized(h) indicates that we processed all artifacts
    /// (except CUPs) up to  height h, which is the first height that finalizes
    /// the last seen CUP. This means we are now ready to insert the CUP at
    /// height h.
    CUPHeightWasFinalized(Height),
    /// All artifacts up to the height with a newer registry version were
    /// restored. The height payload corresponds to the height of a first
    /// block with a validation context referencing a newer version than
    /// locally known.
    NewerRegistryVersion(RegistryVersion),
    /// Can't proceed because artifact validation failed after the given height.
    ValidationIncomplete(Height),
}

/// Deserialize the CUP at the given height and inserts it into the pool.
pub(crate) fn insert_cup_at_height(
    pool: &mut dyn MutablePool<ConsensusMessage, Mutations = Mutations>,
    backup_dir: &Path,
    height: Height,
) -> Result<(), ReplayError> {
    let file = &cup_file_name(backup_dir, height);
    let cup = read_cup_file(file).ok_or(ReplayError::CUPVerificationFailed(height))?;
    pool.apply(
        ChangeAction::AddToValidated(ValidatedConsensusArtifact {
            msg: cup.into_message(),
            timestamp: UNIX_EPOCH,
        })
        .into(),
    );
    Ok(())
}

pub(crate) fn read_cup_proto_file(file: &Path) -> Option<pb::CatchUpPackage> {
    let buffer = read_file(file);

    match pb::CatchUpPackage::decode(buffer.as_slice()) {
        Ok(proto) => Some(proto),
        Err(err) => {
            rename_file(file);
            println!(
                "Protobuf decoding of CUP at {} failed: {:?}",
                file.display(),
                err
            );
            None
        }
    }
}

/// Deserializes the CUP file and returns it.
pub(crate) fn read_cup_file(file: &Path) -> Option<CatchUpPackage> {
    let protobuf = read_cup_proto_file(file)?;

    match CatchUpPackage::try_from(&protobuf) {
        Ok(cup) => Some(cup),
        Err(err) => {
            rename_file(file);
            println!("{}", deserialization_error(file, err));
            None
        }
    }
}

/// Deduce the file name of a CUP at a specific height
pub(crate) fn cup_file_name(backup_dir: &Path, height: Height) -> PathBuf {
    let group_key = (height.get() / BACKUP_GROUP_SIZE) * BACKUP_GROUP_SIZE;
    backup_dir
        .join(group_key.to_string())
        .join(height.to_string())
        .join("catch_up_package.bin")
}

/// Read all files from the backup folder starting from the `start_height` and
/// convert them into batches.
pub(super) fn heights_to_artifacts_metadata(
    backup_dir: &Path,
    start_height: Height,
) -> Result<BTreeMap<Height, HeightArtifacts>, std::io::Error> {
    let mut results = Vec::new();
    for group_dir in fs::read_dir(backup_dir)? {
        for height_dir in fs::read_dir(group_dir?.path())? {
            let path = height_dir?.path();
            let height = Height::from(
                path.file_name()
                    .unwrap_or_default()
                    .to_str()
                    .unwrap_or_default()
                    .parse::<u64>()
                    .expect("Couldn't parse the height directory name"),
            );

            // Skip all height folders below the start height,
            if height < start_height {
                continue;
            }
            let mut files = Vec::new();
            for file in fs::read_dir(&path)? {
                let file_path = file?.path();
                files.push(
                    file_path
                        .file_name()
                        .unwrap_or_default()
                        .to_str()
                        .unwrap_or_default()
                        .to_string(),
                );
            }
            let get_files = |s| {
                files
                    .iter()
                    .filter(|file| file.starts_with(s))
                    .cloned()
                    .collect::<Vec<_>>()
            };
            results.push((
                height,
                HeightArtifacts {
                    path,
                    contains_cup: !get_files("catch_up_package").is_empty(),
                    proposals: get_files("block_proposal"),
                    finalizations: get_files("finalization"),
                    notarizations: get_files("notarization"),
                },
            ));
        }
    }
    Ok(results.into_iter().collect())
}

fn read_artifact_if_correct_height<T, PBT>(
    file: &PathBuf,
    artifact_type: &str,
    height: Height,
) -> Result<T, ExitPoint>
where
    T: TryFrom<PBT> + HasHeight,
    PBT: prost::Message + std::default::Default,
{
    let buffer = read_file(file);
    let Ok(fn_pb) = PBT::decode(buffer.as_slice()) else {
        println!("Error: Protobuf decoding of {artifact_type} failed: {file:?}");
        rename_file(file);
        return Err(ExitPoint::ValidationIncomplete(height));
    };

    let Ok(artifact) = T::try_from(fn_pb) else {
        println!("Error: Deserialization of the {artifact_type}: failed: {file:?}",);
        rename_file(file);
        return Err(ExitPoint::ValidationIncomplete(height));
    };

    if height == artifact.height() {
        Ok(artifact)
    } else {
        println!("Error: A {artifact_type} with an unexpected height detected: {file:?}");
        rename_file(file);
        Err(ExitPoint::ValidationIncomplete(height))
    }
}

/// Deserializes consensus artifacts, reading them from the backup spool height
/// by height and inserting them into the consensus pool. It stops at certain
/// points which require the execution state to catch up.
// TODO(CON-1494): change the return type of this function. Most variants of ExitPoint
// are not result of errors.
pub(crate) fn deserialize_consensus_artifacts(
    registry_client: Arc<dyn RegistryClient>,
    crypto: Arc<dyn CryptoComponentForVerificationOnly>,
    pool: &mut ConsensusPoolImpl,
    height_to_batches: &mut BTreeMap<Height, HeightArtifacts>,
    subnet_id: SubnetId,
    validator: &ReplayValidator,
    dkg_manager: &mut DkgKeyManager,
    invalid_artifacts: &mut Vec<InvalidArtifact>,
) -> Result<(), ExitPoint> {
    let time_source = validator.get_timesource();
    let mut last_cup_height: Option<Height> = None;

    loop {
        let height = match height_to_batches.iter().next() {
            Some((height, _)) => *height,
            // No heights in the queue, we are done.
            None => return Ok(()),
        };
        let height_artifacts = height_to_batches
            .remove(&height)
            .expect("Couldn't read value for the next key");

        let path = &height_artifacts.path;

        // If we see a height_artifacts containing a CUP, we save its height for later.
        // We cannot insert a CUP right away into the pool as it changes the
        // behaviour of the pool cache. So we should insert the CUP at the next
        // finalized height.
        if height > Height::from(0) && height_artifacts.contains_cup {
            last_cup_height = Some(height);
            let file = &path.join("catch_up_package.bin");
            if let Some(cup) = read_cup_file(file)
                && cup.height() != height
            {
                println!("A CUP with an unexpected height detected: {file:?}");
                rename_file(file);
                return Ok(());
            }
        }

        let mut artifacts = Vec::new();
        let mut expected = HashMap::new();

        if height_artifacts.proposals.is_empty() {
            println!(
                "Stopping deserialization at height {height:?} as this height contains no proposals.",
            );
            return Ok(());
        }

        let pool_reader = PoolReader::new(pool);
        let registry_version = pool_reader
            .registry_version(height)
            .expect("Cannot retrieve the registry version from the pool");
        let last_finalized_height = pool_reader.get_finalized_height();

        let mut finalized_block_hash = None;
        // We should never insert more than one finalization, because it breaks a lot of
        // invariants of the pool.
        if let Some(file_name) = &height_artifacts.finalizations.first() {
            // Save the hash of the finalized block proposal.
            finalized_block_hash = file_name.split('_').nth(1);
            let file = path.join(file_name);
            let finalization = read_artifact_if_correct_height::<Finalization, pb::Finalization>(
                &file,
                "finalization",
                height,
            )?;
            let unique_signers: BTreeSet<_> =
                finalization.signature.signers.clone().into_iter().collect();
            if unique_signers.len() != finalization.signature.signers.len() {
                println!("Detected repeated signers on the finalization signature");
                rename_file(&file);
            } else if let Err(err) = crypto.verify_multi_sig_combined(
                &finalization.signature.signature,
                &finalization.content,
                unique_signers,
                registry_version,
            ) {
                println!("Cannot verify the signature on the finalization: {err:?}");
                rename_file(&file);
            } else {
                let message = finalization.into_message();
                expected.insert(message.get_cm_hash(), file);
                artifacts.push(message);
            }
        }

        // Insert the finalized block proposal.
        if let Some(file_name) = height_artifacts.proposals.first() {
            let file = path.join(file_name);
            let proposal = read_artifact_if_correct_height::<BlockProposal, pb::BlockProposal>(
                &file,
                "block proposal",
                height,
            )?;
            let validation_context = &proposal.content.as_ref().context;
            let block_registry_version = validation_context.registry_version;
            if block_registry_version > registry_client.get_latest_version() {
                println!(
                    "Found a block with a newer registry version {:?} at height {:?}",
                    block_registry_version,
                    proposal.content.as_ref().height,
                );
                // If an NNS block references a newer registry version than that we have,
                // we exit to apply all changes from the registry canister into the local
                // store. Otherwise, we cannot progress until we sync the local store.
                let root_subnet_id = registry_client
                    .get_root_subnet_id(registry_version)
                    .unwrap()
                    .unwrap();
                if subnet_id == root_subnet_id {
                    height_to_batches.insert(height, height_artifacts);
                    return Err(ExitPoint::NewerRegistryVersion(block_registry_version));
                } else {
                    return Ok(());
                }
            }

            let message = proposal.into_message();
            expected.insert(message.get_cm_hash(), file);
            artifacts.push(message);
        }

        // Insert the random beacon and the random tape.
        let rb_path = path.join("random_beacon.bin");
        if !rb_path.exists() {
            println!(
                "Stopping deserialization at height {height:?} as this height contains no random beacon.",
            );
            return Ok(());
        }
        let rb = read_artifact_if_correct_height::<RandomBeacon, pb::RandomBeacon>(
            &rb_path,
            "random beacon",
            height,
        )?;
        artifacts.push(rb.into_message());

        let rt_path = path.join("random_tape.bin");
        if !rt_path.exists() {
            println!(
                "Stopping deserialization at height {height:?} as this height contains no random tape.",
            );
            return Ok(());
        }
        let rt = read_artifact_if_correct_height::<RandomTape, pb::RandomTape>(
            &rt_path,
            "random tape",
            height,
        )?;
        artifacts.push(rt.into_message());

        // Insert the finalized notarization.
        if let Some(file_name) = height_artifacts.notarizations.first() {
            let file = path.join(file_name);
            let not = read_artifact_if_correct_height::<Notarization, pb::Notarization>(
                &file,
                "notarization",
                height,
            )?;
            let message = not.into_message();
            expected.insert(message.get_cm_hash(), file);
            artifacts.push(message);
        }

        artifacts.into_iter().for_each(|message| {
            pool.insert(UnvalidatedArtifact {
                message,
                peer_id: validator.replica_cfg.node_id,
                timestamp: time_source.get_relative_time(),
            })
        });

        // If we are adding a new finalization this round, artifacts should be validated
        // up until the new height, else we stay at the last finalized height
        let target_height = if finalized_block_hash.is_some() {
            height
        } else {
            last_finalized_height
        };
        // call validator, which moves artifacts to validated or removes invalid
        let (mut invalid, failure_after_height) =
            match validator.validate(pool, &mut expected, dkg_manager, target_height) {
                Ok(artifacts) => (artifacts, None),
                Err(ReplayError::ValidationIncomplete(h, artifacts)) => (artifacts, Some(h)),
                Err(other) => {
                    println!("Unexpected failure during validation: {other:?}");
                    (Vec::new(), Some(last_finalized_height))
                }
            };
        for i in &invalid {
            match i.get_file_name() {
                Some(name) => {
                    let artifact_path = path.join(name);
                    assert!(
                        artifact_path.exists(),
                        "Path to invalid artifact doesn't exist."
                    );
                    println!("Invalid artifact detected: {:?}", &artifact_path);
                    rename_file(&artifact_path);
                    return Err(ExitPoint::ValidationIncomplete(height));
                }
                None => println!("Failed to get path for invalid artifact: {i:?}"),
            }
        }
        invalid_artifacts.append(&mut invalid);

        // All the artifacts that we expect to be validated and hence removed from the collection.
        // If they weren't we remove them here and hopefully rsync the correct ones next time.
        for (_, artifact_path) in expected {
            println!("Artifact couldn't be validated: {artifact_path:?}");
            rename_file(&artifact_path);
        }

        if let Some(height) = failure_after_height {
            return Err(ExitPoint::ValidationIncomplete(height));
        }

        // If we just inserted a height_artifacts, which finalizes the last seen CUP
        // height, we need to deliver all batches before we insert the cup.
        if let Some(cup_height) = last_cup_height
            && height >= cup_height
            && !height_artifacts.finalizations.is_empty()
        {
            println!("Found a CUP at height {cup_height:?}, finalized at height {height:?}");
            return Err(ExitPoint::CUPHeightWasFinalized(cup_height));
        }
    }
}

fn deserialization_error(file: &Path, err: ProxyDecodeError) -> String {
    format!("Couldn't deserialize artifact {file:?}: {err}")
}
