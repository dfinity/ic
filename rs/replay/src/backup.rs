use ic_artifact_pool::consensus_pool::ConsensusPoolImpl;
use ic_config::artifact_pool::BACKUP_GROUP_SIZE;
use ic_consensus::consensus::{pool_reader::PoolReader, utils::lookup_replica_version};
use ic_consensus_message::ConsensusMessageHashable;
use ic_interfaces::{
    certification::{Verifier, VerifierError},
    consensus_pool::{ChangeAction, MutableConsensusPool},
    crypto::{MultiSigVerifier, ThresholdSigVerifierByPublicKey},
    registry::RegistryClient,
    state_manager::{StateHashError, StateManager},
    time_source::SysTimeSource,
    validation::ValidationResult,
};
use ic_logger::replica_logger::no_op_logger;
use ic_protobuf::types::v1 as pb;
use ic_registry_client::helper::subnet::SubnetRegistry;
use ic_types::{
    consensus::{
        certification::Certification, BlockProposal, CatchUpContentProtobufBytes, CatchUpPackage,
        Finalization, HasHeight, Notarization, RandomBeacon, RandomTape,
    },
    crypto::{CombinedThresholdSig, CombinedThresholdSigOf},
    Height, RegistryVersion, ReplicaVersion, SubnetId,
};
use prost::Message;
use std::{
    collections::{BTreeMap, BTreeSet},
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
    let mut file = fs::File::open(path)
        .unwrap_or_else(|err| panic!("Couldn't open file {:?}: {:?}", path, err));
    file.read_to_end(&mut buffer)
        .unwrap_or_else(|err| panic!("Couldn't read file {:?}: {:?}", path, err));
    buffer
}

/// All possible exits from the deserialization loop of the artifacts. All
/// exits except for `Done` require for the upper layers to catch up.
pub(crate) enum ExitPoint {
    /// All available complete rounds were successfully restored.
    Done,
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
    /// We restored all artifacts before a block with the certified height in
    /// the validation context higher than the last state height.
    StateBehind(Height),
}

/// Deserialize the CUP at the given height and inserts it into the pool.
pub(crate) fn insert_cup_at_height(
    pool: &mut dyn MutableConsensusPool,
    registry: Arc<dyn RegistryClient>,
    subnet_id: SubnetId,
    backup_dir: &Path,
    height: Height,
) {
    let cup = read_cup_at_height(registry, subnet_id, backup_dir, height);
    pool.apply_changes(
        &SysTimeSource::new(),
        ChangeAction::AddToValidated(cup.into_message()).into(),
    );
}

/// Deserializes the CUP at the given height and returns it.
pub(crate) fn read_cup_at_height(
    registry: Arc<dyn RegistryClient>,
    subnet_id: SubnetId,
    backup_dir: &Path,
    height: Height,
) -> CatchUpPackage {
    let group_key = (height.get() / BACKUP_GROUP_SIZE) * BACKUP_GROUP_SIZE;
    let buffer = read_file(
        &backup_dir
            .join(group_key.to_string())
            .join(height.to_string())
            .join("catch_up_package.bin"),
    );

    let protobuf = ic_protobuf::types::v1::CatchUpPackage::decode(buffer.as_slice())
        .expect("Protobuf decoding failed");

    let cup = CatchUpPackage::try_from(&protobuf)
        .unwrap_or_else(|_| panic!("{}", deserialization_error(height)));

    // We cannot verify the genesis CUP with this subnet's public key.
    if height.get() != 0 {
        let crypto =
            ic_crypto::CryptoComponentFatClient::new_for_verification_only(registry.clone());
        crypto
            .verify_combined_threshold_sig_by_public_key(
                &CombinedThresholdSigOf::new(CombinedThresholdSig(protobuf.signature)),
                &CatchUpContentProtobufBytes(protobuf.content),
                subnet_id,
                cup.content.block.get_value().context.registry_version,
            )
            .expect("Verification of the signature on the CUP failed");
    }

    cup
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

/// Deserializes consensus artifacts, reading them from the backup spool height
/// by height and inserting them into the consensus pool. It stops at certain
/// points which require the execution state to catch up.
pub(crate) fn deserialize_consensus_artifacts(
    registry_client: Arc<dyn RegistryClient>,
    pool: &mut ConsensusPoolImpl,
    height_to_batches: &mut BTreeMap<Height, HeightArtifacts>,
    subnet_id: SubnetId,
    current_replica_version: &ReplicaVersion,
    latest_state_height: Height,
) -> ExitPoint {
    let time_source = SysTimeSource::new();
    let mut last_cup_height: Option<Height> = None;
    let crypto =
        ic_crypto::CryptoComponentFatClient::new_for_verification_only(registry_client.clone());

    loop {
        let height = match height_to_batches.iter().next() {
            Some((height, _)) => *height,
            // No heights in the queue, we are done.
            None => return ExitPoint::Done,
        };
        let height_artifacts = height_to_batches
            .remove(&height)
            .expect("Couldn't read value for the next key");

        // If we see a height_artifacts containing a CUP, we save its height for later.
        // We cannot insert a CUP right away into the pool as it changes the
        // behaviour of the pool cache. So we should insert the CUP at the next
        // finalized height.
        if height > Height::from(0) && height_artifacts.contains_cup {
            last_cup_height = Some(height);
        }

        let path = &height_artifacts.path;
        let mut artifacts = Vec::new();

        if height_artifacts.proposals.is_empty() {
            println!(
                "Stopping deserialization at height {:?} as this height contains no proposals.",
                height,
            );
            return ExitPoint::Done;
        }

        let pool_reader = PoolReader::new(pool);
        let registry_version = pool_reader
            .registry_version(height)
            .expect("Cannot retrieve the registry version from the pool");

        let mut finalized_block_hash = None;
        // We should never insert more than one finalization, because it breaks a lot of
        // invariants of the pool.
        if let Some(file_name) = &height_artifacts.finalizations.get(0) {
            // Save the hash of the finalized block proposal.
            finalized_block_hash = file_name.split('_').nth(1);
            let buffer = read_file(&path.join(file_name));
            let finalization = Finalization::try_from(
                pb::Finalization::decode(buffer.as_slice()).expect("Protobuf decoding failed"),
            )
            .unwrap_or_else(|_| panic!("{}", deserialization_error(height)));

            let unique_signers: BTreeSet<_> =
                finalization.signature.signers.clone().into_iter().collect();
            if unique_signers.len() != finalization.signature.signers.len() {
                panic!("Detected repeated signers on the finalization signature");
            }

            crypto
                .verify_multi_sig_combined(
                    &finalization.signature.signature,
                    &finalization.content,
                    unique_signers,
                    registry_version,
                )
                .expect("Cannot verify the signature on the finalization");
            artifacts.push(finalization.into_message());
        }

        // Insert block proposals.
        for file_name in height_artifacts
            .proposals
            .iter()
            // If there was a finalization, insert only the finalized proposal.
            // Otherwise, insert all.
            .filter(|name| name.contains(finalized_block_hash.unwrap_or("")))
        {
            let buffer = read_file(&path.join(file_name));
            let proposal = BlockProposal::try_from(
                pb::BlockProposal::decode(buffer.as_slice()).expect("Protobuf decoding failed"),
            )
            .unwrap_or_else(|_| panic!("{}", deserialization_error(height)));

            let validation_context = &proposal.content.as_ref().context;
            let certified_height = validation_context.certified_height;
            // If the block references newer execution height than we have, we exit.
            if certified_height > latest_state_height {
                height_to_batches.insert(height, height_artifacts);
                return ExitPoint::StateBehind(certified_height);
            }

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
                    return ExitPoint::NewerRegistryVersion(block_registry_version);
                } else {
                    return ExitPoint::Done;
                }
            }

            artifacts.push(proposal.into_message());
        }

        // Insert the random beacon and the random tape.
        let rb_path = path.join("random_beacon.bin");
        if !rb_path.exists() {
            println!(
                "Stopping deserialization at height {:?} as this height contains no random beacon.",
                height,
            );
            return ExitPoint::Done;
        }
        let buffer = read_file(&rb_path);
        artifacts.push(
            RandomBeacon::try_from(
                pb::RandomBeacon::decode(buffer.as_slice()).expect("Protobuf decoding failed"),
            )
            .unwrap_or_else(|_| panic!("{}", deserialization_error(height)))
            .into_message(),
        );

        let rt_path = path.join("random_tape.bin");
        if !rt_path.exists() {
            println!(
                "Stopping deserialization at height {:?} as this height contains no random tape.",
                height,
            );
            return ExitPoint::Done;
        }
        let buffer = read_file(&rt_path);
        artifacts.push(
            RandomTape::try_from(
                pb::RandomTape::decode(buffer.as_slice()).expect("Protobuf decoding failed"),
            )
            .unwrap_or_else(|_| panic!("{}", deserialization_error(height)))
            .into_message(),
        );

        // Insert the notarizations.
        for file_name in &height_artifacts.notarizations {
            let buffer = read_file(&path.join(file_name));
            artifacts.push(
                Notarization::try_from(
                    pb::Notarization::decode(buffer.as_slice()).expect("Protobuf decoding failed"),
                )
                .unwrap_or_else(|_| panic!("{}", deserialization_error(height)))
                .into_message(),
            );
        }

        assert!(
            artifacts.iter().all(|v| v.check_integrity()),
            "The integrity of all artifacts is ensured"
        );

        pool.apply_changes(
            &time_source,
            artifacts
                .into_iter()
                .map(ChangeAction::AddToValidated)
                .collect(),
        );

        // If we just inserted a height_artifacts, which finalizes the last seen CUP
        // height, we need to deliver all batches before we insert the cup.
        if let Some(cup_height) = last_cup_height {
            if height >= cup_height && !height_artifacts.finalizations.is_empty() {
                println!(
                    "Found a CUP at height {:?}, finalized at height {:?}",
                    cup_height, height
                );
                match lookup_replica_version(
                    &*registry_client,
                    subnet_id,
                    &no_op_logger(),
                    registry_version,
                ) {
                    Some(replica_version) if &replica_version != current_replica_version => {
                        println!(
                            "⚠️  Please use the replay tool of version {} to continue backup recovery from height {:?}",
                            replica_version, cup_height
                        );
                    }
                    _ => {}
                }
                return ExitPoint::CUPHeightWasFinalized(cup_height);
            }
        }
    }
}

/// Checks that the restored catch-up package contains the same state hash as
/// the one computed by the state manager from the restored artifacts and drops
/// all states below the last CUP.
pub(crate) fn assert_consistency_and_clean_up<T>(
    state_manager: &dyn StateManager<State = T>,
    pool: &mut ConsensusPoolImpl,
) {
    let last_cup = pool.get_cache().catch_up_package();
    if last_cup.height() == Height::from(0) {
        return;
    }
    let hash = loop {
        match state_manager.get_state_hash_at(last_cup.height()) {
            Ok(hash) => break hash,
            Err(StateHashError::Transient(err)) => {
                println!(
                    "REPLAY WARN: no hash for the state at CUP height {:?}: {:?}; waiting...",
                    last_cup.height(),
                    err
                );
                std::thread::sleep(std::time::Duration::from_secs(3));
            }
            Err(StateHashError::Permanent(err)) => {
                panic!(
                    "REPLAY ERROR: couldn't fetch the state at CUP height {:?}: {:?}",
                    last_cup.height(),
                    err
                );
            }
        }
    };
    assert_eq!(
        hash,
        last_cup.content.state_hash,
        "The hash state of the CUP at height {:?} does not correspond to the hash of the computed state",
        last_cup.height()
    );
    let purge_height = last_cup.height();
    println!("Removing all states below height {:?}", purge_height);
    state_manager.remove_states_below(purge_height);
    pool.apply_changes(
        &SysTimeSource::new(),
        ChangeAction::PurgeValidatedBelow(purge_height).into(),
    );
}

fn deserialization_error(height: Height) -> String {
    format!("Couldn't deserialize artifacts at height {:?}", height)
}

// A mock we're using to instantiate the StateManager. Since we're not verifying
// any certifications during the backup, we can use a mocked verifier.
pub(crate) struct MockVerifier {}

impl Verifier for MockVerifier {
    fn validate(
        &self,
        _subnet_id: SubnetId,
        _certification: &Certification,
        _registry_version: RegistryVersion,
    ) -> ValidationResult<VerifierError> {
        Ok(())
    }
}
