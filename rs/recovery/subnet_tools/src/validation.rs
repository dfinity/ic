use crate::{
    agent_helper::{AgentHelper, StateTree},
    state_tool_helper,
    utils::get_cup,
};

use ic_base_types::SubnetId;
use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key_from_der;
use ic_recovery::error::{RecoveryError, RecoveryResult};
use ic_types::{consensus::HasHeight, crypto::threshold_sig::ThresholdSigPublicKey};
use slog::{Logger, error, info};
use url::Url;

use std::{fmt::Display, path::Path};

/// Validates the following artifacts of a subnet that was halted at a CUP:
/// 1. NNS signed State Tree;
/// 2. the CUP the subnet halted at;
/// 3. the manifest of the state the subnet halted at.
pub fn validate_artifacts(
    state_tree_path: impl AsRef<Path>,
    nns_public_key_path: Option<&Path>,
    cup_path: impl AsRef<Path>,
    state_manifest_path: impl AsRef<Path>,
    subnet_id: SubnetId,
    logger: &Logger,
) -> RecoveryResult<()> {
    let validated_subnet_public_key = validation_helper(
        "State Tree signed by the NNS",
        "extracted authentic subnet key from the NNS state tree",
        logger,
        || {
            validate_state_tree_and_extract_subnet_public_key(
                state_tree_path.as_ref(),
                nns_public_key_path,
                subnet_id,
                logger,
            )
        },
    )?;

    let state_hash = validation_helper(
        "the CUP the subnet halted at",
        "the CUP signature is valid",
        logger,
        || {
            validate_cup_and_extract_state_hash(
                cup_path.as_ref(),
                &validated_subnet_public_key,
                logger,
            )
        },
    )?;

    validation_helper(
        "the manifest of the state the subnet halted at",
        "recomputed manifest root hash matches the one in the CUP",
        logger,
        || validate_manifest(state_manifest_path.as_ref(), &state_hash, logger),
    )?;

    Ok(())
}

fn validate_cup_and_extract_state_hash(
    cup_path: &Path,
    subnet_public_key: &ThresholdSigPublicKey,
    logger: &Logger,
) -> RecoveryResult<String> {
    let cup = get_cup(cup_path)?;

    if let Some((_, transcript)) = cup
        .content
        .block
        .as_ref()
        .payload
        .as_ref()
        .as_summary()
        .dkg
        .current_transcripts()
        .iter()
        .next()
    {
        info!(
            logger,
            "Dealer subnet from the CUP: {}", transcript.dkg_id.dealer_subnet
        );
    }
    info!(logger, "CUP height: {}", &cup.content.height());

    let block_time = cup.content.block.as_ref().context.time;

    info!(
        logger,
        "Block time from the CUP: {} (nanos since unix epoch: {})",
        block_time,
        block_time.as_nanos_since_unix_epoch()
    );

    let state_hash = hex::encode(&cup.content.state_hash.get_ref().0);
    info!(logger, "State hash from the CUP: {}", state_hash);

    ic_crypto_utils_threshold_sig::verify_combined(
        &cup.content,
        &cup.signature.signature,
        subnet_public_key,
    )
    .map_err(|err| {
        RecoveryError::ValidationFailed(format!("Failed to validate the CUP signature: {err}"))
    })?;

    Ok(state_hash)
}

fn validate_state_tree_and_extract_subnet_public_key(
    state_tree_path: &Path,
    nns_public_key_path: Option<&Path>,
    subnet_id: SubnetId,
    logger: &Logger,
) -> RecoveryResult<ThresholdSigPublicKey> {
    let agent_helper = AgentHelper::new(
        &Url::parse("https://ic0.app").unwrap(),
        nns_public_key_path,
        logger.clone(),
    )?;

    let state_tree = StateTree::read_from_file(state_tree_path, subnet_id)?;

    agent_helper.validate_state_tree(&state_tree)?;

    let bytes = state_tree.lookup_public_key()?;

    parse_threshold_sig_key_from_der(bytes).map_err(|err| {
        RecoveryError::UnexpectedError(format!("Failed to parse the public key bytes: {err}"))
    })
}

fn validate_manifest(
    state_manifest_path: &Path,
    state_hash_from_cup: &String,
    logger: &Logger,
) -> RecoveryResult<()> {
    let state_hash = state_tool_helper::verify_manifest(state_manifest_path).map_err(|err| {
        RecoveryError::validation_failed("Failed to validate the state manifest", err)
    })?;

    info!(logger, "state hash from the CUP: {}", state_hash_from_cup);
    info!(logger, "state hash from the State Manifest: {}", state_hash);

    if state_hash != *state_hash_from_cup {
        return Err(RecoveryError::validation_failed(
            "Failed to validate the state manifest",
            "hash from the state manifest differs from the state hash from the CUP",
        ));
    }

    Ok(())
}

fn validation_helper<T>(
    label: impl Display,
    on_success_message: impl Display,
    logger: &Logger,
    validator: impl FnOnce() -> RecoveryResult<T>,
) -> RecoveryResult<T> {
    info!(logger, "Validating {}", label);

    let result = (validator)();
    match &result {
        Ok(_) => info!(logger, "Validation succeeded: {}.", on_success_message),
        Err(err) => error!(logger, "Validation failed: {}.", err),
    }

    info!(logger, "");

    result
}
