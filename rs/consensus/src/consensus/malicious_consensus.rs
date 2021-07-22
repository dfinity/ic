//! This module defines malicious behaviour regarding the consensus crate,
//! enabling testing consensus algorithm and implementation in the presence
//! of malicious nodes.
#[cfg(feature = "malicious_code")]
use crate::consensus::{
    add_all_to_validated, block_maker::BlockMaker, finalizer::Finalizer, notary::Notary,
    pool_reader::PoolReader, validator,
};
#[cfg(feature = "malicious_code")]
use ic_interfaces::consensus_pool::{ChangeAction, ChangeSet};
#[cfg(feature = "malicious_code")]
use ic_interfaces::ingress_pool::IngressPoolSelect;
#[cfg(feature = "malicious_code")]
use ic_logger::ReplicaLogger;
#[cfg(feature = "malicious_code")]
use ic_types::consensus::ConsensusMessage::{BlockProposal, FinalizationShare};
#[cfg(feature = "malicious_code")]
use ic_types::malicious_flags::MaliciousFlags;

#[cfg(feature = "malicious_code")]
#[allow(clippy::too_many_arguments)]
pub fn maliciously_alter_changeset(
    pool: &PoolReader,
    ingress_pool: &dyn IngressPoolSelect,
    honest_changeset: ChangeSet,
    malicious_flags: &MaliciousFlags,
    block_maker: &BlockMaker,
    finalizer: &Finalizer,
    notary: &Notary,
    logger: &ReplicaLogger,
) -> ChangeSet {
    let mut changeset = honest_changeset;

    if malicious_flags.maliciously_propose_equivocating_blocks
        || malicious_flags.maliciously_propose_empty_blocks
    {
        // If maliciously_propose_empty_blocks is enabled, we should remove non-empty
        // block proposals by the honest code from the changeset.
        if malicious_flags.maliciously_propose_empty_blocks {
            changeset.retain(|change_action| {
                !matches!(
                    change_action,
                    ChangeAction::AddToValidated(BlockProposal(_))
                )
            });
        }

        changeset.append(&mut add_all_to_validated(
            block_maker.maliciously_propose_blocks(
                pool,
                ingress_pool,
                malicious_flags.maliciously_propose_empty_blocks,
                malicious_flags.maliciously_propose_equivocating_blocks,
            ),
        ));
    }

    if malicious_flags.maliciously_notarize_all {
        // First undo validations and invalidations of block proposals by the honest
        // code. We would not want the new ChangeActions to contradict or repeat
        // an existing ChangeAction.
        changeset.retain(|change_action| {
            !matches!(
                change_action,
                ChangeAction::RemoveFromUnvalidated(BlockProposal(_))
                    | ChangeAction::MoveToValidated(BlockProposal(_))
                    | ChangeAction::HandleInvalid(BlockProposal(_), _)
            )
        });

        // Validate all block proposals in a range
        changeset.append(&mut validator::maliciously_validate_all_blocks(
            pool, logger,
        ));

        // Notarize all valid block proposals
        changeset.append(&mut add_all_to_validated(
            notary.maliciously_notarize_all(pool),
        ));
    }

    if malicious_flags.maliciously_finalize_all {
        // Remove any finalization shares that might have been output by the honest
        // code, to avoid deduplication.
        changeset.retain(|change_action| {
            !matches!(
                change_action,
                ChangeAction::AddToValidated(FinalizationShare(_))
            )
        });

        // Finalize all block proposals
        changeset.append(&mut add_all_to_validated(
            finalizer.maliciously_finalize_all(pool),
        ));
    }

    changeset
}
