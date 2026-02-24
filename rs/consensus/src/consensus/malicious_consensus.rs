//! This module defines malicious behavior regarding the consensus crate,
//! enabling testing consensus algorithm and implementation in the presence
//! of malicious nodes.
use crate::consensus::{ConsensusImpl, add_all_to_validated, block_maker};
use ic_consensus_utils::pool_reader::PoolReader;
use ic_interfaces::consensus_pool::{ChangeAction, HeightRange, Mutations};
use ic_logger::{info, trace};
use ic_protobuf::log::malicious_behavior_log_entry::v1::{
    MaliciousBehavior, MaliciousBehaviorLogEntry,
};
use ic_types::{
    Height, Time,
    consensus::{
        Block, BlockMetadata, BlockProposal, ConsensusMessage, FinalizationContent,
        FinalizationShare, HasHeight, HashedBlock, NotarizationShare, Rank, hashed,
    },
    malicious_flags::MaliciousFlags,
};
use std::time::Duration;

impl ConsensusImpl {
    /// Maliciously propose blocks irrespective of the rank, based on the flags
    /// received. If maliciously_propose_empty_blocks is set, propose only empty
    /// blocks. If maliciously_equivocation_blockmaker is set, propose
    /// multiple blocks at once.
    fn maliciously_propose_blocks(
        &self,
        pool: &PoolReader<'_>,
        maliciously_propose_empty_blocks: bool,
        maliciously_equivocation_blockmaker: bool,
    ) -> Vec<BlockProposal> {
        trace!(self.log, "maliciously_propose_blocks");
        let number_of_proposals = 5;

        let my_node_id = self.replica_config.node_id;
        let (beacon, parent) = match block_maker::get_dependencies(pool) {
            Some((b, p)) => (b, p),
            None => {
                return Vec::new();
            }
        };
        let height = beacon.content.height.increment();
        let registry_version = match pool.registry_version(height) {
            Some(v) => v,
            None => {
                return Vec::new();
            }
        };

        // If this node is a blockmaker, use its rank. If not, use rank 0.
        // If the rank is not yet available, wait further.
        let maybe_rank = match self
            .block_maker
            .membership
            .get_block_maker_rank(height, &beacon, my_node_id)
        {
            Ok(Some(rank)) => Some(rank),
            // TODO: introduce a malicious flag which will instruct a malicious node to propose a block
            // when it's not elected a block maker; implement a system test which uses the flag.
            Ok(None) => None,
            Err(_) => None,
        };

        if let Some(rank) = maybe_rank
            && !block_maker::already_proposed(pool, height, my_node_id)
        {
            // If maliciously_propose_empty_blocks is set, propose only empty blocks.
            let maybe_proposal = match maliciously_propose_empty_blocks {
                true => self.maliciously_propose_empty_block(pool, rank, parent),
                false => self.block_maker.propose_block(pool, rank, parent),
            };

            if let Some(proposal) = maybe_proposal {
                let mut proposals = vec![];

                match maliciously_equivocation_blockmaker {
                    false => {}
                    true => {
                        let original_block = Block::from(proposal.clone());
                        // Generate more valid proposals based on this proposal, by slightly
                        // increasing the time in the context of
                        // this block.
                        for i in 1..(number_of_proposals - 1) {
                            let mut new_block = original_block.clone();
                            new_block.context.time += Duration::from_nanos(i);
                            let hashed_block =
                                hashed::Hashed::new(ic_types::crypto::crypto_hash, new_block);
                            let metadata = BlockMetadata::from_block(
                                &hashed_block,
                                self.replica_config.subnet_id,
                            );
                            if let Ok(signature) = self.block_maker.crypto.sign(
                                &metadata,
                                self.replica_config.node_id,
                                registry_version,
                            ) {
                                proposals.push(BlockProposal {
                                    signature,
                                    content: hashed_block,
                                });
                            }
                        }
                    }
                };
                proposals.push(proposal);

                if maliciously_propose_empty_blocks {
                    ic_logger::info!(
                        self.log,
                        "[MALICIOUS] proposing empty blocks";
                        malicious_behavior => MaliciousBehaviorLogEntry { malicious_behavior: MaliciousBehavior::ProposeEmptyBlocks as i32}
                    );
                }
                if maliciously_equivocation_blockmaker {
                    ic_logger::info!(
                        self.log,
                        "[MALICIOUS] proposing {} equivocation blocks",
                        proposals.len();
                        malicious_behavior => MaliciousBehaviorLogEntry { malicious_behavior: MaliciousBehavior::ProposeEquivocatingBlocks as i32}
                    );
                }

                return proposals;
            }
        }
        Vec::new()
    }

    /// Maliciously construct a block proposal with valid DKG, but with empty
    /// batch payload.
    fn maliciously_propose_empty_block(
        &self,
        pool: &PoolReader<'_>,
        rank: Rank,
        parent: HashedBlock,
    ) -> Option<BlockProposal> {
        let height = parent.height().increment();
        let mut context = parent.as_ref().context.clone();
        context.certified_height = self.state_manager.latest_certified_height();

        // Note that we will skip blockmaking if registry versions or replica_versions
        // are missing or temporarily not retrievable.
        let registry_version = pool.registry_version(height)?;

        // Get the subnet records that are relevant to making a block
        let stable_registry_version = self
            .block_maker
            .get_stable_registry_version(parent.as_ref())?;
        let subnet_records = block_maker::subnet_records_for_registry_version(
            &self.block_maker,
            registry_version,
            stable_registry_version,
        )?;

        self.block_maker.construct_block_proposal(
            pool,
            context,
            parent,
            height,
            rank,
            registry_version,
            &subnet_records,
        )
    }

    /// Maliciously notarize all unnotarized proposals for the current height.
    fn maliciously_notarize_all(&self, pool: &PoolReader<'_>) -> Vec<NotarizationShare> {
        trace!(self.log, "maliciously_notarize");
        let mut notarization_shares = Vec::<NotarizationShare>::new();

        for proposal in
            self.get_all_blocks_higher_than(pool, pool.get_finalized_height().increment())
        {
            if !self
                .notary
                .is_proposal_already_notarized_by_me(pool, &proposal)
                && let Some(share) = self.notary.notarize_block(pool, &proposal.content)
            {
                notarization_shares.push(share);
            }
        }

        if !notarization_shares.is_empty() {
            ic_logger::info!(
                self.log,
                "[MALICIOUS] maliciously notarizing all {} proposals",
                notarization_shares.len();
                malicious_behavior => MaliciousBehaviorLogEntry { malicious_behavior: MaliciousBehavior::NotarizeAll as i32}
            );
        }

        notarization_shares
    }

    /// Generate finalization shares for each notarized block in the validated
    /// pool.
    fn maliciously_finalize_all(&self, pool: &PoolReader<'_>) -> Vec<FinalizationShare> {
        trace!(self.log, "maliciously_finalize");
        let mut finalization_shares = Vec::new();

        for proposal in
            self.get_all_blocks_higher_than(pool, pool.get_finalized_height().increment())
        {
            let block = proposal.as_ref();

            // if this replica already created a finalization share for this block, we do
            // not finality sign this block anymore. The point is not to spam.
            let signed_this_block_before = pool
                .pool()
                .validated()
                .finalization_share()
                .get_by_height(block.height)
                .any(|share| {
                    share.signature.signer == self.replica_config.node_id
                        && share.content.block == *proposal.content.get_hash()
                });

            if !signed_this_block_before
                && let Some(finalization_share) = self.maliciously_finalize_block(pool, block)
            {
                finalization_shares.push(finalization_share);
            }
        }

        if !finalization_shares.is_empty() {
            info!(
                self.log,
                "[MALICIOUS] maliciously finalizing {} proposals",
                finalization_shares.len();
                malicious_behavior => MaliciousBehaviorLogEntry { malicious_behavior: MaliciousBehavior::FinalizeAll as i32}
            );
        }

        finalization_shares
    }

    // Returns both validated and unvalidated blocks.
    fn get_all_blocks_higher_than(
        &self,
        pool: &PoolReader<'_>,
        min_height: Height,
    ) -> impl Iterator<Item = BlockProposal> {
        pool.pool()
            .validated()
            .block_proposal()
            .get_by_height_range(HeightRange {
                min: min_height,
                max: pool
                    .pool()
                    .validated()
                    .block_proposal()
                    .max_height()
                    .unwrap_or(min_height),
            })
            .chain(
                pool.pool()
                    .unvalidated()
                    .block_proposal()
                    .get_by_height_range(HeightRange {
                        min: min_height,
                        max: pool
                            .pool()
                            .validated()
                            .block_proposal()
                            .max_height()
                            .unwrap_or(min_height),
                    }),
            )
    }

    /// Try to create a finalization share for a given block.
    fn maliciously_finalize_block(
        &self,
        pool: &PoolReader<'_>,
        block: &Block,
    ) -> Option<FinalizationShare> {
        let content = FinalizationContent::new(block.height, ic_types::crypto::crypto_hash(block));
        let signature = self
            .finalizer
            .crypto
            .sign(
                &content,
                self.replica_config.node_id,
                pool.registry_version(block.height)?,
            )
            .ok()?;
        Some(FinalizationShare { content, signature })
    }

    /// Simulate malicious consensus behavior by modifying changeset.
    #[allow(unused, clippy::too_many_arguments)]
    pub fn maliciously_alter_changeset(
        &self,
        pool: &PoolReader,
        honest_changeset: Mutations,
        malicious_flags: &MaliciousFlags,
        timestamp: Time,
    ) -> Mutations {
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
                        ChangeAction::AddToValidated(x) if matches!(x.msg ,ConsensusMessage::BlockProposal(_))
                    )
                });
            }

            changeset.append(&mut add_all_to_validated(
                timestamp,
                self.maliciously_propose_blocks(
                    pool,
                    malicious_flags.maliciously_propose_empty_blocks,
                    malicious_flags.maliciously_propose_equivocating_blocks,
                ),
            ));
        }

        if malicious_flags.maliciously_notarize_all {
            changeset.retain(|change_action| {
                !matches!(
                    change_action,
                    ChangeAction::AddToValidated(x) if matches!(x.msg, ConsensusMessage::NotarizationShare(_))
                )
            });

            // Notarize all (both validated and not yet validated) block proposals
            changeset.append(&mut add_all_to_validated(
                timestamp,
                self.maliciously_notarize_all(pool),
            ));
        }

        if malicious_flags.maliciously_finalize_all {
            // Remove any finalization shares that might have been output by the honest
            // code, to avoid deduplication.
            changeset.retain(|change_action| {
                !matches!(
                    change_action,
                    ChangeAction::AddToValidated(x) if matches!(x.msg, ConsensusMessage::FinalizationShare(_))
                )
            });

            // Finalize all (both validated and not yet validated) block proposals
            changeset.append(&mut add_all_to_validated(
                timestamp,
                self.maliciously_finalize_all(pool),
            ));
        }

        changeset
    }
}
