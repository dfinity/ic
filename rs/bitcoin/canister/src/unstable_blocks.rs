use crate::blocktree::{self, BlockChain, BlockDoesNotExtendTree};
use bitcoin::Block;
use ic_replicated_state::bitcoin_state::UnstableBlocks;

/// Pops the `anchor` block iff ∃ a child `C` of the `anchor` block that
/// is stable. The child `C` becomes the new `anchor` block, and all its
/// siblings are discarded.
pub fn pop(blocks: &mut UnstableBlocks) -> Option<Block> {
    // Take all the children of the anchor.
    let mut anchor_child_trees = std::mem::take(&mut blocks.tree.children);

    // Sort them by depth.
    anchor_child_trees.sort_by_key(blocktree::depth);

    match anchor_child_trees.last() {
        Some(deepest_child_tree) => {
            // The deepest child tree must have a depth >= stability_threshold.
            if blocktree::depth(deepest_child_tree) < blocks.stability_threshold {
                // Need a depth of at least >= stability_threshold
                blocks.tree.children = anchor_child_trees;
                return None;
            }

            // If there is more than one child, the difference in depth
            // between the deepest child and all the others must be >= stability_threshold.
            if anchor_child_trees.len() >= 2 {
                if let Some(second_deepest_child_tree) =
                    anchor_child_trees.get(anchor_child_trees.len() - 2)
                {
                    if blocktree::depth(deepest_child_tree)
                        - blocktree::depth(second_deepest_child_tree)
                        < blocks.stability_threshold
                    {
                        // Difference must be >= stability_threshold
                        blocks.tree.children = anchor_child_trees;
                        return None;
                    }
                }
            }

            // The root of the deepest child tree is stable. This deepest
            // child tree becomes the new tree, with its root being the new
            // `anchor` block. All the tree's siblings are discarded.
            let deepest_child_tree = anchor_child_trees.pop().unwrap();
            let old_anchor = blocks.tree.root.clone();
            blocks.tree = deepest_child_tree;
            Some(old_anchor)
        }
        None => {
            // The anchor has no children. Nothing to return.
            None
        }
    }
}

/// Pushes a new block into the store.
pub fn push(blocks: &mut UnstableBlocks, block: Block) -> Result<(), BlockDoesNotExtendTree> {
    blocktree::extend(&mut blocks.tree, block)
}

/// Returns the best guess on what the main blockchain is.
///
/// The most likely chain to be "main", we hypothesize, is the longest
/// chain of blocks with an "uncontested" tip. As in, there exists no other
/// block at the same height as the tip.
pub fn get_main_chain(blocks: &UnstableBlocks) -> BlockChain {
    // Get all the blockchains that extend the anchor.
    let blockchains: Vec<BlockChain> = blocktree::blockchains(&blocks.tree);

    // Find the length of the longest blockchain.
    let mut longest_blockchain_len = 0;
    for blockchain in blockchains.iter() {
        longest_blockchain_len = longest_blockchain_len.max(blockchain.len());
    }

    // Get all the longest blockchains.
    let longest_blockchains: Vec<BlockChain> = blockchains
        .into_iter()
        .filter(|bc| bc.len() == longest_blockchain_len)
        .collect();

    let mut main_chain = vec![];
    for height_idx in 0..longest_blockchain_len {
        // If all the blocks on the same height are identical, then this block is part of the
        // "main" chain.
        let block = longest_blockchains[0][height_idx];
        let block_hash = block.block_hash();

        for chain in longest_blockchains.iter().skip(1) {
            if chain[height_idx].block_hash() != block_hash {
                return main_chain;
            }
        }

        main_chain.push(block);
    }

    main_chain
}

pub fn get_blocks(blocks: &UnstableBlocks) -> Vec<&Block> {
    blocktree::blockchains(&blocks.tree)
        .into_iter()
        .flatten()
        .collect()
}

#[cfg(test)]
mod test {
    use super::*;
    use ic_btc_test_utils::BlockBuilder;

    #[test]
    fn empty() {
        let anchor = BlockBuilder::genesis().build();

        let mut forest = UnstableBlocks::new(1, anchor);
        assert_eq!(pop(&mut forest), None);
    }

    #[test]
    fn single_chain() {
        let block_0 = BlockBuilder::genesis().build();
        let block_1 = BlockBuilder::with_prev_header(block_0.header).build();
        let block_2 = BlockBuilder::with_prev_header(block_1.header).build();

        let mut forest = UnstableBlocks::new(1, block_0.clone());

        push(&mut forest, block_1).unwrap();
        assert_eq!(pop(&mut forest), None);

        push(&mut forest, block_2).unwrap();

        // Block 0 (the anchor) now has one stable child (Block 1).
        // Block 0 should be returned when calling `pop`.
        assert_eq!(pop(&mut forest), Some(block_0));

        // Block 1 is now the anchor. It doesn't have children yet,
        // so calling `pop` should return `None`.
        assert_eq!(pop(&mut forest), None);
    }

    #[test]
    fn forks() {
        let genesis_block = BlockBuilder::genesis().build();
        let block = BlockBuilder::with_prev_header(genesis_block.header).build();
        let forked_block = BlockBuilder::with_prev_header(genesis_block.header).build();

        let mut forest = UnstableBlocks::new(1, genesis_block.clone());

        push(&mut forest, block).unwrap();
        push(&mut forest, forked_block.clone()).unwrap();

        // Neither forks are 1-stable, so we shouldn't get anything.
        assert_eq!(pop(&mut forest), None);

        // Extend fork2 by another block.
        push(
            &mut forest,
            BlockBuilder::with_prev_header(forked_block.header).build(),
        )
        .unwrap();

        // Now fork2 should be 1-stable. The anchor should be returned on `pop`
        // and fork2 becomes the new anchor.
        assert_eq!(pop(&mut forest), Some(genesis_block));
        assert_eq!(forest.tree.root, forked_block);

        // No stable children for fork 2
        assert_eq!(pop(&mut forest), None);
    }

    #[test]
    fn insert_in_order() {
        let block_0 = BlockBuilder::genesis().build();
        let block_1 = BlockBuilder::with_prev_header(block_0.header).build();
        let block_2 = BlockBuilder::with_prev_header(block_1.header).build();

        let mut forest = UnstableBlocks::new(0, block_0.clone());
        push(&mut forest, block_1.clone()).unwrap();
        push(&mut forest, block_2).unwrap();

        assert_eq!(pop(&mut forest), Some(block_0));
        assert_eq!(pop(&mut forest), Some(block_1));
        assert_eq!(pop(&mut forest), None);
    }

    // Creating a forest that looks like this:
    //
    // * -> 1 -> 2
    //
    // Both blocks 1 and 2 are part of the main chain.
    #[test]
    fn get_main_chain_single_blockchain() {
        let block_0 = BlockBuilder::genesis().build();
        let block_1 = BlockBuilder::with_prev_header(block_0.header).build();
        let block_2 = BlockBuilder::with_prev_header(block_1.header).build();

        let mut forest = UnstableBlocks::new(1, block_0.clone());

        push(&mut forest, block_1.clone()).unwrap();
        push(&mut forest, block_2.clone()).unwrap();
        assert_eq!(get_main_chain(&forest), vec![&block_0, &block_1, &block_2]);
    }

    // Creating a forest that looks like this:
    //
    // * -> 1
    // * -> 2
    //
    // Both blocks 1 and 2 contest with each other -> main chain is empty.
    #[test]
    fn get_main_chain_two_contesting_trees() {
        let block_0 = BlockBuilder::genesis().build();
        let block_1 = BlockBuilder::with_prev_header(block_0.header).build();
        let block_2 = BlockBuilder::with_prev_header(block_0.header).build();

        let mut forest = UnstableBlocks::new(1, block_0.clone());

        push(&mut forest, block_1).unwrap();
        push(&mut forest, block_2).unwrap();
        assert_eq!(get_main_chain(&forest), vec![&block_0]);
    }

    // Creating the following forest:
    //
    // * -> 1
    // * -> 2 -> 3
    //
    // "2 -> 3" is the longest blockchain and is should be considered "main".
    #[test]
    fn get_main_chain_longer_fork() {
        let block_0 = BlockBuilder::genesis().build();
        let block_1 = BlockBuilder::with_prev_header(block_0.header).build();
        let block_2 = BlockBuilder::with_prev_header(block_0.header).build();
        let block_3 = BlockBuilder::with_prev_header(block_2.header).build();

        let mut forest = UnstableBlocks::new(1, block_0.clone());

        push(&mut forest, block_1).unwrap();
        push(&mut forest, block_2.clone()).unwrap();
        push(&mut forest, block_3.clone()).unwrap();
        assert_eq!(get_main_chain(&forest), vec![&block_0, &block_2, &block_3]);
    }

    // Creating the following forest:
    //
    // * -> 1 -> 2 -> 3
    //       \-> a -> b
    //
    // "1" should be returned in this case, as its the longest chain
    // without a contested tip.
    #[test]
    fn get_main_chain_fork_at_first_block() {
        let block_0 = BlockBuilder::genesis().build();
        let block_1 = BlockBuilder::with_prev_header(block_0.header).build();
        let block_2 = BlockBuilder::with_prev_header(block_1.header).build();
        let block_3 = BlockBuilder::with_prev_header(block_2.header).build();
        let block_a = BlockBuilder::with_prev_header(block_1.header).build();
        let block_b = BlockBuilder::with_prev_header(block_a.header).build();

        let mut forest = UnstableBlocks::new(1, block_0.clone());

        push(&mut forest, block_1.clone()).unwrap();
        push(&mut forest, block_2).unwrap();
        push(&mut forest, block_3).unwrap();
        push(&mut forest, block_a).unwrap();
        push(&mut forest, block_b).unwrap();
        assert_eq!(get_main_chain(&forest), vec![&block_0, &block_1]);
    }

    // Creating the following forest:
    //
    // * -> 1 -> 2 -> 3
    //       \-> a -> b
    //   -> x -> y -> z
    //
    // All blocks are contested.
    //
    // Then add block `c` that extends block `b`, at that point
    // `1 -> a -> b -> c` becomes the only longest chain, and therefore
    // the "main" chain.
    #[test]
    fn get_main_chain_multiple_forks() {
        let block_0 = BlockBuilder::genesis().build();
        let block_1 = BlockBuilder::with_prev_header(block_0.header).build();
        let block_2 = BlockBuilder::with_prev_header(block_1.header).build();
        let block_3 = BlockBuilder::with_prev_header(block_2.header).build();
        let block_a = BlockBuilder::with_prev_header(block_1.header).build();
        let block_b = BlockBuilder::with_prev_header(block_a.header).build();
        let block_x = BlockBuilder::with_prev_header(block_0.header).build();
        let block_y = BlockBuilder::with_prev_header(block_x.header).build();
        let block_z = BlockBuilder::with_prev_header(block_y.header).build();

        let mut forest = UnstableBlocks::new(1, block_0.clone());

        push(&mut forest, block_x).unwrap();
        push(&mut forest, block_y).unwrap();
        push(&mut forest, block_z).unwrap();
        push(&mut forest, block_1.clone()).unwrap();
        push(&mut forest, block_2).unwrap();
        push(&mut forest, block_3).unwrap();
        push(&mut forest, block_a.clone()).unwrap();
        push(&mut forest, block_b.clone()).unwrap();
        assert_eq!(get_main_chain(&forest), vec![&block_0]);

        // Now add block c to b.
        let block_c = BlockBuilder::with_prev_header(block_b.header).build();
        push(&mut forest, block_c.clone()).unwrap();

        // Now the main chain should be "1 -> a -> b -> c"
        assert_eq!(
            get_main_chain(&forest),
            vec![&block_0, &block_1, &block_a, &block_b, &block_c]
        );
    }

    // Same as the above test, with a different insertion order.
    #[test]
    fn get_main_chain_multiple_forks_2() {
        let block_0 = BlockBuilder::genesis().build();
        let block_1 = BlockBuilder::with_prev_header(block_0.header).build();
        let block_2 = BlockBuilder::with_prev_header(block_1.header).build();
        let block_3 = BlockBuilder::with_prev_header(block_2.header).build();
        let block_a = BlockBuilder::with_prev_header(block_1.header).build();
        let block_b = BlockBuilder::with_prev_header(block_a.header).build();
        let block_x = BlockBuilder::with_prev_header(block_0.header).build();
        let block_y = BlockBuilder::with_prev_header(block_x.header).build();
        let block_z = BlockBuilder::with_prev_header(block_y.header).build();

        let mut forest = UnstableBlocks::new(1, block_0.clone());

        push(&mut forest, block_1).unwrap();
        push(&mut forest, block_2).unwrap();
        push(&mut forest, block_3).unwrap();
        push(&mut forest, block_a).unwrap();
        push(&mut forest, block_b).unwrap();
        push(&mut forest, block_x).unwrap();
        push(&mut forest, block_y).unwrap();
        push(&mut forest, block_z).unwrap();
        assert_eq!(get_main_chain(&forest), vec![&block_0]);
    }

    #[test]
    fn get_main_chain_anchor_only() {
        let block_0 = BlockBuilder::genesis().build();
        let forest = UnstableBlocks::new(1, block_0.clone());

        assert_eq!(get_main_chain(&forest), vec![&block_0]);
    }
}
