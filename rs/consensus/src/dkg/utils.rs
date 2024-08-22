use ic_consensus_utils::pool_reader::PoolReader;
use ic_types::{
    consensus::Block,
    crypto::threshold_sig::ni_dkg::{NiDkgDealing, NiDkgId},
    NodeId,
};
use std::collections::{BTreeMap, HashSet};

pub(super) fn get_dealers_from_chain(
    pool_reader: &PoolReader<'_>,
    block: &Block,
) -> HashSet<(NiDkgId, NodeId)> {
    get_dkg_dealings(pool_reader, block)
        .into_iter()
        .flat_map(|(dkg_id, dealings)| dealings.into_keys().map(move |node_id| (dkg_id, node_id)))
        .collect()
}

// Starts with the given block and creates a nested mapping from the DKG Id to
// the node Id to the dealing. This function panics if multiple dealings
// from one dealer are discovered, hence, we assume a valid block chain.
pub(super) fn get_dkg_dealings(
    pool_reader: &PoolReader<'_>,
    block: &Block,
) -> BTreeMap<NiDkgId, BTreeMap<NodeId, NiDkgDealing>> {
    pool_reader
        .chain_iterator(block.clone())
        .take_while(|block| !block.payload.is_summary())
        .fold(Default::default(), |mut acc, block| {
            block
                .payload
                .as_ref()
                .as_data()
                .dealings
                .messages
                .iter()
                .for_each(|msg| {
                    let collected_dealings = acc.entry(msg.content.dkg_id).or_default();
                    assert!(
                        collected_dealings
                            .insert(msg.signature.signer, msg.content.dealing.clone())
                            .is_none(),
                        "Dealings from the same dealers discovered."
                    );
                });
            acc
        })
}
