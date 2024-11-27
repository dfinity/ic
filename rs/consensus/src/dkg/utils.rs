use ic_consensus_utils::pool_reader::PoolReader;
use ic_types::{
    consensus::Block,
    crypto::threshold_sig::ni_dkg::{NiDkgDealing, NiDkgId},
    NodeId,
};
use std::collections::{BTreeMap, BTreeSet, HashSet};

pub(super) fn get_dealers_from_chain(
    pool_reader: &PoolReader<'_>,
    block: &Block,
) -> HashSet<(NiDkgId, NodeId)> {
    get_dkg_dealings2(pool_reader, block, false)
        .into_iter()
        .flat_map(|(dkg_id, dealings)| {
            dealings
                .into_keys()
                .map(move |node_id| (dkg_id.clone(), node_id))
        })
        .collect()
}

// Starts with the given block and creates a nested mapping from the DKG Id to
// the node Id to the dealing. This function panics if multiple dealings
// from one dealer are discovered, hence, we assume a valid block chain.
#[allow(dead_code)]
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
                .dkg
                .messages
                .iter()
                .for_each(|msg| {
                    let collected_dealings = acc.entry(msg.content.dkg_id.clone()).or_default();
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

// TODO: Remove dead_code

/// Starts with the given block and creates a nested mapping from the DKG Id to
/// the node Id to the dealing. This function panics if multiple dealings
/// from one dealer are discovered, hence, we assume a valid block chain.
/// It also excludes dealings for ni_dkg ids, which already have a transcript in the
/// blockchain.
#[allow(dead_code)]
pub(super) fn get_dkg_dealings2(
    pool_reader: &PoolReader<'_>,
    block: &Block,
    exclude_used: bool,
) -> BTreeMap<NiDkgId, BTreeMap<NodeId, NiDkgDealing>> {
    let mut dealings: BTreeMap<NiDkgId, BTreeMap<NodeId, NiDkgDealing>> = BTreeMap::new();
    let mut used_dealings: BTreeSet<NiDkgId> = BTreeSet::new();

    // Note that the chain iterator is guaranteed to iterate from
    // newest to oldest blocks and that transcripts can not appear before their dealings.
    for block in pool_reader
        .chain_iterator(block.clone())
        .take_while(|block| !block.payload.is_summary())
    {
        let payload = &block.payload.as_ref().as_data().dkg;

        if exclude_used {
            // Update used dealings
            used_dealings.extend(
                payload
                    .transcripts_for_remote_subnets
                    .iter()
                    .map(|transcript| transcript.0.clone()),
            );
        }

        // Find new dealings in this payload
        for (signer, ni_dkg_id, dealing) in payload
            .messages
            .iter()
            // Filer out if they are already used
            .filter(|message| !used_dealings.contains(&message.content.dkg_id))
            .map(|message| {
                (
                    message.signature.signer,
                    message.content.dkg_id.clone(),
                    message.content.dealing.clone(),
                )
            })
        {
            let entry = dealings.entry(ni_dkg_id).or_default();
            let old_entry = entry.insert(signer, dealing);

            assert!(
                old_entry.is_none(),
                "Dealings from the same dealers discovered."
            );
        }
    }

    dealings
}
