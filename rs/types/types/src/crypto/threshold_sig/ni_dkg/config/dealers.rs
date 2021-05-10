//! Types related to dealers for non-interactive DKG.
use super::*;
use crate::crypto::threshold_sig::ni_dkg::config::errors::NiDkgConfigValidationError;

#[cfg(test)]
mod tests;

/// A set of dealers for non-interactive DKG. Satisfies invariants, see
/// `NiDkgDealers::new`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NiDkgDealers {
    dealers: BTreeSet<NodeId>,
    // The count equals `dealers.len()`.
    // This information is redundant since in several places we need the number
    // of dealers as NumberOfNodes. For that, the set length (`usize`) must
    // be converted to `NodeIndex`, which may fail. To avoid doing this in
    // several places this is done here on initialization.
    count: NumberOfNodes,
}

impl NiDkgDealers {
    /// `NiDkgDealers` can only be created if the following invariants hold:
    /// * Dealers are not empty (error: `DealersEmpty`)
    /// * The number of dealers fits into `NodeIndex` (error: `TooManyDealers`)
    ///
    /// If an invariant is not satisifed, the `Err` as indicated above is
    /// returned.
    pub fn new(dealers: BTreeSet<NodeId>) -> Result<Self, NiDkgConfigValidationError> {
        Self::ensure_dealers_not_empty(&dealers)?;
        let count = Self::number_of_dealers(dealers.len())?;
        Ok(NiDkgDealers { dealers, count })
    }

    fn number_of_dealers(
        dealers_count: usize,
    ) -> Result<NumberOfNodes, NiDkgConfigValidationError> {
        number_of_nodes_from_usize(dealers_count)
            .map_err(|_| NiDkgConfigValidationError::TooManyDealers { dealers_count })
    }

    fn ensure_dealers_not_empty(
        dealers: &BTreeSet<NodeId>,
    ) -> Result<(), NiDkgConfigValidationError> {
        if dealers.is_empty() {
            return Err(NiDkgConfigValidationError::DealersEmpty);
        }
        Ok(())
    }

    /// Returns the position of the given `node_id` in the dealers. Returns
    /// `None` if the `node_id` is not a dealer.
    pub fn position(&self, node_id: NodeId) -> Option<NodeIndex> {
        self.iter().find_map(|(node_index, this_node_id)| {
            if node_id == this_node_id {
                Some(node_index)
            } else {
                None
            }
        })
    }

    pub fn get(&self) -> &BTreeSet<NodeId> {
        &self.dealers
    }

    /// Returns nodes with the standard indexing.
    ///
    /// NiDKG relies on a stable indexing of the nodes.  This iterator provides
    /// the canonical indexing.  That stable indexing is based on the natural
    /// ordering of NodeIds, also used by the BTreeSet, however that is an
    /// implementation detail and external code should not rely on this.
    pub fn iter(&self) -> impl Iterator<Item = (NodeIndex, NodeId)> + '_ {
        (0..).zip(self.dealers.iter().copied())
    }

    pub fn count(&self) -> NumberOfNodes {
        self.count
    }
}
