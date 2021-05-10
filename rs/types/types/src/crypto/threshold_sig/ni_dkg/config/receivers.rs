//! Types related to receivers for non-interactive DKG.
use super::*;
use crate::crypto::threshold_sig::ni_dkg::config::errors::NiDkgConfigValidationError;

#[cfg(test)]
mod tests;

/// A set of receivers for non-interactive DKG. Satisfies invariants, see
/// `NiDkgReceivers::new`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NiDkgReceivers {
    receivers: BTreeSet<NodeId>,
    // The count equals receivers.len().
    // This information is redundant since in several places we need the number
    // of receivers as NumberOfNodes. For that, the set length (usize) must
    // be converted to `NodeIndex`, which may fail. To avoid doing this in
    // several places this is done here on initialization.
    count: NumberOfNodes,
}

impl NiDkgReceivers {
    /// `NiDkgReceivers` can only be created if the following invariants hold:
    /// * Receivers are not empty (error: `ReceiversEmpty`)
    /// * The number of receivers fits into `NodeIndex` (error`:
    ///   TooManyReceivers`)
    ///
    /// If an invariant is not satisifed, the `Err` as indicated above is
    /// returned.
    pub fn new(receivers: BTreeSet<NodeId>) -> Result<Self, NiDkgConfigValidationError> {
        Self::ensure_receivers_not_empty(&receivers)?;
        let count = Self::number_of_receivers(receivers.len())?;
        Ok(NiDkgReceivers { receivers, count })
    }

    fn number_of_receivers(
        receivers_count: usize,
    ) -> Result<NumberOfNodes, NiDkgConfigValidationError> {
        number_of_nodes_from_usize(receivers_count)
            .map_err(|_| NiDkgConfigValidationError::TooManyReceivers { receivers_count })
    }

    fn ensure_receivers_not_empty(
        receivers: &BTreeSet<NodeId>,
    ) -> Result<(), NiDkgConfigValidationError> {
        if receivers.is_empty() {
            return Err(NiDkgConfigValidationError::ReceiversEmpty);
        }
        Ok(())
    }

    /// Returns the position of the given `node_id` in the receivers. Returns
    /// `None` if the `node_id` is not a receiver.
    pub fn position(&self, node_id: NodeId) -> Option<NodeIndex> {
        self.receivers
            .iter()
            .position(|receiver| node_id == *receiver)
            .map(|index| NodeIndex::try_from(index).expect("node index overflow"))
    }

    pub fn get(&self) -> &BTreeSet<NodeId> {
        &self.receivers
    }

    /// Returns nodes with the standard indexing.
    ///
    /// NiDKG relies on a stable indexing of the nodes.  This iterator provides
    /// the canonical indexing.  That stable indexing is based on the natural
    /// ordering of NodeIds, also used by the BTreeSet, however that is an
    /// implementation detail and external code should not rely on this.
    pub fn iter(&self) -> impl Iterator<Item = (NodeIndex, NodeId)> + '_ {
        (0..).zip(self.receivers.iter().copied())
    }

    pub fn count(&self) -> NumberOfNodes {
        self.count
    }
}
