//! The DKG public interface.
use ic_types::{consensus::dkg, Height};

/// The DkgPool is used to store messages that are exchanged between nodes in
/// the process of executing dkg.
pub trait DkgPool: Send + Sync {
    fn get_validated(&self) -> Box<dyn Iterator<Item = &dkg::Message> + '_>;
    fn get_unvalidated(&self) -> Box<dyn Iterator<Item = &dkg::Message> + '_>;
    /// The start height of the currently _computed_ DKG interval; the invariant
    /// we want to maintain for all messages in validated and unvalidated
    /// sections is that they correspond to a DKG Id with the start height
    /// equal to current_start_height.
    fn get_current_start_height(&self) -> Height;
    /// Checks if the message is present in the validated section.
    fn validated_contains(&self, msg: &dkg::Message) -> bool;
}

/// Various actions that can be performed in DKG.
#[derive(Debug)]
pub enum ChangeAction {
    AddToValidated(dkg::Message),
    MoveToValidated(dkg::Message),
    RemoveFromUnvalidated(dkg::Message),
    HandleInvalid(dkg::DkgMessageId, String),
    Purge(Height),
}

pub type ChangeSet = Vec<ChangeAction>;

impl From<ChangeAction> for ChangeSet {
    fn from(change_action: ChangeAction) -> Self {
        vec![change_action]
    }
}
