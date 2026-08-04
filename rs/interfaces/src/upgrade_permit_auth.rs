//! Pool trait and change actions for the upgrade permit authorization pool.

use ic_types::consensus::UpgradePermitAuthorizationShare;
use ic_types::artifact::UpgradePermitAuthId;

/// Change actions that can be applied to the [`UpgradePermitAuthPool`].
#[derive(Debug)]
pub enum UpgradePermitAuthChangeAction {
    /// Add a locally-produced share directly to validated.
    AddToValidated(UpgradePermitAuthorizationShare),
    /// Move a gossiped share from unvalidated to validated (after signature
    /// verification).
    MoveToValidated(UpgradePermitAuthorizationShare),
    /// Remove a validated share (e.g. after the request was authorized or
    /// timed out).
    RemoveValidated(UpgradePermitAuthId),
    /// Remove an unvalidated share.
    RemoveUnvalidated(UpgradePermitAuthId),
    /// Handle an invalid share (bad signature, no matching request, etc.).
    HandleInvalid(UpgradePermitAuthId, String),
}

pub type UpgradePermitAuthChangeSet = Vec<UpgradePermitAuthChangeAction>;

/// Query interface for the upgrade permit authorization pool.
pub trait UpgradePermitAuthPool: Send + Sync {
    /// Return an iterator over all validated shares.
    fn get_validated_shares(&self) -> Box<dyn Iterator<Item = &UpgradePermitAuthorizationShare> + '_>;
    /// Return an iterator over all unvalidated shares.
    fn get_unvalidated_shares(
        &self,
    ) -> Box<dyn Iterator<Item = &UpgradePermitAuthorizationShare> + '_>;
}
