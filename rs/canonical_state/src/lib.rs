//! Conversion, filtering and encoding of Replicated State as Canonical State.
//!
//! Version history:
//!
//!   0. Initial version.
//!   1. Added canister module hash and controller.
//!   2. Added support for multiple canister controllers.
//!   3. Added subnet to canister ID ranges routing tables.
//!   4. Added optional `Request::cycles_payment` and `Response::cycles_refund`
//!      fields that are not yet populated.
//!   5. Added support for custom canister metadata sections.
//!   6. Encoding of canister metadata sections.

pub mod encoding;
pub mod hash_tree;
pub mod lazy_tree;
pub mod size_limit_visitor;
pub mod subtree_visitor;
mod traversal;
pub mod visitor;

#[cfg(test)]
mod test_visitors;

/// Label applied to tree edges in the Canonical State.
pub type Label = Vec<u8>;

pub use lazy_tree::conversion::LabelLike;
pub use traversal::traverse;
pub use visitor::{Control, Visitor};

/// Maximum supported certification version. The replica will panic if requested
/// to certify using a version higher than this.
///
/// Must be greater than or equal to `CURRENT_CERTIFICATION_VERSION`.
///
/// For virtually all certification version changes must be bumped at least one
/// release before bumping `CURRENT_CERTIFICATION_VERSION` in order to ensure
/// forwards compatibility in the case of a replica downgrade.
pub const MAX_SUPPORTED_CERTIFICATION_VERSION: u32 = 6;

/// The Canonical State certification version that should be used for newly
/// computed states.
pub const CURRENT_CERTIFICATION_VERSION: u32 = 4;
