//! Conversion, filtering and encoding of Replicated State as Canonical State.

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

/// The Canonical State certification version that should be used for newly
/// computed states.
///
/// Version history:
///
///   0. Initial version.
///   1. Added canister module hash and controller.
///   2. Added support for multiple canister controllers.
///   3. Added subnet to canister ID ranges routing tables.
///   4. Added optional `Request::cycles_payment` and `Response::cycles_refund`
///      fields that are not yet populated.
pub const CURRENT_CERTIFICATION_VERSION: u32 = 4;
