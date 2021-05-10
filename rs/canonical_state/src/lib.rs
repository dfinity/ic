//! Conversion, filtering and encoding of Replicated State as Canonical State.

pub mod encoding;
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
pub use traversal::{traverse, traverse_partial};
pub use visitor::{Control, Visitor};

/// The Canonical State certification version produced by this crate.
pub const CURRENT_CERTIFICATION_VERSION: u32 = 1;
