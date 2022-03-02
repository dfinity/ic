//! Conversion, filtering and encoding of Replicated State as Canonical State.
//!
//! The Canonical State is an actually identical representation of the public
//! parts of a subnet's Replicated State (streams, ingress history, etc.). It is
//! a way for a subnet’s replicas to express agreement on the externally visible
//! parts of the deterministic state machine’s Replicated State, by having them
//! certified by a majority of the subnet’s replicas using threshold signatures.
//!
//! ## Structure
//!
//! The Canonical State is conceptually a rose tree with labeled edges,
//! well-defined structure and well-defined, deterministic (CBOR) encoding of
//! leaf nodes. It is actually represented as a binary Merkle Tree, constructed
//! by converting each internal node of the conceptual representation having
//! more than one child into a binary tree whose left children are all complete
//! binary trees of maximum size.
//!
//! ## Canonical Versions
//!
//! The encoding of the Canonical State must reliably produce identical outputs
//! across all honest replicas in order for state certification to work.
//!
//! But some changes to the protocol (e.g. response rerouting via explicit
//! reject signals in streams) necessarily imply changes to the canonical
//! encoding. This requires the use of versioning (via numbered certification
//! versions) and staged rollouts.
//!
//! Canonical State versioning involves two related but subtly different
//! concepts:
//!
//! * Canonical encoding
//!
//!   Defines the actual structure of the canonical state tree and leaf node
//!   types; and their binary encoding. Two replicas using the same canonical
//!   encoding will produce identical Canonical State trees that encode to the
//!   exact same byte sequence.
//!
//! * Certification version
//!
//!   A combination of default canonical encoding and supported canonical
//!   encodings. Two replicas having different but compatible certification
//!   versions may use the same default canonical encoding and only differ in
//!   their sets of supported canonical encodings; or use different default
//!   canonical encodings but support each other’s default canonical encoding
//!   (so they can be upgraded/downgraded to one another; and communicate over
//!   XNet).
//!
//! Canonical state versioning and staged rollouts are used to ensure backwards
//! and forwards compatibility in a couple of contexts: subnet replica upgrades
//! and XNet communication.
//!
//! ## Versioning and Rollouts
//!
//! Under the core assumption that replica upgrades / downgrades never skip a
//! certification version, the following constraints must be satisfied when
//! changes are made to the canonical encoding:
//!
//! * Newly added canonical state tree branches and leaf type fields must
//!   initially be optional (i.e. nullable) and not populated.
//!
//! * To be removed branches / fields must also be made optional as a first
//!   step (if not already so). To be removed leaf node fields must initially be
//!   converted to optional and always kept in place (or replaced with an
//!   optional `_unused_N` field) in order to preserve field indices (as the
//!   packed CBOR encoding uses indices to identify specific fields).
//!
//! * In order to transparently support replica downgrades, canonical encoding
//!   changes must be staged across two certification versions: the intended
//!   final state as certification version `N+2`; and an intermediate
//!   certification version `N+1` (defined as using the same canonical encoding
//!   as certification version `N`, but having support for producing the
//!   canonical encoding of certification version `N+2`).
//!
//! E.g. when adding a leaf node field:
//!
//! 1. Start from a replica using certification version `N` (no support for the
//!    leaf node field); and implicitly supporting certification version `N+1`
//!    (having, by definition, the same canonical encoding as certification
//!    version `N`).
//!
//! 2. In a single change:
//!
//!    * define the optional field in the respective `ic_canonical_state` type;
//!    * fully implement the logic (e.g. decode the `reject_signals` field and
//!      reroute any `Response` for which a reject signal was received);
//!    * add conditional code to populate the field at versions `N+2` and above;
//!    * bump the default certification version to `N+1` (and, implicitly, the
//!      max supported certification version to `N+2`).
//!
//! 3. Bump the default certification version to `N+2` (with implicit support
//!    for future certification version `N+3`, defined by default as having
//!    identical canonical encoding to `N+2`).
//!
//! This ensures that a downgrade from certification version `N+1` to `N` will
//! succeed because the two canonical encodings are identical. And a downgrade
//! from future certification version `N+2` to `N+1` will succeed because an
//! `N+1` replica has support for encoding a canonical state with certification
//! version `N+2`.
//!
//! On both the forward and the rollback path, subnet replica upgrades (using
//! the respective certification versions) must take place between stages:
//!
//! * On each subnet independently, for subnet-local changes (e.g. changes to
//!   ingress history or canister metadata).
//!
//! * Across all subnets, for streams-related changes. I.e. in specific cases,
//!   it is possible to have more than 2 successive certification versions
//!   deployed across IC subnets, but only as long as the changes are not to
//!   the structure of the `/streams` subtree or its leaf node types.
//!
//! Multiple parallel or interleaved changes are supported by this model, as
//! long as:
//!
//! * The canonical encoding of certification version `N+1` is fully defined
//!   (whether explicitly; or implicitly as identical to certification version
//!   `N`) when certification version `N` is deployed.
//!
//! * The canonical encoding of certification version `N+1` is immutable,
//!   meaning among other things that an in-progress change must be deployed
//!   before any subsequent changes can be made (in a following certification
//!   version).
//!
//! The implementation makes use of a `CURRENT_CERTIFICATION_VERSION` constant
//! (the certification version used by default) and makes an implicit assumption
//! that all certification versions up to and including
//! `CURRENT_CERTIFICATION_VERSION+1` are supported. If the replica is requested
//! to encode a canonical state using a certification version greater than
//! `CURRENT_CERTIFICATION_VERSION+1` it will panic, in order to avoid undefined
//! behavior.
//!
//! ## Version history
//!
//!   0. Initial version.
//!   1. Added canister module hash and controller.
//!   2. Added support for multiple canister controllers.
//!   3. Added subnet to canister ID ranges routing tables.
//!   4. Added optional `Request::cycles_payment` and `Response::cycles_refund`
//!      fields that are not yet populated.
//!   5. Added support for canister metadata custom sections.
//!   6. Encoding of canister metadata custom sections.

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
pub const CURRENT_CERTIFICATION_VERSION: u32 = 6;

/// Maximum supported certification version. Always
/// `CURRENT_CERTIFICATION_VERSION + 1`, since any given canonical state change
/// is either:
///
///  * not yet implemented (true for all future canonical state changes), in
///    which case the canonical encoding of `CURRENT_CERTIFICATION_VERSION + 1`
///    must be identical to that of `CURRENT_CERTIFICATION_VERSION` (with the
///    difference consisting exactly in the fact that that replica is able to
///    produce the `CURRENT_CERTIFICATION_VERSION + 2` canonical encoding); or
///
///  * supported but not enabled, meaning that the canonical encoding for
///    `CURRENT_CERTIFICATION_VERSION + 1` is explicitly supported.
///
/// The replica will panic if requested to certify using a version higher than
/// this.
pub fn max_supported_certification_version() -> u32 {
    CURRENT_CERTIFICATION_VERSION + 1
}
